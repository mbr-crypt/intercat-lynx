"""Product selection: catalog, followed products, matching and feed."""

from datetime import datetime, timedelta, timezone

import pytest

from backend.models import ProductCatalog, User, UserRole, Vulnerability, WatchedProduct
from backend.security import passwords
from backend.services import watchlist_service as wl

PASSWORD = "Sehr-Langes-Passwort-42"
BASE = "/api/v1/watchlist"


def make_user(db, username, role=UserRole.VIEWER):
    user = User(
        email=f"{username}@example.org",
        username=username,
        hashed_password=passwords.hash_password(PASSWORD),
        role=role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def token_of(client, username):
    r = client.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def h(token):
    return {"Authorization": f"Bearer {token}"}


NOW = datetime.now(timezone.utc)


def add_cve(db, cve_id, days_ago=1, severity="HIGH", cpes=None, vendors=None, products=None,
            exploited=False, score=7.5):
    vuln = Vulnerability(
        cve_id=cve_id,
        title=f"Title {cve_id}",
        severity=severity,
        cvss_score=score,
        published_at=NOW - timedelta(days=days_ago),
        affected_products=cpes or [],
        vendors=vendors or [],
        products=products or [],
        exploited_in_the_wild=exploited,
    )
    db.add(vuln)
    db.commit()
    return vuln


@pytest.fixture()
def data(db_session):
    """A few CVEs: Fortinet via CPE, Microsoft via CPE, one named only, one old."""
    add_cve(db_session, "CVE-2026-0001", 1, "CRITICAL", exploited=True,
            cpes=["cpe:2.3:o:fortinet:fortios:7.0.1:*:*:*:*:*:*:*"],
            vendors=["Fortinet"], products=["Fortios"])
    add_cve(db_session, "CVE-2026-0002", 3, "MEDIUM",
            cpes=["cpe:2.3:a:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"],
            vendors=["Microsoft"], products=["Windows Server 2022"])
    add_cve(db_session, "CVE-2026-0003", 2, "HIGH", vendors=["Fortinet"], products=["Fortiweb"])
    add_cve(db_session, "CVE-2026-0004", 60, "HIGH",
            cpes=["cpe:2.3:o:fortinet:fortios:6.0:*:*:*:*:*:*:*"])
    add_cve(db_session, "CVE-2026-0005", 1, "LOW",
            cpes=["cpe:2.3:a:forti:other:1.0:*:*:*:*:*:*:*"])
    wl.rebuild_catalog(db_session)
    return db_session


@pytest.fixture()
def alice(client, db_session, data):
    make_user(db_session, "alice", UserRole.ANALYST)
    return token_of(client, "alice")


# --- catalog ---------------------------------------------------------------


def test_catalog_counts_pairs_and_skips_ambiguous_names(db_session):
    add_cve(db_session, "CVE-2026-1001", cpes=["cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*",
                                               "cpe:2.3:a:acme:widget:2:*:*:*:*:*:*:*"])
    add_cve(db_session, "CVE-2026-1002", cpes=["cpe:2.3:a:acme:widget:3:*:*:*:*:*:*:*"])
    # no CPE, exactly one vendor: pairs come from the names
    add_cve(db_session, "CVE-2026-1003", vendors=["Acme"], products=["Gadget Pro"])
    # no CPE, two vendors: products cannot be tied to a vendor, skipped
    add_cve(db_session, "CVE-2026-1004", vendors=["A", "B"], products=["X"])
    result = wl.rebuild_catalog(db_session)
    assert result["vulnerabilities"] == 4
    rows = {(r.vendor, r.product): r.cve_count for r in db_session.query(ProductCatalog)}
    assert rows == {("acme", "widget"): 2, ("acme", "gadget_pro"): 1}


def test_catalog_rebuild_replaces_old_rows(db_session):
    add_cve(db_session, "CVE-2026-1101", cpes=["cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*"])
    wl.rebuild_catalog(db_session)
    wl.rebuild_catalog(db_session)
    assert db_session.query(ProductCatalog).count() == 1


def test_catalog_search_finds_vendor_and_products(client, alice):
    r = client.get(f"{BASE}/catalog", params={"q": "forti"}, headers=h(alice))
    assert r.status_code == 200
    body = r.json()
    assert {v["vendor"] for v in body["vendors"]} == {"fortinet", "forti"}
    assert {(p["vendor"], p["product"]) for p in body["products"]} >= {("fortinet", "fortios")}
    assert body["catalog_size"] > 0
    # blank search returns nothing instead of the whole catalog
    assert client.get(f"{BASE}/catalog", params={"q": " "}, headers=h(alice)).json()["products"] == []


def test_catalog_search_treats_underscore_literally(client, alice):
    body = client.get(f"{BASE}/catalog", params={"q": "windows server"}, headers=h(alice)).json()
    assert [p["product"] for p in body["products"]] == ["windows_server_2022"]
    body = client.get(f"{BASE}/catalog", params={"q": "%"}, headers=h(alice)).json()
    assert body["products"] == []


# --- following products ----------------------------------------------------


def test_requires_login(client):
    for path in ("", "/feed", "/summary", "/catalog?q=x"):
        assert client.get(BASE + path).status_code in (401, 403)


def test_add_list_and_remove(client, alice):
    r = client.post(BASE, json={"vendor": "Fortinet", "product": "FortiOS"}, headers=h(alice))
    assert r.status_code == 201, r.text
    watch = r.json()
    assert (watch["vendor"], watch["product"]) == ("fortinet", "fortios")
    assert watch["label"] == "Fortinet Fortios"
    assert watch["cves_30d"] == 1 and watch["cves_7d"] == 1

    listed = client.get(BASE, headers=h(alice)).json()
    assert [w["id"] for w in listed] == [watch["id"]]
    assert client.delete(f"{BASE}/{watch['id']}", headers=h(alice)).status_code == 204
    assert client.get(BASE, headers=h(alice)).json() == []


def test_follow_whole_vendor_and_duplicates(client, alice):
    assert client.post(BASE, json={"vendor": "microsoft"}, headers=h(alice)).status_code == 201
    assert client.post(BASE, json={"vendor": "microsoft", "product": ""}, headers=h(alice)).status_code == 409
    assert client.post(BASE, json={"vendor": "microsoft", "product": "windows_server_2022"},
                       headers=h(alice)).status_code == 201


def test_unknown_product_is_refused(client, alice):
    r = client.post(BASE, json={"vendor": "nobody", "product": "nothing"}, headers=h(alice))
    assert r.status_code == 404
    r = client.post(BASE, json={"vendor": "fortinet", "product": "nothing"}, headers=h(alice))
    assert r.status_code == 404


def test_limit_per_user(client, db_session, alice, monkeypatch):
    monkeypatch.setattr(wl, "MAX_WATCHES_PER_USER", 1)
    assert client.post(BASE, json={"vendor": "fortinet"}, headers=h(alice)).status_code == 201
    assert client.post(BASE, json={"vendor": "microsoft"}, headers=h(alice)).status_code == 400


def test_lists_are_private(client, db_session, alice):
    make_user(db_session, "bob")
    bob = token_of(client, "bob")
    watch = client.post(BASE, json={"vendor": "fortinet"}, headers=h(alice)).json()
    assert client.get(BASE, headers=h(bob)).json() == []
    assert client.delete(f"{BASE}/{watch['id']}", headers=h(bob)).status_code == 404
    assert client.get(BASE, headers=h(alice)).json()[0]["id"] == watch["id"]


# --- feed and summary --------------------------------------------------------


def follow(client, token, vendor, product=None):
    body = {"vendor": vendor}
    if product:
        body["product"] = product
    assert client.post(BASE, json=body, headers=h(token)).status_code == 201


def feed(client, token, **params):
    r = client.get(f"{BASE}/feed", params=params, headers=h(token))
    assert r.status_code == 200, r.text
    return r.json()


def test_feed_is_empty_without_followed_products(client, alice):
    body = feed(client, alice)
    assert body["total"] == 0 and body["items"] == []


def test_feed_matches_by_cpe_and_by_name(client, alice):
    follow(client, alice, "fortinet")
    body = feed(client, alice, days=30)
    # 0001 by CPE, 0003 by name only; not 0004 (too old), not the vendor "forti"
    assert [i["cve_id"] for i in body["items"]] == ["CVE-2026-0001", "CVE-2026-0003"]
    assert body["items"][0]["products"] == ["Fortinet (all products)"]


def test_feed_product_scope(client, alice):
    follow(client, alice, "fortinet", "fortiweb")
    assert [i["cve_id"] for i in feed(client, alice)["items"]] == ["CVE-2026-0003"]


def test_feed_window_severity_and_exploited_filters(client, alice):
    follow(client, alice, "fortinet")
    assert feed(client, alice, days=90)["total"] == 3
    assert feed(client, alice, days=2)["total"] == 1  # only 0001 (1 day old); 0003 is 2 days old
    assert [i["cve_id"] for i in feed(client, alice, min_severity="critical")["items"]] == ["CVE-2026-0001"]
    assert feed(client, alice, min_severity="HIGH")["total"] == 2
    assert [i["cve_id"] for i in feed(client, alice, exploited_only="true")["items"]] == ["CVE-2026-0001"]
    r = client.get(f"{BASE}/feed", params={"min_severity": "nope"}, headers=h(alice))
    assert r.status_code == 422


def test_feed_pagination(client, alice):
    follow(client, alice, "fortinet")
    first = feed(client, alice, page=1, page_size=1)
    second = feed(client, alice, page=2, page_size=1)
    assert first["total"] == 2 and len(first["items"]) == 1
    assert first["items"][0]["cve_id"] != second["items"][0]["cve_id"]


def test_feed_does_not_confuse_similar_names(client, alice):
    follow(client, alice, "forti")
    assert [i["cve_id"] for i in feed(client, alice)["items"]] == ["CVE-2026-0005"]


def test_underscore_in_product_names_is_not_a_wildcard(client, db_session, alice):
    add_cve(db_session, "CVE-2026-0100", cpes=["cpe:2.3:a:acme:windowsXserver:1:*:*:*:*:*:*:*"])
    add_cve(db_session, "CVE-2026-0101", cpes=["cpe:2.3:a:acme:windows_server:1:*:*:*:*:*:*:*"])
    wl.rebuild_catalog(db_session)
    follow(client, alice, "acme", "windows_server")
    assert [i["cve_id"] for i in feed(client, alice)["items"]] == ["CVE-2026-0101"]


def test_summary_counts(client, db_session, alice):
    add_cve(db_session, "CVE-2026-0006", 0.1, "CRITICAL",
            cpes=["cpe:2.3:o:fortinet:fortios:7.2:*:*:*:*:*:*:*"])
    follow(client, alice, "fortinet")
    follow(client, alice, "microsoft")
    s = client.get(f"{BASE}/summary", headers=h(alice)).json()
    assert s["watch_count"] == 2
    assert s["last_7d"] == {"new": 4, "critical": 2, "high": 1, "exploited": 1}
    assert s["last_24h"] == {"new": 1, "critical": 1, "high": 0, "exploited": 0}


# --- the two matchers must agree --------------------------------------------


def test_sql_and_python_matching_agree(db_session, data):
    vulns = db_session.query(Vulnerability).all()
    watches = [
        WatchedProduct(user_id=1, vendor=v, product=p)
        for v, p in [
            ("fortinet", None), ("fortinet", "fortios"), ("fortinet", "fortiweb"),
            ("microsoft", "windows_server_2022"), ("microsoft", "windows"),
            ("forti", None), ("nobody", "x"),
        ]
    ]
    for w in watches:
        by_sql = {
            v.cve_id for v in db_session.query(Vulnerability).filter(wl.watch_clause(w.vendor, w.product))
        }
        by_python = {v.cve_id for v in vulns if wl.matching_watches(v, [w])}
        assert by_sql == by_python, (w.vendor, w.product, by_sql, by_python)


# --- housekeeping -------------------------------------------------------------


def test_only_admins_rebuild_the_catalog(client, db_session, alice):
    assert client.post(f"{BASE}/catalog/rebuild", headers=h(alice)).status_code == 403
    make_user(db_session, "root", UserRole.ADMIN)
    r = client.post(f"{BASE}/catalog/rebuild", headers=h(token_of(client, "root")))
    assert r.status_code == 200 and r.json()["products"] > 0


def test_deleting_a_user_removes_followed_products(client, db_session, alice):
    follow(client, alice, "fortinet")
    root = make_user(db_session, "root", UserRole.ADMIN)
    token = token_of(client, "root")
    alice_id = db_session.query(User).filter(User.username == "alice").one().id
    r = client.delete(f"/api/v1/admin/users/{alice_id}", headers=h(token))
    assert r.status_code in (200, 204), r.text
    assert db_session.query(WatchedProduct).count() == 0
