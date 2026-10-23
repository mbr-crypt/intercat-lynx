"""API tokens and the read-only Zabbix endpoints."""

from datetime import datetime, timedelta, timezone

import pytest

from backend.models import ApiToken, User, UserRole, Vulnerability, WatchedProduct
from backend.security import passwords
from backend.services import api_token_service as tokens

PASSWORD = "Sehr-Langes-Passwort-42"
TOKENS = "/api/v1/api-tokens"
Z = "/api/v1/zabbix"
NOW = datetime.now(timezone.utc)


def make_user(db, username, role=UserRole.ANALYST, active=True):
    user = User(
        email=f"{username}@example.org",
        username=username,
        hashed_password=passwords.hash_password(PASSWORD),
        role=role,
        is_active=active,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def jwt_of(client, username):
    r = client.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def h(token):
    return {"Authorization": f"Bearer {token}"}


def add_cve(db, cve_id, hours_ago, severity, vendor="fortinet", product="fortios",
            exploited=False, score=7.0):
    db.add(Vulnerability(
        cve_id=cve_id, title=cve_id, severity=severity, cvss_score=score,
        published_at=NOW - timedelta(hours=hours_ago),
        affected_products=[f"cpe:2.3:o:{vendor}:{product}:1:*:*:*:*:*:*:*"],
        vendors=[vendor.title()], products=[product.title()],
        exploited_in_the_wild=exploited,
    ))
    db.commit()


@pytest.fixture()
def alice(client, db_session):
    user = make_user(db_session, "alice")
    return user, jwt_of(client, "alice")


@pytest.fixture()
def monitored(client, db_session, alice):
    """alice follows Fortinet FortiOS and all of Microsoft, and owns a token."""
    user, jwt = alice
    db_session.add_all([
        WatchedProduct(user_id=user.id, vendor="fortinet", product="fortios"),
        WatchedProduct(user_id=user.id, vendor="microsoft", product=None),
    ])
    add_cve(db_session, "CVE-1", 2, "CRITICAL", exploited=True, score=9.8)       # fortios, 24h
    add_cve(db_session, "CVE-2", 30, "HIGH", score=8.1)                           # fortios, 7d only
    add_cve(db_session, "CVE-3", 5, "MEDIUM", vendor="microsoft", product="windows", score=5.5)
    add_cve(db_session, "CVE-4", 24 * 20, "CRITICAL", score=9.9)                  # too old
    add_cve(db_session, "CVE-5", 2, "CRITICAL", vendor="cisco", product="ios")    # not followed
    token = client.post(TOKENS, json={"name": "zabbix"}, headers=h(jwt)).json()["token"]
    return user, token


# --- token management ------------------------------------------------------------


def test_token_management_needs_login(client):
    assert client.get(TOKENS).status_code in (401, 403)
    assert client.post(TOKENS, json={"name": "x"}).status_code in (401, 403)


def test_token_is_shown_once_and_stored_as_hash(client, db_session, alice):
    r = client.post(TOKENS, json={"name": "Zabbix Server"}, headers=h(alice[1]))
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    assert token.startswith("lynx_") and len(token) > 40
    listed = client.get(TOKENS, headers=h(alice[1])).json()
    assert [t["name"] for t in listed] == ["Zabbix Server"]
    assert token not in str(listed) and listed[0]["prefix"] == token[:12]
    row = db_session.query(ApiToken).one()
    assert row.token_hash == tokens.hash_token(token) and token not in str(row.__dict__)


def test_token_limit_name_and_delete(client, db_session, alice, monkeypatch):
    t = h(alice[1])
    assert client.post(TOKENS, json={"name": "  "}, headers=t).status_code == 422
    monkeypatch.setattr(tokens, "MAX_TOKENS_PER_USER", 2)
    ids = [client.post(TOKENS, json={"name": f"t{i}"}, headers=t).json()["info"]["id"] for i in range(2)]
    assert client.post(TOKENS, json={"name": "t3"}, headers=t).status_code == 400
    assert client.delete(f"{TOKENS}/{ids[0]}", headers=t).status_code == 204
    assert client.delete(f"{TOKENS}/{ids[0]}", headers=t).status_code == 404
    assert client.post(TOKENS, json={"name": "t3"}, headers=t).status_code == 201


def test_tokens_are_private(client, db_session, alice):
    make_user(db_session, "bob")
    bob = jwt_of(client, "bob")
    tid = client.post(TOKENS, json={"name": "mine"}, headers=h(alice[1])).json()["info"]["id"]
    assert client.get(TOKENS, headers=h(bob)).json() == []
    assert client.delete(f"{TOKENS}/{tid}", headers=h(bob)).status_code == 404


# --- who may call the Zabbix endpoints ----------------------------------------------


@pytest.mark.parametrize("path", ["/summary", "/products", "/discovery"])
def test_zabbix_endpoints_reject_missing_wrong_and_login_tokens(client, alice, path):
    assert client.get(Z + path).status_code in (401, 403)
    assert client.get(Z + path, headers=h("lynx_nope")).status_code == 401
    assert client.get(Z + path, headers=h("garbage")).status_code == 401
    # a login token is not an API token
    assert client.get(Z + path, headers=h(alice[1])).status_code == 401


def test_api_token_does_not_work_elsewhere(client, monitored):
    token = monitored[1]
    for path in ("/api/v1/watchlist", "/api/v1/auth/me", "/api/v1/notification-settings", TOKENS):
        assert client.get(path, headers=h(token)).status_code in (401, 403), path


def test_expired_token_and_disabled_user(client, db_session, monitored):
    user, token = monitored
    row = db_session.query(ApiToken).one()
    row.expires_at = NOW - timedelta(minutes=1)
    db_session.commit()
    assert client.get(f"{Z}/summary", headers=h(token)).status_code == 401
    row.expires_at = None
    db_session.commit()
    assert client.get(f"{Z}/summary", headers=h(token)).status_code == 200
    user.is_active = False
    db_session.commit()
    assert client.get(f"{Z}/summary", headers=h(token)).status_code == 401


def test_last_used_is_recorded(client, db_session, monitored):
    assert db_session.query(ApiToken).one().last_used_at is None
    client.get(f"{Z}/summary", headers=h(monitored[1]))
    assert db_session.query(ApiToken).one().last_used_at is not None


def test_token_with_expiry_in_days(client, db_session, alice):
    client.post(TOKENS, json={"name": "short", "expires_in_days": 7}, headers=h(alice[1]))
    exp = db_session.query(ApiToken).one().expires_at
    exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
    assert timedelta(days=6) < exp - NOW < timedelta(days=8)


# --- what they report ---------------------------------------------------------------


def test_summary_counts(client, monitored):
    s = client.get(f"{Z}/summary", headers=h(monitored[1])).json()
    assert s == {
        "watch_count": 2,
        "new_24h": 2, "critical_24h": 1, "high_24h": 0, "exploited_24h": 1,
        "new_7d": 3, "critical_7d": 1, "high_7d": 1, "exploited_7d": 1,
        "max_cvss_7d": 9.8,
    }


def test_products_have_one_entry_each(client, monitored):
    items = client.get(f"{Z}/products", headers=h(monitored[1])).json()["items"]
    by_key = {i["key"]: i for i in items}
    assert set(by_key) == {"fortinet:fortios", "microsoft"}
    fos = by_key["fortinet:fortios"]
    assert (fos["vendor"], fos["product"], fos["label"]) == ("fortinet", "fortios", "Fortinet Fortios")
    assert (fos["new_24h"], fos["critical_24h"], fos["new_7d"], fos["high_7d"]) == (1, 1, 2, 1)
    ms = by_key["microsoft"]
    assert ms["product"] == "" and ms["new_7d"] == 1 and ms["max_cvss_7d"] == 5.5


def test_discovery_uses_zabbix_macros(client, monitored):
    body = client.get(f"{Z}/discovery", headers=h(monitored[1])).json()
    assert set(body) == {"data"}
    assert body["data"] == [
        {"{#KEY}": "fortinet:fortios", "{#VENDOR}": "fortinet", "{#PRODUCT}": "fortios",
         "{#LABEL}": "Fortinet Fortios"},
        {"{#KEY}": "microsoft", "{#VENDOR}": "microsoft", "{#PRODUCT}": "",
         "{#LABEL}": "Microsoft (all products)"},
    ]


def test_nothing_followed_gives_zeros_and_empty_lists(client, alice):
    token = client.post(TOKENS, json={"name": "t"}, headers=h(alice[1])).json()["token"]
    assert client.get(f"{Z}/summary", headers=h(token)).json()["new_7d"] == 0
    assert client.get(f"{Z}/products", headers=h(token)).json() == {"items": []}
    assert client.get(f"{Z}/discovery", headers=h(token)).json() == {"data": []}


def test_each_token_reports_only_its_owners_products(client, db_session, monitored):
    bob = make_user(db_session, "bob")
    db_session.add(WatchedProduct(user_id=bob.id, vendor="cisco", product=None))
    db_session.commit()
    token = client.post(TOKENS, json={"name": "b"}, headers=h(jwt_of(client, "bob"))).json()["token"]
    keys = [i["key"] for i in client.get(f"{Z}/products", headers=h(token)).json()["items"]]
    assert keys == ["cisco"]


def test_deleting_a_user_removes_tokens(client, db_session, monitored):
    make_user(db_session, "root", UserRole.ADMIN)
    r = client.delete(f"/api/v1/admin/users/{monitored[0].id}", headers=h(jwt_of(client, "root")))
    assert r.status_code in (200, 204), r.text
    assert db_session.query(ApiToken).count() == 0
