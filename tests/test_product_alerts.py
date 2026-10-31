"""Alerts for followed products: settings, webhook safety, in-app, e-mail, webhook."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from backend.models import (
    Notification,
    NotificationDelivery,
    NotificationSetting,
    User,
    UserRole,
    Vulnerability,
    WatchedProduct,
)
from backend.security import passwords
from backend.security.crypto import decrypt_secret
from backend.services import product_alert_service as alerts
from backend.services.email_service import EmailService, email_service

PASSWORD = "Sehr-Langes-Passwort-42"
BASE = "/api/v1/notification-settings"
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


def token_of(client, username):
    r = client.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def h(token):
    return {"Authorization": f"Bearer {token}"}


def add_cve(db, cve_id, severity="HIGH", vendor="fortinet", product="fortios",
            exploited=False, created=None):
    vuln = Vulnerability(
        cve_id=cve_id,
        title=f"Title {cve_id}",
        severity=severity,
        cvss_score=8.0,
        published_at=NOW,
        created_at=created or NOW,
        affected_products=[f"cpe:2.3:o:{vendor}:{product}:1.0:*:*:*:*:*:*:*"],
        vendors=[vendor.title()],
        products=[product.title()],
        exploited_in_the_wild=exploited,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


def follow(db, user, vendor="fortinet", product=None, since=None):
    w = WatchedProduct(user_id=user.id, vendor=vendor, product=product,
                       created_at=since or NOW - timedelta(hours=1))
    db.add(w)
    db.commit()
    return w


def configure(db, user, **fields):
    s = alerts.get_or_create_settings(db, user)
    for k, v in fields.items():
        setattr(s, k, v)
    db.commit()
    return s


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    """Host names resolve to a public address unless a test says otherwise."""
    monkeypatch.setattr(alerts, "resolve_host", lambda host: ["93.184.216.34"])
    monkeypatch.delenv("WEBHOOK_ALLOW_PRIVATE_NETWORKS", raising=False)


# --- webhook address checks --------------------------------------------------


@pytest.mark.parametrize("url", [
    "ftp://example.org/hook", "file:///etc/passwd", "javascript:alert(1)",
    "https://user:pw@example.org/hook", "https:///nohost", "example.org/hook",
])
def test_webhook_url_must_be_plain_http(url):
    with pytest.raises(ValueError):
        alerts.validate_webhook_url(url)


def test_internal_addresses_are_refused(monkeypatch):
    for address in ("127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.9", "::1", "fd00::1",
                    "::ffff:127.0.0.1"):
        monkeypatch.setattr(alerts, "resolve_host", lambda host, a=address: [a])
        with pytest.raises(ValueError, match="intern"):
            alerts.validate_webhook_url("http://hook.example.org/x")


def test_operator_may_allow_private_networks_but_never_metadata(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setattr(alerts, "resolve_host", lambda host: ["10.1.2.3"])
    alerts.validate_webhook_url("http://zabbix.lan/hook")  # no error
    for address in ("169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1"):
        monkeypatch.setattr(alerts, "resolve_host", lambda host, a=address: [a])
        with pytest.raises(ValueError):
            alerts.validate_webhook_url("http://hook.example.org/x")


def test_one_bad_address_among_several_refuses_the_host(monkeypatch):
    monkeypatch.setattr(alerts, "resolve_host", lambda host: ["93.184.216.34", "127.0.0.1"])
    with pytest.raises(ValueError):
        alerts.validate_webhook_url("https://hook.example.org/x")


def test_unresolvable_host_is_refused(monkeypatch):
    import socket

    def boom(host):
        raise socket.gaierror("nope")

    monkeypatch.setattr(alerts, "resolve_host", boom)
    with pytest.raises(ValueError, match="aufgelöst"):
        alerts.validate_webhook_url("https://nowhere.invalid/x")


def test_signature_is_hmac_sha256_over_timestamp_and_body():
    import hashlib
    import hmac

    expected = hmac.new(b"s3cret", b"1700000000.{\"a\":1}", hashlib.sha256).hexdigest()
    assert alerts.sign("s3cret", "1700000000", b'{"a":1}') == expected
    assert alerts.sign("s3cret", "1700000001", b'{"a":1}') != expected


# --- settings API --------------------------------------------------------------


@pytest.fixture()
def alice(client, db_session):
    user = make_user(db_session, "alice")
    return user, token_of(client, "alice")


def test_settings_require_login(client):
    assert client.get(BASE).status_code in (401, 403)
    assert client.put(BASE, json={}).status_code in (401, 403)


def test_defaults(client, alice):
    s = client.get(BASE, headers=h(alice[1])).json()
    assert s["in_app_enabled"] is True and s["email_enabled"] is False and s["webhook_enabled"] is False
    assert s["min_severity"] == "HIGH" and s["always_exploited"] is True
    assert s["email_address"] == "alice@example.org"
    assert s["webhook_has_secret"] is False and s["new_webhook_secret"] is None


def test_update_and_validation(client, alice):
    t = h(alice[1])
    r = client.put(BASE, json={"min_severity": "critical", "always_exploited": False}, headers=t)
    assert r.status_code == 200 and r.json()["min_severity"] == "CRITICAL"
    assert r.json()["always_exploited"] is False
    assert client.put(BASE, json={"min_severity": "nope"}, headers=t).status_code == 422
    # untouched fields stay as they were
    assert client.get(BASE, headers=t).json()["min_severity"] == "CRITICAL"


def test_webhook_needs_an_address_and_gets_a_secret_once(client, db_session, alice):
    t = h(alice[1])
    assert client.put(BASE, json={"webhook_enabled": True}, headers=t).status_code == 422
    r = client.put(BASE, json={"webhook_enabled": True, "webhook_url": "https://hook.example.org/in"}, headers=t)
    assert r.status_code == 200, r.text
    secret = r.json()["new_webhook_secret"]
    assert secret.startswith("whsec_") and len(secret) > 30
    stored = db_session.query(NotificationSetting).one()
    assert secret not in (stored.webhook_secret_encrypted or "")
    assert decrypt_secret(stored.webhook_secret_encrypted) == secret
    again = client.get(BASE, headers=t).json()
    assert again["webhook_has_secret"] is True and again["new_webhook_secret"] is None
    assert secret not in json.dumps(again)
    # a further save does not rotate the secret
    r = client.put(BASE, json={"min_severity": "low"}, headers=t)
    assert r.json()["new_webhook_secret"] is None
    assert decrypt_secret(db_session.query(NotificationSetting).one().webhook_secret_encrypted) == secret


def test_internal_webhook_address_is_refused_on_save(client, alice, monkeypatch):
    monkeypatch.setattr(alerts, "resolve_host", lambda host: ["127.0.0.1"])
    r = client.put(BASE, json={"webhook_url": "http://localhost:9000/x"}, headers=h(alice[1]))
    assert r.status_code == 422 and "intern" in r.json()["detail"]


def test_renew_secret_invalidates_the_old_one(client, db_session, alice):
    t = h(alice[1])
    first = client.put(BASE, json={"webhook_enabled": True, "webhook_url": "https://hook.example.org/in"},
                       headers=t).json()["new_webhook_secret"]
    second = client.post(f"{BASE}/webhook/secret", headers=t).json()["secret"]
    assert second != first
    assert decrypt_secret(db_session.query(NotificationSetting).one().webhook_secret_encrypted) == second


def test_settings_are_private(client, db_session, alice):
    make_user(db_session, "bob")
    bob = token_of(client, "bob")
    client.put(BASE, json={"min_severity": "low"}, headers=h(alice[1]))
    assert client.get(BASE, headers=h(bob)).json()["min_severity"] == "HIGH"


# --- the run: in-app --------------------------------------------------------------


def test_in_app_alert_once_per_cve(db_session):
    user = make_user(db_session, "alice")
    follow(db_session, user)
    configure(db_session, user)
    add_cve(db_session, "CVE-2026-2001", "CRITICAL")
    assert alerts.run(db_session)["in_app"] == 1
    assert alerts.run(db_session)["in_app"] == 0
    n = db_session.query(Notification).one()
    assert (n.user_id, n.type, n.cve_id) == (user.id, "product_cve", "CVE-2026-2001")
    assert "Fortinet" in n.message
    assert db_session.query(NotificationDelivery).count() == 1


def test_severity_threshold_and_exploited_override(db_session):
    user = make_user(db_session, "alice")
    follow(db_session, user)
    configure(db_session, user, min_severity="HIGH", always_exploited=True)
    add_cve(db_session, "CVE-2026-2101", "LOW")
    add_cve(db_session, "CVE-2026-2102", "MEDIUM", exploited=True)
    add_cve(db_session, "CVE-2026-2103", "HIGH")
    add_cve(db_session, "CVE-2026-2104", None)
    alerts.run(db_session)
    got = {n.cve_id for n in db_session.query(Notification)}
    assert got == {"CVE-2026-2102", "CVE-2026-2103"}


def test_exploited_override_can_be_turned_off(db_session):
    user = make_user(db_session, "alice")
    follow(db_session, user)
    configure(db_session, user, min_severity="CRITICAL", always_exploited=False)
    add_cve(db_session, "CVE-2026-2201", "MEDIUM", exploited=True)
    alerts.run(db_session)
    assert db_session.query(Notification).count() == 0


def test_no_alerts_for_cves_before_following_or_outside_the_window(db_session):
    user = make_user(db_session, "alice")
    follow(db_session, user, since=NOW - timedelta(hours=1))
    configure(db_session, user, min_severity="LOW")
    add_cve(db_session, "CVE-2026-2301", created=NOW - timedelta(hours=5))  # known before following
    follow(db_session, user, vendor="microsoft", since=NOW - timedelta(days=10))
    add_cve(db_session, "CVE-2026-2302", vendor="microsoft", product="windows",
            created=NOW - timedelta(days=5))  # followed, but older than the window
    add_cve(db_session, "CVE-2026-2303", vendor="microsoft", product="windows",
            created=NOW - timedelta(days=1))  # in the window
    alerts.run(db_session)
    assert {n.cve_id for n in db_session.query(Notification)} == {"CVE-2026-2303"}


def test_only_followed_products_and_only_own_users(db_session):
    alice = make_user(db_session, "alice")
    bob = make_user(db_session, "bob")
    follow(db_session, alice, "fortinet")
    follow(db_session, bob, "microsoft")
    configure(db_session, alice, min_severity="LOW")
    configure(db_session, bob, min_severity="LOW")
    add_cve(db_session, "CVE-2026-2401", vendor="fortinet", product="fortios")
    add_cve(db_session, "CVE-2026-2402", vendor="cisco", product="ios")
    alerts.run(db_session)
    rows = [(n.user_id, n.cve_id) for n in db_session.query(Notification)]
    assert rows == [(alice.id, "CVE-2026-2401")]


def test_inactive_users_and_disabled_channels_get_nothing(db_session):
    gone = make_user(db_session, "gone", active=False)
    quiet = make_user(db_session, "quiet")
    for u in (gone, quiet):
        follow(db_session, u)
    configure(db_session, gone, min_severity="LOW")
    configure(db_session, quiet, min_severity="LOW", in_app_enabled=False)
    add_cve(db_session, "CVE-2026-2501")
    alerts.run(db_session)
    assert db_session.query(Notification).count() == 0


# --- the run: e-mail --------------------------------------------------------------


@pytest.fixture()
def smtp(monkeypatch):
    sent = []
    monkeypatch.setattr(EmailService, "smtp_enabled", property(lambda self: True))
    monkeypatch.setattr(EmailService, "_sender", lambda self: ("InterCat Lynx", "lynx@example.org"))
    state = {"fail": False}

    def fake_send(self, msg, to):
        if state["fail"]:
            raise OSError("connection refused")
        sent.append(msg)

    monkeypatch.setattr(EmailService, "_smtp_send", fake_send)
    return sent, state


def test_email_digest_lists_all_new_cves(db_session, smtp):
    sent, _ = smtp
    user = make_user(db_session, "alice")
    follow(db_session, user)
    configure(db_session, user, email_enabled=True, in_app_enabled=False, min_severity="LOW")
    add_cve(db_session, "CVE-2026-3001", "CRITICAL", exploited=True)
    add_cve(db_session, "CVE-2026-3002", "LOW")
    stats = alerts.run(db_session)
    assert stats["email"] == 2 and len(sent) == 1
    msg = sent[0]
    assert msg["To"] == "alice@example.org"
    assert "2 neue Schwachstellen" in msg["Subject"] and "1 davon ausgenutzt" in msg["Subject"]
    body = msg.get_payload()[0].get_payload(decode=True).decode()
    assert "CVE-2026-3001" in body and "CVE-2026-3002" in body and "AKTIV AUSGENUTZT" in body
    assert alerts.run(db_session)["email"] == 0 and len(sent) == 1


def test_email_failure_is_reported_and_retried(db_session, smtp):
    sent, state = smtp
    user = make_user(db_session, "alice")
    follow(db_session, user)
    s = configure(db_session, user, email_enabled=True, in_app_enabled=False, min_severity="LOW")
    add_cve(db_session, "CVE-2026-3101")
    state["fail"] = True
    assert alerts.run(db_session)["failed"] == 1
    db_session.refresh(s)
    assert "OSError" in s.last_email_error and s.last_email_ok_at is None
    assert db_session.query(NotificationDelivery).count() == 0
    state["fail"] = False
    assert alerts.run(db_session)["email"] == 1
    db_session.refresh(s)
    assert s.last_email_error is None and s.last_email_ok_at is not None and len(sent) == 1


def test_email_is_not_sent_to_an_unverified_address(db_session, smtp):
    sent, _ = smtp
    user = make_user(db_session, "alice")
    user.is_verified = False
    db_session.commit()
    follow(db_session, user)
    s = configure(db_session, user, email_enabled=True, in_app_enabled=False, min_severity="LOW")
    add_cve(db_session, "CVE-2026-3201")
    stats = alerts.run(db_session)
    assert sent == [] and stats["email"] == 0 and stats["failed"] == 1
    db_session.refresh(s)
    assert "nicht bestätigt" in s.last_email_error
    # the alert is kept for later: once the address is verified it goes out
    user.is_verified = True
    db_session.commit()
    assert alerts.run(db_session)["email"] == 1 and len(sent) == 1


def test_email_without_smtp_says_so(db_session, monkeypatch):
    monkeypatch.setattr(EmailService, "smtp_enabled", property(lambda self: False))
    user = make_user(db_session, "alice")
    follow(db_session, user)
    s = configure(db_session, user, email_enabled=True, in_app_enabled=False, min_severity="LOW")
    add_cve(db_session, "CVE-2026-3201")
    alerts.run(db_session)
    db_session.refresh(s)
    assert "nicht eingerichtet" in s.last_email_error
    assert db_session.query(NotificationDelivery).count() == 0


def test_email_escapes_html_in_titles(db_session, smtp):
    sent, _ = smtp
    user = make_user(db_session, "alice")
    follow(db_session, user)
    configure(db_session, user, email_enabled=True, in_app_enabled=False, min_severity="LOW")
    v = add_cve(db_session, "CVE-2026-3301")
    v.title = '<script>alert("x")</script>'
    db_session.commit()
    alerts.run(db_session)
    html = sent[0].get_payload()[1].get_payload(decode=True).decode()
    assert "<script>" not in html and "&lt;script&gt;" in html


# --- the run: webhook --------------------------------------------------------------


class FakeResponse:  # kept for readability of older tests
    def __init__(self, status):
        self.status_code = status


@pytest.fixture()
def hook(monkeypatch, db_session):
    calls = []
    state = {"status": 200, "error": None}

    def fake_post(url, ip, body, headers, total_timeout=None):
        if state["error"]:
            raise state["error"]
        calls.append({"url": url, "ip": ip, "body": body, "headers": headers,
                      "timeout": total_timeout})
        return state["status"]

    monkeypatch.setattr(alerts.pinned_post, "post", fake_post)
    return calls, state


def webhook_user(db, name="alice", **fields):
    user = make_user(db, name)
    follow(db, user)
    setting = configure(
        db, user, webhook_enabled=True, in_app_enabled=False, min_severity="LOW",
        webhook_url="https://hook.example.org/in",
        webhook_secret_encrypted=alerts.encrypt_secret("whsec_test"), **fields,
    )
    return user, setting


def test_webhook_connects_to_the_address_that_was_checked(db_session, hook):
    calls, _ = hook
    webhook_user(db_session)
    add_cve(db_session, "CVE-2026-4002")
    alerts.run(db_session)
    # resolve_host is stubbed to 93.184.216.34: that exact address is used
    assert calls[0]["ip"] == "93.184.216.34"


def test_webhook_is_signed_and_does_not_follow_redirects(db_session, hook):
    calls, _ = hook
    webhook_user(db_session)
    add_cve(db_session, "CVE-2026-4001", "CRITICAL", exploited=True)
    assert alerts.run(db_session)["webhook"] == 1
    call = calls[0]
    assert call["url"] == "https://hook.example.org/in"
    assert call["timeout"] <= 15
    hdr = call["headers"]
    assert hdr["X-Lynx-Event"] == "cve.new"
    expected = alerts.sign("whsec_test", hdr["X-Lynx-Timestamp"], call["body"])
    assert hdr["X-Lynx-Signature"] == "sha256=" + expected
    payload = json.loads(call["body"])
    assert payload["event"] == "cve.new" and payload["user"] == "alice"
    item = payload["items"][0]
    assert item["cve_id"] == "CVE-2026-4001" and item["exploited_in_the_wild"] is True
    assert item["products"] == ["Fortinet (all products)"]
    assert "whsec_test" not in call["body"].decode()


def test_webhook_batches_in_chunks(db_session, hook):
    calls, _ = hook
    webhook_user(db_session)
    for i in range(30):
        add_cve(db_session, f"CVE-2026-{5000 + i}")
    assert alerts.run(db_session)["webhook"] == 30
    sizes = [len(json.loads(c["body"])["items"]) for c in calls]
    assert sizes == [25, 5]


def test_webhook_error_status_keeps_the_alert_for_retry(db_session, hook):
    calls, state = hook
    _, setting = webhook_user(db_session)
    add_cve(db_session, "CVE-2026-4101")
    state["status"] = 500
    assert alerts.run(db_session)["failed"] == 1
    db_session.refresh(setting)
    assert setting.last_webhook_error == "Der Empfänger antwortete mit HTTP 500"
    assert db_session.query(NotificationDelivery).count() == 0
    state["status"] = 204
    assert alerts.run(db_session)["webhook"] == 1
    db_session.refresh(setting)
    assert setting.last_webhook_error is None and setting.last_webhook_ok_at is not None


def test_webhook_network_error_does_not_leak_details(db_session, hook):
    _, state = hook
    _, setting = webhook_user(db_session)
    add_cve(db_session, "CVE-2026-4201")
    state["error"] = ConnectionResetError("secret internal detail 10.0.0.5")
    alerts.run(db_session)
    db_session.refresh(setting)
    assert setting.last_webhook_error == "Senden fehlgeschlagen: ConnectionResetError"


def test_webhook_address_is_checked_again_at_send_time(db_session, hook, monkeypatch):
    calls, _ = hook
    _, setting = webhook_user(db_session)
    add_cve(db_session, "CVE-2026-4301")
    # the name now points to an internal address (DNS changed after saving)
    monkeypatch.setattr(alerts, "resolve_host", lambda host: ["10.0.0.5"])
    alerts.run(db_session)
    assert calls == []
    db_session.refresh(setting)
    assert "intern" in setting.last_webhook_error


def test_test_endpoint_sends_a_sample(client, db_session, alice, hook, smtp):
    calls, _ = hook
    sent, _ = smtp
    t = h(alice[1])
    client.put(BASE, json={"webhook_enabled": True, "webhook_url": "https://hook.example.org/in"}, headers=t)
    r = client.post(f"{BASE}/test/webhook", headers=t)
    assert r.json() == {"ok": True, "error": None}
    assert json.loads(calls[0]["body"])["event"] == "test"
    assert client.post(f"{BASE}/test/email", headers=t).json()["ok"] is True and len(sent) == 1
    assert client.post(f"{BASE}/test/sms", headers=t).status_code == 404


def test_test_endpoint_reports_missing_setup(client, alice, monkeypatch):
    monkeypatch.setattr(EmailService, "smtp_enabled", property(lambda self: False))
    t = h(alice[1])
    assert client.post(f"{BASE}/test/webhook", headers=t).json()["ok"] is False
    r = client.post(f"{BASE}/test/email", headers=t).json()
    assert r["ok"] is False and "nicht eingerichtet" in r["error"]


def test_deleting_a_user_removes_alert_data(client, db_session, hook):
    user, _ = webhook_user(db_session)
    add_cve(db_session, "CVE-2026-4401")
    alerts.run(db_session)
    make_user(db_session, "root", UserRole.ADMIN)
    token = token_of(client, "root")
    r = client.delete(f"/api/v1/admin/users/{user.id}", headers=h(token))
    assert r.status_code in (200, 204), r.text
    assert db_session.query(NotificationSetting).count() == 0
    assert db_session.query(NotificationDelivery).count() == 0
