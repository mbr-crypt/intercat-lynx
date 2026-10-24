"""Administration > Einstellungen: mail server, NVD key, registration, branding."""

import base64

import pytest

from backend.models import AppSetting, AuditEvent, UserRole
from backend.services import branding_service, settings_service
from backend.services.email_service import email_service
from tests.test_auth_2fa import auth
from tests.test_setup_api import _admin_token

# 1x1 pixel images, enough for the magic bytes
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg=="
)
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
WEBP = b"RIFF\x1a\x00\x00\x00WEBPVP8 " + b"\x00" * 16
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'

SMTP = {
    "enabled": True,
    "host": "smtp.example.org",
    "port": 587,
    "security": "starttls",
    "username": "lynx@example.org",
    "password": "geheim-1234",
    "from_email": "lynx@example.org",
    "from_name": "Lynx",
}


@pytest.fixture()
def admin(client, db_session):
    return auth(_admin_token(client, db_session))


def put(client, admin, body):
    return client.put("/api/v1/admin/settings", json=body, headers=admin)


def audit_actions(db_session):
    return [e.action for e in db_session.query(AuditEvent).all()]


# --- access ---


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/v1/admin/settings"),
        ("put", "/api/v1/admin/settings"),
        ("post", "/api/v1/admin/settings/smtp-test"),
        ("put", "/api/v1/admin/settings/branding/logo/light"),
        ("delete", "/api/v1/admin/settings/branding/logo/light"),
    ],
)
def test_settings_need_an_administrator(client, db_session, method, path):
    assert getattr(client, method)(path).status_code in (401, 403)
    token = _admin_token(client, db_session, "viewer1", UserRole.VIEWER)
    assert getattr(client, method)(path, headers=auth(token)).status_code == 403


# --- reading ---


def test_defaults_without_any_entry(client, admin, monkeypatch):
    for name in ("SMTP_HOST", "SMTP_PASSWORD", "NVD_API_KEY", "PUBLIC_URL", "SMTP_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    body = client.get("/api/v1/admin/settings", headers=admin).json()
    assert body["smtp"]["enabled"] is False and body["smtp"]["host"] == ""
    assert body["nvd"] == {"api_key_set": False, "source": "default"}
    assert body["branding"]["name"] == "InterCat Lynx" and body["branding"]["name_is_default"] is True
    assert body["branding"]["logo_light"] is None


def test_shows_where_a_value_comes_from(client, admin, monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "mail.from-env.test")
    monkeypatch.setenv("NVD_API_KEY", "env-key")
    body = client.get("/api/v1/admin/settings", headers=admin).json()
    assert body["smtp"]["host"] == "mail.from-env.test" and body["smtp"]["source"] == "env"
    assert body["nvd"] == {"api_key_set": True, "source": "env"}
    assert put(client, admin, {"smtp": SMTP}).json()["smtp"]["source"] == "db"


def test_secrets_are_never_returned(client, admin, db_session):
    body = put(client, admin, {"smtp": SMTP, "nvd_api_key": "nvd-secret-key"}).json()
    text = str(body)
    assert "geheim-1234" not in text and "nvd-secret-key" not in text
    assert body["smtp"]["password_set"] is True and body["nvd"]["api_key_set"] is True
    # stored encrypted, not as plain text
    stored = db_session.get(AppSetting, "smtp.password")
    assert stored.is_secret and "geheim-1234" not in stored.value
    assert settings_service.get(db_session, "smtp.password") == "geheim-1234"


# --- writing ---


def test_smtp_is_saved_under_the_keys_the_mail_service_reads(client, admin, db_session):
    put(client, admin, {"smtp": SMTP})
    assert settings_service.get(db_session, "smtp.host") == "smtp.example.org"
    assert settings_service.get(db_session, "smtp.enabled") == "true"
    # the keys are exactly the ones EmailService reads (database > environment)
    for key in ("smtp.host", "smtp.port", "smtp.security", "smtp.username", "smtp.from_email", "smtp.from_name"):
        assert settings_service.get(db_session, key) not in (None, ""), key


def test_empty_password_keeps_the_old_one_and_clear_removes_it(client, admin, db_session):
    put(client, admin, {"smtp": SMTP})
    put(client, admin, {"smtp": {**SMTP, "password": None, "port": 465, "security": "ssl"}})
    assert settings_service.get(db_session, "smtp.password") == "geheim-1234"
    assert settings_service.get(db_session, "smtp.port") == "465"
    body = put(client, admin, {"smtp": {**SMTP, "password": None}, "clear_smtp_password": True}).json()
    assert body["smtp"]["password_set"] is False


def test_smtp_needs_host_and_valid_values(client, admin):
    assert put(client, admin, {"smtp": {**SMTP, "host": ""}}).status_code == 422
    assert put(client, admin, {"smtp": {**SMTP, "from_email": "kein-mail"}}).status_code == 422
    assert put(client, admin, {"smtp": {**SMTP, "port": 70000}}).status_code == 422
    assert put(client, admin, {"smtp": {**SMTP, "security": "magic"}}).status_code == 422


def test_nvd_key_set_and_removed(client, admin, db_session, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    assert put(client, admin, {"nvd_api_key": "  abc-123  "}).json()["nvd"]["api_key_set"] is True
    assert settings_service.get(db_session, "nvd.api_key") == "abc-123"
    assert put(client, admin, {"nvd_api_key": ""}).json()["nvd"]["api_key_set"] is False
    # None = unchanged
    put(client, admin, {"nvd_api_key": "abc-123"})
    put(client, admin, {"registration_enabled": True})
    assert settings_service.is_set(db_session, "nvd.api_key")


def test_registration_and_public_url(client, admin, db_session):
    body = put(client, admin, {"registration_enabled": False, "public_url": "https://lynx.example.org/"}).json()
    assert body["registration_enabled"] is False
    assert body["public_url"] == "https://lynx.example.org"  # no trailing slash
    assert settings_service.registration_allowed(db_session) is False
    assert put(client, admin, {"public_url": "javascript:alert(1)"}).status_code == 422
    assert put(client, admin, {"public_url": "lynx.example.org"}).status_code == 422
    assert put(client, admin, {"public_url": ""}).json()["public_url_source"] in ("env", "default")


def test_nothing_is_written_when_one_part_is_invalid(client, admin, db_session):
    r = put(client, admin, {"registration_enabled": False, "branding": {"accent": "#ffff00"}})
    assert r.status_code == 422
    assert settings_service.get(db_session, "registration.enabled") is None


def test_changes_are_audited_without_secrets(client, admin, db_session):
    put(client, admin, {"smtp": SMTP, "nvd_api_key": "nvd-secret-key", "public_url": "https://x.example.org"})
    rows = db_session.query(AuditEvent).all()
    actions = {e.action for e in rows}
    assert {"setting.smtp", "setting.nvd_key", "setting.public_url"} <= actions
    joined = " ".join(e.detail or "" for e in rows)
    assert "geheim-1234" not in joined and "nvd-secret-key" not in joined
    assert "password=changed" in joined


# --- test mail ---


def test_smtp_test_reports_success_and_failure(client, admin, db_session, monkeypatch):
    async def ok(to):
        assert to == "ziel@example.org"
        return True, None

    async def bad(to):
        return False, "SMTPAuthenticationError: 535"

    monkeypatch.setattr(email_service, "send_test_email", ok)
    assert client.post("/api/v1/admin/settings/smtp-test", json={"to": "ziel@example.org"}, headers=admin).json() == {
        "ok": True,
        "error": None,
    }
    monkeypatch.setattr(email_service, "send_test_email", bad)
    r = client.post("/api/v1/admin/settings/smtp-test", json={"to": "ziel@example.org"}, headers=admin).json()
    assert r["ok"] is False and "535" in r["error"]
    assert client.post("/api/v1/admin/settings/smtp-test", json={"to": "nope"}, headers=admin).status_code == 422
    assert audit_actions(db_session).count("setting.smtp_test") == 2


# --- branding ---


def test_public_branding_is_the_default_without_entries(client):
    body = client.get("/api/v1/branding").json()
    assert body["name"] == "InterCat Lynx" and body["custom"] is False
    assert body["accent"] is None and body["logo_light"] is None and body["logo_dark"] is None


def test_branding_texts(client, admin):
    body = put(
        client,
        admin,
        {"branding": {"name": " PERI Threat Desk ", "accent": "#C8102E", "footer_text": "Nur für interne Nutzung", "url": "https://intranet.example.org"}},
    ).json()["branding"]
    assert body["name"] == "PERI Threat Desk" and body["accent"] == "#c8102e"
    pub = client.get("/api/v1/branding").json()
    assert pub["custom"] is True and pub["name"] == "PERI Threat Desk"
    assert pub["footer_text"] == "Nur für interne Nutzung" and pub["url"] == "https://intranet.example.org"
    # back to the defaults
    put(client, admin, {"branding": {"name": "", "accent": "", "footer_text": "", "url": ""}})
    assert client.get("/api/v1/branding").json()["custom"] is False


@pytest.mark.parametrize(
    "branding",
    [
        {"name": "x" * 41},
        {"accent": "rot"},
        {"accent": "#fff"},
        {"accent": "#ffff00"},  # too light for white text
        {"footer_text": "x" * 201},
        {"url": "javascript:alert(1)"},
        {"url": "ftp://example.org"},
        {"url": "https://exa mple.org"},
    ],
)
def test_branding_rejects_bad_values(client, admin, branding):
    assert put(client, admin, {"branding": branding}).status_code == 422


def test_contrast_calculation():
    assert branding_service.contrast_with_white("#000000") == pytest.approx(21, rel=0.01)
    assert branding_service.contrast_with_white("#ffffff") == pytest.approx(1, rel=0.01)
    assert branding_service.contrast_with_white("#2271b3") > 4.5


def test_logo_upload_and_delivery(client, admin):
    r = client.put("/api/v1/admin/settings/branding/logo/light", content=PNG, headers=admin)
    assert r.status_code == 200 and r.json()["branding"]["has_logo_light"] is True
    pub = client.get("/api/v1/branding").json()
    assert pub["logo_light"].startswith("/api/v1/branding/logo/light?v=")
    # only one logo: the dark scheme uses it as well
    assert pub["logo_dark"].startswith("/api/v1/branding/logo/light?v=")
    img = client.get("/api/v1/branding/logo/light")
    assert img.status_code == 200 and img.content == PNG
    assert img.headers["content-type"] == "image/png"
    assert img.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in img.headers["content-security-policy"]
    assert "immutable" in img.headers["cache-control"]
    # a second logo for the dark scheme
    client.put("/api/v1/admin/settings/branding/logo/dark", content=WEBP, headers=admin)
    pub = client.get("/api/v1/branding").json()
    assert "/logo/dark?" in pub["logo_dark"] and "/logo/light?" in pub["logo_light"]
    assert client.get("/api/v1/branding/logo/dark").headers["content-type"] == "image/webp"


def test_logo_changes_the_address_so_browsers_reload(client, admin):
    client.put("/api/v1/admin/settings/branding/logo/light", content=PNG, headers=admin)
    first = client.get("/api/v1/branding").json()["logo_light"]
    client.put("/api/v1/admin/settings/branding/logo/light", content=JPEG, headers=admin)
    assert client.get("/api/v1/branding").json()["logo_light"] != first


@pytest.mark.parametrize("data", [SVG, b"GIF89a....", b"", b"<html>nope</html>", b"MZ\x90\x00"])
def test_logo_refuses_other_files(client, admin, data):
    r = client.put("/api/v1/admin/settings/branding/logo/light", content=data, headers=admin)
    assert r.status_code == 422
    assert client.get("/api/v1/branding/logo/light").status_code == 404


def test_logo_refuses_too_large_and_unknown_variant(client, admin):
    big = PNG + b"\x00" * (branding_service.MAX_LOGO_BYTES + 10)
    assert client.put("/api/v1/admin/settings/branding/logo/light", content=big, headers=admin).status_code in (413, 422)
    assert client.put("/api/v1/admin/settings/branding/logo/evil", content=PNG, headers=admin).status_code == 422
    assert client.get("/api/v1/branding/logo/evil").status_code == 404
    assert client.get("/api/v1/branding/logo/..%2Fsetup").status_code == 404


def test_logo_content_type_is_decided_by_the_bytes_not_the_header(client, admin):
    r = client.put(
        "/api/v1/admin/settings/branding/logo/light",
        content=SVG,
        headers={**admin, "Content-Type": "image/png"},
    )
    assert r.status_code == 422


def test_logo_removal(client, admin):
    client.put("/api/v1/admin/settings/branding/logo/dark", content=PNG, headers=admin)
    r = client.delete("/api/v1/admin/settings/branding/logo/dark", headers=admin)
    assert r.status_code == 200 and r.json()["branding"]["has_logo_dark"] is False
    assert client.get("/api/v1/branding/logo/dark").status_code == 404


def test_damaged_logo_entry_counts_as_missing(client, db_session):
    settings_service.set_value(db_session, "brand.logo_light", "das-ist-kein-base64!!")
    assert client.get("/api/v1/branding/logo/light").status_code == 404
    settings_service.set_value(db_session, "brand.logo_light", base64.b64encode(b"nur text").decode())
    assert client.get("/api/v1/branding/logo/light").status_code == 404


def test_logo_changes_are_audited(client, admin, db_session):
    client.put("/api/v1/admin/settings/branding/logo/light", content=PNG, headers=admin)
    client.delete("/api/v1/admin/settings/branding/logo/light", headers=admin)
    details = [e.detail for e in db_session.query(AuditEvent).filter_by(action="setting.branding")]
    assert "logo_light: uploaded" in details and "logo_light: removed" in details


def test_branding_has_its_own_rate_limit_budget():
    from backend.middleware.redis_rate_limit import STATUS_PATHS

    assert "/api/v1/branding" in STATUS_PATHS
