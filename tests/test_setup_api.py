"""Setup assistant: protection, root user creation, settings, import, closing."""

import pytest

from backend.models import AppSetting, User, UserRole
from backend.security import totp
from backend.services import import_job, settings_service
from tests.test_auth_2fa import auth, make_user

TOKEN = "unit-test-setup-token"
H = {"X-Setup-Token": TOKEN}
ADMIN = {
    "username": "root",
    "email": "root@example.org",
    "password": "Ein-Sehr-Langes-Passwort-7",
}


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setenv("SETUP_TOKEN", TOKEN)


def test_status_is_public_and_says_setup_required(client):
    r = client.get("/api/v1/setup/status")
    assert r.status_code == 200
    assert r.json() == {"setup_required": True, "admin_exists": False}


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/v1/setup/checks"),
        ("post", "/api/v1/setup/admin"),
        ("put", "/api/v1/setup/settings"),
        ("post", "/api/v1/setup/import"),
        ("post", "/api/v1/setup/complete"),
    ],
)
def test_every_step_needs_the_setup_token(client, method, path):
    kwargs = {} if method == "get" else {"json": {}}
    assert getattr(client, method)(path, **kwargs).status_code == 403
    r = getattr(client, method)(path, headers={"X-Setup-Token": "wrong"}, **kwargs)
    assert r.status_code == 403


def test_system_checks_report_database_and_key(client):
    r = client.get("/api/v1/setup/checks", headers=H)
    assert r.status_code == 200
    names = {c["name"]: c for c in r.json()["checks"]}
    assert names["Datenbank"]["ok"] is True
    assert names["Geheimer Schlüssel (SECRET_KEY)"]["ok"] is True


def test_create_admin_once(client, db_session):
    r = client.post("/api/v1/setup/admin", json=ADMIN, headers=H)
    assert r.status_code == 201, r.text
    assert r.json()["access_token"]
    user = db_session.query(User).filter_by(username="root").one()
    assert user.role == UserRole.ADMIN and user.hashed_password.startswith("$argon2id$")
    again = client.post(
        "/api/v1/setup/admin", json={**ADMIN, "username": "second"}, headers=H
    )
    assert again.status_code == 409


def test_marker_blocks_a_concurrent_second_admin(client, db_session):
    # simulates the losing request of a race: marker row already exists
    db_session.add(AppSetting(key="setup.admin_created", value="x"))
    db_session.commit()
    r = client.post("/api/v1/setup/admin", json=ADMIN, headers=H)
    assert r.status_code == 409
    assert db_session.query(User).count() == 0


@pytest.mark.parametrize(
    "password",
    ["kurz", "Passwort1234", "aaaaaaaaaaaaaaaa", "root-Passwort-root-1"],
)
def test_weak_passwords_are_rejected(client, password, caplog):
    r = client.post("/api/v1/setup/admin", json={**ADMIN, "password": password}, headers=H)
    assert r.status_code == 422
    # the rejected password must not be echoed back or written to the log
    assert password not in r.text
    assert password not in caplog.text


def test_smtp_password_and_nvd_key_are_stored_encrypted_and_not_returned(client, db_session):
    body = {
        "smtp": {
            "host": "mail.example.org",
            "port": 465,
            "security": "ssl",
            "username": "lynx@example.org",
            "password": "mail-secret-pw",
            "from_email": "lynx@example.org",
        },
        "nvd_api_key": "nvd-key-123456",
        "registration_enabled": False,
    }
    r = client.put("/api/v1/setup/settings", json=body, headers=H)
    assert r.status_code == 200
    assert "mail-secret-pw" not in r.text and "nvd-key-123456" not in r.text
    for key in ("smtp.password", "nvd.api_key"):
        row = db_session.get(AppSetting, key)
        assert row.is_secret and "secret" not in row.value and "123456" not in row.value
    assert settings_service.get(db_session, "smtp.password") == "mail-secret-pw"
    assert settings_service.get(db_session, "smtp.host") == "mail.example.org"


def test_invalid_smtp_security_is_rejected(client):
    body = {"smtp": {"host": "h", "security": "plain", "from_email": "a@example.org"}}
    assert client.put("/api/v1/setup/settings", json=body, headers=H).status_code == 422


def test_complete_needs_admin_and_second_factor(client, db_session):
    assert client.post("/api/v1/setup/complete", json={}, headers=H).status_code == 400
    admin = client.post("/api/v1/setup/admin", json=ADMIN, headers=H).json()
    # no 2FA yet -> refused unless explicitly acknowledged
    r = client.post("/api/v1/setup/complete", json={}, headers=H)
    assert r.status_code == 400 and "two-factor" in r.json()["detail"].lower()

    # set up 2FA with the token from the wizard
    token = admin["access_token"]
    s = client.post(
        "/api/v1/auth/2fa/setup", json={"password": ADMIN["password"]}, headers=auth(token)
    ).json()
    ok = client.post(
        "/api/v1/auth/2fa/enable", json={"code": totp.code_at(s["secret"])}, headers=auth(token)
    )
    assert ok.status_code == 200
    assert client.post("/api/v1/setup/complete", json={}, headers=H).json() == {"completed": True}


def test_after_completion_the_assistant_is_gone(client, db_session):
    client.post("/api/v1/setup/admin", json=ADMIN, headers=H)
    client.post("/api/v1/setup/complete", json={"acknowledge_no_2fa": True}, headers=H)
    assert client.get("/api/v1/setup/status").json()["setup_required"] is False
    assert client.get("/api/v1/setup/checks", headers=H).status_code == 404
    assert client.post("/api/v1/setup/verify-token", headers=H).status_code == 404
    assert client.post("/api/v1/setup/admin", json=ADMIN, headers=H).status_code == 404
    assert db_session.get(AppSetting, "setup.token") is None


def test_registration_closed_before_setup_and_follows_choice_after(client, db_session):
    reg = {"email": "x@example.org", "username": "xuser", "password": "Abcdefg1hij"}
    assert client.post("/api/v1/auth/register", json=reg).status_code == 403  # setup open

    client.post("/api/v1/setup/admin", json=ADMIN, headers=H)
    client.put("/api/v1/setup/settings", json={"registration_enabled": False}, headers=H)
    client.post("/api/v1/setup/complete", json={"acknowledge_no_2fa": True}, headers=H)
    assert client.post("/api/v1/auth/register", json=reg).status_code == 403  # admin chose closed


def test_announce_closes_setup_on_installs_that_already_have_an_admin(db_session, session_factory, monkeypatch):
    from backend.api import setup as setup_api

    make_user(db_session, "olduser", role=UserRole.ADMIN)
    monkeypatch.setattr(setup_api, "SessionLocal", session_factory)
    setup_api.announce_setup_token()
    assert settings_service.get(db_session, "setup.completed") == "true"


# --- import job ---------------------------------------------------------------


class FakeNVD:
    progress_callback = None

    def fetch_recent_cves(self, days):
        self.progress_callback(2000, 6000)
        self.progress_callback(6000, 6000)
        return 6000

    def fetch_all_cves(self):
        raise RuntimeError("no internet")


class FakeKEV:
    called = False

    def update_exploited_vulnerabilities(self, db):
        FakeKEV.called = True


def test_import_job_reports_progress_and_finishes(db_session, session_factory):
    status = import_job.run_import(
        session_factory, "recent", 30,
        nvd_factory=FakeNVD, kev_factory=FakeKEV, stats_refresh=lambda db: True,
    )
    assert status["state"] == "done" and status["processed"] == 6000
    assert FakeKEV.called
    db_session.expire_all()
    assert import_job.read_status(db_session)["state"] == "done"


def test_import_job_failure_is_reported_not_raised(db_session, session_factory):
    status = import_job.run_import(
        session_factory, "full", 30,
        nvd_factory=FakeNVD, kev_factory=FakeKEV, stats_refresh=lambda db: True,
    )
    assert status["state"] == "error" and "no internet" in status["message"]


def test_stale_running_import_is_shown_as_interrupted(db_session):
    import json
    from datetime import datetime, timedelta, timezone

    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    settings_service.set_value(
        db_session, import_job.STATUS_KEY,
        json.dumps({"state": "running", "started_at": old, "heartbeat": old}),
    )
    assert import_job.read_status(db_session)["state"] == "interrupted"
