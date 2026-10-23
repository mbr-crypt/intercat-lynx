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


# --- live display: heartbeat, event log, protection against double start -------


def _store_status(db, **fields):
    import json
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    status = {"state": "running", "started_at": now, "heartbeat": now, **fields}
    settings_service.set_value(db, import_job.STATUS_KEY, json.dumps(status))


def test_import_job_keeps_a_heartbeat_while_nothing_else_happens(db_session, session_factory, monkeypatch):
    """A long wait (NVD answers slowly) must still show signs of life."""
    import json
    import time

    monkeypatch.setattr(import_job, "HEARTBEAT_INTERVAL", 0.05)
    seen = []

    class SlowNVD:
        progress_callback = None
        event_callback = None

        def fetch_recent_cves(self, days):
            self.event_callback("Erste Anfrage an die NVD läuft")
            for _ in range(2):
                time.sleep(0.3)
                db = session_factory()
                try:
                    seen.append(json.loads(settings_service.get(db, import_job.STATUS_KEY)))
                finally:
                    db.close()
            self.progress_callback(10, 100, "Seite 1 von 1: 10 von 100 gespeichert")
            return 10

    status = import_job.run_import(
        session_factory, "recent", 7,
        nvd_factory=SlowNVD, kev_factory=FakeKEV, stats_refresh=lambda db: True,
    )
    assert status["state"] == "done"
    assert seen[0]["state"] == seen[1]["state"] == "running"
    assert seen[1]["heartbeat"] > seen[0]["heartbeat"]  # beat although the import did not report
    assert any("NVD" in e["text"] for e in seen[0]["log"])


def test_import_job_event_log_is_limited_and_carries_the_latest_detail(db_session, session_factory):
    class ChattyNVD:
        progress_callback = None
        event_callback = None

        def fetch_recent_cves(self, days):
            for i in range(40):
                self.event_callback(f"Ereignis {i}")
            self.progress_callback(5, 10, "Seite 1 von 1: 5 von 10 gespeichert")

    status = import_job.run_import(
        session_factory, "recent", 7,
        nvd_factory=ChattyNVD, kev_factory=FakeKEV, stats_refresh=lambda db: True,
    )
    texts = [e["text"] for e in status["log"]]
    assert len(texts) == import_job.LOG_LIMIT
    assert texts[-1] == "Import abgeschlossen" and "Ereignis 39" in texts


def test_read_status_adds_elapsed_time_and_age_of_last_heartbeat(db_session):
    import json
    from datetime import datetime, timedelta, timezone

    started = datetime.now(timezone.utc) - timedelta(seconds=125)
    beat = datetime.now(timezone.utc) - timedelta(seconds=7)
    settings_service.set_value(
        db_session, import_job.STATUS_KEY,
        json.dumps({"state": "running", "started_at": started.isoformat(), "heartbeat": beat.isoformat()}),
    )
    status = import_job.read_status(db_session)
    assert status["state"] == "running"
    assert 124 <= status["elapsed_seconds"] <= 130
    assert 6 <= status["seconds_since_heartbeat"] <= 10
    assert status["phases"] == ["nvd", "cisa_kev", "stats", "catalog"]


def test_slow_but_alive_import_is_not_called_interrupted(db_session):
    """Regression: another API process used to report "interrupted" after 3 minutes
    without a progress report, although the import was still working."""
    import json
    from datetime import datetime, timedelta, timezone

    started = datetime.now(timezone.utc) - timedelta(minutes=20)
    beat = datetime.now(timezone.utc) - timedelta(seconds=40)
    settings_service.set_value(
        db_session, import_job.STATUS_KEY,
        json.dumps({"state": "running", "started_at": started.isoformat(), "heartbeat": beat.isoformat()}),
    )
    assert import_job.read_status(db_session)["state"] == "running"


def test_second_start_is_refused_while_another_process_imports(db_session, session_factory, monkeypatch):
    monkeypatch.setattr(import_job, "run_import", lambda *a, **k: None)
    _store_status(db_session)  # fresh heartbeat: a different process is working
    assert import_job.start_in_background(session_factory, "recent", 7) is False
    assert import_job._running is False


def test_start_is_allowed_after_a_dead_import(db_session, session_factory, monkeypatch):
    import json
    import threading
    from datetime import datetime, timedelta, timezone

    done = threading.Event()
    monkeypatch.setattr(import_job, "run_import", lambda *a, **k: done.set())
    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    settings_service.set_value(
        db_session, import_job.STATUS_KEY,
        json.dumps({"state": "running", "started_at": old, "heartbeat": old}),
    )
    assert import_job.start_in_background(session_factory, "recent", 7) is True
    assert done.wait(5)
    for _ in range(100):  # the flag is reset right after the thread function returns
        if not import_job._running:
            break
        threading.Event().wait(0.02)
    assert import_job._running is False


def test_cve_org_lookup_is_skipped_after_repeated_network_failures(monkeypatch):
    """Without internet every lookup would cost 5 s; after 5 failures stop trying."""
    import requests

    from backend.services.nvd_complete_service import NVDCompleteService

    calls, events = [], []

    def broken_get(*args, **kwargs):
        calls.append(args)
        raise requests.exceptions.ConnectTimeout("no route")

    monkeypatch.setattr("backend.services.nvd_complete_service.requests.get", broken_get)
    nvd = NVDCompleteService(api_key="x")
    nvd.event_callback = events.append
    for i in range(20):
        assert nvd._fetch_vendor_product_fallback(f"CVE-2026-{i:04d}") == {}
    assert len(calls) == 5
    assert len(events) == 1 and "cve.org" in events[0]
