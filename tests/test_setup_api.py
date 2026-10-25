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

    def fetch_recent_cves(self, days, **kw):
        self.progress_callback(2000, 6000)
        self.progress_callback(6000, 6000)
        return 6000

    def fetch_all_cves(self, **kw):
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

        def fetch_recent_cves(self, days, **kw):
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

        def fetch_recent_cves(self, days, **kw):
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

    nvd = NVDCompleteService(api_key="x")
    monkeypatch.setattr(nvd._org_session, "get", broken_get)
    nvd.event_callback = events.append
    for i in range(20):
        assert nvd._fetch_vendor_product_fallback(f"CVE-2026-{i:04d}") == {}
    assert len(calls) == 5
    assert len(events) == 1 and "cve.org" in events[0]


# --- activity display for administrators (after the setup assistant is closed) ---


def _admin_token(client, db_session, username="root", role=UserRole.ADMIN):
    make_user(db_session, username, role=role)
    r = client.post("/api/v1/auth/login", json={"username": username, "password": "Sehr-Langes-Passwort-42"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_activity_needs_an_administrator(client, db_session):
    assert client.get("/api/v1/admin/activity").status_code in (401, 403)
    token = _admin_token(client, db_session, "viewer1", UserRole.VIEWER)
    assert client.get("/api/v1/admin/activity", headers=auth(token)).status_code == 403
    assert client.post("/api/v1/admin/import", json={"mode": "recent"}, headers=auth(token)).status_code == 403


def test_activity_is_empty_without_an_import(client, db_session):
    token = _admin_token(client, db_session)
    r = client.get("/api/v1/admin/activity", headers=auth(token))
    assert r.status_code == 200
    body = r.json()
    assert body["activities"] == [] and body["running"] is False
    assert all(t["state"] == "never" for t in body["scheduled"])


def test_activity_shows_the_running_import_with_progress(client, db_session):
    token = _admin_token(client, db_session)
    _store_status(
        db_session, mode="recent", days=7, phase="nvd", processed=1250, total=4310,
        detail="Seite 1 von 3: 250 von 2000 gespeichert",
        log=[{"t": "2026-10-24T10:00:00+00:00", "text": "Import gestartet"}],
    )
    body = client.get("/api/v1/admin/activity", headers=auth(token)).json()
    assert body["running"] is True
    (item,) = body["activities"]
    assert item["id"] == "import" and item["title"] == "Datenimport, letzte 7 Tage"
    assert item["state"] == "running" and item["processed"] == 1250 and item["total"] == 4310
    assert item["log"][0]["text"] == "Import gestartet"
    assert "elapsed_seconds" in item and "seconds_since_heartbeat" in item


def test_activity_reports_a_dead_import_as_interrupted_not_running(client, db_session):
    import json
    from datetime import datetime, timedelta, timezone

    token = _admin_token(client, db_session)
    old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    settings_service.set_value(
        db_session, import_job.STATUS_KEY,
        json.dumps({"state": "running", "mode": "full", "started_at": old, "heartbeat": old}),
    )
    body = client.get("/api/v1/admin/activity", headers=auth(token)).json()
    assert body["running"] is False
    assert body["activities"][0]["state"] == "interrupted"
    assert body["activities"][0]["title"] == "Datenimport, kompletter Bestand"


def test_admin_can_start_an_import_and_it_is_logged(client, db_session, session_factory, monkeypatch):
    from backend.models import AuditEvent

    started = []
    monkeypatch.setattr(
        import_job, "start_in_background", lambda factory, mode, days, resume=None: started.append((mode, days)) or True
    )
    token = _admin_token(client, db_session)
    r = client.post("/api/v1/admin/import", json={"mode": "recent", "days": 14}, headers=auth(token))
    assert r.status_code == 200 and r.json() == {"started": True}
    assert started == [("recent", 14)]
    event = db_session.query(AuditEvent).filter_by(action="import.started").one()
    assert event.actor_username == "root" and event.detail == "mode=recent days=14"


def test_second_import_start_is_refused_with_409(client, db_session, monkeypatch):
    monkeypatch.setattr(import_job, "start_in_background", lambda *a, **k: False)
    token = _admin_token(client, db_session)
    r = client.post("/api/v1/admin/import", json={"mode": "full"}, headers=auth(token))
    assert r.status_code == 409


@pytest.mark.parametrize("body", [{"mode": "skip"}, {"mode": "bogus"}, {"mode": "recent", "days": 0}, {"mode": "recent", "days": 500}])
def test_import_request_is_validated(client, db_session, monkeypatch, body):
    monkeypatch.setattr(import_job, "start_in_background", lambda *a: True)
    token = _admin_token(client, db_session)
    assert client.post("/api/v1/admin/import", json=body, headers=auth(token)).status_code == 422


# --- import speed: cve.org lookups, timings, estimate, resume ---------------------


def _nvd_record(cve_id, with_cpe=False):
    cve = {
        "id": cve_id,  # no dates: the in-memory SQLite test database does not accept ISO strings
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {},
    }
    if with_cpe:
        cve["configurations"] = [
            {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}]}]}
        ]
    return {"cve": cve}


def _nvd_with_pages(monkeypatch, db_session, pages, lookup=None):
    """An NVD service whose API answers are `pages` and whose database is the test database."""
    from backend.services import nvd_complete_service as module

    monkeypatch.setattr(module, "get_db", lambda: iter([db_session]))
    monkeypatch.setattr(module.time, "sleep", lambda s: None)
    monkeypatch.setattr(module, "refresh_stats_cache", lambda db: None)
    nvd = module.NVDCompleteService(api_key="x")
    nvd.RESULTS_PER_PAGE = 2
    answers = iter(pages)
    requested = []

    class Response:
        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self.body

    def get(url, params=None, timeout=None):
        requested.append(dict(params))
        return Response(next(answers))

    monkeypatch.setattr(nvd.session, "get", get)
    asked = []

    def fallback(cve_id):
        asked.append(cve_id)
        return (lookup or {}).get(cve_id, {})

    nvd._fetch_vendor_product_fallback = fallback
    nvd.events = []
    nvd.event_callback = nvd.events.append
    return nvd, requested, asked


def test_cve_org_is_asked_only_for_cves_without_known_products(monkeypatch, db_session):
    from backend.models import Vulnerability

    db_session.add(
        Vulnerability(cve_id="CVE-2026-0002", title="t", vendors=["acme"], products=["widget"], sources=["nvd"])
    )
    db_session.commit()
    page = {
        "totalResults": 4,
        "vulnerabilities": [
            _nvd_record("CVE-2026-0001"),  # new, no product known: ask
            _nvd_record("CVE-2026-0002"),  # already stored with products: do not ask
            _nvd_record("CVE-2026-0003", with_cpe=True),  # NVD names a product: do not ask
            _nvd_record("CVE-2026-0004"),  # new, no product known: ask
        ],
    }
    nvd, _, asked = _nvd_with_pages(
        monkeypatch, db_session, [page], lookup={"CVE-2026-0001": {"Acme": {"Widget"}}}
    )
    nvd.RESULTS_PER_PAGE = 4
    assert nvd.fetch_recent_cves(days=1) == 4
    assert sorted(asked) == ["CVE-2026-0001", "CVE-2026-0004"]
    stored = db_session.query(Vulnerability).filter_by(cve_id="CVE-2026-0001").one()
    assert stored.vendors == ["Acme"] and stored.products == ["Widget"]
    kept = db_session.query(Vulnerability).filter_by(cve_id="CVE-2026-0002").one()
    assert kept.products == ["widget"]  # the stored product survived without a new lookup


def test_cve_org_lookups_run_in_parallel(monkeypatch, db_session):
    import threading
    import time as real_time

    nvd, _, _ = _nvd_with_pages(monkeypatch, db_session, [])
    seen, lock = set(), threading.Lock()

    def slow(cve_id):
        with lock:
            seen.add(threading.current_thread().name)
        real_time.sleep(0.05)
        return {}

    nvd._fetch_vendor_product_fallback = slow
    records = [_nvd_record(f"CVE-2026-{i:04d}") for i in range(1, 17)]
    started = real_time.monotonic()
    answers, count, seconds = nvd._prefetch_fallbacks(records, {})
    took = real_time.monotonic() - started
    assert count == 16 and len(answers) == 16
    assert len(seen) > 1  # several workers
    assert took < 16 * 0.05 * 0.6  # clearly faster than one after the other


def test_page_events_show_where_the_time_goes(monkeypatch, db_session):
    page = {"totalResults": 2, "vulnerabilities": [_nvd_record("CVE-2026-0001"), _nvd_record("CVE-2026-0002")]}
    nvd, _, _ = _nvd_with_pages(monkeypatch, db_session, [page])
    nvd.fetch_recent_cves(days=1)
    text = " | ".join(nvd.events)
    assert "NVD antwortete in" in text
    assert "gespeichert in" in text and "cve.org: 2 Abfragen" in text


def test_statistics_are_not_recalculated_after_every_page(monkeypatch, db_session):
    from backend.services import nvd_complete_service as module

    pages = [
        {"totalResults": 4, "vulnerabilities": [_nvd_record("CVE-2026-0001", True), _nvd_record("CVE-2026-0002", True)]},
        {"totalResults": 4, "vulnerabilities": [_nvd_record("CVE-2026-0003", True), _nvd_record("CVE-2026-0004", True)]},
    ]
    nvd, _, _ = _nvd_with_pages(monkeypatch, db_session, pages)
    calls = []
    monkeypatch.setattr(module, "refresh_stats_cache", lambda db: calls.append(1))
    nvd.fetch_recent_cves(days=1)
    assert len(calls) == 1  # only the final one, not one per page


def test_resume_point_is_reported_after_each_page_and_used_again(monkeypatch, db_session):
    pages = [
        {"totalResults": 4, "vulnerabilities": [_nvd_record("CVE-2026-0001", True), _nvd_record("CVE-2026-0002", True)]},
        {"totalResults": 4, "vulnerabilities": [_nvd_record("CVE-2026-0003", True), _nvd_record("CVE-2026-0004", True)]},
    ]
    nvd, requested, _ = _nvd_with_pages(monkeypatch, db_session, pages)
    points = []
    nvd.checkpoint_callback = points.append
    nvd.fetch_recent_cves(days=1)
    assert [p["start_index"] for p in points] == [2, 4]
    assert points[0]["mod_start"] == requested[0]["lastModStartDate"]

    # a new run continues with the same time window and position
    nvd2, requested2, _ = _nvd_with_pages(monkeypatch, db_session, [pages[1]])
    nvd2.fetch_recent_cves(days=1, resume=points[0])
    assert requested2[0]["startIndex"] == 2
    assert requested2[0]["lastModStartDate"] == points[0]["mod_start"]
    assert requested2[0]["lastModEndDate"] == points[0]["mod_end"]


def test_cve_org_lookup_is_switched_on_again_for_a_new_run(monkeypatch, db_session):
    nvd, _, _ = _nvd_with_pages(monkeypatch, db_session, [{"totalResults": 0, "vulnerabilities": []}])
    nvd._fallback_errors = 5  # an earlier run saw network problems
    nvd.fetch_recent_cves(days=1)
    assert nvd._fallback_errors == 0


def test_throttled_cve_org_reduces_the_parallel_requests(monkeypatch, db_session):
    nvd, _, _ = _nvd_with_pages(monkeypatch, db_session, [])

    def throttled(cve_id):
        nvd._throttled += 1
        return {}

    nvd._fetch_vendor_product_fallback = throttled
    nvd._prefetch_fallbacks([_nvd_record("CVE-2026-0001")], {})
    assert nvd._fallback_workers == nvd.FALLBACK_WORKERS // 2
    assert any("bremst" in e for e in nvd.events)


def test_eta_is_computed_from_speed_and_dropped_when_the_phase_changes(db_session, session_factory, monkeypatch):
    monkeypatch.setattr(import_job, "ETA_MIN_SECONDS", 30.0)
    monkeypatch.setattr(import_job, "ETA_MIN_ITEMS", 50)
    now = {"t": 0.0}
    monkeypatch.setattr(import_job.time, "monotonic", lambda: now["t"])
    reporter = import_job._Reporter(session_factory, {"state": "running"})
    reporter.progress(100, 1100)  # baseline
    now["t"] = 10.0
    reporter.progress(200, 1100)
    assert "eta_seconds" not in reporter._status  # too early to say
    now["t"] = 40.0
    reporter.progress(400, 1100)  # 300 items in 40 s = 7.5/s, 700 left -> ~93 s
    assert 90 <= reporter._status["eta_seconds"] <= 96
    reporter.update(phase="cisa_kev")
    assert "eta_seconds" not in reporter._status


def test_interrupted_import_can_be_resumed_where_it_stopped(db_session, session_factory):
    import json
    from datetime import datetime, timedelta, timezone

    class StoppingNVD:
        progress_callback = event_callback = checkpoint_callback = None

        def fetch_recent_cves(self, days, **kw):
            self.checkpoint_callback({"mod_start": "A", "mod_end": "B", "start_index": 2000})
            raise RuntimeError("Verbindung weg")

    import_job.run_import(
        session_factory, "recent", 7, nvd_factory=StoppingNVD, kev_factory=FakeKEV, stats_refresh=lambda db: True
    )
    status = import_job.read_status(db_session)
    assert status["state"] == "error" and status["can_resume"] is True
    point = import_job.resume_point(db_session)
    assert point == {"mode": "recent", "days": 7, "checkpoint": {"mod_start": "A", "mod_end": "B", "start_index": 2000}}

    received = {}

    class ContinuingNVD:
        progress_callback = event_callback = checkpoint_callback = None

        def fetch_recent_cves(self, days, resume=None):
            received["resume"] = resume
            return 1

    final = import_job.run_import(
        session_factory, "recent", 7, nvd_factory=ContinuingNVD, kev_factory=FakeKEV,
        stats_refresh=lambda db: True, resume=point["checkpoint"],
    )
    assert received["resume"] == point["checkpoint"]
    assert final["state"] == "done" and final.get("resumed") is True
    db_session.expire_all()
    assert import_job.read_status(db_session)["can_resume"] is False  # finished: nothing to resume

    # a finished or never started import offers nothing to resume
    assert import_job.resume_point(db_session) is None


def test_full_import_does_not_use_a_checkpoint_file(db_session, session_factory):
    seen = {}

    class FullNVD:
        progress_callback = event_callback = checkpoint_callback = None

        def fetch_all_cves(self, **kw):
            seen.update(kw)
            return 1

    import_job.run_import(
        session_factory, "full", 30, nvd_factory=FullNVD, kev_factory=FakeKEV, stats_refresh=lambda db: True
    )
    assert seen == {"checkpoint_file": None}  # a stale file must not silently resume a new run


def test_kev_result_is_written_to_the_event_log(db_session, session_factory):
    class ReportingKEV:
        event_callback = None

        def update_exploited_vulnerabilities(self, db):
            return {"status": "success", "updated": 1700, "created": 1640, "not_found": 1640}

    status = import_job.run_import(
        session_factory, "recent", 1, nvd_factory=FakeNVD, kev_factory=ReportingKEV, stats_refresh=lambda db: True
    )
    assert any("1700" in e["text"] and "1640 neu angelegt" in e["text"] for e in status["log"])


def test_admin_can_resume_an_interrupted_import(client, db_session, session_factory, monkeypatch):
    import json
    from datetime import datetime, timedelta, timezone

    token = _admin_token(client, db_session)
    monkeypatch.setattr(import_job, "run_import", lambda *a, **k: None)
    # nothing to resume yet
    r = client.post("/api/v1/admin/import", json={"mode": "recent", "resume": True}, headers=auth(token))
    assert r.status_code == 409

    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    settings_service.set_value(
        db_session, import_job.STATUS_KEY,
        json.dumps({
            "state": "running", "mode": "full", "days": 30, "phase": "nvd", "started_at": old, "heartbeat": old,
            "checkpoint": {"start_index": 4000},
        }),
    )
    activity = client.get("/api/v1/admin/activity", headers=auth(token)).json()["activities"][0]
    assert activity["state"] == "interrupted" and activity["can_resume"] is True

    started = {}
    monkeypatch.setattr(
        "backend.api.admin.import_job.start_in_background",
        lambda factory, mode, days, resume=None: started.update(mode=mode, days=days, resume=resume) or True,
    )
    r = client.post("/api/v1/admin/import", json={"mode": "recent", "resume": True}, headers=auth(token))
    assert r.status_code == 200
    assert started == {"mode": "full", "days": 30, "resume": {"start_index": 4000}}  # taken from the old run
