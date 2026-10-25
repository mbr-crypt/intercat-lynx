"""
Small robustness items: report of scheduled tasks, setup token printed once,
and the atomic claim that keeps two processes from starting the import twice.
"""

import json
import logging

import pytest

from backend.api import setup as setup_api
from backend.security import attempt_limit
from backend.services import import_job, settings_service, task_activity
from tests.test_setup_api import _admin_token
from tests.test_watchlist import h

# --- scheduled tasks ---------------------------------------------------------


@pytest.fixture
def reporting(monkeypatch, session_factory):
    monkeypatch.setattr(task_activity, "SessionLocal", session_factory)


def entry(db, task_id):
    return {t["id"]: t for t in task_activity.read_all(db)}[task_id]


def test_task_that_never_ran_is_listed(db_session):
    rows = task_activity.read_all(db_session)
    assert {r["id"] for r in rows} == set(task_activity.SCHEDULED)
    assert all(r["state"] == "never" for r in rows)


def test_successful_run_is_reported_with_numbers(db_session, reporting):
    @task_activity.tracked("fetch-nvd-recent")
    def job():
        return {"status": "success", "cves_processed": 42, "timestamp": "x"}

    assert job()["cves_processed"] == 42  # the result passes through unchanged
    e = entry(db_session, "fetch-nvd-recent")
    assert e["state"] == "ok"
    assert "cves processed: 42" in e["message"]
    assert e["finished_at"]


def test_error_result_is_reported(db_session, reporting):
    @task_activity.tracked("send-product-alerts")
    def job():
        return {"status": "error", "message": "boom"}

    job()
    e = entry(db_session, "send-product-alerts")
    assert e["state"] == "error" and e["message"] == "boom"


def test_exception_is_reported_and_raised_again(db_session, reporting):
    class Retry(Exception):
        pass

    @task_activity.tracked("fetch-cisa-kev")
    def job():
        raise Retry("secret detail that must not be shown")

    with pytest.raises(Retry):
        job()
    e = entry(db_session, "fetch-cisa-kev")
    assert e["state"] == "error"
    assert e["message"] == "wird wiederholt"
    assert "secret" not in json.dumps(e)


def test_running_task_is_shown_and_old_run_counts_as_interrupted(db_session):
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    settings_service.set_value(
        db_session, "task.refresh-stats-cache",
        json.dumps({"state": "running", "started_at": now.isoformat()}),
    )
    assert entry(db_session, "refresh-stats-cache")["state"] == "running"
    old = (now - timedelta(hours=5)).isoformat()
    settings_service.set_value(
        db_session, "task.refresh-stats-cache", json.dumps({"state": "running", "started_at": old})
    )
    assert entry(db_session, "refresh-stats-cache")["state"] == "interrupted"


def test_reporting_failure_does_not_break_the_task(monkeypatch):
    def broken():
        raise RuntimeError("database down")

    monkeypatch.setattr(task_activity, "SessionLocal", broken)

    @task_activity.tracked("fetch-cisa-kev")
    def job():
        return {"status": "success"}

    assert job() == {"status": "success"}  # even opening the session may fail


def test_write_errors_are_swallowed(monkeypatch, session_factory):
    class BadSession:
        def __init__(self):
            self.rolled = False

        def rollback(self):
            self.rolled = True

        def close(self):
            pass

        def get(self, *a, **k):
            raise RuntimeError("database down")

    monkeypatch.setattr(task_activity, "SessionLocal", BadSession)

    @task_activity.tracked("fetch-cisa-kev")
    def job():
        return {"status": "success"}

    assert job() == {"status": "success"}


def test_activity_endpoint_lists_scheduled_tasks(client, db_session):
    admin = h(_admin_token(client, db_session))
    body = client.get("/api/v1/admin/activity", headers=admin).json()
    assert [t["id"] for t in body["scheduled"]] == list(task_activity.SCHEDULED)
    assert body["activities"] == []  # the import part is unchanged


# --- setup token printed once -------------------------------------------------


def test_claim_once_without_redis_always_says_yes(monkeypatch):
    monkeypatch.setattr(attempt_limit, "USE_REDIS", False)
    assert attempt_limit.claim_once("x", 60) is True
    assert attempt_limit.claim_once("x", 60) is True


def test_claim_once_with_redis_says_yes_only_once(monkeypatch):
    seen = set()

    class FakeRedis:
        def set(self, key, value, nx=False, ex=None):
            if nx and key in seen:
                return None
            seen.add(key)
            return True

    monkeypatch.setattr(attempt_limit, "_redis", lambda: FakeRedis())
    assert attempt_limit.claim_once("setup-token-announced", 60) is True
    assert attempt_limit.claim_once("setup-token-announced", 60) is False


def test_token_is_logged_by_one_process_only(db_session, session_factory, monkeypatch, caplog):
    monkeypatch.setattr(setup_api, "SessionLocal", session_factory)
    answers = iter([True, False, False, False])
    monkeypatch.setattr(attempt_limit, "claim_once", lambda *a, **k: next(answers))
    with caplog.at_level(logging.WARNING, logger=setup_api.logger.name):
        for _ in range(4):  # 2 replicas x 2 workers
            setup_api.announce_setup_token()
    printed = [r for r in caplog.records if "setup token" in r.getMessage()]
    assert len(printed) == 1
    # all of them still agree on one stored token
    token = settings_service.get(db_session, setup_api.TOKEN_KEY)
    assert token and token in printed[0].getMessage()


# --- atomic start of the import ------------------------------------------------


def test_claim_marks_the_import_as_running_for_everybody_else(db_session, session_factory):
    assert import_job._claim(session_factory) is True
    status = json.loads(settings_service.get(db_session, import_job.STATUS_KEY))
    assert status["state"] == "running" and status["heartbeat"]
    # a second process asking right now is turned away
    assert import_job._claim(session_factory) is False


def test_claim_keeps_the_checkpoint_of_an_interrupted_run(db_session, session_factory):
    from datetime import datetime, timedelta, timezone

    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    settings_service.set_value(
        db_session, import_job.STATUS_KEY,
        json.dumps({"state": "running", "started_at": old, "heartbeat": old, "checkpoint": {"start_index": 4000}}),
    )
    assert import_job._claim(session_factory) is True
    status = json.loads(settings_service.get(db_session, import_job.STATUS_KEY))
    assert status["checkpoint"] == {"start_index": 4000}
