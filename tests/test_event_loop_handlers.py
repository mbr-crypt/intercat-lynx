"""Handlers that do blocking work must not run on the event loop.

An ``async def`` handler executes on the single event loop of its uvicorn
worker. Synchronous SQLAlchemy, DNS lookups, ``requests`` and Celery's
``.get()`` inside it freeze every other request of that worker. A plain ``def``
handler runs in FastAPI's thread pool instead.
"""

import asyncio

import pytest

from backend.api import notification_settings, stats, tasks
from backend.api.v1 import llm
from backend.models import User, UserRole, Vulnerability
from backend.security import passwords

PASSWORD = "Sehr-Langes-Passwort-42"

BLOCKING_HANDLERS = [
    notification_settings.read_settings,
    notification_settings.update_settings,
    notification_settings.renew_webhook_secret,
    notification_settings.send_test,
    stats.get_top_vendors,
    tasks.get_workers_status,
    tasks.get_llm_processing_stats,
    llm.get_processing_stats,
    llm.process_batch,
    llm.process_single_cve,
    llm.get_task_status,
]


@pytest.mark.parametrize("handler", BLOCKING_HANDLERS, ids=lambda f: f"{f.__module__}.{f.__name__}")
def test_blocking_handler_is_not_a_coroutine(handler):
    assert not asyncio.iscoroutinefunction(handler)


def _analyst_headers(client, db_session):
    db_session.add(User(
        email="ana@example.org", username="ana",
        hashed_password=passwords.hash_password(PASSWORD),
        role=UserRole.ANALYST, is_active=True, is_verified=True,
    ))
    db_session.commit()
    token = client.post(
        "/api/v1/auth/login", json={"username": "ana", "password": PASSWORD}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_llm_batch_route_is_reachable(client, db_session, monkeypatch):
    """POST /llm/process/batch used to be swallowed by /llm/process/{cve_id}."""
    queued = {}

    class _Task:
        id = "task-1"

    def fake_delay(**kwargs):
        queued.update(kwargs)
        return _Task()

    monkeypatch.setattr(llm.process_llm_queue, "delay", fake_delay)
    monkeypatch.setattr(
        llm.process_single_cve.__globals__["process_cve_with_llm"],
        "delay",
        lambda cve_id: pytest.fail(f"batch request was treated as CVE id {cve_id!r}"),
    )
    r = client.post(
        "/api/v1/llm/process/batch?batch_size=5&priority=low",
        headers=_analyst_headers(client, db_session),
    )
    assert r.status_code == 200, r.text
    assert queued == {"batch_size": 5, "priority": "low"}


def test_llm_stats_do_not_wait_for_celery(client, db_session, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("stats must not be queued behind the Celery worker")

    monkeypatch.setattr(llm.get_llm_stats, "delay", boom)
    # the task opens its own session; hand it the in-memory test database
    monkeypatch.setattr("backend.tasks.llm_tasks.get_db", lambda: iter([db_session]))
    r = client.get("/api/v1/llm/stats", headers=_analyst_headers(client, db_session))
    assert r.status_code == 200, r.text
    assert "total_cves" in r.json()


def test_top_vendors_limit_is_bounded(client, db_session):
    headers = _analyst_headers(client, db_session)
    assert client.get("/api/v1/stats/top-vendors?limit=100000000", headers=headers).status_code == 422
    assert client.get("/api/v1/stats/top-vendors?limit=0", headers=headers).status_code == 422


def test_top_vendors_counts_and_limits(client, db_session):
    for i, vendors in enumerate([["A", "B"], ["A"], ["A", "C"], ["B"]]):
        db_session.add(Vulnerability(cve_id=f"CVE-2026-9{i:03d}", title="t", vendors=vendors))
    db_session.commit()
    headers = _analyst_headers(client, db_session)
    body = client.get("/api/v1/stats/top-vendors?limit=2", headers=headers).json()
    assert body["vendors"] == [{"name": "A", "count": 3}, {"name": "B", "count": 2}]
