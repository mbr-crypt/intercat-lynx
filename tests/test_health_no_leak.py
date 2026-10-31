"""The anonymous health endpoints must not echo driver error text.

A failing database raises messages such as
``connection to server at "10.0.0.5", port 5432 failed: FATAL: password
authentication failed for user "intercat"`` - host, port and user name.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api import health
from backend.database import get_db

SECRET = 'connection to server at "10.0.0.5", port 5432 failed for user "intercat_secret"'


class _BrokenSession:
    def execute(self, *args, **kwargs):
        raise RuntimeError(SECRET)


def _client():
    app = FastAPI()
    app.include_router(health.router)
    app.dependency_overrides[get_db] = lambda: _BrokenSession()
    return TestClient(app)


def test_health_does_not_leak_database_error():
    resp = _client().get("/health")
    assert "intercat_secret" not in resp.text
    assert "10.0.0.5" not in resp.text
    assert resp.json()["database"] == "unhealthy"


def test_detailed_health_does_not_leak_database_error():
    resp = _client().get("/health/detailed")
    assert "intercat_secret" not in resp.text
    assert "10.0.0.5" not in resp.text
    assert resp.json()["checks"]["database"]["status"] == "unhealthy"


def test_readiness_does_not_leak_database_error():
    resp = _client().get("/health/ready")
    assert "intercat_secret" not in resp.text
