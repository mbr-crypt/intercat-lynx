"""The whole site is for signed-in users only."""

import pytest

from backend.dependencies.auth import require_login
from backend.main import app
from tests.test_setup_api import _admin_token
from tests.test_watchlist import h

# Routes that stay open on purpose, with the reason. Everything else needs a
# signed-in user. A new route that is not listed here fails the test below.
OPEN = {
    ("GET", "/"): "API root",
    ("GET", "/health"): "health checks of Docker and monitoring",
    ("GET", "/health/detailed"): "health checks (nginx answers 404 from outside)",
    ("GET", "/health/live"): "health checks",
    ("GET", "/health/ready"): "health checks",
    ("POST", "/api/v1/auth/login"): "sign in",
    ("POST", "/api/v1/auth/login/2fa"): "sign in with second factor",
    ("POST", "/api/v1/auth/register"): "registration (can be switched off in the administration)",
    ("POST", "/api/v1/auth/send-verification-code"): "registration",
    ("POST", "/api/v1/auth/verify-email"): "registration",
    ("GET", "/api/v1/branding"): "the sign-in page needs name, logo and colour",
    ("GET", "/api/v1/branding/logo/{variant}"): "the sign-in page needs the logo",
    ("GET", "/api/v1/csrf-token"): "needed before signing in",
    ("POST", "/api/v1/csrf-token/refresh"): "needed before signing in",
    ("POST", "/api/v1/analytics/track"): "page view counter (also counts the sign-in page)",
    ("POST", "/api/v1/setup/admin"): "setup assistant, protected by the setup token",
    ("GET", "/api/v1/setup/checks"): "setup assistant",
    ("POST", "/api/v1/setup/complete"): "setup assistant",
    ("POST", "/api/v1/setup/import"): "setup assistant",
    ("GET", "/api/v1/setup/import/status"): "setup assistant",
    ("PUT", "/api/v1/setup/settings"): "setup assistant",
    ("POST", "/api/v1/setup/smtp-test"): "setup assistant",
    ("GET", "/api/v1/setup/status"): "tells the frontend whether the setup is still open",
    ("POST", "/api/v1/setup/verify-token"): "setup assistant",
    ("GET", "/api/v1/waitlist/count"): "waitlist of the original, no page uses it (open point)",
    ("POST", "/api/v1/waitlist/join"): "waitlist of the original, rate limited (open point)",
    ("GET", "/api/v1/waitlist/verify"): "waitlist of the original (open point)",
}

# data routes that used to be readable without signing in
FORMER_PUBLIC = [
    "/api/v1/vulnerabilities",
    "/api/v1/vulnerabilities/recent",
    "/api/v1/vulnerabilities/exploited",
    "/api/v1/vulnerabilities/CVE-2026-0001",
    "/api/v1/search?q=test",
    "/api/v1/search/suggest?q=te",
    "/api/v1/stats",
    "/api/v1/stats/trend",
    "/api/v1/stats/timeline",
    "/api/v1/stats/top-vendors",
    "/api/v1/stats/severity-distribution",
    "/api/v1/news/articles",
    "/api/v1/news/sources",
    "/api/v1/news/stats",
    "/api/v1/bsi/advisories",
    "/api/v1/bsi/cve/CVE-2026-0001",
    "/api/v1/feeds/rss",
    "/api/v1/feeds/exploited",
    "/api/v1/feeds/critical",
    "/api/v1/data-sources/list",
    "/api/v1/data-sources/nvd/status",
    "/api/v1/data-sources/cisa-kev/status",
]


@pytest.fixture
def login_required(client):
    """The default test client has the guard switched off; here it is on."""
    app.dependency_overrides.pop(require_login, None)
    yield client


def test_every_route_needs_a_login_except_the_listed_ones():
    open_routes = set()
    for path, operations in app.openapi()["paths"].items():
        for method, operation in operations.items():
            if method in ("get", "post", "put", "patch", "delete") and not operation.get("security"):
                open_routes.add((method.upper(), path))
    unexpected = sorted(open_routes - set(OPEN))
    assert not unexpected, f"Open without login, add a login guard or list it in OPEN with a reason: {unexpected}"
    stale = sorted(set(OPEN) - open_routes)
    assert not stale, f"Listed as open but no longer open or no longer there: {stale}"


@pytest.mark.parametrize("path", FORMER_PUBLIC)
def test_data_is_refused_without_login(login_required, path):
    assert login_required.get(path).status_code in (401, 403)


@pytest.mark.parametrize("path", FORMER_PUBLIC)
def test_a_wrong_token_is_refused(login_required, path):
    assert login_required.get(path, headers=h("not-a-token")).status_code in (401, 403)


def test_a_signed_in_viewer_can_read(login_required, db_session):
    from backend.models import UserRole

    token = _admin_token(login_required, db_session, "reader", UserRole.VIEWER)
    for path in ("/api/v1/vulnerabilities", "/api/v1/stats", "/api/v1/news/articles", "/api/v1/bsi/advisories"):
        assert login_required.get(path, headers=h(token)).status_code == 200, path


def test_sign_in_and_branding_stay_reachable(login_required):
    assert login_required.get("/api/v1/branding").status_code == 200
    assert login_required.get("/api/v1/setup/status").status_code == 200
    assert login_required.get("/health").status_code == 200
