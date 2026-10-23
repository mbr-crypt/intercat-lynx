"""
Every endpoint that needs a login must apply the SAME checks: revoked tokens,
deactivated accounts and "password change required" must not work on the
older endpoints (bookmarks, notifications, comments) either.
"""

from pathlib import Path

import pytest

from tests.test_watchlist import PASSWORD, h, make_user, token_of

# Endpoints that used the old second implementation in utils/auth.py
PROTECTED = ["/api/v1/bookmarks", "/api/v1/notifications", "/api/v1/notifications/unread-count"]


@pytest.fixture()
def user_and_token(client, db_session):
    user = make_user(db_session, "olduser")
    return user, token_of(client, "olduser")


@pytest.mark.parametrize("path", PROTECTED)
def test_valid_token_works(client, user_and_token, path):
    _, token = user_and_token
    assert client.get(path, headers=h(token)).status_code == 200


@pytest.mark.parametrize("path", PROTECTED)
def test_revoked_token_is_rejected(client, db_session, user_and_token, path):
    user, token = user_and_token
    user.token_version += 1  # what "sign out everywhere" / password change does
    db_session.commit()
    assert client.get(path, headers=h(token)).status_code == 401


@pytest.mark.parametrize("path", PROTECTED)
def test_deactivated_account_is_rejected(client, db_session, user_and_token, path):
    user, token = user_and_token
    user.is_active = False
    db_session.commit()
    assert client.get(path, headers=h(token)).status_code in (401, 403)


@pytest.mark.parametrize("path", PROTECTED)
def test_pending_password_change_blocks_everything_else(client, db_session, user_and_token, path):
    user, token = user_and_token
    user.must_change_password = True
    db_session.commit()
    r = client.get(path, headers=h(token))
    assert r.status_code == 403
    assert "Password change required" in r.text


@pytest.mark.parametrize("path", PROTECTED)
def test_2fa_step_token_is_not_a_login(client, db_session, path):
    from datetime import timedelta

    from backend.utils.auth import create_access_token

    user = make_user(db_session, "halfway")
    mfa = create_access_token({"user_id": user.id, "purpose": "mfa"}, expires_delta=timedelta(minutes=5))
    assert client.get(path, headers=h(mfa)).status_code == 401


def test_optional_auth_ignores_revoked_tokens(client, db_session, user_and_token):
    """Public endpoints with optional login treat a dead token as anonymous."""
    from backend.dependencies.auth import optional_user
    from backend.dependencies.auth import HTTPAuthorizationCredentials

    user, token = user_and_token
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    assert optional_user(creds, db_session).id == user.id
    user.token_version += 1
    db_session.commit()
    assert optional_user(creds, db_session) is None


def test_only_one_auth_dependency_exists():
    """The old copy in utils/auth.py (no revocation check, leaked DB sessions) is gone."""
    backend = Path(__file__).resolve().parent.parent / "backend"
    utils_auth = (backend / "utils" / "auth.py").read_text()
    assert "def get_current_user" not in utils_auth
    assert "def get_current_active_user" not in utils_auth
    assert "def get_optional_current_user" not in utils_auth
    assert "next(get_db())" not in utils_auth
    for path in backend.rglob("*.py"):
        text = path.read_text()
        assert "from ..utils.auth import get_current" not in text, path
        assert "from ..utils.auth import get_optional" not in text, path
        assert "utils.auth import get_current_active_user" not in text, path
