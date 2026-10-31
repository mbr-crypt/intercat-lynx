"""API tokens must die together with the sessions of their account."""

import pytest

from backend.models import ApiToken, User, UserRole
from backend.security import passwords

PASSWORD = "Sehr-Langes-Passwort-42"
NEW_PASSWORD = "Ganz-Anderes-Passwort-77"
TOKENS = "/api/v1/api-tokens"
ZABBIX = "/api/v1/zabbix/summary"


def h(token):
    return {"Authorization": f"Bearer {token}"}


def make_user(db, username, role=UserRole.ANALYST):
    user = User(
        email=f"{username}@example.org",
        username=username,
        hashed_password=passwords.hash_password(PASSWORD),
        role=role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def jwt_of(client, username, password=PASSWORD):
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture()
def victim(client, db_session):
    user = make_user(db_session, "alice")
    jwt = jwt_of(client, "alice")
    token = client.post(TOKENS, json={"name": "zabbix"}, headers=h(jwt)).json()["token"]
    return user, jwt, token


def _token_count(db_session, user):
    db_session.expire_all()
    return db_session.query(ApiToken).filter(ApiToken.user_id == user.id).count()


def test_own_password_change_revokes_api_tokens(client, db_session, victim):
    user, jwt, token = victim
    r = client.post(
        "/api/v1/auth/change-password",
        json={"old_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers=h(jwt),
    )
    assert r.status_code == 200, r.text
    assert _token_count(db_session, user) == 0
    assert client.get(ZABBIX, headers=h(token)).status_code == 401


def test_admin_revoke_sessions_revokes_api_tokens(client, db_session, victim):
    user, _, token = victim
    make_user(db_session, "root", UserRole.ADMIN)
    admin = jwt_of(client, "root")
    r = client.post(f"/api/v1/admin/users/{user.id}/revoke-sessions", headers=h(admin))
    assert r.status_code == 200, r.text
    assert _token_count(db_session, user) == 0
    assert client.get(ZABBIX, headers=h(token)).status_code == 401


def test_admin_password_reset_revokes_api_tokens(client, db_session, victim):
    user, _, token = victim
    make_user(db_session, "root", UserRole.ADMIN)
    admin = jwt_of(client, "root")
    r = client.post(f"/api/v1/admin/users/{user.id}/reset-password", json={}, headers=h(admin))
    assert r.status_code == 200, r.text
    assert _token_count(db_session, user) == 0
    assert client.get(ZABBIX, headers=h(token)).status_code == 401


def test_token_of_account_with_pending_password_change_is_refused(client, db_session, victim):
    user, _, token = victim
    assert client.get(ZABBIX, headers=h(token)).status_code == 200
    user.must_change_password = True
    db_session.commit()
    assert client.get(ZABBIX, headers=h(token)).status_code == 401
