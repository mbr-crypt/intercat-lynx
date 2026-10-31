"""An e-mail code proves the mailbox once, shortly - not forever."""

from datetime import datetime, timedelta, timezone

import pytest

from backend.models import EmailVerification, User
from backend.services import settings_service

EMAIL = "newbie@example.org"
PW = "Sehr-Langes-Passwort-42"


@pytest.fixture(autouse=True)
def registration_open(db_session):
    settings_service.set_value(db_session, "setup.completed", "true")


def _used_code(db, verified_ago):
    now = datetime.now(timezone.utc)
    db.add(EmailVerification(
        email=EMAIL, code="123456", verification_type="registration", is_used=True,
        created_at=now - verified_ago, expires_at=now + timedelta(minutes=5),
        verified_at=now - verified_ago,
    ))
    db.commit()


def _register(client, username="newbie"):
    return client.post(
        "/api/v1/auth/register", json={"email": EMAIL, "username": username, "password": PW}
    )


def _verified(db):
    db.expire_all()
    return db.query(User).filter(User.email == EMAIL).one().is_verified


def test_fresh_proof_verifies_the_account_and_is_consumed(client, db_session):
    _used_code(db_session, timedelta(minutes=2))
    assert _register(client).status_code == 201
    assert _verified(db_session) is True
    assert db_session.query(EmailVerification).filter_by(email=EMAIL).count() == 0


def test_old_proof_does_not_verify_a_later_registration(client, db_session):
    _used_code(db_session, timedelta(days=40))
    assert _register(client).status_code == 201
    assert _verified(db_session) is False


def test_deleted_account_cannot_be_recreated_as_verified(client, db_session):
    _used_code(db_session, timedelta(minutes=2))
    assert _register(client).status_code == 201
    token = client.post(
        "/api/v1/auth/login", json={"username": "newbie", "password": PW}
    ).json().get("access_token")
    user = db_session.query(User).filter(User.email == EMAIL).one()
    user.is_verified = True  # as after the e-mail step
    db_session.commit()
    assert client.delete("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert _register(client, "newbie2").status_code == 201
    assert _verified(db_session) is False
