"""The e-mail address changes only through the verified flow."""

from backend.models import User, UserRole
from backend.security import passwords

PASSWORD = "Sehr-Langes-Passwort-42"


def test_put_me_cannot_change_the_email(client, db_session):
    db_session.add(User(
        email="alice@example.org", username="alice",
        hashed_password=passwords.hash_password(PASSWORD),
        role=UserRole.ANALYST, is_active=True, is_verified=True,
    ))
    db_session.commit()
    token = client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": PASSWORD}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    r = client.put("/api/v1/auth/me", json={"email": "attacker@example.net"}, headers=headers)
    assert r.status_code == 400

    db_session.expire_all()
    user = db_session.query(User).filter(User.username == "alice").one()
    assert user.email == "alice@example.org" and user.is_verified is True

    # a request that carries the unchanged address is harmless
    ok = client.put("/api/v1/auth/me", json={"email": "alice@example.org"}, headers=headers)
    assert ok.status_code == 200
