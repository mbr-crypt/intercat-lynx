"""Login, Argon2id upgrade and two-factor authentication through the API."""

import pytest
from passlib.hash import bcrypt

from backend.models import User, UserRole
from backend.security import passwords, totp

PASSWORD = "Sehr-Langes-Passwort-42"


def make_user(db, username="alice", password=PASSWORD, hashed=None, role=UserRole.ADMIN):
    user = User(
        email=f"{username}@example.org",
        username=username,
        hashed_password=hashed or passwords.hash_password(password),
        role=role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def login(client, username="alice", password=PASSWORD):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def enable_2fa(client, db, token, password=PASSWORD):
    r = client.post("/api/v1/auth/2fa/setup", json={"password": password}, headers=auth(token))
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    assert r.json()["qr_svg"].lstrip().startswith("<svg")
    r = client.post(
        "/api/v1/auth/2fa/enable", json={"code": totp.code_at(secret)}, headers=auth(token)
    )
    assert r.status_code == 200, r.text
    return secret, r.json()["recovery_codes"]


def test_login_without_2fa_returns_token(client, db_session):
    make_user(db_session)
    r = login(client)
    assert r.status_code == 200
    assert r.json()["access_token"] and not r.json()["mfa_required"]


def test_wrong_password_and_unknown_user_look_identical(client, db_session):
    make_user(db_session)
    a = login(client, password="falsch-falsch-1")
    b = login(client, username="nobody")
    assert a.status_code == b.status_code == 401
    assert a.json()["detail"] == b.json()["detail"]


def test_legacy_bcrypt_hash_is_upgraded_on_login(client, db_session):
    user = make_user(db_session, hashed=bcrypt.hash(PASSWORD))
    assert user.hashed_password.startswith("$2")
    assert login(client).status_code == 200
    db_session.refresh(user)
    assert user.hashed_password.startswith("$argon2id$")
    assert login(client).status_code == 200  # still works after upgrade


def test_account_locks_after_five_failures(client, db_session):
    make_user(db_session)
    for _ in range(5):
        assert login(client, password="falsch-falsch-1").status_code == 401
    assert login(client).status_code == 403  # even the right password is refused


def test_full_2fa_lifecycle(client, db_session):
    user = make_user(db_session)
    token = login(client).json()["access_token"]
    secret, recovery = enable_2fa(client, db_session, token)

    # secret is stored encrypted, not in clear
    db_session.refresh(user)
    assert user.totp_enabled and secret not in user.totp_secret_enc

    # password alone no longer yields an access token
    r = login(client)
    assert r.json()["mfa_required"] is True and r.json()["access_token"] is None
    mfa_token = r.json()["mfa_token"]

    # the mfa token must not work as a login token
    assert client.get("/api/v1/auth/me", headers=auth(mfa_token)).status_code == 401

    # wrong code rejected, right code accepted
    bad = client.post("/api/v1/auth/login/2fa", json={"mfa_token": mfa_token, "code": "000000"})
    assert bad.status_code == 401
    code = totp.code_at(secret)
    # the enabling code was already consumed -> replay refused
    replay = client.post("/api/v1/auth/login/2fa", json={"mfa_token": mfa_token, "code": code})
    assert replay.status_code == 401

    # a recovery code works exactly once
    ok = client.post(
        "/api/v1/auth/login/2fa", json={"mfa_token": mfa_token, "code": recovery[0]}
    )
    assert ok.status_code == 200 and ok.json()["access_token"]
    again = client.post(
        "/api/v1/auth/login/2fa", json={"mfa_token": mfa_token, "code": recovery[0]}
    )
    assert again.status_code == 401
    assert client.get("/api/v1/auth/me", headers=auth(ok.json()["access_token"])).json()[
        "totp_enabled"
    ] is True


def test_2fa_attempts_count_towards_lockout(client, db_session):
    user = make_user(db_session)
    token = login(client).json()["access_token"]
    enable_2fa(client, db_session, token)
    mfa_token = login(client).json()["mfa_token"]
    # The lockout does not apply to the address of the last login (so it cannot
    # be used to lock the real user out); simulate a guess from elsewhere.
    user.last_login_ip = None
    db_session.commit()
    for _ in range(5):
        r = client.post("/api/v1/auth/login/2fa", json={"mfa_token": mfa_token, "code": "111111"})
        assert r.status_code == 401
    r = client.post("/api/v1/auth/login/2fa", json={"mfa_token": mfa_token, "code": "111111"})
    assert r.status_code == 403


def test_setup_requires_password_and_disable_requires_code(client, db_session):
    make_user(db_session)
    token = login(client).json()["access_token"]
    r = client.post("/api/v1/auth/2fa/setup", json={"password": "wrong-wrong-1"}, headers=auth(token))
    assert r.status_code == 403
    _, recovery = enable_2fa(client, db_session, token)
    r = client.post(
        "/api/v1/auth/2fa/disable",
        json={"password": PASSWORD, "code": "123456"},
        headers=auth(token),
    )
    assert r.status_code == 403
    r = client.post(
        "/api/v1/auth/2fa/disable",
        json={"password": PASSWORD, "code": recovery[1]},
        headers=auth(token),
    )
    assert r.status_code == 200
    assert login(client).json()["access_token"]


def test_admin_can_reset_2fa_of_other_user(client, db_session):
    make_user(db_session, "admin1")
    victim = make_user(db_session, "bob", role=UserRole.VIEWER)
    bob_token = login(client, "bob").json()["access_token"]
    enable_2fa(client, db_session, bob_token)
    admin_token = login(client, "admin1").json()["access_token"]
    r = client.put(f"/api/v1/auth/users/{victim.id}/reset-2fa", headers=auth(admin_token))
    assert r.status_code == 200
    assert login(client, "bob").json()["access_token"]
    # a normal user may not do this
    r = client.put(f"/api/v1/auth/users/{victim.id}/reset-2fa", headers=auth(bob_token))
    assert r.status_code in (401, 403)


@pytest.mark.parametrize(
    "path",
    ["/api/v1/notifications", "/api/v1/bookmarks", "/api/v1/auth/me"],
)
def test_mfa_token_is_not_accepted_as_login_token_anywhere(client, db_session, path):
    """
    The token of the 2FA step is issued after the *password* only. If any
    endpoint accepted it as a login token, the second factor would be bypassed.
    Several endpoints use a second, older auth dependency, so test them too.
    """
    make_user(db_session)
    token = login(client).json()["access_token"]
    enable_2fa(client, db_session, token)
    mfa_token = login(client).json()["mfa_token"]

    assert client.get(path, headers=auth(mfa_token)).status_code == 401
    # and the real login token is, of course, not a valid mfa token
    r = client.post("/api/v1/auth/login/2fa", json={"mfa_token": token, "code": "123456"})
    assert r.status_code == 401
