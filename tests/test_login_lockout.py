"""Lockout must stop strangers guessing, but not be a weapon against the real user."""

import pytest
import redis

from backend.security import login_throttle
from tests.test_auth_2fa import PASSWORD, enable_2fa, make_user
from backend.security import totp

OWNER = "203.0.113.10"
STRANGER = "198.51.100.77"
BAD = "falsch-falsch-1"


@pytest.fixture(autouse=True)
def behind_one_proxy(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "1")


def login_from(client, ip, username="alice", password=PASSWORD, spoof=None):
    xff = f"{spoof}, {ip}" if spoof else ip
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
        headers={"X-Forwarded-For": xff},
    )


def lock_from(client, ip, username="alice"):
    for _ in range(5):
        assert login_from(client, ip, username, BAD).status_code == 401


def test_successful_login_remembers_the_address(client, db_session):
    user = make_user(db_session)
    assert login_from(client, STRANGER, password=BAD).status_code == 401
    db_session.refresh(user)
    assert user.last_login_ip is None  # failed attempts are not remembered
    assert login_from(client, OWNER).status_code == 200
    db_session.refresh(user)
    assert user.last_login_ip == OWNER


def test_stranger_is_locked_out_after_five_failures(client, db_session):
    make_user(db_session)
    lock_from(client, STRANGER)
    assert login_from(client, STRANGER).status_code == 403  # even with the right password


def test_stranger_cannot_lock_the_owner_out(client, db_session):
    user = make_user(db_session)
    assert login_from(client, OWNER).status_code == 200  # owner's usual address
    lock_from(client, STRANGER)
    db_session.refresh(user)
    assert user.locked_until is not None  # the account is locked ...
    assert login_from(client, STRANGER).status_code == 403  # ... for the stranger
    r = login_from(client, OWNER)  # ... but not for the owner
    assert r.status_code == 200 and r.json()["access_token"]
    db_session.refresh(user)
    assert user.locked_until is None and user.failed_login_attempts == 0


def test_admin_account_is_not_lockable_from_outside(client, db_session):
    make_user(db_session, "chef")
    assert login_from(client, OWNER, "chef").status_code == 200
    lock_from(client, STRANGER, "chef")
    for _ in range(3):  # the stranger keeps hammering, the lock is refreshed, not the owner's problem
        assert login_from(client, STRANGER, "chef", BAD).status_code == 403
    assert login_from(client, OWNER, "chef").status_code == 200


def test_wrong_password_from_the_known_address_is_a_plain_401(client, db_session):
    make_user(db_session)
    assert login_from(client, OWNER).status_code == 200
    lock_from(client, STRANGER)
    assert login_from(client, OWNER, password=BAD).status_code == 401


def test_a_forged_header_does_not_make_the_stranger_look_like_the_owner(client, db_session):
    make_user(db_session)
    assert login_from(client, OWNER).status_code == 200
    lock_from(client, STRANGER)
    # the stranger writes the owner's address into the header; nginx appends the real one
    assert login_from(client, STRANGER, spoof=OWNER).status_code == 403


def test_a_user_who_never_logged_in_is_locked_for_everyone(client, db_session):
    make_user(db_session)
    lock_from(client, STRANGER)
    assert login_from(client, OWNER).status_code == 403


def test_second_factor_lock_also_spares_the_known_address(client, db_session):
    user = make_user(db_session)
    token = login_from(client, OWNER).json()["access_token"]
    enable_2fa(client, db_session, token)
    mfa_token = login_from(client, OWNER).json()["mfa_token"]

    def second(ip, code):
        return client.post(
            "/api/v1/auth/login/2fa",
            json={"mfa_token": mfa_token, "code": code},
            headers={"X-Forwarded-For": ip},
        )

    for _ in range(5):
        assert second(STRANGER, "111111").status_code == 401
    assert second(STRANGER, "111111").status_code == 403
    # the owner, from the known address, can still finish (recovery code needed, the
    # authenticator code of the enabling step is used up)
    db_session.refresh(user)
    assert user.locked_until is not None
    assert second(OWNER, "000000").status_code == 401  # reaches the check, not the lock


def test_one_address_can_only_fail_so_often_in_total(client, db_session):
    make_user(db_session)
    for i in range(login_throttle.MAX_FAILURES):
        assert login_from(client, STRANGER, username=f"nobody{i}", password=BAD).status_code == 401
    blocked = login_from(client, STRANGER)  # correct credentials, still refused
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    # somebody else is not affected
    assert login_from(client, OWNER).status_code == 200


def test_successful_logins_do_not_reset_the_address_counter(client, db_session):
    make_user(db_session)
    make_user(db_session, "mine")
    for i in range(login_throttle.MAX_FAILURES - 1):
        login_from(client, STRANGER, username=f"nobody{i}", password=BAD)
    assert login_from(client, STRANGER, "mine").status_code == 200  # attacker has a valid account
    assert login_from(client, STRANGER, username="nobody-x", password=BAD).status_code == 401
    assert login_from(client, STRANGER, "mine").status_code == 429


def test_throttle_falls_back_to_memory_when_redis_is_down(monkeypatch):
    class Dead:
        def get(self, *a):
            raise redis.ConnectionError("down")

        def incr(self, *a):
            raise redis.ConnectionError("down")

    monkeypatch.setattr(login_throttle, "USE_REDIS", True)
    monkeypatch.setattr(login_throttle, "_client", Dead())
    monkeypatch.setattr(login_throttle, "_redis_down_until", 0.0)
    login_throttle.reset_memory()
    for _ in range(3):
        login_throttle.record_failure("192.0.2.1")
    assert login_throttle.failures("192.0.2.1") == 3  # counted in memory, no exception
    for _ in range(login_throttle.MAX_FAILURES):
        login_throttle.record_failure("192.0.2.1")
    with pytest.raises(Exception) as caught:
        login_throttle.check("192.0.2.1")
    assert getattr(caught.value, "status_code", None) == 429


def test_lock_does_not_kill_the_owners_live_session(client, db_session):
    """A stranger's failed guesses must not make the owner's valid token return 403."""
    make_user(db_session)
    token = login_from(client, OWNER).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "X-Forwarded-For": OWNER}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    lock_from(client, STRANGER)  # the account is now locked for password logins from strangers
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
