"""Admin user management, forced password change, session revocation."""

import pytest

from backend.models import AuditEvent, User, UserRole
from backend.security import passwords

PASSWORD = "Sehr-Langes-Passwort-42"
BASE = "/api/v1/admin/users"


def make_user(db, username, role=UserRole.VIEWER, active=True):
    user = User(
        email=f"{username}@example.org",
        username=username,
        hashed_password=passwords.hash_password(PASSWORD),
        role=role,
        is_active=active,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def login(client, username, password=PASSWORD):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def token_of(client, username, password=PASSWORD):
    r = login(client, username, password)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def h(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin(client, db_session):
    user = make_user(db_session, "root", UserRole.ADMIN)
    return user, token_of(client, "root")


def test_only_admins_may_manage_users(client, db_session, admin):
    make_user(db_session, "alice", UserRole.ANALYST)
    make_user(db_session, "victor", UserRole.VIEWER)
    assert client.get(BASE).status_code in (401, 403)
    for name in ("alice", "victor"):
        t = token_of(client, name)
        assert client.get(BASE, headers=h(t)).status_code == 403
        assert client.post(BASE, json={}, headers=h(t)).status_code in (403, 422)
        assert client.get(f"{BASE}/audit", headers=h(t)).status_code == 403
    assert client.get(BASE, headers=h(admin[1])).status_code == 200


def test_create_user_generates_temporary_password_and_forces_change(client, db_session, admin):
    r = client.post(
        BASE,
        json={"username": "newbie", "email": "newbie@example.org", "role": "analyst"},
        headers=h(admin[1]),
    )
    assert r.status_code == 201, r.text
    temp = r.json()["temporary_password"]
    assert temp and len(temp) >= 12
    assert r.json()["user"]["role"] == "analyst"
    assert r.json()["user"]["must_change_password"] is True
    assert "hashed_password" not in r.text

    # The generated password passes the application's own rules
    passwords.validate_strength(temp)

    login_result = login(client, "newbie", temp)
    assert login_result.status_code == 200
    assert login_result.json()["must_change_password"] is True
    t = login_result.json()["access_token"]

    # Until the password is changed only /me and /change-password work
    assert client.get("/api/v1/auth/me", headers=h(t)).status_code == 200
    blocked = client.post("/api/v1/auth/2fa/setup", json={"password": temp}, headers=h(t))
    assert blocked.status_code == 403 and "Password change" in blocked.json()["detail"]

    # Changing it back to the temporary one is refused, a new one works
    same = client.post(
        "/api/v1/auth/change-password",
        json={"old_password": temp, "new_password": temp},
        headers=h(t),
    )
    assert same.status_code == 400
    ok = client.post(
        "/api/v1/auth/change-password",
        json={"old_password": temp, "new_password": "Ganz-Neues-Passwort-7"},
        headers=h(t),
    )
    assert ok.status_code == 200
    new_token = ok.json()["access_token"]
    assert client.get("/api/v1/auth/me", headers=h(new_token)).json()["must_change_password"] is False
    free = client.post(
        "/api/v1/auth/2fa/setup", json={"password": "Ganz-Neues-Passwort-7"}, headers=h(new_token)
    )
    assert free.status_code == 200  # no longer blocked
    # the old token ended with the password change
    assert client.get("/api/v1/auth/me", headers=h(t)).status_code == 401

    events = [e.action for e in db_session.query(AuditEvent).all()]
    assert "user.created" in events


def test_create_user_with_chosen_password_and_validation(client, db_session, admin):
    ok = client.post(
        BASE,
        json={"username": "chosen", "email": "chosen@example.org", "password": "Gewaehlt-Passwort-9"},
        headers=h(admin[1]),
    )
    assert ok.status_code == 201 and ok.json()["temporary_password"] is None
    assert login(client, "chosen", "Gewaehlt-Passwort-9").status_code == 200

    weak = client.post(
        BASE,
        json={"username": "weak", "email": "weak@example.org", "password": "kurz"},
        headers=h(admin[1]),
    )
    assert weak.status_code == 422

    dup_name = client.post(
        BASE, json={"username": "chosen", "email": "x@example.org"}, headers=h(admin[1])
    )
    dup_mail = client.post(
        BASE, json={"username": "other", "email": "CHOSEN@example.org"}, headers=h(admin[1])
    )
    assert dup_name.status_code == dup_mail.status_code == 400


def test_list_search_filter_and_pagination(client, db_session, admin):
    for i in range(5):
        make_user(db_session, f"user{i}")
    make_user(db_session, "ana", UserRole.ANALYST)
    make_user(db_session, "gone", active=False)

    everything = client.get(BASE, headers=h(admin[1])).json()
    assert everything["total"] == 8
    assert all("hashed_password" not in u for u in everything["items"])

    assert client.get(f"{BASE}?q=USER", headers=h(admin[1])).json()["total"] == 5
    assert client.get(f"{BASE}?role=analyst", headers=h(admin[1])).json()["total"] == 1
    assert client.get(f"{BASE}?status=inactive", headers=h(admin[1])).json()["total"] == 1
    page = client.get(f"{BASE}?page=2&page_size=3", headers=h(admin[1])).json()
    assert len(page["items"]) == 3 and page["total"] == 8
    assert client.get(f"{BASE}?status=bogus", headers=h(admin[1])).status_code == 422


def test_update_user_role_and_details_are_audited(client, db_session, admin):
    victim = make_user(db_session, "victim")
    r = client.patch(
        f"{BASE}/{victim.id}",
        json={"role": "analyst", "full_name": "Vic Tim", "email": "vic@example.org"},
        headers=h(admin[1]),
    )
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "analyst" and r.json()["full_name"] == "Vic Tim"
    actions = {e.action for e in db_session.query(AuditEvent).all()}
    assert {"user.updated", "user.role_changed"} <= actions

    clash = client.patch(f"{BASE}/{victim.id}", json={"email": "root@example.org"}, headers=h(admin[1]))
    assert clash.status_code == 400
    assert client.patch(f"{BASE}/9999", json={}, headers=h(admin[1])).status_code == 404


def test_role_change_ends_open_sessions(client, db_session, admin):
    victim = make_user(db_session, "victim", UserRole.ANALYST)
    t = token_of(client, "victim")
    assert client.get("/api/v1/auth/me", headers=h(t)).status_code == 200
    client.patch(f"{BASE}/{victim.id}", json={"role": "viewer"}, headers=h(admin[1]))
    assert client.get("/api/v1/auth/me", headers=h(t)).status_code == 401


def test_admin_cannot_lock_themselves_out(client, db_session, admin):
    me = admin[0]
    for body in ({"role": "viewer"}, {"is_active": False}):
        assert client.patch(f"{BASE}/{me.id}", json=body, headers=h(admin[1])).status_code == 400
    assert client.delete(f"{BASE}/{me.id}", headers=h(admin[1])).status_code == 400
    assert client.post(f"{BASE}/{me.id}/reset-password", json={}, headers=h(admin[1])).status_code == 400
    # their own name and mail can be edited
    assert client.patch(f"{BASE}/{me.id}", json={"full_name": "Boss"}, headers=h(admin[1])).status_code == 200


def test_last_admin_cannot_delete_own_account(client, db_session, admin):
    r = client.delete("/api/v1/auth/me", headers=h(admin[1]))
    assert r.status_code == 400 and "last administrator" in r.json()["detail"]
    # with a second admin it works
    make_user(db_session, "second", UserRole.ADMIN)
    assert client.delete("/api/v1/auth/me", headers=h(admin[1])).status_code == 200


def test_deactivate_blocks_login_and_existing_token_then_reactivate(client, db_session, admin):
    victim = make_user(db_session, "victim")
    t = token_of(client, "victim")
    assert client.patch(f"{BASE}/{victim.id}", json={"is_active": False}, headers=h(admin[1])).status_code == 200
    assert client.get("/api/v1/auth/me", headers=h(t)).status_code in (401, 403)
    assert login(client, "victim").status_code == 403
    assert client.patch(f"{BASE}/{victim.id}", json={"is_active": True}, headers=h(admin[1])).status_code == 200
    assert login(client, "victim").status_code == 200


def test_unlock_resets_lockout(client, db_session, admin):
    victim = make_user(db_session, "victim")
    for _ in range(5):
        login(client, "victim", "falsch-falsch-1")
    assert login(client, "victim").status_code == 403
    listed = client.get(f"{BASE}?status=locked", headers=h(admin[1])).json()
    assert [u["username"] for u in listed["items"]] == ["victim"]
    assert client.post(f"{BASE}/{victim.id}/unlock", headers=h(admin[1])).json()["is_locked"] is False
    assert login(client, "victim").status_code == 200


def test_reset_password_revokes_old_password_and_sessions(client, db_session, admin):
    victim = make_user(db_session, "victim")
    old_token = token_of(client, "victim")
    r = client.post(f"{BASE}/{victim.id}/reset-password", json={}, headers=h(admin[1]))
    assert r.status_code == 200, r.text
    temp = r.json()["temporary_password"]
    assert login(client, "victim").status_code == 401  # old password is gone
    assert login(client, "victim", temp).json()["must_change_password"] is True
    assert client.get("/api/v1/auth/me", headers=h(old_token)).status_code == 401
    # the temporary password itself is never stored in the audit log
    assert all(temp not in (e.detail or "") for e in db_session.query(AuditEvent).all())


def test_revoke_sessions(client, db_session, admin):
    victim = make_user(db_session, "victim")
    t = token_of(client, "victim")
    assert client.post(f"{BASE}/{victim.id}/revoke-sessions", headers=h(admin[1])).status_code == 200
    assert client.get("/api/v1/auth/me", headers=h(t)).status_code == 401
    assert login(client, "victim").status_code == 200  # signing in again works


def test_delete_user_removes_dependent_data(client, db_session, admin):
    from backend.models import Bookmark, Comment, Notification, Vulnerability

    victim = make_user(db_session, "victim")
    other = make_user(db_session, "other")
    vuln = Vulnerability(cve_id="CVE-2026-0001", title="t", exploited_in_the_wild=False)
    db_session.add(vuln)
    db_session.commit()
    db_session.add(Bookmark(user_id=victim.id, cve_id=vuln.cve_id))
    parent = Comment(content="a", cve_id=vuln.cve_id, user_id=victim.id)
    db_session.add(parent)
    db_session.commit()
    db_session.add(Comment(content="reply", cve_id=vuln.cve_id, user_id=other.id, parent_id=parent.id))
    db_session.commit()

    r = client.delete(f"{BASE}/{victim.id}", headers=h(admin[1]))
    assert r.status_code == 200, r.text
    assert db_session.query(User).filter(User.username == "victim").count() == 0
    assert db_session.query(Bookmark).count() == 0
    assert db_session.query(Comment).count() == 0
    assert db_session.query(User).filter(User.username == "other").count() == 1
    event = db_session.query(AuditEvent).filter(AuditEvent.action == "user.deleted").one()
    assert event.target_username == "victim"  # log stays readable after deletion


def test_registration_switch_and_audit_list(client, db_session, admin):
    r = client.get(f"{BASE}/settings/registration", headers=h(admin[1]))
    assert r.status_code == 200
    r = client.put(
        f"{BASE}/settings/registration", json={"registration_enabled": False}, headers=h(admin[1])
    )
    assert r.json() == {"registration_enabled": False}
    assert client.get(f"{BASE}/settings/registration", headers=h(admin[1])).json() == {
        "registration_enabled": False
    }
    log = client.get(f"{BASE}/audit", headers=h(admin[1])).json()
    assert log["total"] >= 1 and log["items"][0]["action"] == "setting.registration"
    assert log["items"][0]["actor_username"] == "root"


def test_me_exposes_role(client, db_session, admin):
    me = client.get("/api/v1/auth/me", headers=h(admin[1])).json()
    assert me["role"] == "admin" and me["must_change_password"] is False
