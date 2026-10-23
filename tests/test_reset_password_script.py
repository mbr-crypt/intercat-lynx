"""scripts/reset_password.py: emergency reset by shell access."""

import runpy
import sys

import pytest

from backend.models import User, UserRole
from backend.security import passwords
from tests.test_auth_2fa import make_user


def _run(monkeypatch, session_factory, argv, answers):
    import backend.database as database

    monkeypatch.setattr(database, "SessionLocal", session_factory)
    monkeypatch.setattr(sys, "argv", ["reset_password.py", *argv])
    it = iter(answers)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(it))
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path("scripts/reset_password.py", run_name="__main__")
    return exit_info.value.code


def test_reset_changes_password_and_ends_sessions(db_session, session_factory, monkeypatch):
    make_user(db_session, "boss", "Altes-Passwort-Lang-1", role=UserRole.ADMIN)
    user = db_session.query(User).filter_by(username="boss").one()
    version = user.token_version
    user.failed_login_attempts = 7

    db_session.commit()
    code = _run(monkeypatch, session_factory, ["boss"], ["Neues-Sehr-Langes-Passwort-9"] * 2)
    assert code == 0
    db_session.expire_all()
    user = db_session.query(User).filter_by(username="boss").one()
    assert passwords.verify_password("Neues-Sehr-Langes-Passwort-9", user.hashed_password)
    assert user.token_version == version + 1
    assert user.failed_login_attempts == 0 and user.must_change_password is True


def test_reset_rejects_weak_or_mismatching_password(db_session, session_factory, monkeypatch):
    make_user(db_session, "boss", "Altes-Passwort-Lang-1", role=UserRole.ADMIN)
    assert _run(monkeypatch, session_factory, ["boss"], ["kurz", "kurz"]) == 1
    assert _run(monkeypatch, session_factory, ["boss"], ["Neues-Sehr-Langes-Passwort-9", "anders"]) == 1
    assert _run(monkeypatch, session_factory, ["nobody"], []) == 1
