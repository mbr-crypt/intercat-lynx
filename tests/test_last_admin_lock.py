"""The last-administrator guard must hold under concurrency.

SQLite (used by the tests) ignores row locks, so the race itself cannot be
replayed here. What can be checked is the SQL the guard sends to PostgreSQL:
it must lock every active administrator row, in a fixed order.
"""

from sqlalchemy.dialects import postgresql

from backend.services import user_service


def test_admin_count_locks_rows_in_a_fixed_order(db_session):
    sql = str(
        user_service.active_admins_query(db_session)
        .statement.compile(dialect=postgresql.dialect())
    )
    assert "FOR UPDATE" in sql
    assert "ORDER BY users.id" in sql


def test_other_active_admins_excludes_the_given_account(db_session):
    from backend.models import User, UserRole

    for name in ("a1", "a2"):
        db_session.add(User(
            email=f"{name}@example.org", username=name, hashed_password="x",
            role=UserRole.ADMIN, is_active=True, is_verified=True,
        ))
    db_session.add(User(
        email="gone@example.org", username="gone", hashed_password="x",
        role=UserRole.ADMIN, is_active=False, is_verified=True,
    ))
    db_session.commit()
    first = db_session.query(User).filter(User.username == "a1").one()
    assert user_service.other_active_admins(db_session, first.id) == 1
