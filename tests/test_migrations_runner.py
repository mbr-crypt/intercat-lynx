"""Tests for the SQL migration runner helpers."""

from backend.migrations.run_migrations import _CONCURRENT_INDEX


def test_concurrent_index_statements_are_split_out():
    sql = (
        "CREATE TABLE t (id INT);\n"
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(id);\n"
        "create unique index concurrently idx_b on t(id) WHERE id > 0;\n"
        "ALTER TABLE t ADD COLUMN x INT;\n"
    )

    found = _CONCURRENT_INDEX.findall(sql)
    rest = _CONCURRENT_INDEX.sub("", sql)

    assert len(found) == 2
    assert "CONCURRENTLY" not in rest.upper()
    assert "CREATE TABLE t" in rest and "ALTER TABLE t" in rest


def test_plain_index_is_left_alone():
    sql = "CREATE INDEX IF NOT EXISTS idx_a ON t(id);"
    assert _CONCURRENT_INDEX.findall(sql) == []


# --- Start-up with several processes (found in the first Docker test) -------

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS = ROOT / "backend" / "migrations"


def test_schema_lock_is_a_no_op_without_postgresql(monkeypatch):
    from sqlalchemy import create_engine

    from backend.migrations import run_migrations

    monkeypatch.setattr(run_migrations, "engine", create_engine("sqlite://"))
    with run_migrations._schema_lock():
        pass  # SQLite in the tests: must not try to take an advisory lock


def test_lock_polls_instead_of_blocking():
    """
    A blocking pg_advisory_lock() hangs the start for good together with
    CREATE INDEX CONCURRENTLY (the waiting sessions count as open transactions
    that the index build waits for). Only the polling variant may be used.
    """
    source = (MIGRATIONS / "run_migrations.py").read_text()
    assert "pg_try_advisory_lock" in source
    assert not re.search(r"(?<!try_)advisory_lock\(", source)


def test_sql_migrations_run_under_the_lock():
    source = (MIGRATIONS / "run_migrations.py").read_text()
    body = source.split("def run_migrations")[1].split("def _run_sql_migrations")[0]
    assert "_schema_lock()" in body


def test_legacy_comments_migration_skips_fresh_databases():
    sql = (MIGRATIONS / "fix_comments_schema.sql").read_text()
    assert sql.lstrip().startswith("--") and "DO $$" in sql
    # the guard: only databases that still have the old column "edited"
    assert "column_name = 'edited'" in sql and "RETURN;" in sql


@pytest.mark.skipif(
    not os.getenv("TEST_POSTGRES_URL"),
    reason="set TEST_POSTGRES_URL to an empty, disposable PostgreSQL database",
)
def test_parallel_start_has_no_migration_errors():
    """Six processes migrate at the same time, like replicas x workers in Docker."""
    env = {**os.environ, "DATABASE_URL": os.environ["TEST_POSTGRES_URL"], "PYTHONPATH": str(ROOT)}
    script = (
        "import logging;logging.basicConfig(level=logging.ERROR);"
        "from backend.migrations.run_migrations import run_alembic_upgrade, run_migrations;"
        "run_alembic_upgrade();run_migrations()"
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", script], env=env, cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for _ in range(6)
    ]
    outputs = [p.communicate(timeout=180)[0] for p in procs]
    assert all(p.returncode == 0 for p in procs), outputs
    assert not [line for out in outputs for line in out.splitlines() if "✗" in line], outputs
