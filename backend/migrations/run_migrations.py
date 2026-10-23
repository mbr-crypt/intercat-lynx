#!/usr/bin/env python3
"""
Run database migrations on startup.
This script is executed automatically when the backend starts.
"""

import logging
import re
import os
import time
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import text

from backend.database import engine

logger = logging.getLogger(__name__)

_CONCURRENT_INDEX = re.compile(
    r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY[^;]*;", re.IGNORECASE
)


# One lock for everything that changes the schema at start-up. The backend runs
# as several processes (replicas x uvicorn workers) that all start at the same
# moment; without it they migrate in parallel and fail with deadlocks and
# "duplicate key" errors (seen in the first Docker test).
_LOCK_ID = 727270101


@contextmanager
def _schema_lock(timeout: float = 600.0, poll: float = 0.25):
    """
    Hold a PostgreSQL advisory lock while the schema is changed (no-op elsewhere).

    The lock is taken by polling ``pg_try_advisory_lock`` instead of blocking in
    ``pg_advisory_lock``. A process that waits inside a blocking call counts as
    an open transaction, and ``CREATE INDEX CONCURRENTLY`` waits for all open
    transactions - including the ones waiting for the very lock its own process
    holds. That cycle is invisible to PostgreSQL's deadlock detector and hangs
    the start for good (reproduced with six parallel processes).
    """
    if engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as lock:
        deadline = time.monotonic() + timeout
        while not lock.execute(
            text("SELECT pg_try_advisory_lock(:id)"), {"id": _LOCK_ID}
        ).scalar():
            if time.monotonic() > deadline:
                raise RuntimeError(
                    "Another process has been changing the database schema for "
                    f"more than {int(timeout)} seconds"
                )
            time.sleep(poll)
        try:
            yield
        finally:
            lock.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _LOCK_ID})


def run_alembic_upgrade() -> None:
    """
    Bring the database schema to the newest version (``alembic upgrade head``).

    Runs at every start so that a fresh installation needs no manual command -
    the setup assistant can start on an empty database. A PostgreSQL advisory
    lock makes sure that several backend containers starting at the same time
    do not migrate in parallel.
    """
    if engine.dialect.name != "postgresql":
        return

    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parents[2]
    ini = root / "alembic.ini"
    if not ini.exists():
        logger.warning("alembic.ini not found, skipping schema upgrade")
        return

    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(root / "alembic"))

    with _schema_lock():
        command.upgrade(cfg, "head")


def run_migrations():
    """
    Run all SQL migrations in the migrations directory.
    Migrations are idempotent and safe to run multiple times. They run one
    process at a time (advisory lock), so the second process simply finds
    everything in place.
    """
    with _schema_lock():
        _run_sql_migrations()


def _run_sql_migrations():
    migrations_dir = Path(__file__).parent
    migration_files = sorted(migrations_dir.glob("*.sql"))

    if not migration_files:
        logger.info("No migration files found")
        return

    logger.info(f"Found {len(migration_files)} migration file(s)")

    for migration_file in migration_files:
        logger.info(f"Running migration: {migration_file.name}")

        try:
            with open(migration_file, "r") as f:
                migration_sql = f.read()

            # CREATE INDEX CONCURRENTLY is not allowed inside a transaction
            # block - and a multi-statement string is sent as one implicit
            # transaction even in autocommit mode. So pull those statements
            # out, run the rest transactionally, then run each concurrent
            # index on its own in autocommit mode. (Without this,
            # create_stats_cache.sql never ran and /stats stayed empty.)
            concurrent = [m.group(0) for m in _CONCURRENT_INDEX.finditer(migration_sql)]
            rest = _CONCURRENT_INDEX.sub("", migration_sql)

            with engine.begin() as conn:
                conn.execute(text(rest))

            for statement in concurrent:
                with engine.connect().execution_options(
                    isolation_level="AUTOCOMMIT"
                ) as conn:
                    conn.execute(text(statement))

            logger.info(f"✓ Migration {migration_file.name} completed successfully")

        except Exception as e:
            # Each file gets its own connection/transaction, so one failure
            # can no longer poison the following files (upstream issue #44).
            logger.error(f"✗ Migration {migration_file.name} failed: {e}")
            # Don't raise - continue with other migrations

    logger.info("All migrations completed")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    run_migrations()
