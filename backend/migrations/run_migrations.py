#!/usr/bin/env python3
"""
Run database migrations on startup.
This script is executed automatically when the backend starts.
"""

import logging
import re
import os
from pathlib import Path

from sqlalchemy import text

from backend.database import engine

logger = logging.getLogger(__name__)

_CONCURRENT_INDEX = re.compile(
    r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY[^;]*;", re.IGNORECASE
)


def run_migrations():
    """
    Run all SQL migrations in the migrations directory.
    Migrations are idempotent and safe to run multiple times.
    """
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
