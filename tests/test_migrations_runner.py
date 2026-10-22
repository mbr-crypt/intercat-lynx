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
