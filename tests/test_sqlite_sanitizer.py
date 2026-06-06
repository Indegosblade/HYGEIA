"""Basic tests for HYGEIA SQLite sanitizer module."""

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.sqlite_sanitizer import (
    checkpoint_and_prepare,
    vacuum_and_cleanup,
    sanitize_database,
    find_all_databases,
    delete_wal_orphans,
)


def test_checkpoint_and_prepare():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE test (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO test VALUES (1, 'hello')")
    conn.commit()
    checkpoint_and_prepare(conn)
    conn.close()
    db_path.unlink()


def test_sanitize_database():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE users (id INTEGER, email TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'test@example.com')")
    conn.execute("INSERT INTO users VALUES (2, 'user@icloud.com')")
    conn.commit()
    conn.close()

    sanitize_database(db_path, ["DELETE FROM users WHERE email LIKE '%@icloud.com'"])

    conn = sqlite3.connect(str(db_path))
    rows = conn.execute("SELECT * FROM users").fetchall()
    assert len(rows) == 1
    assert rows[0][1] == "test@example.com"

    freelist = conn.execute("PRAGMA freelist_count").fetchone()[0]
    assert freelist == 0

    conn.close()
    db_path.unlink()


def test_find_all_databases():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        db1 = tmpdir / "test.db"
        db2 = tmpdir / "test.sqlite"
        conn1 = sqlite3.connect(str(db1))
        conn1.execute("CREATE TABLE t (id INTEGER)")
        conn1.commit()
        conn1.close()
        conn2 = sqlite3.connect(str(db2))
        conn2.execute("CREATE TABLE t (id INTEGER)")
        conn2.commit()
        conn2.close()

        found = find_all_databases(tmpdir)
        assert len(found) >= 2


def test_delete_wal_orphans():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        orphan_wal = tmpdir / "missing.db-wal"
        orphan_shm = tmpdir / "missing.db-shm"
        orphan_wal.write_bytes(b"fake wal data")
        orphan_shm.write_bytes(b"fake shm data")

        delete_wal_orphans(tmpdir)

        assert not orphan_wal.exists()
        assert not orphan_shm.exists()


if __name__ == "__main__":
    test_checkpoint_and_prepare()
    test_sanitize_database()
    test_find_all_databases()
    test_delete_wal_orphans()
    print("All tests passed.")
