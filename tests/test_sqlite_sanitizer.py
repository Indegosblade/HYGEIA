"""Basic tests for HYGEIA SQLite sanitizer module."""

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.sqlite_sanitizer import (
    checkpoint_and_prepare,
    sanitize_database,
    find_all_databases,
    delete_wal_orphans,
    vacuum_and_cleanup,
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


def test_vacuum_succeeds_after_connection_cleanup():
    """
    Simulate the Chrome Login Data scenario: sanitize_database must leave
    zero free pages even when rows were deleted before the call.
    The VACUUM fix (close all cursors, WAL checkpoint, retry) covers this.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "Login Data"
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE logins "
            "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, origin_url TEXT)"
        )
        for i in range(200):
            conn.execute(
                "INSERT INTO logins VALUES (?, ?, ?, ?)",
                (i, f"user{i}@example.com", f"secret{i}", f"https://site{i}.example.com"),
            )
        conn.commit()
        conn.execute("DELETE FROM logins WHERE id > 10")
        conn.commit()
        conn.close()

        result = sanitize_database(db_path, ["DELETE FROM logins"])
        assert "error" not in result, f"sanitize_database raised: {result.get('error')}"

        vconn = sqlite3.connect(str(db_path))
        free_pages = vconn.execute("PRAGMA freelist_count").fetchone()[0]
        vconn.close()
        assert free_pages == 0, f"Expected 0 free pages after VACUUM, got {free_pages}"


def test_vacuum_and_cleanup_returns_false_when_locked():
    """#15: a real VACUUM failure (external write lock — the 'locked WAL'
    scenario the code explicitly anticipates) must be reported as False, not
    silently tolerated. A False return is the fail-closed signal that freelist
    pages of deleted records were NOT reclaimed."""
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "x.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE t (id INTEGER, v TEXT)")
        # Large per-row values across many pages so deleting most rows leaves
        # whole freelist pages (recoverable deleted-record bytes) behind.
        conn.executemany("INSERT INTO t VALUES (?, ?)",
                         [(i, "x" * 300) for i in range(600)])
        conn.commit()
        conn.execute("DELETE FROM t WHERE id > 5")
        conn.commit()
        assert conn.execute("PRAGMA freelist_count").fetchone()[0] > 0

        # Another connection holds a write lock so VACUUM cannot run.
        locker = sqlite3.connect(str(db))
        locker.execute("BEGIN IMMEDIATE")
        locker.execute("CREATE TABLE lock_me (x)")
        try:
            ok = vacuum_and_cleanup(conn, db)  # closes conn internally
        finally:
            locker.rollback()
            locker.close()
        assert ok is False, "VACUUM failure under lock must return False (fail closed)"


def test_wal_orphan_kept_when_suffix_in_parent_dir():
    """#17/#39: a directory name containing '-journal' must not corrupt parent-DB
    resolution. A live DB's companion journal must be KEPT, not deleted as a
    false orphan (the old global str.replace collapsed the dir → data loss)."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / "case-journal" / "clean"
        d.mkdir(parents=True)
        db = d / "x.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()
        journal = Path(str(db) + "-journal")
        journal.write_bytes(b"committed frames not yet merged")

        deleted = delete_wal_orphans(Path(tmp))

        assert journal.exists(), "live DB companion wrongly deleted as orphan (data loss)"
        assert journal not in deleted


def test_true_orphan_wal_deleted_despite_suffix_in_path():
    """#17/#39: a genuine orphan WAL under a '-wal' directory must still be
    deleted even when an unrelated DB exists at the path the buggy replace-all
    would collapse to — otherwise the orphan's recoverable PII frames survive."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "wallet-wal").mkdir()
        orphan = tmp / "wallet-wal" / "data.db-wal"
        orphan.write_bytes(b"recoverable deleted-record frames with PII")
        # Unrelated DB at the path replace('-wal','') would resolve the orphan to.
        (tmp / "wallet").mkdir()
        (tmp / "wallet" / "data.db").write_bytes(b"unrelated file")

        deleted = delete_wal_orphans(tmp)

        assert not orphan.exists(), "true orphan WAL survived — recoverable PII kept (false clean)"
        assert orphan in deleted


if __name__ == "__main__":
    test_checkpoint_and_prepare()
    test_sanitize_database()
    test_find_all_databases()
    test_delete_wal_orphans()
    test_vacuum_succeeds_after_connection_cleanup()
    test_vacuum_and_cleanup_returns_false_when_locked()
    test_wal_orphan_kept_when_suffix_in_parent_dir()
    test_true_orphan_wal_deleted_despite_suffix_in_path()
    print("All tests passed.")
