"""Connection ownership on corrupt-input and preparation failure paths."""

import sqlite3
from contextlib import closing

import pytest

from hygeia import platform_handlers, sqlite_sanitizer


@pytest.fixture
def connections(monkeypatch):
    original_connect = sqlite3.connect
    opened = []

    class TrackedConnection(sqlite3.Connection):
        closed = False

        def close(self):
            self.closed = True
            super().close()

    def connect(*args, **kwargs):
        kwargs["factory"] = TrackedConnection
        conn = original_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", connect)
    yield opened
    for conn in opened:
        conn.close()


@pytest.mark.parametrize("consumer", ["generic", "detect"])
def test_corrupt_input_closes_connection(tmp_path, connections, consumer):
    db = tmp_path / "corrupt.db"
    db.write_bytes(b"SQLite format 3\0" + bytes(4096))
    if consumer == "generic":
        assert sqlite_sanitizer.sanitize_database_generic(db).get("error")
    else:
        assert platform_handlers.detect_database_type(db) is None
    assert connections, "corrupt input must reach the actual SQLite open"
    assert all(conn.closed for conn in connections)


def test_failed_preparation_closes_before_ownership_transfer(tmp_path, connections, monkeypatch):
    db = tmp_path / "prepare.db"
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("CREATE TABLE records(payload TEXT)")

    def fail_prepare(conn):
        raise sqlite3.OperationalError("preparation failed")

    monkeypatch.setattr(platform_handlers, "checkpoint_and_prepare", fail_prepare)
    result = platform_handlers.run_platform_handler(db, "chrome_history")
    assert result.get("error")
    assert all(conn.closed for conn in connections)


def test_vacuum_closes_reopened_connection_on_database_error(tmp_path, connections, monkeypatch):
    db = tmp_path / "vacuum.db"
    source = sqlite3.connect(db)
    source.execute("CREATE TABLE records(payload TEXT)")
    source.commit()
    connection_type = type(source)
    original_execute = connection_type.execute

    def fail_vacuum(conn, sql, *args):
        if sql == "VACUUM":
            raise sqlite3.DatabaseError("database became corrupt")
        return original_execute(conn, sql, *args)

    monkeypatch.setattr(connection_type, "execute", fail_vacuum)
    with pytest.raises(sqlite3.DatabaseError):
        sqlite_sanitizer.vacuum_and_cleanup(source, db)
    assert len(connections) == 2
    assert all(conn.closed for conn in connections)


def test_vacuum_consumes_source_even_when_commit_fails(tmp_path, connections, monkeypatch):
    db = tmp_path / "commit.db"
    source = sqlite3.connect(db)

    def fail_commit(conn):
        raise sqlite3.OperationalError("commit failed")

    monkeypatch.setattr(type(source), "commit", fail_commit)
    with pytest.raises(sqlite3.OperationalError):
        sqlite_sanitizer.vacuum_and_cleanup(source, db)
    assert source.closed
