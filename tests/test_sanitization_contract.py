"""Fail-closed API and audit contracts across SQLite, handlers, and CLI."""

import json
import re
import sqlite3

import pytest

from hygeia import cli, platform_handlers
from hygeia.manifest import generate_manifest
from hygeia.patterns import PatternRegistry
from hygeia.scanner import ScanResult
from hygeia.sqlite_sanitizer import sanitize_database, sanitize_database_generic
from hygeia.verifier import VerificationResult


def _registry(**kwargs):
    return PatternRegistry(regex_patterns={"email": re.compile(r"\w+@example\.com")}, **kwargs)


@pytest.mark.parametrize("sensitive", [False, True])
@pytest.mark.parametrize("rejection", ["RAISE(ABORT, 'blocked')", "RAISE(IGNORE)"])
def test_rejected_row_is_reported_and_later_rows_are_redacted(tmp_path, sensitive, rejection):
    db = tmp_path / "blocked.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, payload TEXT)")
        conn.executemany("INSERT INTO records VALUES (?, ?)", [
            (1, "alice@example.com"), (2, "bob@example.com"),
        ])
        conn.execute(f"""CREATE TRIGGER reject_redaction BEFORE UPDATE ON records
                        WHEN old.id = 1 BEGIN SELECT {rejection}; END""")
    registry = _registry(sensitive_columns={"payload"} if sensitive else set())
    result = sanitize_database_generic(db, registry=registry)
    with sqlite3.connect(db) as conn:
        values = dict(conn.execute("SELECT id, payload FROM records"))
    assert values[1] == "alice@example.com"
    assert "bob@example.com" not in values[2], "one failed row must not abandon later rows"
    assert result.get("error"), "valid SQLite structure does not prove complete redaction"
    assert result["errors_count"] >= 1
    assert result["errors"]
    assert "alice@example.com" not in json.dumps(result)


def test_shadowed_rowid_column_does_not_address_unrelated_rows(tmp_path):
    db = tmp_path / "shadowed.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE records(rowid TEXT, payload TEXT)")
        conn.executemany("INSERT INTO records VALUES (?, ?)", [
            ("same", "alice@example.com"), ("same", "safe payload"),
        ])
    result = sanitize_database_generic(db, registry=_registry())
    assert not result.get("error"), result
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT payload FROM records WHERE _rowid_=2").fetchone()[0] == "safe payload"


@pytest.mark.parametrize("sensitive", [False, True])
def test_after_trigger_cannot_restore_pii_without_failure_signal(tmp_path, sensitive):
    db = tmp_path / "restored.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, payload TEXT)")
        conn.execute("INSERT INTO records VALUES (1, 'alice@example.com')")
        conn.execute("""CREATE TRIGGER restore_value AFTER UPDATE ON records BEGIN
                        UPDATE records SET payload=old.payload WHERE id=old.id; END""")
    result = sanitize_database_generic(
        db, registry=_registry(sensitive_columns={"payload"} if sensitive else set())
    )
    assert result.get("error"), "rowcount=1 does not prove the redaction was retained"


def test_error_evidence_is_bounded(tmp_path):
    db = tmp_path / "errors.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE records(payload TEXT)")
        conn.executemany("INSERT INTO records VALUES (?)", [("alice@example.com",)] * 150)
        conn.execute("""CREATE TRIGGER reject_redaction BEFORE UPDATE ON records
                        BEGIN SELECT RAISE(IGNORE); END""")
    result = sanitize_database_generic(db, registry=_registry())
    assert result["errors_count"] >= 150
    assert len(result["errors"]) == 100


def test_without_rowid_is_explicitly_incomplete(tmp_path):
    db = tmp_path / "without-rowid.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE records(key TEXT PRIMARY KEY, payload TEXT) WITHOUT ROWID")
        conn.execute("INSERT INTO records VALUES ('x', 'alice@example.com')")
    result = sanitize_database_generic(db, registry=_registry())
    assert result.get("error"), "unsupported row addressing must never be silently certified"


def test_residual_sweep_error_reaches_platform_result(tmp_path, monkeypatch):
    monkeypatch.setattr(platform_handlers, "detect_database_type", lambda _: "chrome_history")
    monkeypatch.setattr(platform_handlers, "run_platform_handler", lambda *args: {
        "action": "platform_sanitize", "rows_deleted": 0,
    })
    monkeypatch.setattr(platform_handlers, "sanitize_database_generic", lambda *args: {
        "error": "redaction incomplete", "errors_count": 2,
        "errors": [{"operation": "redact_cell"}],
    })
    result = platform_handlers.sanitize_with_platform_detection(tmp_path / "data.db")
    assert result.get("error")
    assert result["residual_error"] == "redaction incomplete"


def test_explicit_sql_failure_is_reported_and_remaining_commands_run(tmp_path):
    db = tmp_path / "commands.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE records(payload TEXT)")
        conn.execute("INSERT INTO records VALUES ('private value')")
    result = sanitize_database(db, ["DELETE FROM nonexistent", "DELETE FROM records"])
    assert result.get("error")
    assert result["commands_executed"] == 1
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM records").fetchone()[0] == 0


def test_platform_table_nuke_does_not_hide_trigger_failure(tmp_path):
    db = tmp_path / "history.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT)")
        conn.execute("INSERT INTO urls VALUES (1, 'private history')")
        conn.execute("""CREATE TRIGGER refuse_delete BEFORE DELETE ON urls
                        BEGIN SELECT RAISE(ABORT, 'blocked'); END""")
    result = platform_handlers.run_platform_handler(db, "chrome_history")
    assert result.get("error")


def test_platform_vacuum_failure_is_not_ignored(tmp_path, monkeypatch):
    db = tmp_path / "history.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT)")
    monkeypatch.setattr(platform_handlers, "vacuum_and_cleanup", lambda *args: False)
    result = platform_handlers.run_platform_handler(db, "chrome_history")
    assert result.get("error")
    assert result["vacuum_failed"] is True


def test_external_fts5_rebuilt_from_sanitized_source_and_verified(tmp_path):
    db = tmp_path / "external.db"
    with sqlite3.connect(db) as conn:
        # Deliberately put the FTS schema before its authoritative source.
        conn.execute("CREATE VIRTUAL TABLE search USING fts5(payload, content='records', content_rowid='id')")
        conn.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, payload TEXT)")
        conn.execute("INSERT INTO records VALUES (1, 'reach uniqvictim@example.com')")
        conn.execute("INSERT INTO search(search) VALUES('rebuild')")
    result = sanitize_database_generic(db, registry=_registry())
    assert not result.get("error"), result
    with sqlite3.connect(db) as conn:
        assert "uniqvictim" not in conn.execute("SELECT payload FROM records").fetchone()[0]
        assert conn.execute("SELECT count(*) FROM search WHERE search MATCH 'uniqvictim'").fetchone()[0] == 0
        conn.execute("INSERT INTO search(search, rank) VALUES('integrity-check', 1)")
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert b"uniqvictim" not in db.read_bytes(), "secure_delete + VACUUM must purge old index bytes"


def test_external_fts5_with_unreadable_source_fails_closed(tmp_path):
    db = tmp_path / "missing-source.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE VIRTUAL TABLE search USING fts5(payload, content='missing')")
    result = sanitize_database_generic(db, registry=_registry())
    assert result.get("error")
    assert "search" in result.get("fts_cleanup_incomplete", [])


def test_external_fts5_source_redaction_error_cannot_be_certified(tmp_path):
    db = tmp_path / "fts-blocked.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, payload TEXT)")
        conn.execute("INSERT INTO records VALUES (1, 'alice@example.com')")
        conn.execute("CREATE VIRTUAL TABLE search USING fts5(payload, content='records')")
        conn.execute("INSERT INTO search(search) VALUES('rebuild')")
        conn.execute("""CREATE TRIGGER refuse_update BEFORE UPDATE ON records
                        BEGIN SELECT RAISE(ABORT, 'blocked'); END""")
    result = sanitize_database_generic(db, registry=_registry())
    assert result.get("error"), "index/source consistency does not prove source redaction succeeded"


def test_content_option_text_in_quoted_fts_column_is_not_external_source(tmp_path):
    db = tmp_path / "quoted-fts-column.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE records(payload TEXT)")
        conn.execute("INSERT INTO records VALUES ('preserve unrelated source')")
        conn.execute('''CREATE VIRTUAL TABLE search USING fts5("content='records'")''')
        conn.execute("INSERT INTO search VALUES ('alice@example.com')")
    result = sanitize_database_generic(db, registry=_registry())
    assert not result.get("error"), result
    with sqlite3.connect(db) as conn:
        assert "alice@example.com" not in conn.execute("SELECT * FROM search").fetchone()[0]
        assert conn.execute("SELECT * FROM records").fetchone()[0] == "preserve unrelated source"


def test_manifest_preserves_verification_scope_and_incomplete_checks(tmp_path):
    result = VerificationResult(passed=False, scope="identity", incomplete=[{
        "check": "sqlite_content", "path": "data.db", "reason": "locked",
    }])
    manifest = generate_manifest(tmp_path, ScanResult(), [], result)
    assert manifest["verification"]["incomplete"] == result.incomplete
    assert manifest["verification"]["scope"] == "identity"


def test_cli_does_not_call_skipped_verification_passed(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    monkeypatch.setattr("sys.argv", ["hygeia", "-i", str(source), "-o", str(output),
                                     "--skip-verify", "--skip-exif", "--skip-forensic"])
    cli.main()
    printed = capsys.readouterr().out
    assert "Verification:        SKIPPED" in printed
    data = json.loads((tmp_path / "deletion_manifest.json").read_text())
    assert data["verification"]["passed"] is False
    assert data["verification"]["performed"] is False


def test_cli_action_error_blocks_clean_verification(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr("sys.argv", ["hygeia", "-i", str(source), "-o", str(tmp_path / "output"),
                                     "--skip-exif", "--skip-forensic"])
    monkeypatch.setattr(cli, "sanitize_databases", lambda *args, **kwargs: [{
        "action": "generic_sanitize", "path": "data.db", "error": "redaction incomplete",
    }])
    monkeypatch.setattr(cli, "verify_sanitization", lambda _: VerificationResult())
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert "PASSED" not in capsys.readouterr().out
