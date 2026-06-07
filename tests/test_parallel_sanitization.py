"""
Tests for parallel sanitization (--workers flag).

Covers:
  - --workers 0 auto-detects cpu_count
  - --workers 4 creates the right pool size
  - Parallel text sanitization produces the same results as sequential
  - Parallel DB sanitization produces the same results as sequential
  - Progress logging emitted for each completed item
"""

import json
import logging
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.cli import _resolve_workers, sanitize_databases
from hygeia.scanner import ScanResult
from hygeia.text_sanitizer import sanitize_all_text_files


# ---------------------------------------------------------------------------
# _resolve_workers tests
# ---------------------------------------------------------------------------

def test_workers_auto_detect_returns_cpu_count():
    """workers=0 should resolve to os.cpu_count() (or at least 1)."""
    resolved = _resolve_workers(0)
    expected = os.cpu_count() or 1
    assert resolved == expected, f"Expected {expected}, got {resolved}"


def test_workers_explicit_4():
    """workers=4 should resolve to exactly 4."""
    assert _resolve_workers(4) == 4


def test_workers_1_sequential():
    """workers=1 should resolve to 1 (sequential mode)."""
    assert _resolve_workers(1) == 1


def test_workers_negative_clamped():
    """Negative values should be clamped to 1."""
    assert _resolve_workers(-1) == 1


# ---------------------------------------------------------------------------
# Helper: build a small synthetic dump
# ---------------------------------------------------------------------------

def _make_dump(root: Path):
    """Create a small dump with JSON, log, CSV, and SQLite files containing PII."""
    # JSON with sensitive keys
    (root / "config.json").write_text(
        json.dumps({"username": "alice", "password": "secret123", "version": "2.0"}),
        encoding="utf-8",
    )
    # Log with PII
    (root / "app.log").write_text(
        "2026-01-01 Login from user@example.com\n2026-01-01 System OK\n",
        encoding="utf-8",
    )
    # CSV with PII columns
    (root / "users.csv").write_text(
        "id,email,role\n1,bob@test.com,admin\n2,carol@test.com,user\n",
        encoding="utf-8",
    )
    # SQLite DB with PII
    db = root / "data.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE contacts (id INTEGER, email TEXT, notes TEXT)")
    conn.execute("INSERT INTO contacts VALUES (1, 'dave@pii.com', 'call dave')")
    conn.execute("INSERT INTO contacts VALUES (2, 'eve@pii.com', 'email eve')")
    conn.commit()
    conn.close()


def _collect_manifest(root: Path) -> dict:
    """Collect a lightweight manifest of file contents for comparison."""
    manifest = {}
    for f in sorted(root.rglob("*")):
        if f.is_file():
            try:
                manifest[str(f.relative_to(root))] = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                manifest[str(f.relative_to(root))] = "<unreadable>"
    return manifest


# ---------------------------------------------------------------------------
# Parallel vs sequential text sanitization
# ---------------------------------------------------------------------------

def test_text_parallel_same_as_sequential():
    """
    Sanitize the same dump with workers=1 and workers=2.
    The resulting file contents should be identical.
    """
    with tempfile.TemporaryDirectory() as base:
        base = Path(base)

        # Sequential copy
        seq_root = base / "seq"
        seq_root.mkdir()
        _make_dump(seq_root)

        # Parallel copy — same inputs
        par_root = base / "par"
        par_root.mkdir()
        _make_dump(par_root)

        # Sanitize
        seq_actions = sanitize_all_text_files(seq_root, dry_run=False, workers=1)
        par_actions = sanitize_all_text_files(par_root, dry_run=False, workers=2)

        # Compare file contents
        seq_manifest = _collect_manifest(seq_root)
        par_manifest = _collect_manifest(par_root)

        # Same set of files
        assert set(seq_manifest.keys()) == set(par_manifest.keys()), (
            f"File sets differ:\n  seq={set(seq_manifest.keys())}\n  par={set(par_manifest.keys())}"
        )

        # Same content for every text file
        for fname in seq_manifest:
            assert seq_manifest[fname] == par_manifest[fname], (
                f"Content mismatch in {fname}:\n  seq={seq_manifest[fname][:200]}\n"
                f"  par={par_manifest[fname][:200]}"
            )

        # Both should have redacted PII
        assert not (seq_root / "config.json").read_text().find("secret123") != -1, \
            "Sequential should redact password"
        assert not (par_root / "config.json").read_text().find("secret123") != -1, \
            "Parallel should redact password"

        # Action counts should match
        seq_count = len(seq_actions)
        par_count = len(par_actions)
        assert seq_count == par_count, f"Action count mismatch: seq={seq_count}, par={par_count}"


# ---------------------------------------------------------------------------
# Parallel vs sequential DB sanitization
# ---------------------------------------------------------------------------

def test_db_parallel_same_as_sequential():
    """
    Sanitize the same DB dump with workers=1 and workers=2.
    The sanitized DB content should be identical.
    """
    with tempfile.TemporaryDirectory() as base:
        base = Path(base)

        def _make_db_dump(root: Path):
            root.mkdir(exist_ok=True)
            db = root / "contacts.db"
            conn = sqlite3.connect(str(db))
            conn.execute("CREATE TABLE contacts (id INTEGER, email TEXT, notes TEXT)")
            conn.execute("INSERT INTO contacts VALUES (1, 'frank@pii.com', 'call frank')")
            conn.execute("INSERT INTO contacts VALUES (2, 'grace@pii.com', 'notes about grace')")
            conn.commit()
            conn.close()
            return db

        seq_root = base / "seq"
        _make_db_dump(seq_root)

        par_root = base / "par"
        _make_db_dump(par_root)

        scan = ScanResult()

        seq_actions = sanitize_databases(seq_root, scan, compliance=None,
                                          dry_run=False, workers=1)
        par_actions = sanitize_databases(par_root, scan, compliance=None,
                                          dry_run=False, workers=2)

        # Both DBs should have been sanitized
        def _read_contacts(db_path: Path):
            conn = sqlite3.connect(str(db_path))
            rows = conn.execute("SELECT email FROM contacts ORDER BY id").fetchall()
            conn.close()
            return [r[0] for r in rows]

        seq_emails = _read_contacts(seq_root / "contacts.db")
        par_emails = _read_contacts(par_root / "contacts.db")

        # Both should have redacted the email column
        for email in seq_emails:
            assert email != "frank@pii.com" and email != "grace@pii.com", \
                f"Sequential did not redact email: {email}"
        for email in par_emails:
            assert email != "frank@pii.com" and email != "grace@pii.com", \
                f"Parallel did not redact email: {email}"

        # Results should be identical
        assert seq_emails == par_emails, \
            f"DB results differ:\n  seq={seq_emails}\n  par={par_emails}"


# ---------------------------------------------------------------------------
# Progress logging
# ---------------------------------------------------------------------------

def test_progress_logging_emitted(caplog):
    """
    With workers=1 (sequential), progress log messages should be emitted
    for each text file processed.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "a.json").write_text(json.dumps({"username": "x"}), encoding="utf-8")
        (root / "b.json").write_text(json.dumps({"password": "y"}), encoding="utf-8")

        with caplog.at_level(logging.INFO, logger="hygeia.text"):
            sanitize_all_text_files(root, dry_run=False, workers=1)

        progress_msgs = [r.message for r in caplog.records
                         if "Sanitizing" in r.message and "/" in r.message]
        assert len(progress_msgs) >= 2, \
            f"Expected >=2 progress messages, got {len(progress_msgs)}: {progress_msgs}"


def test_progress_logging_parallel(caplog):
    """
    With workers=2, progress log messages should still be emitted
    (via as_completed) for each file.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        for i in range(4):
            (root / f"f{i}.json").write_text(
                json.dumps({"password": f"secret{i}"}), encoding="utf-8"
            )

        with caplog.at_level(logging.INFO, logger="hygeia.text"):
            sanitize_all_text_files(root, dry_run=False, workers=2)

        progress_msgs = [r.message for r in caplog.records
                         if "Sanitizing text file" in r.message]
        assert len(progress_msgs) == 4, \
            f"Expected 4 progress messages, got {len(progress_msgs)}: {progress_msgs}"


# ---------------------------------------------------------------------------
# Dry-run still works with workers flag
# ---------------------------------------------------------------------------

def test_dry_run_unaffected_by_workers():
    """Dry-run with workers=4 should not modify any files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        cfg = root / "config.json"
        original = json.dumps({"password": "top-secret"})
        cfg.write_text(original, encoding="utf-8")

        actions = sanitize_all_text_files(root, dry_run=True, workers=4)

        # File should be untouched
        assert cfg.read_text(encoding="utf-8") == original, "Dry-run modified a file"

        # Actions should be recorded as dry_run
        assert any(a.get("dry_run") for a in actions), "No dry_run actions recorded"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        if t.__code__.co_varnames and "caplog" in t.__code__.co_varnames:
            print(f"  SKIP (needs pytest): {t.__name__}")
            continue
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__} — {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed (caplog tests need pytest)")
    sys.exit(1 if failed else 0)
