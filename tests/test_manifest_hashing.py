"""
Tests for SHA256 chain-of-custody hashing in sanitization actions.

Verifies that:
- sanitize_database_generic produces hash_before and hash_after
- hashes are valid SHA256 hex digests (64 chars, hex)
- hash_before != hash_after when PII is redacted (file was modified)
- deleted file actions include hash_before but NOT hash_after
"""

import hashlib
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.sqlite_sanitizer import sanitize_database_generic
from hygeia.forensic_cleaner import clean_swap_temp_files
from hygeia.utils import sha256 as _sha256


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_db_with_pii(path: Path) -> None:
    """Create a SQLite database with PII that will be redacted."""
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE users (id INTEGER, email TEXT, notes TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'victim@example.com', 'call 555-123-4567')")
    conn.execute("INSERT INTO users VALUES (2, 'admin@corp.com', 'SSN: 123-45-6789')")
    conn.commit()
    conn.close()


def _make_db_clean(path: Path) -> None:
    """Create a SQLite database with no PII (won't be modified by sanitizer)."""
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE config (id INTEGER, value TEXT)")
    conn.execute("INSERT INTO config VALUES (1, 'safe_value')")
    conn.commit()
    conn.close()


def _is_valid_sha256(h: str) -> bool:
    """Return True if h looks like a valid SHA256 hex digest."""
    if not isinstance(h, str):
        return False
    if len(h) != 64:
        return False
    try:
        int(h, 16)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# _sha256 helper tests
# ---------------------------------------------------------------------------

def test_sha256_helper_returns_valid_digest():
    """_sha256() must return a 64-character hex string."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"hello world")
        p = Path(f.name)
    try:
        digest = _sha256(p)
        assert _is_valid_sha256(digest), f"Not a valid SHA256: {digest!r}"
        # Known SHA256 of b"hello world"
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert digest == expected, f"Hash mismatch: {digest} != {expected}"
    finally:
        p.unlink(missing_ok=True)


def test_sha256_different_content_differs():
    """Files with different content must produce different hashes."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f1:
        f1.write(b"content A")
        p1 = Path(f1.name)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f2:
        f2.write(b"content B")
        p2 = Path(f2.name)
    try:
        assert _sha256(p1) != _sha256(p2)
    finally:
        p1.unlink(missing_ok=True)
        p2.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# sanitize_database_generic hashing tests
# ---------------------------------------------------------------------------

def test_generic_sanitize_has_hash_before_and_after():
    """sanitize_database_generic must include hash_before and hash_after."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        _make_db_with_pii(db_path)
        result = sanitize_database_generic(db_path)
        assert "hash_before" in result, "Missing hash_before"
        assert "hash_after" in result, "Missing hash_after"
    finally:
        db_path.unlink(missing_ok=True)


def test_generic_sanitize_hashes_are_valid_sha256():
    """hash_before and hash_after must be valid 64-char hex SHA256 digests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        _make_db_with_pii(db_path)
        result = sanitize_database_generic(db_path)
        assert _is_valid_sha256(result["hash_before"]), f"hash_before invalid: {result.get('hash_before')!r}"
        assert _is_valid_sha256(result["hash_after"]), f"hash_after invalid: {result.get('hash_after')!r}"
    finally:
        db_path.unlink(missing_ok=True)


def test_generic_sanitize_hashes_differ_after_redaction():
    """hash_before must differ from hash_after when PII was redacted."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        _make_db_with_pii(db_path)
        result = sanitize_database_generic(db_path)
        assert result.get("rows_redacted", 0) > 0, "Expected rows to be redacted"
        assert result["hash_before"] != result["hash_after"], (
            "hash_before should differ from hash_after after sanitization"
        )
    finally:
        db_path.unlink(missing_ok=True)


def test_generic_sanitize_has_hashes_even_when_no_pii():
    """hash_before and hash_after are present even when no PII is found."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        _make_db_clean(db_path)
        result = sanitize_database_generic(db_path)
        assert "hash_before" in result, "Missing hash_before on clean DB"
        assert "hash_after" in result, "Missing hash_after on clean DB"
        assert _is_valid_sha256(result["hash_before"])
        assert _is_valid_sha256(result["hash_after"])
    finally:
        db_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Deleted file actions: hash_before only, no hash_after
# ---------------------------------------------------------------------------

def test_deleted_file_has_hash_before_no_hash_after():
    """
    Forensic cleaner delete actions must carry hash_before but NOT hash_after
    (the file no longer exists after deletion).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        # Create a swap file that will be deleted
        swap_file = tmpdir_path / "leftover.swp"
        swap_file.write_bytes(b"vim swap file contents")

        actions = clean_swap_temp_files(tmpdir_path, dry_run=False)

        delete_actions = [a for a in actions if a.get("action") == "delete_swap_file"]
        assert len(delete_actions) >= 1, "Expected at least one delete_swap_file action"

        for action in delete_actions:
            assert "hash_before" in action, f"delete action missing hash_before: {action}"
            assert "hash_after" not in action, (
                f"delete action should not have hash_after (file is gone): {action}"
            )
            assert _is_valid_sha256(action["hash_before"]), (
                f"hash_before is not a valid SHA256: {action['hash_before']!r}"
            )
            # Verify the file is actually gone
            assert not (tmpdir_path / action["path"]).exists()


def test_deleted_file_hash_before_matches_original_content():
    """hash_before recorded for a deleted file must match the file's pre-deletion hash."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        swap_file = tmpdir_path / "session.tmp"
        content = b"temporary session data with email user@example.com"
        swap_file.write_bytes(content)

        expected_hash = hashlib.sha256(content).hexdigest()

        actions = clean_swap_temp_files(tmpdir_path, dry_run=False)
        delete_actions = [a for a in actions if a.get("action") == "delete_swap_file"]
        assert len(delete_actions) == 1
        assert delete_actions[0]["hash_before"] == expected_hash


# ---------------------------------------------------------------------------
# manifest summary: files_with_hashes count
# ---------------------------------------------------------------------------

def test_manifest_summary_files_with_hashes():
    """generate_manifest summary must count actions that carry hash_before or hash_after."""
    from hygeia.manifest import generate_manifest
    from hygeia.verifier import VerificationResult

    # Minimal scan result stub
    class _MinimalJailbreak:
        detected = False
        jailbreak_type = ""
        preserve_paths = []

    class _MinimalScanResult:
        total_files = 10
        total_size = 1024
        delete_count = 0
        delete_size = 0
        preserve_count = 0
        classifications = []
        jailbreak = _MinimalJailbreak()

    scan = _MinimalScanResult()
    verification = VerificationResult()
    verification.passed = True

    with tempfile.TemporaryDirectory() as tmpdir:
        dump_path = Path(tmpdir)

        actions = [
            {"action": "generic_sanitize", "path": "a.db", "hash_before": "a" * 64, "hash_after": "b" * 64},
            {"action": "generic_sanitize", "path": "b.db", "hash_before": "c" * 64, "hash_after": "d" * 64},
            {"action": "delete_swap_file", "path": "x.swp", "hash_before": "e" * 64},
            {"action": "delete_cache_dir", "path": "cache/"},  # no hashes — directory
        ]

        manifest = generate_manifest(
            dump_path=dump_path,
            scan_result=scan,
            sanitization_actions=actions,
            verification_result=verification,
            elapsed_seconds=1.0,
        )

        assert manifest["summary"]["files_with_hashes"] == 3, (
            f"Expected 3 actions with hashes, got {manifest['summary']['files_with_hashes']}"
        )


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except Exception as e:
            import traceback
            print(f"  FAIL: {t.__name__} — {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
