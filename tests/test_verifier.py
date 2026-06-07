"""Tests for post-sanitization PII verifier."""

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.verifier import (
    verify_sanitization, scan_text_files, scan_sqlite_content,
    scan_sqlite_freelist, _is_false_positive,
)


def test_clean_directory_passes():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "safe.txt").write_text("No personal data here at all")
    result = verify_sanitization(root)
    assert result.passed, f"Clean dir should pass, got {result.total_findings} findings"
    import shutil; shutil.rmtree(d)


def test_email_detected_in_text():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "leak.txt").write_text("Contact user@example.com for info")
    result = verify_sanitization(root)
    assert not result.passed, "Email should be detected"
    assert any(m.pattern_name == "email" for m in result.pii_matches)
    import shutil; shutil.rmtree(d)


def test_phone_detected_in_text():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "leak.txt").write_text("Call (555) 123-4567 for help")
    result = verify_sanitization(root)
    assert not result.passed
    import shutil; shutil.rmtree(d)


def test_ssn_detected_in_text():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "leak.txt").write_text("SSN: 123-45-6789")
    result = verify_sanitization(root)
    assert not result.passed
    import shutil; shutil.rmtree(d)


def test_email_detected_in_sqlite():
    d = tempfile.mkdtemp()
    root = Path(d)
    db = root / "test.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE users (id INTEGER, info TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'user@leaked.com')")
    conn.commit()
    conn.close()
    matches = scan_sqlite_content(root)
    assert len(matches) >= 1
    assert any("email" in m.pattern_name for m in matches)
    import shutil; shutil.rmtree(d)


def test_freelist_detection():
    d = tempfile.mkdtemp()
    db = Path(d) / "test.db"
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (id INTEGER, data TEXT)")
    for i in range(1000):
        conn.execute("INSERT INTO t VALUES (?, ?)", (i, f"data_{i}"))
    conn.commit()
    conn.execute("DELETE FROM t WHERE id > 5")
    conn.commit()
    conn.close()
    findings = scan_sqlite_freelist(db)
    assert len(findings) >= 1, "Should detect non-zero freelist"
    import shutil; shutil.rmtree(d, ignore_errors=True)


def test_false_positive_url_column():
    assert _is_false_positive("db:table.url", "phone_us", "5551234567") is True
    assert _is_false_positive("db:table.url", "ssn", "123-45-6789") is True


def test_false_positive_system_path():
    assert _is_false_positive("System/Library/file.txt", "email", "test@test.com") is True


def test_false_positive_redacted():
    assert _is_false_positive("any.txt", "email", "[REDACTED_EMAIL]") is True


def test_not_false_positive_real_pii():
    assert _is_false_positive("data/notes.txt", "email", "user@real.com") is False


def test_system_dir_skip():
    d = tempfile.mkdtemp()
    root = Path(d)
    sys_dir = root / "System" / "Library"
    sys_dir.mkdir(parents=True)
    (sys_dir / "framework.txt").write_text("admin@apple.com internal")
    matches = scan_text_files(root)
    assert len(matches) == 0, "System paths should be skipped"
    import shutil; shutil.rmtree(d)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__} — {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
