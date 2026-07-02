"""Tests for shared safety helpers (SQL identifier quoting, path containment).

These assert *behavior against the real primitives* — a table whose name
contains a double-quote is actually created and read back through sqlite3, and
a symlink that escapes the dump is actually rejected — not merely that the
helper returns without raising.
"""

import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.utils import (
    quote_identifier,
    resolve_within,
    is_safe_regular_file,
    safe_utime,
)


def test_quote_identifier_plain():
    assert quote_identifier("messages") == '"messages"'


def test_quote_identifier_escapes_embedded_quote():
    # a"b  ->  "a""b"
    assert quote_identifier('a"b') == '"a""b"'


def test_quote_identifier_works_against_real_sqlite():
    """A table named `mes"sages` must be creatable, insertable and queryable
    using the quoted identifier — this is the exact case the generic sanitizer
    skipped, leaving PII behind."""
    conn = sqlite3.connect(":memory:")
    name = 'mes"sages'
    qi = quote_identifier(name)
    conn.execute(f"CREATE TABLE {qi} (body TEXT)")
    conn.execute(f"INSERT INTO {qi} (body) VALUES (?)", ("victim@example.com",))
    rows = conn.execute(f"SELECT body FROM {qi}").fetchall()
    conn.close()
    assert rows == [("victim@example.com",)]


def test_naive_quoting_breaks_negative_control():
    """Negative control: the old `"{name}"` interpolation raises on an
    embedded-quote identifier, which is why the error was swallowed and the
    table skipped. This proves the quoting fix is load-bearing."""
    conn = sqlite3.connect(":memory:")
    name = 'mes"sages'
    with pytest.raises(sqlite3.OperationalError):
        conn.execute(f'CREATE TABLE "{name}" (body TEXT)')
    conn.close()


def test_resolve_within_accepts_descendant():
    d = tempfile.mkdtemp()
    root = Path(d)
    child = root / "sub" / "file.txt"
    child.parent.mkdir(parents=True)
    child.write_text("x")
    assert resolve_within(child, root) is not None
    # cleanup
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def test_resolve_within_rejects_escape():
    d = tempfile.mkdtemp()
    root = Path(d) / "dump"
    root.mkdir()
    outside = Path(d) / "outside.txt"
    outside.write_text("host file")
    escape = root / ".." / "outside.txt"
    assert resolve_within(escape, root) is None
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def test_is_safe_regular_file_accepts_real_file():
    d = tempfile.mkdtemp()
    root = Path(d)
    f = root / "note.txt"
    f.write_text("data")
    assert is_safe_regular_file(f, root) is True
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def test_is_safe_regular_file_rejects_symlink_escaping_dump():
    """A symlink inside the dump pointing at a host file outside it must be
    rejected, so an in-place rewriter never follows it and clobbers the host."""
    d = tempfile.mkdtemp()
    host = Path(d) / "host_secret.docx"
    host.write_text("operator's real file")
    dump = Path(d) / "dump"
    dump.mkdir()
    link = dump / "report.docx"
    try:
        link.symlink_to(host)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/privilege level")
    assert link.is_symlink()
    assert is_safe_regular_file(link, dump) is False
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def test_safe_utime_does_not_follow_symlink_out_of_dump():
    """safe_utime must refuse a symlink target outside the dump, leaving the
    host file's mtime untouched."""
    d = tempfile.mkdtemp()
    host = Path(d) / "host_file"
    host.write_text("host")
    original_mtime = host.stat().st_mtime
    dump = Path(d) / "dump"
    dump.mkdir()
    link = dump / "link"
    try:
        link.symlink_to(host)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/privilege level")
    applied = safe_utime(link, dump, (0.0, 0.0))
    assert applied is False
    assert host.stat().st_mtime == original_mtime, "host file mtime must be untouched"
    import shutil
    shutil.rmtree(d, ignore_errors=True)


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
