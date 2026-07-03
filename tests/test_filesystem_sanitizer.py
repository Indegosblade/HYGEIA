"""Tests for forensic artifact cleanup."""

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.filesystem_sanitizer import sanitize_filesystem


def test_leveldb_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    ldb = root / "Local Storage" / "leveldb"
    ldb.mkdir(parents=True)
    (ldb / "000001.ldb").write_bytes(b"fake")
    (ldb / "MANIFEST-000001").write_bytes(b"fake")
    sanitize_filesystem(root)
    assert not ldb.exists(), "LevelDB directory should be deleted"
    shutil.rmtree(d, ignore_errors=True)


def test_shell_history_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / ".bash_history").write_text("secret command\n")
    (root / ".zsh_history").write_text("another secret\n")
    (root / "keepme.txt").write_text("safe\n")
    sanitize_filesystem(root)
    assert not (root / ".bash_history").exists()
    assert not (root / ".zsh_history").exists()
    assert (root / "keepme.txt").exists()
    shutil.rmtree(d, ignore_errors=True)


def test_thumbnail_cache_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    thumbs = root / "PhotoData" / "Thumbnails"
    thumbs.mkdir(parents=True)
    (thumbs / "thumb1.jpg").write_bytes(b"\xff\xd8")
    sanitize_filesystem(root)
    assert not thumbs.exists()
    shutil.rmtree(d, ignore_errors=True)


def test_spotlight_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    spotlight = root / ".Spotlight-V100"
    spotlight.mkdir()
    (spotlight / "store.db").write_bytes(b"index")
    sanitize_filesystem(root)
    assert not spotlight.exists()
    shutil.rmtree(d, ignore_errors=True)


def test_session_file_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "Current Session").write_bytes(b"session data")
    (root / "Last Session").write_bytes(b"old session")
    sanitize_filesystem(root)
    assert not (root / "Current Session").exists()
    assert not (root / "Last Session").exists()
    shutil.rmtree(d, ignore_errors=True)


def test_forensic_file_patterns():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "data.ldb").write_bytes(b"leveldb")
    (root / "Thumbcache_256.db").write_bytes(b"thumb")
    (root / "keepme.py").write_text("code")
    sanitize_filesystem(root)
    assert not (root / "data.ldb").exists()
    assert not (root / "Thumbcache_256.db").exists()
    assert (root / "keepme.py").exists()
    shutil.rmtree(d, ignore_errors=True)


def test_timestamp_normalization():
    d = tempfile.mkdtemp()
    root = Path(d)
    f = root / "test.txt"
    f.write_text("content")
    actions = sanitize_filesystem(root, normalize_timestamps=True)
    ts_action = next((a for a in actions if a.get("action") == "normalize_timestamps"), None)
    assert ts_action is not None
    assert ts_action["files_normalized"] >= 1
    mtime = os.path.getmtime(f)
    assert mtime == 946684800, f"Expected epoch 2000-01-01, got {mtime}"
    shutil.rmtree(d, ignore_errors=True)


def test_dry_run_no_changes():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / ".bash_history").write_text("secret\n")
    spotlight = root / ".Spotlight-V100"
    spotlight.mkdir()
    (spotlight / "db").write_bytes(b"x")
    actions = sanitize_filesystem(root, dry_run=True)
    assert (root / ".bash_history").exists(), "Dry run should not delete"
    assert spotlight.exists(), "Dry run should not delete"
    assert any(a.get("dry_run") for a in actions)
    shutil.rmtree(d, ignore_errors=True)


def test_normalize_timestamps_symlink_to_outside_file_untouched():
    """Regression for finding #29: a symlink preserved in the dump (copy_dump
    uses copytree(symlinks=True)) whose target lives OUTSIDE dump_path must
    not have its mtime rewritten. Raw os.utime(f, times) defaults to
    follow_symlinks=True, so normalizing timestamps used to reset the
    modification time of an arbitrary host file the symlink pointed at --
    e.g. /etc/hosts or a copied /home link."""
    d = tempfile.mkdtemp()
    host_dir = tempfile.mkdtemp()
    try:
        root = Path(d)
        host_file = Path(host_dir) / "host_secret.txt"
        host_file.write_text("operator's real file, not part of the dump")
        original_mtime = host_file.stat().st_mtime

        link = root / "preserved_link.txt"
        try:
            link.symlink_to(host_file)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this platform/privilege level")

        # A genuine in-dump file must still get normalized, proving the pass ran.
        in_dump = root / "note.txt"
        in_dump.write_text("in-dump content")

        sanitize_filesystem(root, normalize_timestamps=True)

        assert host_file.stat().st_mtime == original_mtime, (
            "normalize_timestamps must never follow a symlink out of the dump"
        )
        assert in_dump.stat().st_mtime == 946684800, (
            "a genuine in-dump file must still be normalized"
        )
    finally:
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(host_dir, ignore_errors=True)


def test_symlinked_forensic_dir_not_reported_as_deleted():
    """Regression for finding #30: shutil.rmtree() refuses to operate on a
    symlink (it raises, and ignore_errors=True swallows the error), so a
    symlinked forensic-artifact directory is never actually removed. The old
    code appended a "delete_forensic_dir" success action unconditionally --
    a false clean recorded for a store that still exists in full. The real
    target (living outside the dump, as a crafted dump could arrange) must
    survive, and no success action may be recorded for it."""
    d = tempfile.mkdtemp()
    target_dir = tempfile.mkdtemp()
    try:
        root = Path(d)
        target = Path(target_dir)
        (target / "CURRENT").write_bytes(b"1")
        pii_file = target / "000001.ldb"
        pii_file.write_bytes(b"recoverable leveldb PII bytes")

        (root / "Local Storage").mkdir(parents=True)
        symlinked_store = root / "Local Storage" / "leveldb"
        try:
            symlinked_store.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this platform/privilege level")

        actions = sanitize_filesystem(root)

        assert target.exists() and pii_file.exists(), (
            "the real store outside the dump must survive -- rmtree must "
            "never follow a symlink"
        )
        assert not any(
            a.get("action") == "delete_forensic_dir" and a.get("path") == "Local Storage/leveldb"
            for a in actions
        ), "must not record a successful deletion for a symlinked store that was never removed"
    finally:
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(target_dir, ignore_errors=True)


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
