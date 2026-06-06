"""Tests for forensic artifact cleanup."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.filesystem_sanitizer import sanitize_filesystem


def test_leveldb_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    ldb = root / "Local Storage" / "leveldb"
    ldb.mkdir(parents=True)
    (ldb / "000001.ldb").write_bytes(b"fake")
    (ldb / "MANIFEST-000001").write_bytes(b"fake")
    actions = sanitize_filesystem(root)
    assert not ldb.exists(), "LevelDB directory should be deleted"
    import shutil; shutil.rmtree(d, ignore_errors=True)


def test_shell_history_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / ".bash_history").write_text("secret command\n")
    (root / ".zsh_history").write_text("another secret\n")
    (root / "keepme.txt").write_text("safe\n")
    actions = sanitize_filesystem(root)
    assert not (root / ".bash_history").exists()
    assert not (root / ".zsh_history").exists()
    assert (root / "keepme.txt").exists()
    import shutil; shutil.rmtree(d, ignore_errors=True)


def test_thumbnail_cache_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    thumbs = root / "PhotoData" / "Thumbnails"
    thumbs.mkdir(parents=True)
    (thumbs / "thumb1.jpg").write_bytes(b"\xff\xd8")
    actions = sanitize_filesystem(root)
    assert not thumbs.exists()
    import shutil; shutil.rmtree(d, ignore_errors=True)


def test_spotlight_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    spotlight = root / ".Spotlight-V100"
    spotlight.mkdir()
    (spotlight / "store.db").write_bytes(b"index")
    actions = sanitize_filesystem(root)
    assert not spotlight.exists()
    import shutil; shutil.rmtree(d, ignore_errors=True)


def test_session_file_deletion():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "Current Session").write_bytes(b"session data")
    (root / "Last Session").write_bytes(b"old session")
    actions = sanitize_filesystem(root)
    assert not (root / "Current Session").exists()
    assert not (root / "Last Session").exists()
    import shutil; shutil.rmtree(d, ignore_errors=True)


def test_forensic_file_patterns():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "data.ldb").write_bytes(b"leveldb")
    (root / "Thumbcache_256.db").write_bytes(b"thumb")
    (root / "keepme.py").write_text("code")
    actions = sanitize_filesystem(root)
    assert not (root / "data.ldb").exists()
    assert not (root / "Thumbcache_256.db").exists()
    assert (root / "keepme.py").exists()
    import shutil; shutil.rmtree(d, ignore_errors=True)


def test_timestamp_normalization():
    d = tempfile.mkdtemp()
    root = Path(d)
    f = root / "test.txt"
    f.write_text("content")
    actions = sanitize_filesystem(root, normalize_timestamps=True)
    ts_action = next((a for a in actions if a.get("action") == "normalize_timestamps"), None)
    assert ts_action is not None
    assert ts_action["files_normalized"] >= 1
    import os
    mtime = os.path.getmtime(f)
    assert mtime == 946684800, f"Expected epoch 2000-01-01, got {mtime}"
    import shutil; shutil.rmtree(d, ignore_errors=True)


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
    import shutil; shutil.rmtree(d, ignore_errors=True)


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
