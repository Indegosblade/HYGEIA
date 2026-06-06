"""Basic tests for HYGEIA scanner module."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.scanner import FileScanner, FileAction, JailbreakInfo


def _make_dump_with_file(tmpdir, rel_path):
    """Create a minimal file in a temp dump directory."""
    full = Path(tmpdir) / rel_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(b"test")
    return Path(tmpdir)


def test_scanner_init():
    scanner = FileScanner()
    assert scanner.delete_patterns is not None
    assert scanner.preserve_patterns is not None
    assert scanner.selective_db_rules is not None
    assert scanner.plist_patterns is not None


def test_classify_system_file():
    scanner = FileScanner()
    jb = JailbreakInfo()
    with tempfile.TemporaryDirectory() as tmpdir:
        dump = _make_dump_with_file(tmpdir, "System/Library/Caches/com.apple.kernelcaches/kernelcache")
        result = scanner.classify_file("System/Library/Caches/com.apple.kernelcaches/kernelcache", dump, jb)
        assert result.action == FileAction.PRESERVE


def test_classify_sms_database():
    scanner = FileScanner()
    jb = JailbreakInfo()
    with tempfile.TemporaryDirectory() as tmpdir:
        rel = "private/var/mobile/Library/SMS/sms.db"
        dump = _make_dump_with_file(tmpdir, rel)
        result = scanner.classify_file(rel, dump, jb)
        assert result.action == FileAction.DELETE


def test_classify_photos():
    scanner = FileScanner()
    jb = JailbreakInfo()
    with tempfile.TemporaryDirectory() as tmpdir:
        rel = "private/var/mobile/Media/DCIM/100APPLE/IMG_0001.HEIC"
        dump = _make_dump_with_file(tmpdir, rel)
        result = scanner.classify_file(rel, dump, jb)
        assert result.action == FileAction.DELETE


def test_unknown_defaults_to_preserve():
    scanner = FileScanner()
    jb = JailbreakInfo()
    with tempfile.TemporaryDirectory() as tmpdir:
        rel = "some/unknown/path/file.xyz"
        dump = _make_dump_with_file(tmpdir, rel)
        result = scanner.classify_file(rel, dump, jb)
        assert result.action == FileAction.PRESERVE


if __name__ == "__main__":
    test_scanner_init()
    test_classify_system_file()
    test_classify_sms_database()
    test_classify_photos()
    test_unknown_defaults_to_preserve()
    print("All tests passed.")
