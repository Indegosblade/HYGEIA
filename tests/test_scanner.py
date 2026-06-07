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


def test_wifi_plist_is_deleted():
    """WiFi plists must be DELETED, not sanitized — they contain SSIDs, BSSIDs, and passwords."""
    scanner = FileScanner()
    jb = JailbreakInfo()
    for wifi_file in [
        "com.apple.wifi.plist",
        "com.apple.wifi.known-networks.plist",
        "com.apple.wifi-private-mac-oui-data.plist",
        "com.apple.wifi.sharing.plist",
    ]:
        with tempfile.TemporaryDirectory() as tmpdir:
            rel = f"private/var/mobile/Library/Preferences/{wifi_file}"
            dump = _make_dump_with_file(tmpdir, rel)
            result = scanner.classify_file(rel, dump, jb)
            assert result.action == FileAction.DELETE, (
                f"{wifi_file} should be DELETE (got {result.action}): "
                "WiFi plists contain SSIDs, BSSIDs, and passwords — full PII"
            )


def test_wifi_plist_not_sanitized_when_in_sanitize_path():
    """WiFi plist DELETE must fire before PLIST_SANITIZE path check."""
    scanner = FileScanner()
    jb = JailbreakInfo()
    with tempfile.TemporaryDirectory() as tmpdir:
        # /wireless/Library/Preferences/ is in plist sanitize_paths
        rel = "wireless/Library/Preferences/com.apple.wifi.plist"
        dump = _make_dump_with_file(tmpdir, rel)
        result = scanner.classify_file(rel, dump, jb)
        assert result.action == FileAction.DELETE, (
            "WiFi plist DELETE must take priority over PLIST_SANITIZE path match"
        )


def test_database_patterns_wired_to_scanner():
    """database_patterns in delete_patterns.json must be enforced by the scanner."""
    scanner = FileScanner()
    jb = JailbreakInfo()
    # sms.db outside its usual directory — should still be deleted
    with tempfile.TemporaryDirectory() as tmpdir:
        rel = "some/unexpected/path/sms.db"
        dump = _make_dump_with_file(tmpdir, rel)
        result = scanner.classify_file(rel, dump, jb)
        assert result.action == FileAction.DELETE, (
            "sms.db should be DELETE regardless of directory (database_patterns wired)"
        )


def test_database_patterns_covers_known_databases():
    """Spot-check several entries from database_patterns are honoured by scanner."""
    scanner = FileScanner()
    jb = JailbreakInfo()
    known_dbs = [
        "AddressBook.sqlitedb",
        "CallHistory.storedata",
        "healthdb_secure.sqlite",
        "Accounts3.sqlite",
        "SiriAnalytics.db",
    ]
    for db_name in known_dbs:
        with tempfile.TemporaryDirectory() as tmpdir:
            rel = f"some/path/{db_name}"
            dump = _make_dump_with_file(tmpdir, rel)
            result = scanner.classify_file(rel, dump, jb)
            assert result.action == FileAction.DELETE, (
                f"{db_name} should be DELETE via database_patterns (got {result.action})"
            )


if __name__ == "__main__":
    test_scanner_init()
    test_classify_system_file()
    test_classify_sms_database()
    test_classify_photos()
    test_unknown_defaults_to_preserve()
    test_wifi_plist_is_deleted()
    test_wifi_plist_not_sanitized_when_in_sanitize_path()
    test_database_patterns_wired_to_scanner()
    test_database_patterns_covers_known_databases()
    print("All tests passed.")
