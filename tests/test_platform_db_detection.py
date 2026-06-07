"""
Tests for platform-specific database detection.

Covers the new entries added to delete_patterns.json database_patterns
and the new PII_TABLES entries added to sqlite_sanitizer.py.
"""

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.scanner import FileScanner, FileAction, JailbreakInfo
from hygeia.sqlite_sanitizer import sanitize_database_generic


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_file(tmpdir: str, rel_path: str) -> Path:
    """Create a minimal file at rel_path inside tmpdir and return dump root."""
    full = Path(tmpdir) / rel_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(b"test")
    return Path(tmpdir)


def _scanner_deletes(db_name: str) -> None:
    """Assert the scanner classifies db_name as DELETE via database_patterns."""
    scanner = FileScanner()
    jb = JailbreakInfo()
    with tempfile.TemporaryDirectory() as tmpdir:
        rel = f"some/path/{db_name}"
        dump = _make_file(tmpdir, rel)
        result = scanner.classify_file(rel, dump, jb)
        assert result.action == FileAction.DELETE, (
            f"{db_name!r} should be DELETE via database_patterns (got {result.action})"
        )


def _make_db_with_table(tmp_path: Path, table_name: str) -> Path:
    """Create a SQLite database containing table_name with one row."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(f'CREATE TABLE "{table_name}" (id INTEGER, data TEXT)')
    conn.execute(f'INSERT INTO "{table_name}" VALUES (1, "sensitive")')
    conn.commit()
    conn.close()
    return db_path


# ---------------------------------------------------------------------------
# Chrome database patterns
# ---------------------------------------------------------------------------

CHROME_DBS = [
    "Web Data",
    "Login Data",
    "Shortcuts",
    "Network Action Predictor",
    "Affiliation Database",
    "Extension Cookies",
]


def test_chrome_web_data_deleted():
    _scanner_deletes("Web Data")


def test_chrome_login_data_deleted():
    _scanner_deletes("Login Data")


def test_chrome_shortcuts_deleted():
    _scanner_deletes("Shortcuts")


def test_chrome_network_action_predictor_deleted():
    _scanner_deletes("Network Action Predictor")


def test_chrome_affiliation_database_deleted():
    _scanner_deletes("Affiliation Database")


def test_chrome_extension_cookies_deleted():
    _scanner_deletes("Extension Cookies")


# ---------------------------------------------------------------------------
# Firefox database patterns
# ---------------------------------------------------------------------------

FIREFOX_DBS = [
    "signons.sqlite",
    "key4.db",
    "cert9.db",
    "content-prefs.sqlite",
    "permissions.sqlite",
]


def test_firefox_signons_deleted():
    _scanner_deletes("signons.sqlite")


def test_firefox_key4_deleted():
    _scanner_deletes("key4.db")


def test_firefox_cert9_deleted():
    _scanner_deletes("cert9.db")


def test_firefox_content_prefs_deleted():
    _scanner_deletes("content-prefs.sqlite")


def test_firefox_permissions_deleted():
    _scanner_deletes("permissions.sqlite")


# ---------------------------------------------------------------------------
# Android database patterns
# ---------------------------------------------------------------------------

ANDROID_DBS = [
    "contacts2.db",
    "telephony.db",
    "mmssms.db",
    "calendar.db",
    "accounts.db",
]


def test_android_contacts2_deleted():
    _scanner_deletes("contacts2.db")


def test_android_telephony_deleted():
    _scanner_deletes("telephony.db")


def test_android_mmssms_deleted():
    _scanner_deletes("mmssms.db")


def test_android_calendar_deleted():
    _scanner_deletes("calendar.db")


def test_android_accounts_deleted():
    _scanner_deletes("accounts.db")


# ---------------------------------------------------------------------------
# Windows database / artifact patterns
# ---------------------------------------------------------------------------

WINDOWS_DBS = [
    "WebCacheV01.dat",
    "ActivitiesCache.db",
    "Amcache.hve",
]


def test_windows_webcachev01_deleted():
    _scanner_deletes("WebCacheV01.dat")


def test_windows_activitiescache_deleted():
    _scanner_deletes("ActivitiesCache.db")


def test_windows_amcache_deleted():
    _scanner_deletes("Amcache.hve")


# ---------------------------------------------------------------------------
# macOS database patterns
# ---------------------------------------------------------------------------

def test_macos_knowledgec_deleted():
    _scanner_deletes("knowledgeC.db")


# interactionC.db was already present — guard against regression
def test_macos_interactionc_still_deleted():
    _scanner_deletes("interactionC.db")


# ---------------------------------------------------------------------------
# PII_TABLES: stats_table and location_history
# ---------------------------------------------------------------------------

def test_pii_table_stats_table_nuked():
    """stats_table rows must be deleted by the generic sanitizer."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = _make_db_with_table(Path(tmpdir), "stats_table")
        result = sanitize_database_generic(db_path)
        assert "error" not in result, f"Sanitizer error: {result.get('error')}"
        conn = sqlite3.connect(str(db_path))
        count = conn.execute('SELECT COUNT(*) FROM "stats_table"').fetchone()[0]
        conn.close()
        assert count == 0, f"stats_table should be empty after sanitize (got {count} rows)"


def test_pii_table_location_history_nuked():
    """location_history rows must be deleted by the generic sanitizer."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = _make_db_with_table(Path(tmpdir), "location_history")
        result = sanitize_database_generic(db_path)
        assert "error" not in result, f"Sanitizer error: {result.get('error')}"
        conn = sqlite3.connect(str(db_path))
        count = conn.execute('SELECT COUNT(*) FROM "location_history"').fetchone()[0]
        conn.close()
        assert count == 0, f"location_history should be empty after sanitize (got {count} rows)"


def test_pii_table_credit_cards_still_nuked():
    """Regression: credit_cards must remain in PII_TABLES."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = _make_db_with_table(Path(tmpdir), "credit_cards")
        result = sanitize_database_generic(db_path)
        assert "error" not in result, f"Sanitizer error: {result.get('error')}"
        conn = sqlite3.connect(str(db_path))
        count = conn.execute('SELECT COUNT(*) FROM "credit_cards"').fetchone()[0]
        conn.close()
        assert count == 0, f"credit_cards should be empty after sanitize (got {count} rows)"


def test_pii_table_messages_still_nuked():
    """Regression: messages must remain in PII_TABLES."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = _make_db_with_table(Path(tmpdir), "messages")
        result = sanitize_database_generic(db_path)
        assert "error" not in result, f"Sanitizer error: {result.get('error')}"
        conn = sqlite3.connect(str(db_path))
        count = conn.execute('SELECT COUNT(*) FROM "messages"').fetchone()[0]
        conn.close()
        assert count == 0, f"messages should be empty after sanitize (got {count} rows)"


def test_pii_table_moz_annos_still_nuked():
    """Regression: moz_annos must remain in PII_TABLES."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = _make_db_with_table(Path(tmpdir), "moz_annos")
        result = sanitize_database_generic(db_path)
        assert "error" not in result, f"Sanitizer error: {result.get('error')}"
        conn = sqlite3.connect(str(db_path))
        count = conn.execute('SELECT COUNT(*) FROM "moz_annos"').fetchone()[0]
        conn.close()
        assert count == 0, f"moz_annos should be empty after sanitize (got {count} rows)"


# ---------------------------------------------------------------------------
# Bulk coverage: all new database_patterns must be classified DELETE
# ---------------------------------------------------------------------------

ALL_NEW_DB_PATTERNS = CHROME_DBS + FIREFOX_DBS + ANDROID_DBS + WINDOWS_DBS + ["knowledgeC.db"]


def test_all_new_database_patterns_deleted():
    """Bulk check: every new database_patterns entry must be DELETE."""
    scanner = FileScanner()
    jb = JailbreakInfo()
    failures = []
    for db_name in ALL_NEW_DB_PATTERNS:
        with tempfile.TemporaryDirectory() as tmpdir:
            rel = f"some/path/{db_name}"
            dump = _make_file(tmpdir, rel)
            result = scanner.classify_file(rel, dump, jb)
            if result.action != FileAction.DELETE:
                failures.append(f"{db_name!r}: got {result.action}")
    assert not failures, "These new DB patterns were NOT classified DELETE:\n" + "\n".join(failures)


if __name__ == "__main__":
    # Run quick smoke-test without pytest
    tests = [
        test_chrome_web_data_deleted,
        test_chrome_login_data_deleted,
        test_chrome_shortcuts_deleted,
        test_chrome_network_action_predictor_deleted,
        test_chrome_affiliation_database_deleted,
        test_chrome_extension_cookies_deleted,
        test_firefox_signons_deleted,
        test_firefox_key4_deleted,
        test_firefox_cert9_deleted,
        test_firefox_content_prefs_deleted,
        test_firefox_permissions_deleted,
        test_android_contacts2_deleted,
        test_android_telephony_deleted,
        test_android_mmssms_deleted,
        test_android_calendar_deleted,
        test_android_accounts_deleted,
        test_windows_webcachev01_deleted,
        test_windows_activitiescache_deleted,
        test_windows_amcache_deleted,
        test_macos_knowledgec_deleted,
        test_macos_interactionc_still_deleted,
        test_pii_table_stats_table_nuked,
        test_pii_table_location_history_nuked,
        test_pii_table_credit_cards_still_nuked,
        test_pii_table_messages_still_nuked,
        test_pii_table_moz_annos_still_nuked,
        test_all_new_database_patterns_deleted,
    ]
    for t in tests:
        t()
        print(f"  PASS  {t.__name__}")
    print(f"\nAll {len(tests)} tests passed.")
