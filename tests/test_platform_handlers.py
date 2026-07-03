"""
Tests for hygeia.platform_handlers.

Coverage:
- detect_database_type: minimal SQLite databases with the right table names
- run_platform_handler / handler functions: create test DBs with PII data,
  run handler, verify data deleted/redacted
- sanitize_with_platform_detection: integration path
- fallback behaviour on unrecognised databases
"""

import sqlite3
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.platform_handlers import (
    detect_database_type,
    run_platform_handler,
    sanitize_with_platform_detection,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db(tmp_path: Path, tables: dict) -> Path:
    """
    Create a SQLite database in tmp_path.
    tables maps table_name -> list of column definition strings.
    """
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    for table_name, col_defs in tables.items():
        cols = ", ".join(col_defs)
        conn.execute(f'CREATE TABLE IF NOT EXISTS "{table_name}" ({cols})')
    conn.commit()
    conn.close()
    return db_path


def _make_db_with_rows(tmp_path: Path, table_name: str, col_defs: list,
                       rows: list) -> Path:
    """Create a SQLite database with one table containing the given rows."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    cols = ", ".join(col_defs)
    conn.execute(f'CREATE TABLE IF NOT EXISTS "{table_name}" ({cols})')
    placeholders = ", ".join("?" * len(rows[0]))
    conn.executemany(f'INSERT INTO "{table_name}" VALUES ({placeholders})', rows)
    conn.commit()
    conn.close()
    return db_path


def _count_rows(db_path: Path, table: str) -> int:
    conn = sqlite3.connect(str(db_path))
    count = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
    conn.close()
    return count


# ---------------------------------------------------------------------------
# 1. detect_database_type -- auto-detection tests
# ---------------------------------------------------------------------------

class TestDetectDatabaseType:

    def test_detect_chrome_history(self, tmp_path):
        db = _make_db(tmp_path, {
            "urls": ["id INTEGER", "url TEXT"],
            "visits": ["id INTEGER", "url INTEGER"],
            "visit_source": ["id INTEGER", "source INTEGER"],
            "meta": ["key TEXT", "value TEXT"],
        })
        assert detect_database_type(db) == "chrome_history"

    def test_detect_chrome_login(self, tmp_path):
        db = _make_db(tmp_path, {
            "logins": ["id INTEGER", "username_value TEXT", "password_value BLOB"],
            "insecure_credentials": ["parent_id INTEGER", "insecurity_type INTEGER"],
            "meta": ["key TEXT", "value TEXT"],
        })
        assert detect_database_type(db) == "chrome_login"

    def test_detect_chrome_cookies(self, tmp_path):
        db = _make_db(tmp_path, {
            "cookies": ["creation_utc INTEGER", "host_key TEXT", "value TEXT"],
            "meta": ["key TEXT", "value TEXT"],
        })
        assert detect_database_type(db) == "chrome_cookies"

    def test_detect_chrome_webdata(self, tmp_path):
        db = _make_db(tmp_path, {
            "autofill": ["name TEXT", "value TEXT"],
            "credit_cards": ["guid TEXT", "card_number_encrypted BLOB"],
            "keywords": ["id INTEGER", "short_name TEXT"],
        })
        assert detect_database_type(db) == "chrome_webdata"

    def test_detect_firefox_places(self, tmp_path):
        db = _make_db(tmp_path, {
            "moz_places": ["id INTEGER", "url TEXT"],
            "moz_historyvisits": ["id INTEGER", "place_id INTEGER"],
        })
        assert detect_database_type(db) == "firefox_places"

    def test_detect_firefox_formhistory(self, tmp_path):
        db = _make_db(tmp_path, {
            "moz_formhistory": ["id INTEGER", "fieldname TEXT", "value TEXT"],
        })
        assert detect_database_type(db) == "firefox_formhistory"

    def test_detect_firefox_cookies(self, tmp_path):
        db = _make_db(tmp_path, {
            "moz_cookies": ["id INTEGER", "host TEXT", "value TEXT"],
        })
        assert detect_database_type(db) == "firefox_cookies"

    def test_detect_contacts_ios(self, tmp_path):
        db = _make_db(tmp_path, {
            "ABPerson": ["ROWID INTEGER", "First TEXT", "Last TEXT"],
            "ABMultiValue": ["UID INTEGER", "record_id INTEGER"],
        })
        assert detect_database_type(db) == "contacts_ios"

    def test_detect_messages_ios(self, tmp_path):
        db = _make_db(tmp_path, {
            "message": ["ROWID INTEGER", "text TEXT"],
            "chat": ["ROWID INTEGER", "guid TEXT"],
            "handle": ["ROWID INTEGER", "id TEXT"],
        })
        assert detect_database_type(db) == "messages_ios"

    def test_detect_safari_history(self, tmp_path):
        db = _make_db(tmp_path, {
            "history_items": ["id INTEGER", "url TEXT"],
            "history_visits": ["id INTEGER", "history_item INTEGER"],
        })
        assert detect_database_type(db) == "safari_history"

    def test_detect_android_contacts(self, tmp_path):
        db = _make_db(tmp_path, {
            "raw_contacts": ["_id INTEGER", "display_name TEXT"],
            "data": ["_id INTEGER", "raw_contact_id INTEGER"],
            "mimetypes": ["_id INTEGER", "mimetype TEXT"],
        })
        assert detect_database_type(db) == "android_contacts"

    def test_detect_android_sms(self, tmp_path):
        db = _make_db(tmp_path, {
            "sms": ["_id INTEGER", "address TEXT", "body TEXT"],
            "threads": ["_id INTEGER", "recipient_ids TEXT"],
            "canonical_addresses": ["_id INTEGER", "address TEXT"],
        })
        assert detect_database_type(db) == "android_sms"

    def test_detect_android_calendar(self, tmp_path):
        db = _make_db(tmp_path, {
            "Events": ["_id INTEGER", "title TEXT"],
            "Calendars": ["_id INTEGER", "calendar_displayName TEXT"],
            "Attendees": ["_id INTEGER", "event_id INTEGER", "attendeeEmail TEXT"],
        })
        assert detect_database_type(db) == "android_calendar"

    def test_detect_returns_none_for_empty_db(self, tmp_path):
        db_path = tmp_path / "empty.db"
        conn = sqlite3.connect(str(db_path))
        conn.close()
        assert detect_database_type(db_path) is None

    def test_detect_returns_none_for_unknown_schema(self, tmp_path):
        db = _make_db(tmp_path, {
            "foobar": ["id INTEGER", "data TEXT"],
            "baz": ["id INTEGER", "val BLOB"],
        })
        assert detect_database_type(db) is None

    def test_detect_returns_none_for_non_sqlite_file(self, tmp_path):
        bad = tmp_path / "notadb.db"
        bad.write_bytes(b"this is not a sqlite file at all")
        assert detect_database_type(bad) is None

    def test_detect_returns_none_for_missing_file(self, tmp_path):
        missing = tmp_path / "ghost.db"
        assert detect_database_type(missing) is None


# ---------------------------------------------------------------------------
# 2. Handler tests -- data actually gets deleted/redacted
# ---------------------------------------------------------------------------

class TestChromeHistoryHandler:

    def test_urls_table_cleared(self, tmp_path):
        db = _make_db_with_rows(
            tmp_path, "urls",
            ["id INTEGER", "url TEXT", "title TEXT"],
            [(1, "https://gmail.com", "Gmail"), (2, "https://bank.com", "Bank")],
        )
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE visits (id INTEGER, url INTEGER)")
        conn.execute("CREATE TABLE visit_source (id INTEGER, source INTEGER)")
        conn.execute("INSERT INTO visits VALUES (1, 1)")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "chrome_history")
        assert result["platform"] == "chrome_history"
        assert "urls" in result["tables_cleared"]
        assert _count_rows(db, "urls") == 0

    def test_visits_table_cleared(self, tmp_path):
        db = _make_db(tmp_path, {
            "urls": ["id INTEGER", "url TEXT"],
            "visits": ["id INTEGER", "url INTEGER"],
            "visit_source": ["id INTEGER", "source INTEGER"],
        })
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO visits VALUES (1, 1)")
        conn.execute("INSERT INTO visits VALUES (2, 1)")
        conn.commit()
        conn.close()

        run_platform_handler(db, "chrome_history")
        assert _count_rows(db, "visits") == 0


class TestChromeLoginHandler:

    def test_logins_cleared(self, tmp_path):
        db = _make_db_with_rows(
            tmp_path, "logins",
            ["id INTEGER", "origin_url TEXT", "username_value TEXT", "password_value BLOB"],
            [
                (1, "https://example.com", "alice@example.com", b"secret"),
                (2, "https://bank.com", "alice", b"hunter2"),
            ],
        )
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE insecure_credentials (parent_id INTEGER)")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "chrome_login")
        assert result["platform"] == "chrome_login"
        assert _count_rows(db, "logins") == 0
        assert result["rows_deleted"] >= 2

    def test_insecure_credentials_cleared(self, tmp_path):
        db = _make_db(tmp_path, {
            "logins": ["id INTEGER", "username_value TEXT"],
            "insecure_credentials": ["parent_id INTEGER", "insecurity_type INTEGER"],
        })
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO insecure_credentials VALUES (1, 1)")
        conn.commit()
        conn.close()

        run_platform_handler(db, "chrome_login")
        assert _count_rows(db, "insecure_credentials") == 0


class TestChromeCookiesHandler:

    def test_cookies_cleared(self, tmp_path):
        db = _make_db_with_rows(
            tmp_path, "cookies",
            ["creation_utc INTEGER", "host_key TEXT", "name TEXT", "value TEXT"],
            [
                (100, "gmail.com", "session", "abc123"),
                (200, "bank.com", "auth", "xyz789"),
            ],
        )
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE meta (key TEXT, value TEXT)")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "chrome_cookies")
        assert result["platform"] == "chrome_cookies"
        assert _count_rows(db, "cookies") == 0
        assert result["rows_deleted"] == 2


class TestChromeWebDataHandler:

    def test_autofill_and_credit_cards_cleared(self, tmp_path):
        db = _make_db(tmp_path, {
            "autofill": ["name TEXT", "value TEXT", "count INTEGER"],
            "credit_cards": ["guid TEXT", "name_on_card TEXT"],
            "keywords": ["id INTEGER", "short_name TEXT", "url TEXT"],
        })
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO autofill VALUES ('email', 'alice@example.com', 5)")
        conn.execute("INSERT INTO credit_cards VALUES ('abc', 'Alice Smith')")
        conn.execute("INSERT INTO keywords VALUES (1, 'Google', 'https://google.com')")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "chrome_webdata")
        assert result["platform"] == "chrome_webdata"
        assert _count_rows(db, "autofill") == 0
        assert _count_rows(db, "credit_cards") == 0
        # keywords (search engines) should NOT be deleted
        assert _count_rows(db, "keywords") == 1


class TestFirefoxHandlers:

    def test_firefox_places_cleared(self, tmp_path):
        db = _make_db(tmp_path, {
            "moz_places": ["id INTEGER", "url TEXT", "title TEXT"],
            "moz_historyvisits": ["id INTEGER", "place_id INTEGER"],
        })
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO moz_places VALUES (1, 'https://example.com', 'Example')")
        conn.execute("INSERT INTO moz_historyvisits VALUES (1, 1)")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "firefox_places")
        assert result["platform"] == "firefox_places"
        assert _count_rows(db, "moz_places") == 0
        assert _count_rows(db, "moz_historyvisits") == 0

    def test_firefox_formhistory_cleared(self, tmp_path):
        db = _make_db_with_rows(
            tmp_path, "moz_formhistory",
            ["id INTEGER", "fieldname TEXT", "value TEXT", "timesUsed INTEGER"],
            [(1, "email", "alice@example.com", 10), (2, "address", "123 Main St", 3)],
        )
        result = run_platform_handler(db, "firefox_formhistory")
        assert result["platform"] == "firefox_formhistory"
        assert _count_rows(db, "moz_formhistory") == 0

    def test_firefox_cookies_cleared(self, tmp_path):
        db = _make_db_with_rows(
            tmp_path, "moz_cookies",
            ["id INTEGER", "host TEXT", "name TEXT", "value TEXT"],
            [(1, "example.com", "session", "tok123")],
        )
        result = run_platform_handler(db, "firefox_cookies")
        assert result["platform"] == "firefox_cookies"
        assert _count_rows(db, "moz_cookies") == 0


class TestiOSHandlers:

    def test_ios_contacts_cleared(self, tmp_path):
        db = _make_db(tmp_path, {
            "ABPerson": ["ROWID INTEGER", "First TEXT", "Last TEXT", "Birthday REAL"],
            "ABMultiValue": ["UID INTEGER", "record_id INTEGER", "label INTEGER", "value TEXT"],
            "ABGroup": ["ROWID INTEGER", "Name TEXT"],
        })
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO ABPerson VALUES (1, 'Alice', 'Smith', NULL)")
        conn.execute("INSERT INTO ABMultiValue VALUES (1, 1, 4, 'alice@example.com')")
        conn.execute("INSERT INTO ABGroup VALUES (1, 'Family')")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "contacts_ios")
        assert result["platform"] == "contacts_ios"
        assert _count_rows(db, "ABPerson") == 0
        assert _count_rows(db, "ABMultiValue") == 0
        # ABGroup schema preserved
        assert _count_rows(db, "ABGroup") == 1

    def test_ios_messages_cleared(self, tmp_path):
        db = _make_db(tmp_path, {
            "message": ["ROWID INTEGER", "text TEXT", "date INTEGER"],
            "chat": ["ROWID INTEGER", "guid TEXT"],
            "handle": ["ROWID INTEGER", "id TEXT"],
            "attachment": ["ROWID INTEGER", "filename TEXT"],
        })
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO message VALUES (1, 'Hello there', 700000000)")
        conn.execute("INSERT INTO handle VALUES (1, '+1-555-0100')")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "messages_ios")
        assert result["platform"] == "messages_ios"
        assert _count_rows(db, "message") == 0
        assert _count_rows(db, "handle") == 0

    def test_safari_history_cleared(self, tmp_path):
        db = _make_db(tmp_path, {
            "history_items": ["id INTEGER", "url TEXT", "domain_expansion TEXT"],
            "history_visits": ["id INTEGER", "history_item INTEGER", "visit_time REAL"],
        })
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO history_items VALUES (1, 'https://bank.com/login', 'bank.com')")
        conn.execute("INSERT INTO history_visits VALUES (1, 1, 700000000.0)")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "safari_history")
        assert result["platform"] == "safari_history"
        assert _count_rows(db, "history_items") == 0
        assert _count_rows(db, "history_visits") == 0

    def test_android_sms_cleared(self, tmp_path):
        db = _make_db(tmp_path, {
            "sms": ["_id INTEGER", "address TEXT", "body TEXT", "date INTEGER"],
            "threads": ["_id INTEGER", "recipient_ids TEXT"],
            "canonical_addresses": ["_id INTEGER", "address TEXT"],
        })
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO sms VALUES (1, '+15550100', 'Meet me at 123 Main St', 1600000000)")
        conn.execute("INSERT INTO canonical_addresses VALUES (1, '+15550100')")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "android_sms")
        assert result["platform"] == "android_sms"
        assert _count_rows(db, "sms") == 0
        assert _count_rows(db, "canonical_addresses") == 0


class TestPhotosIOSHandler:
    """
    Regression coverage for audit finding #2 (CRITICAL): the photos_ios
    detection signature used to require BOTH ZASSET and ZGENERICASSET as
    base tables. A real Photos.sqlite never has both -- iOS <=13 names the
    asset table ZGENERICASSET, iOS 14+ renamed it to ZASSET -- so detection
    never fired on any real device, _handle_photos_ios never ran, and GPS
    coordinates in ZLATITUDE/ZLONGITUDE fell through to the generic
    sanitizer, which never scans FLOAT-typed columns. Net effect: every
    photo's home/work GPS coordinates survived in the "sanitized" database.
    """

    @staticmethod
    def _make_photos_db(tmp_path: Path, asset_table: str) -> Path:
        """
        Build a minimal Photos.sqlite with only ONE of the two possible
        asset-table names (mirroring a real device, which never has both),
        holding one row with real GPS coordinates and one row with no
        location fix at all.
        """
        db_path = tmp_path / "Photos.sqlite"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            f'CREATE TABLE "{asset_table}" ('
            "Z_PK INTEGER PRIMARY KEY, ZLATITUDE FLOAT, ZLONGITUDE FLOAT, "
            "ZFILENAME TEXT)"
        )
        conn.execute(
            f'INSERT INTO "{asset_table}" VALUES '
            "(1, 37.7749, -122.4194, 'IMG_0001.HEIC')"
        )
        conn.execute(
            f'INSERT INTO "{asset_table}" VALUES '
            "(2, NULL, NULL, 'IMG_0002.HEIC')"
        )
        conn.commit()
        conn.close()
        return db_path

    def test_detect_fires_on_zasset_only_ios14_schema(self, tmp_path):
        """iOS 14+ schema (only ZASSET) must be detected as photos_ios."""
        db = self._make_photos_db(tmp_path, "ZASSET")
        assert detect_database_type(db) == "photos_ios"

    def test_detect_fires_on_zgenericasset_only_ios13_schema(self, tmp_path):
        """iOS <=13 schema (only ZGENERICASSET) must be detected as photos_ios."""
        db = self._make_photos_db(tmp_path, "ZGENERICASSET")
        assert detect_database_type(db) == "photos_ios"

    def test_gps_coordinates_cleared_on_ios14_schema(self, tmp_path):
        """
        The audit's exact failure scenario: an iOS 16 Photos.sqlite with
        only ZASSET present. The handler must trigger (not silently fall
        through to the generic sanitizer) and must clear the float GPS
        columns -- not just leave them because they aren't strings.
        """
        db = self._make_photos_db(tmp_path, "ZASSET")

        assert detect_database_type(db) == "photos_ios", (
            "detection must fire on ZASSET alone -- ZGENERICASSET never "
            "coexists with it on a real device"
        )

        result = run_platform_handler(db, "photos_ios")
        assert result["platform"] == "photos_ios"
        assert "error" not in result

        conn = sqlite3.connect(str(db))
        with_fix = conn.execute(
            'SELECT ZLATITUDE, ZLONGITUDE, typeof(ZLATITUDE) '
            'FROM "ZASSET" WHERE Z_PK = 1'
        ).fetchone()
        without_fix = conn.execute(
            'SELECT ZLATITUDE, ZLONGITUDE FROM "ZASSET" WHERE Z_PK = 2'
        ).fetchone()
        conn.close()

        # The recoverable home/work coordinates must be gone, not merely
        # skipped because they were floats rather than strings.
        assert with_fix[0] != 37.7749
        assert with_fix[1] != -122.4194
        assert with_fix[0] == "[GPS_REMOVED]"
        assert with_fix[1] == "[GPS_REMOVED]"
        # A row that never had a location fix is left alone (NULL, not "fixed").
        assert without_fix == (None, None)

    def test_gps_coordinates_cleared_on_legacy_ios13_schema(self, tmp_path):
        """Same failure scenario, but on the pre-iOS-14 ZGENERICASSET name."""
        db = self._make_photos_db(tmp_path, "ZGENERICASSET")

        assert detect_database_type(db) == "photos_ios"
        result = run_platform_handler(db, "photos_ios")
        assert result["platform"] == "photos_ios"
        assert "error" not in result

        conn = sqlite3.connect(str(db))
        row = conn.execute(
            'SELECT ZLATITUDE, ZLONGITUDE FROM "ZGENERICASSET" WHERE Z_PK = 1'
        ).fetchone()
        conn.close()
        assert row == ("[GPS_REMOVED]", "[GPS_REMOVED]")

    def test_end_to_end_via_sanitize_with_platform_detection(self, tmp_path):
        """
        The real pipeline entry point (cli.py) calls
        sanitize_with_platform_detection, not detect_database_type or
        run_platform_handler directly. It must also route an iOS 14+ dump
        through the photos_ios handler instead of silently falling back to
        the generic sanitizer that cannot see FLOAT columns.
        """
        db = self._make_photos_db(tmp_path, "ZASSET")

        result = sanitize_with_platform_detection(db)

        assert result["platform_detected"] is True
        assert result["platform"] == "photos_ios"

        conn = sqlite3.connect(str(db))
        lat, lon = conn.execute(
            'SELECT ZLATITUDE, ZLONGITUDE FROM "ZASSET" WHERE Z_PK = 1'
        ).fetchone()
        conn.close()
        assert lat != 37.7749
        assert lon != -122.4194


# ---------------------------------------------------------------------------
# 3. Result structure tests
# ---------------------------------------------------------------------------

class TestResultStructure:

    def test_result_has_required_keys(self, tmp_path):
        db = _make_db_with_rows(
            tmp_path, "moz_cookies",
            ["id INTEGER", "host TEXT", "value TEXT"],
            [(1, "example.com", "tok")],
        )
        result = run_platform_handler(db, "firefox_cookies")
        assert "action" in result
        assert result["action"] == "platform_sanitize"
        assert "platform" in result
        assert "tables_cleared" in result
        assert "rows_deleted" in result
        assert isinstance(result["tables_cleared"], list)
        assert isinstance(result["rows_deleted"], int)

    def test_rows_deleted_is_accurate(self, tmp_path):
        db = _make_db(tmp_path, {
            "moz_formhistory": ["id INTEGER", "fieldname TEXT", "value TEXT"],
        })
        conn = sqlite3.connect(str(db))
        for i in range(7):
            conn.execute(f"INSERT INTO moz_formhistory VALUES ({i}, 'name', 'val{i}')")
        conn.commit()
        conn.close()

        result = run_platform_handler(db, "firefox_formhistory")
        assert result["rows_deleted"] == 7

    def test_unknown_handler_falls_back_to_generic(self, tmp_path):
        db = _make_db(tmp_path, {
            "random_table": ["id INTEGER", "email TEXT"],
        })
        result = run_platform_handler(db, "nonexistent_platform")
        assert result.get("fallback_to_generic") is True

    def test_windows_webcache_returns_warning(self, tmp_path):
        db = tmp_path / "WebCacheV01.dat"
        db.write_bytes(b"ESE format header placeholder")
        result = run_platform_handler(db, "windows_webcache")
        assert result["platform"] == "windows_webcache"
        assert "warning" in result
        assert "ESE" in result["warning"]


# ---------------------------------------------------------------------------
# 4. sanitize_with_platform_detection integration
# ---------------------------------------------------------------------------

class TestSanitizeWithPlatformDetection:

    def test_recognised_db_sets_platform_detected_true(self, tmp_path):
        db = _make_db_with_rows(
            tmp_path, "moz_cookies",
            ["id INTEGER", "host TEXT", "value TEXT"],
            [(1, "example.com", "tok")],
        )
        result = sanitize_with_platform_detection(db)
        assert result["platform_detected"] is True
        assert result["platform"] == "firefox_cookies"

    def test_unrecognised_db_sets_platform_detected_false(self, tmp_path):
        db = _make_db(tmp_path, {"stuff": ["id INTEGER", "data TEXT"]})
        result = sanitize_with_platform_detection(db)
        assert result["platform_detected"] is False

    def test_residual_scan_runs_after_platform_handler(self, tmp_path):
        # Build a firefox cookies DB, add an extra table with an email the
        # handler doesn't know about -- the residual sweep should catch it.
        db = _make_db(tmp_path, {
            "moz_cookies": ["id INTEGER", "host TEXT", "value TEXT"],
            "extra_data": ["id INTEGER", "email TEXT"],
        })
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO moz_cookies VALUES (1, 'example.com', 'tok')")
        conn.execute("INSERT INTO extra_data VALUES (1, 'alice@example.com')")
        conn.commit()
        conn.close()

        result = sanitize_with_platform_detection(db)
        # The residual key should be present
        assert "residual_rows_redacted" in result
