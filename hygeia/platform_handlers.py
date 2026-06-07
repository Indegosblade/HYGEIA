"""
HYGEIA Platform Handlers — Schema-aware surgical sanitization.

Generic scanning catches PII in any SQLite database via regex + column-name
heuristics.  Platform-specific handlers go further: they know the exact schema,
which tables to nuke entirely, which columns to redact, and what's safe to keep.

Usage
-----
    from hygeia.platform_handlers import detect_database_type, run_platform_handler

    db_type = detect_database_type(db_path)
    if db_type:
        result = run_platform_handler(db_path, db_type)
    else:
        result = sanitize_database_generic(db_path)  # fallback
"""

import logging
import sqlite3
from pathlib import Path
from typing import Optional

from .sqlite_sanitizer import (
    checkpoint_and_prepare,
    vacuum_and_cleanup,
    sanitize_database_generic,
    is_sqlite_database,
)

log = logging.getLogger("hygeia.platform_handlers")


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

# Map of (required_tables, optional_tables_that_boost_confidence) -> db_type
# A DB type matches when ALL required tables exist.
_DETECTION_SIGNATURES: list[tuple[frozenset, str]] = [
    # Chrome — order matters: more-specific checks first
    (frozenset({"logins", "insecure_credentials"}), "chrome_login"),
    (frozenset({"cookies", "meta"}), "chrome_cookies"),
    (frozenset({"autofill", "credit_cards", "keywords"}), "chrome_webdata"),
    (frozenset({"urls", "visits", "visit_source"}), "chrome_history"),
    # Firefox
    (frozenset({"moz_places", "moz_historyvisits"}), "firefox_places"),
    (frozenset({"moz_formhistory"}), "firefox_formhistory"),
    (frozenset({"moz_cookies"}), "firefox_cookies"),
    # iOS
    (frozenset({"ABPerson", "ABMultiValue"}), "contacts_ios"),
    (frozenset({"message", "chat", "handle"}), "messages_ios"),
    (frozenset({"ZASSET", "ZGENERICASSET"}), "photos_ios"),
    (frozenset({"samples", "quantity_samples", "objects"}), "health_ios"),
    (frozenset({"history_items", "history_visits"}), "safari_history"),
    (frozenset({"bookmarks", "folders"}), "safari_bookmarks"),
    (frozenset({"ZICCLOUDSYNCINGOBJECT", "ZICNOTEDATA"}), "notes_ios"),
    (frozenset({"ZOBJECT", "ZSTRUCTUREDMETADATA"}), "knowledgec"),
    (frozenset({"kusage", "kapp_usage"}), "screentime"),
    (frozenset({"access"}), "tcc"),
    # Android
    (frozenset({"raw_contacts", "data", "mimetypes"}), "android_contacts"),
    (frozenset({"sms", "threads", "canonical_addresses"}), "android_sms"),
    (frozenset({"Events", "Calendars", "Attendees"}), "android_calendar"),
    # Windows
    (frozenset({"Entries", "Containers"}), "windows_webcache"),
]


def detect_database_type(db_path: Path) -> Optional[str]:
    """
    Examine table names/schema to identify the database type.

    Returns one of the known type strings (see module docstring) or None
    if the database is not recognised.
    """
    if not db_path.exists() or not is_sqlite_database(db_path):
        return None

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()
    except sqlite3.Error as e:
        log.debug(f"detect_database_type failed on {db_path}: {e}")
        return None

    if not tables:
        return None

    tables_lower = {t.lower() for t in tables}

    for required, db_type in _DETECTION_SIGNATURES:
        required_lower = {t.lower() for t in required}
        if required_lower.issubset(tables_lower):
            return db_type

    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _delete_tables(conn: sqlite3.Connection, tables_to_clear: list[str]) -> tuple[list[str], int]:
    """
    DELETE all rows from each named table that exists in the database.
    Returns (cleared_table_names, total_rows_deleted).
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )
    existing = {row[0].lower() for row in cursor.fetchall()}

    cleared = []
    total = 0
    for t in tables_to_clear:
        if t.lower() not in existing:
            continue
        try:
            cursor.execute(f'SELECT COUNT(*) FROM "{t}"')
            count = cursor.fetchone()[0]
            cursor.execute(f'DELETE FROM "{t}"')
            cleared.append(t)
            total += count
        except sqlite3.Error as e:
            log.warning(f"Could not clear table {t!r}: {e}")
    conn.commit()
    return cleared, total


def _redact_columns(
    conn: sqlite3.Connection,
    table: str,
    columns: list[str],
    redact_value: str = "[REDACTED]",
) -> int:
    """
    UPDATE non-null, non-empty values in specified columns to redact_value.
    Returns rows affected.
    """
    cursor = conn.cursor()
    # Confirm table exists
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )
    existing = {row[0].lower() for row in cursor.fetchall()}
    if table.lower() not in existing:
        return 0

    # Get actual column names (preserve case)
    cursor.execute(f'PRAGMA table_info("{table}")')
    actual_cols = {row[1].lower(): row[1] for row in cursor.fetchall()}

    total = 0
    for col in columns:
        actual = actual_cols.get(col.lower())
        if actual is None:
            continue
        try:
            cursor.execute(
                f'UPDATE "{table}" SET "{actual}" = ? '
                f'WHERE "{actual}" IS NOT NULL AND "{actual}" != ""',
                (redact_value,),
            )
            total += cursor.rowcount if cursor.rowcount > 0 else 0
        except sqlite3.Error as e:
            log.warning(f"Could not redact {table}.{actual}: {e}")
    conn.commit()
    return total


def _open_and_prepare(db_path: Path):
    """Open a connection, checkpoint WAL, enable secure_delete."""
    conn = sqlite3.connect(str(db_path))
    checkpoint_and_prepare(conn)
    return conn


def _build_result(db_type: str, db_path: Path) -> dict:
    return {
        "action": "platform_sanitize",
        "platform": db_type,
        "path": str(db_path),
        "tables_cleared": [],
        "rows_deleted": 0,
    }


# ---------------------------------------------------------------------------
# Chrome handlers
# ---------------------------------------------------------------------------

def _handle_chrome_history(db_path: Path) -> dict:
    result = _build_result("chrome_history", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "urls", "visits", "visit_source", "keyword_search_terms",
            "typed_url_stats", "downloads", "downloads_url_chains",
            "content_annotations", "context_annotations",
            "network_action_predictor", "omni_box_shortcuts",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"chrome_history handler failed on {db_path}: {e}")
    return result


def _handle_chrome_login(db_path: Path) -> dict:
    result = _build_result("chrome_login", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "logins", "stats", "insecure_credentials",
            "compromised_credentials", "password_notes",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"chrome_login handler failed on {db_path}: {e}")
    return result


def _handle_chrome_cookies(db_path: Path) -> dict:
    result = _build_result("chrome_cookies", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, ["cookies"])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"chrome_cookies handler failed on {db_path}: {e}")
    return result


def _handle_chrome_webdata(db_path: Path) -> dict:
    result = _build_result("chrome_webdata", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "autofill", "autofill_profiles", "autofill_profile_names",
            "autofill_profile_emails", "autofill_profile_phones",
            "autofill_profile_addresses", "autofill_profiles_trash",
            "local_addresses", "local_numbers", "local_names", "local_emails",
            "contact_info", "server_addresses", "server_card_metadata",
            "credit_cards", "local_ibans", "server_card_cloud_token_data",
            "masked_credit_cards",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"chrome_webdata handler failed on {db_path}: {e}")
    return result


# ---------------------------------------------------------------------------
# Firefox handlers
# ---------------------------------------------------------------------------

def _handle_firefox_places(db_path: Path) -> dict:
    result = _build_result("firefox_places", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "moz_places", "moz_historyvisits", "moz_inputhistory",
            "moz_annos", "moz_places_metadata",
            "moz_places_metadata_search_queries", "moz_bookmarks_deleted",
            "moz_perms", "moz_hosts",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"firefox_places handler failed on {db_path}: {e}")
    return result


def _handle_firefox_formhistory(db_path: Path) -> dict:
    result = _build_result("firefox_formhistory", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, ["moz_formhistory"])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"firefox_formhistory handler failed on {db_path}: {e}")
    return result


def _handle_firefox_cookies(db_path: Path) -> dict:
    result = _build_result("firefox_cookies", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, ["moz_cookies"])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"firefox_cookies handler failed on {db_path}: {e}")
    return result


# ---------------------------------------------------------------------------
# iOS handlers
# ---------------------------------------------------------------------------

def _handle_contacts_ios(db_path: Path) -> dict:
    result = _build_result("contacts_ios", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "ABPerson", "ABMultiValue", "ABMultiValueEntry",
            "ABMultiValueLabel", "ABGroupMembers",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"contacts_ios handler failed on {db_path}: {e}")
    return result


def _handle_messages_ios(db_path: Path) -> dict:
    result = _build_result("messages_ios", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "message", "chat", "attachment", "handle",
            "chat_message_join", "chat_handle_join",
            "deleted_messages", "message_attachment_join",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"messages_ios handler failed on {db_path}: {e}")
    return result


def _handle_photos_ios(db_path: Path) -> dict:
    """
    Selective: NULL GPS coordinates and delete facial recognition tables.
    Keep schema and non-geographic metadata so the Photos library remains usable.
    """
    result = _build_result("photos_ios", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "ZPERSON", "ZDETECTEDFACE", "ZDETECTEDFACEPRINT",
            "ZCLOUDSHAREDALBUMINVITATIONRECORD", "ZSHARE",
            "ZMEMORY", "ZSCENEPRINT",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows

        # Redact GPS from asset tables
        gps_cols = ["ZLATITUDE", "ZLONGITUDE", "ZLOCATION"]
        for asset_table in ("ZASSET", "ZGENERICASSET"):
            gps_rows = _redact_columns(conn, asset_table, gps_cols, "[GPS_REMOVED]")
            result["rows_deleted"] += gps_rows

        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"photos_ios handler failed on {db_path}: {e}")
    return result


def _handle_health_ios(db_path: Path) -> dict:
    result = _build_result("health_ios", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "samples", "quantity_samples", "category_samples",
            "correlation_samples", "workout_events", "workout_activities",
            "data_provenances", "activity_caches", "ecg_samples",
            "audiogram_samples", "vision_prescriptions",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"health_ios handler failed on {db_path}: {e}")
    return result


def _handle_safari_history(db_path: Path) -> dict:
    result = _build_result("safari_history", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "history_items", "history_visits", "history_tombstones",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"safari_history handler failed on {db_path}: {e}")
    return result


def _handle_safari_bookmarks(db_path: Path) -> dict:
    result = _build_result("safari_bookmarks", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "bookmarks", "folders", "tags",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"safari_bookmarks handler failed on {db_path}: {e}")
    return result


def _handle_notes_ios(db_path: Path) -> dict:
    """
    Redact note titles, snippets, and text previews in ZICCLOUDSYNCINGOBJECT.
    Delete rows that carry actual note content (ZICNOTEDATA holds body blobs).
    """
    result = _build_result("notes_ios", db_path)
    try:
        conn = _open_and_prepare(db_path)

        # Redact text-identity columns
        redacted = _redact_columns(
            conn, "ZICCLOUDSYNCINGOBJECT",
            ["ZTITLE1", "ZSNIPPET", "ZTEXTPREVIEW", "ZTITLE"],
        )
        result["rows_deleted"] += redacted

        # Delete raw note-data rows (ZICNOTEDATA holds encrypted/compressed body blobs)
        cleared, rows = _delete_tables(conn, ["ZICNOTEDATA"])
        result["tables_cleared"] = cleared
        result["rows_deleted"] += rows

        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"notes_ios handler failed on {db_path}: {e}")
    return result


def _handle_knowledgec(db_path: Path) -> dict:
    """Redact third-party app names, delete Siri/Safari/messaging streams."""
    result = _build_result("knowledgec", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cursor = conn.cursor()

        # Redact third-party bundle IDs
        cursor.execute(
            "UPDATE ZOBJECT SET ZVALUESTRING = '[REDACTED]' "
            "WHERE ZVALUESTRING NOT LIKE 'com.apple.%' AND ZVALUESTRING IS NOT NULL"
        )
        result["rows_deleted"] += cursor.rowcount if cursor.rowcount > 0 else 0

        # Remove sensitive stream types
        for stream in ("%safari%", "%siri%", "%messaging%"):
            cursor.execute("DELETE FROM ZOBJECT WHERE ZSTREAMNAME LIKE ?", (stream,))
            result["rows_deleted"] += cursor.rowcount if cursor.rowcount > 0 else 0

        conn.commit()
        result["tables_cleared"] = ["ZOBJECT"]
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"knowledgec handler failed on {db_path}: {e}")
    return result


def _handle_screentime(db_path: Path) -> dict:
    result = _build_result("screentime", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "kusage", "kapp_usage", "kwebsite_usage",
            "kdevice_activity", "knotification_usage",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"screentime handler failed on {db_path}: {e}")
    return result


def _handle_tcc(db_path: Path) -> dict:
    """
    TCC (Transparency, Consent, and Control) — DELETE access table.
    Reveals which apps have which permissions — privacy-sensitive.
    """
    result = _build_result("tcc", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, ["access"])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"tcc handler failed on {db_path}: {e}")
    return result


# ---------------------------------------------------------------------------
# Android handlers
# ---------------------------------------------------------------------------

def _handle_android_contacts(db_path: Path) -> dict:
    result = _build_result("android_contacts", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "raw_contacts", "data", "agg_exceptions",
            "phone_lookup", "name_lookup", "calls",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"android_contacts handler failed on {db_path}: {e}")
    return result


def _handle_android_sms(db_path: Path) -> dict:
    result = _build_result("android_sms", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "sms", "threads", "canonical_addresses",
            "pdu", "addr", "part", "pending_msgs",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"android_sms handler failed on {db_path}: {e}")
    return result


def _handle_android_calendar(db_path: Path) -> dict:
    result = _build_result("android_calendar", db_path)
    try:
        conn = _open_and_prepare(db_path)
        cleared, rows = _delete_tables(conn, [
            "Events", "Attendees", "Reminders",
            "ExtendedProperties", "EventsRawTimes",
        ])
        result["tables_cleared"] = cleared
        result["rows_deleted"] = rows
        vacuum_and_cleanup(conn, db_path)
    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"android_calendar handler failed on {db_path}: {e}")
    return result


# ---------------------------------------------------------------------------
# Windows handler
# ---------------------------------------------------------------------------

def _handle_windows_webcache(db_path: Path) -> dict:
    """
    WebCacheV01.dat uses the ESE (Extensible Storage Engine) format, not SQLite.
    Python cannot parse ESE natively -- log a warning, return an advisory result.
    """
    result = _build_result("windows_webcache", db_path)
    result["warning"] = (
        "WebCacheV01.dat uses ESE format (not SQLite). "
        "Python cannot sanitize it natively. "
        "Delete or process with ese2sql / libesedb externally."
    )
    log.warning(
        f"windows_webcache: {db_path.name} is ESE format -- cannot sanitize in Python. "
        "Use libesedb or delete the file."
    )
    return result


# ---------------------------------------------------------------------------
# Handler registry
# ---------------------------------------------------------------------------

_HANDLERS: dict[str, callable] = {
    "chrome_history":      _handle_chrome_history,
    "chrome_login":        _handle_chrome_login,
    "chrome_cookies":      _handle_chrome_cookies,
    "chrome_webdata":      _handle_chrome_webdata,
    "firefox_places":      _handle_firefox_places,
    "firefox_formhistory": _handle_firefox_formhistory,
    "firefox_cookies":     _handle_firefox_cookies,
    "contacts_ios":        _handle_contacts_ios,
    "messages_ios":        _handle_messages_ios,
    "photos_ios":          _handle_photos_ios,
    "health_ios":          _handle_health_ios,
    "safari_history":      _handle_safari_history,
    "safari_bookmarks":    _handle_safari_bookmarks,
    "notes_ios":           _handle_notes_ios,
    "knowledgec":          _handle_knowledgec,
    "screentime":          _handle_screentime,
    "tcc":                 _handle_tcc,
    "android_contacts":    _handle_android_contacts,
    "android_sms":         _handle_android_sms,
    "android_calendar":    _handle_android_calendar,
    "windows_webcache":    _handle_windows_webcache,
}


def run_platform_handler(db_path: Path, db_type: str) -> dict:
    """
    Run the platform-specific handler for db_type.

    If the handler raises an unhandled exception, falls back to the generic
    sanitizer and adds ``fallback_to_generic: True`` to the result.
    """
    handler = _HANDLERS.get(db_type)
    if handler is None:
        log.warning(f"No handler registered for db_type={db_type!r}, using generic")
        result = sanitize_database_generic(db_path)
        result["fallback_to_generic"] = True
        return result

    try:
        result = handler(db_path)
        log.info(
            f"Platform handler [{db_type}] on {db_path.name}: "
            f"{result.get('rows_deleted', 0)} rows, "
            f"tables={result.get('tables_cleared', [])}"
        )
        return result
    except Exception as e:
        log.error(f"Platform handler [{db_type}] crashed ({e}), falling back to generic")
        fallback = sanitize_database_generic(db_path)
        fallback["fallback_to_generic"] = True
        fallback["handler_error"] = str(e)
        return fallback


def sanitize_with_platform_detection(
    db_path: Path,
    extra_columns: set = None,
    extra_tables: set = None,
) -> dict:
    """
    Auto-detect platform type and run the appropriate handler.

    If the database is recognised, the platform handler runs first (surgical
    nuking of known-PII tables), then the generic scanner runs as a residual
    sweep to catch anything the handler missed.

    If the database is not recognised, only the generic scanner runs.
    """
    db_type = detect_database_type(db_path)

    if db_type is None:
        result = sanitize_database_generic(db_path, extra_columns, extra_tables)
        result["platform_detected"] = False
        return result

    # Run the platform handler
    platform_result = run_platform_handler(db_path, db_type)
    platform_result["platform_detected"] = True

    # Skip residual generic scan for Windows ESE files (can't open as SQLite)
    if db_type == "windows_webcache":
        return platform_result

    # Residual generic sweep -- catches any columns the handler didn't cover
    try:
        generic_result = sanitize_database_generic(db_path, extra_columns, extra_tables)
        platform_result["residual_rows_redacted"] = generic_result.get("rows_redacted", 0)
        platform_result["residual_pii_types"] = generic_result.get("pii_types_found", [])
    except Exception as e:
        log.warning(f"Residual generic scan failed on {db_path}: {e}")

    return platform_result
