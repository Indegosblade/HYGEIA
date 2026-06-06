"""
HYGEIA SQLite Sanitizer -- WAL-aware database sanitization pipeline.

SQLite WAL files contain 50-95% of deleted records with full PII.
Standard deletion leaves them intact. Every database goes through:
checkpoint > secure_delete > sanitize > VACUUM > delete WAL.
"""

import sqlite3
import os
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("hygeia.sqlite")

SQLITE_EXTENSIONS = {".sqlite", ".db", ".sqlitedb", ".storedata", ".plsql"}
WAL_SUFFIXES = ["-wal", "-shm", "-journal"]


def is_sqlite_database(path: Path) -> bool:
    """Check if file is a SQLite database by magic bytes."""
    try:
        with open(path, "rb") as f:
            magic = f.read(16)
        return magic[:6] == b"SQLite"
    except (OSError, IOError):
        return False


def checkpoint_and_prepare(conn: sqlite3.Connection):
    """Checkpoint WAL into main database and enable secure deletion."""
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError:
        pass  # Not in WAL mode
    conn.execute("PRAGMA secure_delete = ON")


def vacuum_and_cleanup(conn: sqlite3.Connection, db_path: Path):
    """VACUUM to rebuild database eliminating free pages, then delete WAL/SHM."""
    conn.commit()
    try:
        conn.execute("VACUUM")
    except sqlite3.OperationalError as e:
        log.warning(f"VACUUM failed on {db_path}: {e}")
    conn.close()

    # Delete WAL/SHM/journal files
    for suffix in WAL_SUFFIXES:
        wal_file = Path(str(db_path) + suffix)
        if wal_file.exists():
            wal_file.unlink()
            log.debug(f"Deleted {wal_file.name}")


def delete_database(db_path: Path) -> dict:
    """
    Securely delete a SQLite database and all companion files.
    Checkpoints WAL first to prevent PII leakage in orphaned WAL files.
    """
    result = {"action": "delete_database", "path": str(db_path), "wal_files_removed": []}

    if is_sqlite_database(db_path):
        try:
            conn = sqlite3.connect(str(db_path))
            checkpoint_and_prepare(conn)
            conn.close()
        except sqlite3.Error as e:
            log.warning(f"Could not checkpoint {db_path} before deletion: {e}")

    # Delete companion files first
    for suffix in WAL_SUFFIXES:
        wal_file = Path(str(db_path) + suffix)
        if wal_file.exists():
            wal_file.unlink()
            result["wal_files_removed"].append(wal_file.name)

    # Delete main database
    if db_path.exists():
        db_path.unlink()

    return result


def sanitize_database(db_path: Path, sql_commands: list[str]) -> dict:
    """
    Full SQLite sanitization with WAL handling.
    1. Checkpoint WAL into main database
    2. Enable secure_delete
    3. Execute sanitization SQL commands
    4. VACUUM to rebuild and eliminate free pages
    5. Remove WAL/SHM files
    """
    result = {
        "action": "sanitize_database",
        "path": str(db_path),
        "commands_executed": 0,
        "rows_affected": 0,
    }

    if not db_path.exists():
        result["error"] = "Database not found"
        return result

    try:
        conn = sqlite3.connect(str(db_path))
        checkpoint_and_prepare(conn)

        cursor = conn.cursor()
        for sql in sql_commands:
            try:
                cursor.execute(sql)
                result["rows_affected"] += cursor.rowcount if cursor.rowcount > 0 else 0
                result["commands_executed"] += 1
            except sqlite3.Error as e:
                log.warning(f"SQL error in {db_path.name}: {e} (command: {sql[:80]})")

        vacuum_and_cleanup(conn, db_path)
        log.info(f"Sanitized {db_path.name}: {result['commands_executed']} commands, {result['rows_affected']} rows")

    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"Failed to sanitize {db_path}: {e}")

    return result


def sanitize_knowledgec(db_path: Path) -> dict:
    """
    Column-level sanitization for knowledgeC.db.
    Preserves com.apple.* system app data, redacts third-party app names
    and browsing/Siri streams.
    """
    return sanitize_database(db_path, [
        "UPDATE ZOBJECT SET ZVALUESTRING = '[REDACTED]' WHERE ZVALUESTRING NOT LIKE 'com.apple.%' AND ZVALUESTRING IS NOT NULL",
        "DELETE FROM ZOBJECT WHERE ZSTREAMNAME LIKE '%safari%'",
        "DELETE FROM ZOBJECT WHERE ZSTREAMNAME LIKE '%siri%'",
        "DELETE FROM ZOBJECT WHERE ZSTREAMNAME LIKE '%messaging%'",
    ])


def sanitize_photos_sqlite(db_path: Path) -> dict:
    """
    Selective sanitization for Photos.sqlite.
    NULLs GPS coordinates, deletes facial recognition data.
    Preserves schema and non-geographic metadata.
    """
    return sanitize_database(db_path, [
        "UPDATE ZASSET SET ZLATITUDE = NULL, ZLONGITUDE = NULL WHERE ZLATITUDE IS NOT NULL",
        "DELETE FROM ZPERSON",
        "DELETE FROM ZDETECTEDFACE",
        "DELETE FROM ZDETECTEDFACEPRINT",
    ])


def find_all_databases(dump_path: Path) -> list[Path]:
    """Find all SQLite databases in a dump, including by magic bytes."""
    databases = []
    for f in dump_path.rglob("*"):
        if f.is_file():
            if f.suffix.lower() in SQLITE_EXTENSIONS or is_sqlite_database(f):
                databases.append(f)
    return databases


def sanitize_database_generic(db_path: Path) -> dict:
    """
    Platform-agnostic SQLite sanitizer. Scans every TEXT column in every
    table for PII patterns (emails, phones, URLs with user data, IPs,
    credentials) and redacts matches. Then VACUUMs to eliminate free pages.

    Works on Chrome, Firefox, Android, desktop apps — anything with SQLite.
    """
    import re

    PII_PATTERNS = {
        "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "phone_us": re.compile(r'\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
        "phone_intl": re.compile(r'\+(?:44|49|33|91|81|61|86|55|7|34|39|82|31|46|47|48|90)\s?\d[\d\s\-]{6,14}\d\b'),
        "ssn": re.compile(r'\b(?!000|666|9\d{2})[0-8]\d{2}-\d{2}-\d{4}\b'),
        "credit_card": re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
        "ip_v4": re.compile(r'\b(?!(?:0|127|255)\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        "ip_v6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
        "iban": re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'),
        "mac_addr": re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'),
    }

    # Column names that are very likely to contain PII
    SENSITIVE_COLUMNS = {
        "email", "username", "user_name", "login", "password", "passwd",
        "phone", "phone_number", "address", "street", "city", "zip",
        "zipcode", "zip_code", "postal_code", "state", "country",
        "first_name", "last_name", "full_name", "name", "display_name",
        "firstname", "lastname", "fullname", "nickname",
        "company_name", "company", "street_address", "street_number",
        "address_line_1", "address_line_2", "apt", "suite",
        "username_value", "username_element", "password_value",
        "account", "account_name", "credential", "token", "auth",
        "secret", "api_key", "cookie", "session",
        "card_number", "card_holder", "cardholder", "expiration",
        "ssn", "social_security", "date_of_birth", "dob",
        "latitude", "longitude", "lat", "lng", "lon",
        "host_key", "encrypted_value",
    }

    # Tables that are entirely PII — nuke all content, keep schema
    PII_TABLES = {
        # Chrome/Chromium
        "autofill", "autofill_profiles", "autofill_profile_names",
        "autofill_profile_emails", "autofill_profile_phones",
        "autofill_profile_addresses", "local_addresses",
        "local_numbers", "local_names", "local_emails",
        "contact_info", "server_addresses", "server_card_metadata",
        "credit_cards", "local_ibans", "server_card_cloud_token_data",
        "logins", "stats", "cookies", "omni_box_shortcuts",
        "top_sites", "keyword_search_terms",
        # Firefox
        "moz_formhistory", "moz_cookies", "moz_inputhistory",
        "moz_perms", "moz_hosts",
        # Android
        "raw_contacts", "data", "calls", "sms", "threads",
        "canonical_addresses", "attendees",
        # Messaging apps
        "chat_list", "chat_view", "message_thumbnails",
        # macOS
        "access",
        # Generic
        "contacts", "messages", "call_log", "accounts",
        "search_history", "recent_searches",
    }

    # Columns to skip even if name matches — contain system/structural data
    SAFE_COLUMNS = {
        "id", "rowid", "key", "type", "count", "date", "timestamp",
        "length", "size", "width", "height", "version", "flags",
        "origin", "scheme", "port", "priority", "status",
    }

    result = {
        "action": "generic_sanitize",
        "path": str(db_path),
        "tables_scanned": 0,
        "columns_scanned": 0,
        "rows_redacted": 0,
        "pii_types_found": [],
    }

    if not db_path.exists() or not is_sqlite_database(db_path):
        result["error"] = "Not a SQLite database"
        return result

    try:
        conn = sqlite3.connect(str(db_path))
        checkpoint_and_prepare(conn)
        cursor = conn.cursor()

        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0] for row in cursor.fetchall()]

        pii_found = set()

        for table in tables:
            result["tables_scanned"] += 1

            # Nuke entire PII tables
            if table.lower() in PII_TABLES:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM \"{table}\"")
                    count = cursor.fetchone()[0]
                    if count > 0:
                        cursor.execute(f"DELETE FROM \"{table}\"")
                        result["rows_redacted"] += count
                        pii_found.add(f"pii_table:{table}")
                except sqlite3.Error:
                    pass
                continue

            try:
                cursor.execute(f"PRAGMA table_info(\"{table}\")")
                columns = cursor.fetchall()
            except sqlite3.Error:
                continue

            text_cols = []
            for col in columns:
                col_name = col[1]
                col_type = (col[2] or "").upper()
                if any(t in col_type for t in ("TEXT", "VARCHAR", "CHAR", "CLOB")) or col_type == "" or col_name.lower() in SENSITIVE_COLUMNS:
                    text_cols.append(col_name)

            for col_name in text_cols:
                result["columns_scanned"] += 1
                col_lower = col_name.lower()

                # Direct redact columns with sensitive names
                if col_lower in SENSITIVE_COLUMNS:
                    try:
                        cursor.execute(
                            f"UPDATE \"{table}\" SET \"{col_name}\" = '[REDACTED]' "
                            f"WHERE \"{col_name}\" IS NOT NULL AND \"{col_name}\" != ''"
                        )
                        affected = cursor.rowcount if cursor.rowcount > 0 else 0
                        if affected:
                            result["rows_redacted"] += affected
                            pii_found.add(f"sensitive_column:{col_lower}")
                    except sqlite3.Error:
                        pass
                    continue

                # Regex scan other text columns for PII patterns
                for pii_name, pattern in PII_PATTERNS.items():
                    try:
                        cursor.execute(f"SELECT rowid, \"{col_name}\" FROM \"{table}\" WHERE \"{col_name}\" IS NOT NULL LIMIT 5000")
                        rows = cursor.fetchall()
                        for rowid, value in rows:
                            if not isinstance(value, str):
                                continue
                            if pattern.search(value):
                                redacted = pattern.sub(f'[REDACTED_{pii_name.upper()}]', value)
                                cursor.execute(
                                    f"UPDATE \"{table}\" SET \"{col_name}\" = ? WHERE rowid = ?",
                                    (redacted, rowid)
                                )
                                result["rows_redacted"] += 1
                                pii_found.add(pii_name)
                    except sqlite3.Error:
                        continue

        # Multi-pass: keep scanning until no new PII found (URLs embed emails, etc.)
        pass_count = 1
        while result["rows_redacted"] > 0 and pass_count < 5:
            prev_redacted = result["rows_redacted"]
            pass_redacted = 0
            for table in tables:
                try:
                    cursor.execute(f"PRAGMA table_info(\"{table}\")")
                    columns = cursor.fetchall()
                except sqlite3.Error:
                    continue
                text_cols = [c[1] for c in columns if (c[2] or "").upper() in ("TEXT", "VARCHAR", "CHAR", "CLOB", "")]
                for col_name in text_cols:
                    for pii_name, pattern in PII_PATTERNS.items():
                        try:
                            cursor.execute(f"SELECT rowid, \"{col_name}\" FROM \"{table}\" WHERE \"{col_name}\" IS NOT NULL LIMIT 5000")
                            for rowid, value in cursor.fetchall():
                                if not isinstance(value, str):
                                    continue
                                if pattern.search(value):
                                    redacted_val = pattern.sub(f'[REDACTED_{pii_name.upper()}]', value)
                                    cursor.execute(
                                        f"UPDATE \"{table}\" SET \"{col_name}\" = ? WHERE rowid = ?",
                                        (redacted_val, rowid)
                                    )
                                    pass_redacted += 1
                        except sqlite3.Error:
                            continue
            if pass_redacted == 0:
                break
            result["rows_redacted"] += pass_redacted
            pass_count += 1

        # FTS shadow table cleanup — forensic tools parse *_content/*_segments
        for table in tables:
            if table.endswith("_content") or table.endswith("_segments") or table.endswith("_segdir"):
                base = table.rsplit("_", 1)[0]
                if base in tables:
                    try:
                        cursor.execute(f"INSERT INTO \"{base}\"(\"{base}\") VALUES('rebuild')")
                    except sqlite3.Error:
                        try:
                            cursor.execute(f"DELETE FROM \"{table}\"")
                        except sqlite3.Error:
                            pass

        result["pii_types_found"] = sorted(pii_found)
        vacuum_and_cleanup(conn, db_path)
        log.info(f"Generic sanitized {db_path.name}: {result['tables_scanned']} tables, "
                 f"{result['rows_redacted']} rows redacted ({pass_count} passes), PII: {result['pii_types_found']}")

    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"Failed generic sanitize {db_path}: {e}")

    return result


def delete_wal_orphans(dump_path: Path) -> list[Path]:
    """Find and delete orphaned WAL/SHM files with no parent database."""
    deleted = []
    for suffix in WAL_SUFFIXES:
        for wal_file in dump_path.rglob(f"*{suffix}"):
            parent_db = Path(str(wal_file).replace(suffix, ""))
            if not parent_db.exists():
                wal_file.unlink()
                deleted.append(wal_file)
                log.info(f"Deleted orphaned WAL: {wal_file}")
    return deleted
