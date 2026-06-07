"""
HYGEIA SQLite Sanitizer -- WAL-aware database sanitization pipeline.

SQLite WAL files contain 50-95% of deleted records with full PII.
Standard deletion leaves them intact. Every database goes through:
checkpoint > secure_delete > sanitize > VACUUM > delete WAL.
"""

import hashlib
import sqlite3
import time
import logging
from pathlib import Path

log = logging.getLogger("hygeia.sqlite")


def _sha256(filepath: Path) -> str:
    """Return the SHA256 hex digest of a file's contents."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

SQLITE_EXTENSIONS = {".sqlite", ".db", ".sqlitedb", ".storedata", ".plsql", ".PLSQL"}
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
    """VACUUM to rebuild database eliminating free pages, then delete WAL/SHM.

    Chrome's Login Data and similar databases keep in-progress statements open
    while VACUUM runs, causing "cannot VACUUM - SQL statements in progress".
    Fix: flush WAL first, close ALL cursors by reopening a fresh connection
    just for VACUUM, with one retry on failure.
    """
    conn.commit()

    # Flush WAL into the main database file so VACUUM sees a clean state.
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError:
        pass  # Not in WAL mode — ignore

    # Close the connection (and with it every cursor) before VACUUM.
    conn.close()

    def _do_vacuum(path: Path) -> bool:
        vconn = None
        try:
            vconn = sqlite3.connect(str(path))
            vconn.execute("VACUUM")
            vconn.close()
            return True
        except sqlite3.OperationalError as e:
            log.warning(f"VACUUM attempt failed on {path}: {e}")
            if vconn:
                try:
                    vconn.close()
                except Exception:
                    pass
            return False

    def _do_vacuum_journal_delete(path: Path) -> bool:
        """Switch to DELETE journal mode first, then VACUUM.

        Chrome's Login Data uses WAL mode.  Switching to DELETE journal mode
        forces a full WAL checkpoint and removes the WAL file, which clears the
        OS-level lock that was blocking VACUUM.
        """
        vconn = None
        try:
            vconn = sqlite3.connect(str(path))
            vconn.execute("PRAGMA journal_mode=DELETE")
            vconn.commit()
            vconn.execute("VACUUM")
            vconn.close()
            return True
        except sqlite3.OperationalError as e:
            log.warning(f"VACUUM (journal_mode=DELETE) failed on {path}: {e}")
            if vconn:
                try:
                    vconn.close()
                except Exception:
                    pass
            return False

    if not _do_vacuum(db_path):
        # First retry: brief pause to let any OS-level lock clear.
        time.sleep(0.1)
        if not _do_vacuum(db_path):
            # Second retry: switch to DELETE journal mode first (clears WAL
            # lock held by Chrome and similar WAL-mode databases).
            time.sleep(0.5)
            if not _do_vacuum_journal_delete(db_path):
                log.warning(
                    f"VACUUM failed on {db_path} after all retries — "
                    f"free pages may remain (expected for locked WAL databases)"
                )

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


def sanitize_database_generic(db_path: Path, extra_columns: set = None, extra_tables: set = None) -> dict:
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
        "credit_card": re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2})|3(?:0[0-5]|[68]\d)\d|(?:2131|1800|35\d{2})|62\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}(?:[- ]?\d{3})?\b'),
        "ip_v4": re.compile(r'\b(?!(?:0|127|255)\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        "ip_v6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
        "iban": re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'),
        "mac_addr": re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'),
        # Identity documents
        "uk_nino": re.compile(r'\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b'),
        "indian_pan": re.compile(r'\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b'),
        "us_ein": re.compile(r'\b(?:0[1-6]|1[0-6]|2[0-7]|3[0-9]|4[0-8]|5[0-9]|6[0-8]|7[1-7]|8[1-5]|9[0-5])-\d{7}\b'),
        "vin": re.compile(r'\b[A-HJ-NPR-Z0-9]{3}[A-HJ-NPR-Z0-9]{5}[0-9X][A-HJ-NPR-Z0-9]{2}[0-9]{6}\b'),
        # Credentials/tokens
        "jwt": re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
        "aws_key": re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
        "github_token": re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b'),
        "api_key": re.compile(r'\b(?:sk_(?:live|test|prod)_[A-Za-z0-9]{20,}|pk_(?:live|test|prod)_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|xox[bpsa]-[A-Za-z0-9-]{10,})\b'),
        # Crypto wallets
        "btc_wallet": re.compile(r'\b(?:1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[0-9a-zA-HJ-NP-Z]{25,87})\b'),
        "eth_wallet": re.compile(r'\b0x[0-9a-fA-F]{40}\b'),
        # URL with embedded credentials
        "url_creds": re.compile(r'\b(?:https?|ftp)://[^:@\s]+:[^@\s]+@[^\s]+'),
        # Financial identifiers
        "sin_tfn": re.compile(r'\b\d{3}[-\s]\d{3}[-\s]\d{3}\b'),
        "swift_bic": re.compile(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b'),
        "us_routing": re.compile(r'\b(?:0[1-9]|[12]\d|3[0-2])[0-9]{7}\b'),
        # Device identifiers
        "imei": re.compile(r'\b\d{2}[-\s]?\d{6}[-\s]?\d{6}[-\s]?\d\b'),
        "imsi": re.compile(r'\b\d{3}\d{2,3}\d{9,10}\b'),
        # Healthcare/regulatory
        "dea_number": re.compile(r'\b[ABCDEFGHJKLMNPRSTUXabcdefghjklmnprstux][A-Za-z9]\d{7}\b'),
        "npi": re.compile(r'\b(?:80840)?[12]\d{9}\b'),
    }

    # Column names that are very likely to contain PII
    SENSITIVE_COLUMNS = {
        # Identity
        "email", "username", "user_name", "login", "password", "passwd",
        "phone", "phone_number", "mobile", "cell", "fax",
        "first_name", "last_name", "full_name", "name", "display_name",
        "firstname", "lastname", "fullname", "nickname", "given_name", "family_name",
        # Address
        "address", "street", "city", "zip", "zipcode", "zip_code",
        "postal_code", "state", "country", "street_address", "street_number",
        "address_line_1", "address_line_2", "apt", "suite",
        "company_name", "company", "employer", "organization",
        # Auth/Credentials
        "username_value", "username_element", "password_value",
        "account", "account_name", "credential", "token", "auth",
        "secret", "api_key", "apikey", "cookie", "session",
        "access_token", "refresh_token", "id_token", "bearer",
        "client_secret", "oauth_token", "private_key",
        # Financial
        "card_number", "card_holder", "cardholder", "expiration", "cvv",
        "routing_number", "routing", "bank_account", "account_number",
        "swift", "bic", "swift_code", "bic_code",
        "sin", "tfn",
        "salary", "income", "wage", "purchase_history",
        # Government ID
        "ssn", "social_security", "tax_id", "ein", "itin",
        "passport", "passport_number", "drivers_license", "license_number",
        "national_id", "insurance_number", "policy_number",
        # Medical (HIPAA)
        "patient_id", "mrn", "medical_record", "npi", "dea_number",
        "diagnosis", "diagnosis_code", "prescription", "medication",
        "date_of_birth", "dob", "birthdate", "birthday",
        "health_plan_id", "member_id", "subscriber_id",
        # Location
        "latitude", "longitude", "lat", "lng", "lon",
        "geolocation", "coordinates", "gps",
        # Device/Network
        "ip_address", "ipaddr", "remote_addr", "mac_address", "hwaddr",
        "device_id", "device_name", "udid", "serial_number",
        "imei", "imsi", "iccid", "meid",
        "ssid", "wifi_name", "network_name",
        # Biometric/Sensitive
        "fingerprint", "biometric", "face_data",
        "race", "ethnicity", "religion", "political_affiliation",
        "sexual_orientation", "gender", "sex",
        "genetic_data", "health_data",
        # Browser
        "host_key", "encrypted_value", "user_agent",
    }

    # Tables that are entirely PII — nuke all content, keep schema
    PII_TABLES = {
        # Chrome/Chromium
        "autofill", "autofill_profiles", "autofill_profile_names",
        "autofill_profile_emails", "autofill_profile_phones",
        "autofill_profile_addresses", "autofill_profiles_trash",
        "local_addresses", "local_numbers", "local_names", "local_emails",
        "contact_info", "server_addresses", "server_card_metadata",
        "credit_cards", "local_ibans", "server_card_cloud_token_data",
        "masked_credit_cards", "password_notes", "insecure_credentials",
        "logins", "stats", "cookies", "omni_box_shortcuts",
        "top_sites", "keyword_search_terms",
        "content_annotations", "context_annotations",
        "downloads", "downloads_url_chains",
        "network_action_predictor",
        # Firefox
        "moz_formhistory", "moz_cookies", "moz_inputhistory",
        "moz_perms", "moz_hosts", "moz_annos",
        "moz_places_metadata", "moz_places_metadata_search_queries",
        "moz_bookmarks_deleted", "moz_logins",
        "webappsstore2", "storage_sync_data", "storage_sync_mirror",
        # Android
        "raw_contacts", "data", "calls", "sms", "threads", "pdu", "addr", "part",
        "canonical_addresses", "attendees", "phone_lookup", "name_lookup",
        "siminfo", "carriers",
        # Messaging apps
        "chat_list", "chat_view", "message_thumbnails",
        # iOS/macOS
        "access", "history_items", "history_visits", "history_tombstones",
        "cloud_tabs", "bookmark_tags",
        "zperson", "zdetectedface", "zdetectedfaceprint",
        "zcloudsharedalbuminvitationrecord", "zshare", "zmemory", "zsceneprint",
        # Windows
        "notification",
        # Generic
        "contacts", "messages", "call_log", "accounts",
        "search_history", "recent_searches",
        "purchase_history", "geolocation",
        "browsing_history", "form_history",
        "stats_table", "location_history",
    }

    # Columns to skip even if name matches — contain system/structural data
    SAFE_COLUMNS = {
        "id", "rowid", "key", "type", "count", "date", "timestamp",
        "length", "size", "width", "height", "version", "flags",
        "origin", "scheme", "port", "priority", "status",
    }

    if extra_columns:
        SENSITIVE_COLUMNS = SENSITIVE_COLUMNS | extra_columns
    if extra_tables:
        PII_TABLES = PII_TABLES | extra_tables

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

    result["hash_before"] = _sha256(db_path)

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
                        cursor.execute(f"SELECT rowid, \"{col_name}\" FROM \"{table}\" WHERE \"{col_name}\" IS NOT NULL")
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
        for pass_num in range(2, 6):
            pass_redacted = 0
            for table in tables:
                if table.lower() in PII_TABLES:
                    continue
                try:
                    cursor.execute(f"PRAGMA table_info(\"{table}\")")
                    columns = cursor.fetchall()
                except sqlite3.Error:
                    continue
                text_cols = [c[1] for c in columns
                             if any(t in (c[2] or "").upper() for t in ("TEXT", "VARCHAR", "CHAR", "CLOB"))
                             or (c[2] or "").upper() == ""
                             and c[1].lower() not in SAFE_COLUMNS]
                for col_name in text_cols:
                    if col_name.lower() in SENSITIVE_COLUMNS:
                        continue
                    for pii_name, pattern in PII_PATTERNS.items():
                        try:
                            cursor.execute(f"SELECT rowid, \"{col_name}\" FROM \"{table}\" WHERE \"{col_name}\" IS NOT NULL AND \"{col_name}\" NOT LIKE '%[REDACTED%'")
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
            pass_count += 1
            result["rows_redacted"] += pass_redacted

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
        result["hash_after"] = _sha256(db_path)
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
