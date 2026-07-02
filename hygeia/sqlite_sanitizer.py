"""
HYGEIA SQLite Sanitizer -- WAL-aware database sanitization pipeline.

SQLite WAL files contain 50-95% of deleted records with full PII.
Standard deletion leaves them intact. Every database goes through:
checkpoint > secure_delete > sanitize > VACUUM > delete WAL.
"""

import os
import re
import sqlite3
import time
import logging
from pathlib import Path

from .utils import sha256 as _sha256, quote_identifier, is_safe_regular_file

log = logging.getLogger("hygeia.sqlite")

SQLITE_EXTENSIONS = {".sqlite", ".db", ".sqlitedb", ".storedata", ".plsql", ".PLSQL"}
WAL_SUFFIXES = ["-wal", "-shm", "-journal"]

# FTS3/4 (_content/_segments/_segdir) AND FTS5 (_data/_idx/_docsize/_config,
# plus _content for stored-content tables) shadow-table suffixes. Tokenized PII
# lives in these index blobs; the regex pass cannot reach it (finding #16).
FTS_SHADOW_SUFFIXES = (
    "_content", "_segments", "_segdir",
    "_data", "_idx", "_docsize", "_config",
)

# Overwrite passes for secure_delete of a database file before unlink (#45).
_SECURE_OVERWRITE_PASSES = 3

_FTS_VIRTUAL_RE = re.compile(
    r"CREATE\s+VIRTUAL\s+TABLE.+USING\s+fts", re.IGNORECASE | re.DOTALL
)


def _fts_base_tables(master_rows) -> set:
    """Return the names of FTS virtual tables from (name, sql) sqlite_master rows.

    Detecting the FTS *virtual* table by its ``CREATE VIRTUAL TABLE ... USING
    fts`` SQL (rather than guessing from a ``_data``/``_idx`` suffix) is what
    lets us clean the shadow index without mistaking an ordinary table such as
    ``user_data`` — whose sibling ``user`` table happens to exist — for an FTS
    shadow and wrongly wiping it.
    """
    bases = set()
    for row in master_rows:
        name, sql = row[0], row[1]
        if sql and _FTS_VIRTUAL_RE.search(sql):
            bases.add(name)
    return bases


def _redact_cell(value, pattern, pii_name: str):
    """Redact ``pattern`` in a single cell value; return ``(new_value, matched)``.

    SQLite is dynamically typed, so PII text routinely sits in BLOB, INTEGER or
    REAL columns and in bytes/memoryview cells that the old ``isinstance(value,
    str)`` guard dropped untouched (finding #14). ``str`` values are scanned
    directly; ``bytes``/``bytearray``/``memoryview`` values are decoded
    best-effort (utf-8 then utf-16, ``errors='ignore'``) so embedded text
    (bplist, protobuf, gzip'd or raw UTF-16 message bodies) is scanned and, on a
    match, redacted and re-encoded in the same encoding. Non-text scalars
    (int/float/None) never match and are returned unchanged.
    """
    repl = f"[REDACTED_{pii_name.upper()}]"
    if isinstance(value, str):
        if pattern.search(value):
            return pattern.sub(repl, value), True
        return value, False
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytearray):
        value = bytes(value)
    if isinstance(value, bytes):
        for enc in ("utf-8", "utf-16"):
            try:
                text = value.decode(enc, errors="ignore")
            except (LookupError, ValueError):
                continue
            if pattern.search(text):
                redacted = pattern.sub(repl, text)
                try:
                    return redacted.encode(enc, errors="ignore"), True
                except (LookupError, ValueError):
                    return redacted.encode("utf-8", errors="ignore"), True
        return value, False
    return value, False


def _clean_fts_shadow_tables(conn, cursor, fts_bases, existing_tables, result) -> bool:
    """Rebuild or safely clear FTS3/4/5 shadow index tables. Return True iff all
    FTS indexes were cleaned without corrupting the database.

    Preferred path: ask the FTS table to rebuild its inverted index from the
    already-redacted content (``INSERT INTO base(base) VALUES('rebuild')``),
    which regenerates every ``_data``/``_idx``/``_docsize``/``_config`` shadow.
    When rebuild is impossible (contentless FTS5), we fall back to deleting the
    shadow rows — but only inside a SAVEPOINT gated on a post-delete
    ``integrity_check``. A raw ``DELETE FROM base_data`` leaves the index
    "malformed", so on any integrity failure we ROLL BACK the delete (preserving
    the redactions committed earlier) and flag the DB incomplete instead of
    shipping a corrupt or silently PII-leaking database (findings #16, #18).
    """
    all_clean = True
    for base in sorted(fts_bases):
        if base not in existing_tables:
            continue
        qbase = quote_identifier(base)
        try:
            cursor.execute(f"INSERT INTO {qbase}({qbase}) VALUES('rebuild')")
            continue  # index rebuilt from redacted content
        except sqlite3.Error:
            pass

        shadows = [f"{base}{suf}" for suf in FTS_SHADOW_SUFFIXES
                   if f"{base}{suf}" in existing_tables]
        if not shadows:
            all_clean = False
            result.setdefault("fts_cleanup_incomplete", []).append(base)
            continue

        try:
            conn.execute("SAVEPOINT hygeia_fts")
            for shadow in shadows:
                cursor.execute(f"DELETE FROM {quote_identifier(shadow)}")
            chk = conn.execute("PRAGMA integrity_check").fetchone()
            if chk is not None and chk[0] == "ok":
                conn.execute("RELEASE hygeia_fts")
            else:
                conn.execute("ROLLBACK TO hygeia_fts")
                conn.execute("RELEASE hygeia_fts")
                all_clean = False
                result.setdefault("fts_cleanup_incomplete", []).append(base)
                log.error(
                    f"FTS shadow-table clear left {base} malformed "
                    f"({chk[0] if chk else 'unknown'}) — rolled back; "
                    f"tokenized PII may remain in its index"
                )
        except sqlite3.Error as e:
            try:
                conn.execute("ROLLBACK TO hygeia_fts")
                conn.execute("RELEASE hygeia_fts")
            except sqlite3.Error:
                pass
            all_clean = False
            result.setdefault("fts_cleanup_incomplete", []).append(base)
            log.warning(f"FTS cleanup failed for {base}: {e}")
    return all_clean


def _secure_overwrite(path: Path, root: Path | None = None) -> bool:
    """Overwrite a file's bytes with random data before it is unlinked.

    Honors ``delete_database``'s "securely delete" contract: a plain
    ``unlink`` leaves the file's data blocks on disk, forensically carvable
    (finding #45). We overwrite the existing extent with ``os.urandom`` and
    ``fsync`` so the on-disk bytes are destroyed before the directory entry is
    removed. Never follows a symlink: writing through a link would clobber a
    host file outside the dump, so a symlink (or a path escaping ``root`` when
    one is supplied) is refused and reported as not-overwritten.
    """
    if path.is_symlink():
        return False
    if root is not None and not is_safe_regular_file(path, root):
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size == 0:
        return True
    try:
        flags = os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(path), flags)
        try:
            for _ in range(_SECURE_OVERWRITE_PASSES):
                os.lseek(fd, 0, os.SEEK_SET)
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, 1 << 20)
                    os.write(fd, os.urandom(chunk))
                    remaining -= chunk
                os.fsync(fd)
        finally:
            os.close(fd)
        return True
    except OSError as e:
        log.warning(f"Secure overwrite failed for {path}: {e}")
        return False


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


def vacuum_and_cleanup(conn: sqlite3.Connection, db_path: Path) -> bool:
    """VACUUM to rebuild database eliminating free pages, then delete WAL/SHM.

    Chrome's Login Data and similar databases keep in-progress statements open
    while VACUUM runs, causing "cannot VACUUM - SQL statements in progress".
    Fix: flush WAL first, close ALL cursors by reopening a fresh connection
    just for VACUUM, with one retry on failure.

    Returns True only if a VACUUM actually completed. ``secure_delete`` only
    zeroes pages this session freed; the pre-existing freelist pages that hold
    the device's own deleted records are reclaimed ONLY by VACUUM. A persistent
    VACUUM failure therefore leaves recoverable deleted-record PII in the file,
    so callers MUST treat a False return as "not sanitized" and surface it — a
    silent success here is a false clean (finding #15).
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

    strategies = [
        _do_vacuum,
        _do_vacuum,
        _do_vacuum_journal_delete,
    ]
    delays = [0.1, 0.3, 0.9]
    vacuum_ok = False
    for i, fn in enumerate(strategies):
        if fn(db_path):
            vacuum_ok = True
            break
        if i < len(delays):
            time.sleep(delays[i])
    if not vacuum_ok:
        log.warning(
            f"VACUUM failed on {db_path} after all retries — free pages with "
            f"recoverable deleted-record PII may remain; DB not certified sanitized"
        )

    # Delete WAL/SHM/journal files
    for suffix in WAL_SUFFIXES:
        wal_file = Path(str(db_path) + suffix)
        if wal_file.exists():
            wal_file.unlink()
            log.debug(f"Deleted {wal_file.name}")

    return vacuum_ok


def delete_database(db_path: Path, root: Path | None = None) -> dict:
    """
    Securely delete a SQLite database and all companion files.
    Checkpoints WAL first to prevent PII leakage in orphaned WAL files.

    The database and its -wal/-shm/-journal companions are overwritten with
    random bytes before unlink so the deleted records are not recoverable by
    carving the free blocks (finding #45). Pass ``root`` (the dump root) to
    enforce that only real regular files inside the dump are overwritten; a
    symlink is never followed, so this cannot clobber a host file the dump
    points at.
    """
    result = {"action": "delete_database", "path": str(db_path),
              "wal_files_removed": [], "secure_overwrite": []}

    if is_sqlite_database(db_path):
        try:
            conn = sqlite3.connect(str(db_path))
            checkpoint_and_prepare(conn)
            conn.close()
        except sqlite3.Error as e:
            log.warning(f"Could not checkpoint {db_path} before deletion: {e}")

    # Delete companion files first (overwrite bytes, then unlink)
    for suffix in WAL_SUFFIXES:
        wal_file = Path(str(db_path) + suffix)
        if wal_file.exists():
            if _secure_overwrite(wal_file, root):
                result["secure_overwrite"].append(wal_file.name)
            wal_file.unlink()
            result["wal_files_removed"].append(wal_file.name)

    # Delete main database (overwrite bytes, then unlink)
    if db_path.exists():
        if _secure_overwrite(db_path, root):
            result["secure_overwrite"].append(db_path.name)
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

        vacuum_ok = vacuum_and_cleanup(conn, db_path)
        if not vacuum_ok:
            result["vacuum_failed"] = True
            result["error"] = (
                "VACUUM failed after all retries — freelist pages with "
                "recoverable deleted-record PII may remain; DB not certified sanitized"
            )
        log.info(f"Sanitized {db_path.name}: {result['commands_executed']} commands, {result['rows_affected']} rows")

    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"Failed to sanitize {db_path}: {e}")

    return result



def find_all_databases(dump_path: Path) -> list[Path]:
    """Find all SQLite databases in a dump, including by magic bytes.

    Extension-first: files with known SQLite extensions are added directly.
    Only files with unrecognized extensions get the 16-byte magic check.
    """
    databases = []
    unknown = []
    for f in dump_path.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() in SQLITE_EXTENSIONS:
            databases.append(f)
        else:
            unknown.append(f)
    for f in unknown:
        if is_sqlite_database(f):
            databases.append(f)
    return databases


def sanitize_database_generic(db_path: Path, extra_columns: set = None, extra_tables: set = None,
                              registry=None) -> dict:
    """
    Platform-agnostic SQLite sanitizer. Scans every TEXT column in every
    table for PII patterns (emails, phones, URLs with user data, IPs,
    credentials) and redacts matches. Then VACUUMs to eliminate free pages.

    Patterns loaded from rules/pii_patterns.json via the central registry.
    Pass `registry` to override (for --only/--skip filtering).
    """
    from .patterns import get_default_registry

    if registry is None:
        registry = get_default_registry()

    PII_PATTERNS = registry.regex_patterns
    SENSITIVE_COLUMNS = set(registry.sensitive_columns)
    PII_TABLES = set(registry.pii_tables)

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

    # Pre-sanitization integrity check
    try:
        pre_conn = sqlite3.connect(str(db_path))
        integrity = pre_conn.execute("PRAGMA integrity_check").fetchone()
        pre_conn.close()
        if integrity[0] != "ok":
            result["error"] = f"Database corruption detected pre-sanitization: {integrity[0]}"
            result["integrity_pre"] = False
            log.error(f"Integrity check FAILED for {db_path}: {integrity[0]}")
            return result
        result["integrity_pre"] = True
    except sqlite3.Error as e:
        result["error"] = f"Cannot open database for integrity check: {e}"
        return result

    try:
        conn = sqlite3.connect(str(db_path))
        checkpoint_and_prepare(conn)
        cursor = conn.cursor()

        # Get all tables WITH their SQL so we can identify FTS virtual tables
        # and their shadow index tables (never regex-scan an index blob).
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        master_rows = cursor.fetchall()
        tables = [row[0] for row in master_rows]
        table_set = set(tables)
        fts_bases = _fts_base_tables(master_rows)
        fts_shadow = {f"{b}{suf}" for b in fts_bases for suf in FTS_SHADOW_SUFFIXES
                      if f"{b}{suf}" in table_set}

        pii_found = set()

        for table in tables:
            # FTS shadow index tables are handled by rebuild/clear below; a
            # direct write here would corrupt the inverted index (findings #16/#18).
            if table in fts_shadow:
                continue
            result["tables_scanned"] += 1
            qtable = quote_identifier(table)

            # Nuke entire PII tables
            if table.lower() in PII_TABLES:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {qtable}")
                    count = cursor.fetchone()[0]
                    if count > 0:
                        cursor.execute(f"DELETE FROM {qtable}")
                        result["rows_redacted"] += count
                        pii_found.add(f"pii_table:{table}")
                except sqlite3.Error:
                    pass
                continue

            try:
                cursor.execute(f"PRAGMA table_info({qtable})")
                columns = cursor.fetchall()
            except sqlite3.Error:
                continue

            # SQLite is dynamically typed: scan EVERY column, not only declared
            # TEXT/VARCHAR/CHAR/CLOB ones. PII text routinely lives in BLOB /
            # INTEGER / REAL columns; non-text scalar cells simply never match
            # inside _redact_cell, which also decodes BLOB bytes (finding #14).
            text_cols = [col[1] for col in columns]

            for col_name in text_cols:
                result["columns_scanned"] += 1
                col_lower = col_name.lower()
                qcol = quote_identifier(col_name)

                # Direct redact columns with sensitive names
                if col_lower in SENSITIVE_COLUMNS:
                    try:
                        cursor.execute(
                            f"UPDATE {qtable} SET {qcol} = '[REDACTED]' "
                            f"WHERE {qcol} IS NOT NULL AND {qcol} != ''"
                        )
                        affected = cursor.rowcount if cursor.rowcount > 0 else 0
                        if affected:
                            result["rows_redacted"] += affected
                            pii_found.add(f"sensitive_column:{col_lower}")
                    except sqlite3.Error:
                        # UNIQUE/PK constraint — use per-row unique values
                        try:
                            rows = cursor.execute(
                                f"SELECT rowid FROM {qtable} "
                                f"WHERE {qcol} IS NOT NULL AND {qcol} != ''"
                            ).fetchall()
                            for i, (rowid,) in enumerate(rows):
                                cursor.execute(
                                    f"UPDATE {qtable} SET {qcol} = ? WHERE rowid = ?",
                                    (f"[REDACTED_{i}]", rowid),
                                )
                            if rows:
                                result["rows_redacted"] += len(rows)
                                pii_found.add(f"sensitive_column:{col_lower}")
                        except sqlite3.Error:
                            pass
                    continue

                # Regex scan other columns (incl. BLOB / mistyped) for PII
                for pii_name, pattern in PII_PATTERNS.items():
                    try:
                        cursor.execute(f"SELECT rowid, {qcol} FROM {qtable} WHERE {qcol} IS NOT NULL")
                        rows = cursor.fetchall()
                    except sqlite3.Error:
                        continue
                    for rowid, value in rows:
                        new_value, matched = _redact_cell(value, pattern, pii_name)
                        if not matched:
                            continue
                        try:
                            cursor.execute(
                                f"UPDATE {qtable} SET {qcol} = ? WHERE rowid = ?",
                                (new_value, rowid),
                            )
                        except sqlite3.Error:
                            continue
                        result["rows_redacted"] += 1
                        pii_found.add(pii_name)

        # Multi-pass: keep scanning until no new PII found (URLs embed emails, etc.)
        pass_count = 1
        for pass_num in range(2, 6):
            pass_redacted = 0
            for table in tables:
                if table in fts_shadow or table.lower() in PII_TABLES:
                    continue
                qtable = quote_identifier(table)
                try:
                    cursor.execute(f"PRAGMA table_info({qtable})")
                    columns = cursor.fetchall()
                except sqlite3.Error:
                    continue
                text_cols = [c[1] for c in columns if c[1].lower() not in SAFE_COLUMNS]
                for col_name in text_cols:
                    if col_name.lower() in SENSITIVE_COLUMNS:
                        continue
                    qcol = quote_identifier(col_name)
                    for pii_name, pattern in PII_PATTERNS.items():
                        try:
                            cursor.execute(
                                f"SELECT rowid, {qcol} FROM {qtable} "
                                f"WHERE {qcol} IS NOT NULL AND {qcol} NOT LIKE '%[REDACTED%'"
                            )
                            rows = cursor.fetchall()
                        except sqlite3.Error:
                            continue
                        for rowid, value in rows:
                            new_value, matched = _redact_cell(value, pattern, pii_name)
                            if not matched:
                                continue
                            try:
                                cursor.execute(
                                    f"UPDATE {qtable} SET {qcol} = ? WHERE rowid = ?",
                                    (new_value, rowid),
                                )
                            except sqlite3.Error:
                                continue
                            pass_redacted += 1
            if pass_redacted == 0:
                break
            pass_count += 1
            result["rows_redacted"] += pass_redacted

        result["pii_types_found"] = sorted(pii_found)

        # FTS index cleanup: rebuild from redacted content (FTS3/4/5), or clear
        # the shadow tables under an integrity-gated savepoint that rolls back
        # and flags on corruption instead of shipping a broken DB (#16, #18).
        fts_ok = _clean_fts_shadow_tables(conn, cursor, fts_bases, table_set, result)
        if not fts_ok:
            result["error"] = (
                "FTS index cleanup incomplete — tokenized PII may remain in the "
                f"shadow tables of {result.get('fts_cleanup_incomplete')}"
            )

        # VACUUM failure means pre-existing freelist pages of deleted records
        # were never reclaimed — surface it, never report a plain success (#15).
        vacuum_ok = vacuum_and_cleanup(conn, db_path)
        if not vacuum_ok:
            result["vacuum_failed"] = True
            result.setdefault(
                "error",
                "VACUUM failed after all retries — freelist pages with "
                "recoverable deleted-record PII may remain; DB not certified sanitized",
            )

        # Post-sanitization integrity check
        try:
            post_conn = sqlite3.connect(str(db_path))
            integrity = post_conn.execute("PRAGMA integrity_check").fetchone()
            post_conn.close()
            result["integrity_post"] = integrity[0] == "ok"
            if not result["integrity_post"]:
                result.setdefault("error", f"Database corrupt post-sanitization: {integrity[0]}")
                log.error(f"Integrity check FAILED post-sanitization for {db_path}: {integrity[0]}")
        except sqlite3.Error as e:
            result["integrity_post"] = False
            result.setdefault("error", f"Cannot verify integrity post-sanitization: {e}")

        result["hash_after"] = _sha256(db_path)
        log.info(f"Generic sanitized {db_path.name}: {result['tables_scanned']} tables, "
                 f"{result['rows_redacted']} rows redacted ({pass_count} passes), PII: {result['pii_types_found']}")

    except sqlite3.Error as e:
        result["error"] = str(e)
        log.error(f"Failed generic sanitize {db_path}: {e}")

    return result


def delete_wal_orphans(dump_path: Path) -> list[Path]:
    """Find and delete orphaned WAL/SHM/journal files with no parent database.

    The parent DB path is derived by stripping ONLY the trailing companion
    suffix. The old ``str(wal_file).replace(suffix, "")`` removed EVERY
    occurrence of the substring, so a path like
    ``/cases/case-journal/x.db-journal`` mis-resolved to a nonexistent parent
    (deleting a live companion → data loss) and a real orphan under
    ``/dump/wallet-wal/data.db-wal`` mis-mapped onto an unrelated existing DB
    (orphan spared → PII survival). Findings #17/#39.
    """
    deleted = []
    for suffix in WAL_SUFFIXES:
        for wal_file in dump_path.rglob(f"*{suffix}"):
            # A directory can also end in "-wal"/"-shm" (the audit's data-loss
            # case); only real files are companion journals to unlink.
            if not wal_file.is_file():
                continue
            name = str(wal_file)
            if not name.endswith(suffix):
                continue
            parent_db = Path(name.removesuffix(suffix))
            if not parent_db.exists():
                wal_file.unlink()
                deleted.append(wal_file)
                log.info(f"Deleted orphaned WAL: {wal_file}")
    return deleted
