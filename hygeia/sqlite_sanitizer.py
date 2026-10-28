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
from contextlib import closing
from pathlib import Path
from typing import Any

from .sqlite_catalog import column_info, fts_module, fts_option, table_inventory
from .utils import sha256 as _sha256, quote_identifier, is_safe_regular_file

log = logging.getLogger("hygeia.sqlite")

SQLITE_EXTENSIONS = {".sqlite", ".db", ".sqlitedb", ".storedata", ".plsql", ".PLSQL"}
WAL_SUFFIXES = ["-wal", "-shm", "-journal"]
SCAN_BATCH_SIZE = 500
MAX_RECORDED_ERRORS = 100


def _record_sanitize_error(result, operation, table, column=None):
    """Keep bounded, value-free evidence of incomplete redaction (#39).

    SQLite exception strings can contain trigger-supplied PII. Record the
    failing operation and location, never the exception or original cell.
    ``integrity_post`` describes database structure only, not sanitization.
    """
    result["errors_count"] += 1
    if len(result["errors"]) < MAX_RECORDED_ERRORS:
        item = {"operation": operation, "table": table}
        if column is not None:
            item["column"] = column
        result["errors"].append(item)
    result.setdefault("error", "SQLite sanitization incomplete; see errors_count and errors")


def _column_rows(conn, table, column, rowid_name, result, exclude_redacted=False):
    """Stream a column using a separate read cursor so UPDATE does not reset it."""
    qt, qc = quote_identifier(table), quote_identifier(column)
    reader = conn.cursor()
    extra = f" AND {qc} NOT LIKE '%[REDACTED%'" if exclude_redacted else ""
    try:
        # rowid_name is one of SQLite's three built-in aliases, never input SQL.
        has_rowid = True
        try:
            reader.execute(f"SELECT {rowid_name}, {qc} FROM {qt} WHERE {qc} IS NOT NULL{extra}")
        except sqlite3.Error:
            # WITHOUT ROWID carriers still need a complete read. A matched
            # value is reported unsupported if no writable locator is available.
            reader.execute(f"SELECT {qc} FROM {qt} WHERE {qc} IS NOT NULL{extra}")
            has_rowid = False
        while True:
            batch = reader.fetchmany(SCAN_BATCH_SIZE)
            if not batch:
                break
            for row in batch:
                yield row if has_rowid else (None, row[0])
    except sqlite3.Error:
        _record_sanitize_error(result, "read_column", table, column)
    finally:
        reader.close()


def _redaction_retained(conn, qtable, qcol, rowid_name, rowid, value):
    """Detect AFTER triggers that restore a cell or delete/move the target row."""
    row = conn.execute(
        f"SELECT {qcol} FROM {qtable} WHERE {rowid_name} = ?", (rowid,)
    ).fetchone()
    return row is not None and row[0] == value

# FTS3/4 (_content/_segments/_segdir) AND FTS5 (_data/_idx/_docsize/_config,
# plus _content for stored-content tables) shadow-table suffixes. Tokenized PII
# lives in these index blobs; the regex pass cannot reach it (finding #16).
FTS_SHADOW_SUFFIXES = (
    "_content", "_segments", "_segdir",
    "_data", "_idx", "_docsize", "_config", "_stat",
)

# Overwrite passes for secure_delete of a database file before unlink (#45).
_SECURE_OVERWRITE_PASSES = 3


# Matches an explicit ``content`` option in a ``CREATE VIRTUAL TABLE ... USING
# fts3/4/5(...)`` statement: ``content=''`` (contentless) or
# ``content='other_table'`` (external content). FTS3/4 support the same
# option. Its *absence* means FTS is managing its own internal content shadow
# table (``_content``), which a rebuild can always regenerate the index from.


def _fts_content_option(sql):
    return fts_option(sql, "content")


def _fts_external_sources(master_rows, fts_bases):
    """Find explicit external-content sources, including unquoted options."""
    sources = {}
    for name, sql in master_rows:
        if name not in fts_bases or not sql:
            continue
        value = _fts_content_option(sql)
        if value:
            sources[name] = value
    return sources


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
        if sql and fts_module(sql):
            bases.add(name)
    return bases


def _fts_uncleanable_bases(master_rows, fts_bases) -> set:
    """Return the subset of ``fts_bases`` that are structurally contentless or
    external-content FTS tables — i.e. whose ``CREATE VIRTUAL TABLE`` SQL in
    ``sqlite_master`` declares an explicit ``content=`` option.

    This is a STRUCTURAL check, made directly on the DDL text, so it holds
    regardless of the SQLite version running underneath. That independence
    matters: whether ``INSERT INTO base(base) VALUES('rebuild')`` raises for
    a contentless table is a SQLite-version-dependent implementation detail.
    Newer SQLite raises; older SQLite (e.g. the version bundled with Python
    3.10) can silently no-op instead — and a bare "rebuild didn't raise" was
    previously read as "index is clean", which is a false clean on those
    older versions (findings #16/#18). Detecting the option from the DDL
    means the fail-closed decision no longer depends on that behavior at all.

    Both forms are treated identically and conservatively:

    - ``content=''`` (contentless): FTS5 stores no row text anywhere —
      neither in an internal nor external table — only the tokenized
      postings survive in the ``_data``/``_idx`` shadow tables. There is
      literally no content for ``rebuild`` to regenerate the index from, so
      the pre-redaction tokens can persist no matter what ``rebuild`` does.
    - ``content='other_table'`` (external content): the row text lives in a
      separately named table that this function does not itself confirm was
      redacted before rebuild would run, and FTS5's handling of rebuild
      against external content is exactly the kind of edge case whose
      behavior has shifted across SQLite versions. Treating it the same as
      the contentless case is the conservative, fail-closed choice for a
      forensic PII sanitizer: don't guess, flag it.
    """
    uncleanable = set()
    sql_by_name = {row[0]: row[1] for row in master_rows}
    for base in fts_bases:
        sql = sql_by_name.get(base)
        if sql and _fts_content_option(sql) is not None:
            uncleanable.add(base)
    return uncleanable


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


def _clean_fts_shadow_tables(conn, cursor, fts_bases, existing_tables, result,
                              uncleanable_bases=frozenset(), external_bases=frozenset(),
                              shadow_tables=None) -> bool:
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

    ``uncleanable_bases`` (from ``_fts_uncleanable_bases``) names bases that are
    structurally contentless/external-content per their DDL. For those we never
    attempt — and so never trust — the rebuild shortcut: whether it raises is a
    SQLite-version-dependent detail (older SQLite can silently no-op instead of
    raising), and a rebuild that doesn't raise is not proof the tokenized index
    was actually purged. Those bases go straight to the integrity-gated
    shadow-clear path below, on every SQLite version alike.
    """
    if shadow_tables is None:
        shadow_tables = {name for name, table in table_inventory(conn).items() if table.fts_shadow}
    all_clean = True
    for base in sorted(fts_bases):
        if base not in existing_tables:
            continue
        qbase = quote_identifier(base)
        if base in external_bases:
            # The authoritative ordinary table has already passed through the
            # full sanitizer loop. Rebuild discards the old postings; rank=1
            # then verifies the index against that content, not just itself.
            # https://www.sqlite.org/fts5.html#the_integrity_check_command
            try:
                conn.execute("SAVEPOINT hygeia_external_fts")
                cursor.execute(f"INSERT INTO {qbase}({qbase}) VALUES('rebuild')")
                cursor.execute(f"INSERT INTO {qbase}({qbase}, rank) VALUES('integrity-check', 1)")
                conn.execute("RELEASE hygeia_external_fts")
                result.setdefault("fts_rebuilt", []).append(base)
            except sqlite3.Error:
                conn.execute("ROLLBACK TO hygeia_external_fts")
                conn.execute("RELEASE hygeia_external_fts")
                all_clean = False
                result.setdefault("fts_cleanup_incomplete", []).append(base)
            continue
        if base not in uncleanable_bases:
            try:
                cursor.execute(f"INSERT INTO {qbase}({qbase}) VALUES('rebuild')")
                continue  # index rebuilt from redacted content
            except sqlite3.Error:
                pass

        shadows = [f"{base}{suf}" for suf in FTS_SHADOW_SUFFIXES
                   if f"{base}{suf}" in shadow_tables]
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
                if base in uncleanable_bases:
                    # The best-effort wipe happened to leave a structurally
                    # valid (now-empty) index on THIS SQLite build, but that is
                    # not something we take as proof of clean: whether a raw
                    # shadow-table DELETE trips integrity_check is itself the
                    # kind of implementation detail that can vary by SQLite
                    # version, and this base was never rebuilt-and-verified
                    # from content in the first place. Flag it unconditionally
                    # so the fail-closed decision for contentless/external FTS
                    # tables stays structural, not contingent on this DELETE's
                    # outcome on any particular SQLite build.
                    all_clean = False
                    result.setdefault("fts_cleanup_incomplete", []).append(base)
                    log.warning(
                        f"{base} is a contentless/external-content FTS table — "
                        f"shadow rows cleared without corrupting the index, but "
                        f"flagging incomplete regardless since it was never "
                        f"rebuilt-and-verified from content"
                    )
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
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY  # Windows: no CRLF translation on os.write
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
    try:
        conn.commit()
        # Flush WAL into the main database file so VACUUM sees a clean state.
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.OperationalError:
            pass  # Not in WAL mode — ignore
    finally:
        # This function consumes the connection, including on commit failure.
        conn.close()

    def _do_vacuum(path: Path) -> bool:
        try:
            with closing(sqlite3.connect(str(path))) as vconn:
                vconn.execute("VACUUM")
            return True
        except sqlite3.OperationalError as e:
            log.warning(f"VACUUM attempt failed on {path}: {e}")
            return False

    def _do_vacuum_journal_delete(path: Path) -> bool:
        """Switch to DELETE journal mode first, then VACUUM.

        Chrome's Login Data uses WAL mode.  Switching to DELETE journal mode
        forces a full WAL checkpoint and removes the WAL file, which clears the
        OS-level lock that was blocking VACUUM.
        """
        try:
            with closing(sqlite3.connect(str(path))) as vconn:
                vconn.execute("PRAGMA journal_mode=DELETE")
                vconn.commit()
                vconn.execute("VACUUM")
            return True
        except sqlite3.OperationalError as e:
            log.warning(f"VACUUM (journal_mode=DELETE) failed on {path}: {e}")
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

    # Delete WAL/SHM/journal files. A companion can still be locked by another
    # process (e.g. on Windows a -journal held by a DB an external connection
    # left open); tolerate that instead of crashing — vacuum_ok already carries
    # the real success/failure signal.
    for suffix in WAL_SUFFIXES:
        wal_file = Path(str(db_path) + suffix)
        if wal_file.exists():
            try:
                wal_file.unlink()
            except OSError as e:
                log.warning(f"Could not remove companion {wal_file.name}: {e}")
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
    result: dict[str, Any] = {"action": "delete_database", "path": str(db_path),
              "wal_files_removed": [], "secure_overwrite": []}

    if is_sqlite_database(db_path):
        try:
            with closing(sqlite3.connect(str(db_path))) as conn:
                checkpoint_and_prepare(conn)
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
    result: dict[str, Any] = {
        "action": "sanitize_database",
        "path": str(db_path),
        "commands_executed": 0,
        "rows_affected": 0,
        "errors_count": 0,
        "errors": [],
    }

    if not db_path.exists():
        result["error"] = "Database not found"
        return result

    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        checkpoint_and_prepare(conn)

        cursor = conn.cursor()
        for sql in sql_commands:
            try:
                cursor.execute(sql)
                result["rows_affected"] += cursor.rowcount if cursor.rowcount > 0 else 0
                result["commands_executed"] += 1
            except sqlite3.Error:
                _record_sanitize_error(result, "execute_command", "(explicit SQL)")

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
    finally:
        if conn is not None:
            conn.close()

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


def sanitize_database_generic(db_path: Path, extra_columns: set[str] | None = None,
                              extra_tables: set[str] | None = None,
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

    result: dict[str, Any] = {
        "action": "generic_sanitize",
        "path": str(db_path),
        "tables_scanned": 0,
        "columns_scanned": 0,
        "rows_redacted": 0,
        "pii_types_found": [],
        "errors_count": 0,
        "errors": [],
    }

    if not db_path.exists() or not is_sqlite_database(db_path):
        result["error"] = "Not a SQLite database"
        return result

    result["hash_before"] = _sha256(db_path)

    # Pre-sanitization integrity check
    try:
        with closing(sqlite3.connect(str(db_path))) as pre_conn:
            integrity = pre_conn.execute("PRAGMA integrity_check").fetchone()
        if integrity[0] != "ok":
            result["error"] = f"Database corruption detected pre-sanitization: {integrity[0]}"
            result["integrity_pre"] = False
            log.error(f"Integrity check FAILED for {db_path}: {integrity[0]}")
            return result
        result["integrity_pre"] = True
    except sqlite3.Error as e:
        result["error"] = f"Cannot open database for integrity check: {e}"
        return result

    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        checkpoint_and_prepare(conn)
        cursor = conn.cursor()

        # Get all tables WITH their SQL so we can identify FTS virtual tables
        # and their shadow index tables (never regex-scan an index blob).
        inventory = table_inventory(conn)
        master_rows = [(table.name, table.sql) for table in inventory.values()]
        tables = [row[0] for row in master_rows]
        table_set = set(tables)
        fts_bases = _fts_base_tables(master_rows)
        fts_uncleanable = _fts_uncleanable_bases(master_rows, fts_bases)
        fts_sources = _fts_external_sources(master_rows, fts_bases)
        fts_shadow = {name for name, table in inventory.items() if table.fts_shadow}
        ordinary_tables = {
            name.lower() for name, sql in master_rows
            if sql and not re.search(r"CREATE\s+VIRTUAL\s+TABLE", sql, re.IGNORECASE)
            and name not in fts_shadow
        }
        sql_by_name = dict(master_rows)
        external_fts5 = {
            name for name, source in fts_sources.items()
            if source.lower() in ordinary_tables
            and re.search(r"\bUSING\s+fts5\s*\(", sql_by_name[name], re.IGNORECASE)
            # Stored-content FTS5 has a _content shadow. An apparent content=
            # inside a quoted column name must not make us skip its real data.
            and f"{name}_content" not in table_set
        }

        pii_found = set()

        for table in tables:
            # FTS shadow index tables are handled by rebuild/clear below; a
            # direct write here would corrupt the inverted index (findings #16/#18).
            if inventory[table].derived:
                continue
            result["tables_scanned"] += 1
            if table in fts_sources:
                # This virtual table exposes its source's cells. Updating it
                # directly edits postings without updating the source and can
                # corrupt trigger-maintained indexes. Sanitize the source and
                # rebuild after all authoritative tables have been processed.
                if table.lower() in PII_TABLES:
                    _record_sanitize_error(result, "external_table_delete", table)
                continue
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
                    _record_sanitize_error(result, "delete_table", table)
                continue

            try:
                columns = column_info(conn, table)
            except sqlite3.Error:
                _record_sanitize_error(result, "read_schema", table)
                continue

            # SQLite is dynamically typed: scan EVERY column, not only declared
            # TEXT/VARCHAR/CHAR/CLOB ones. PII text routinely lives in BLOB /
            # INTEGER / REAL columns; non-text scalar cells simply never match
            # inside _redact_cell, which also decodes BLOB bytes (finding #14).
            text_cols = [col[1] for col in sorted(columns, key=lambda col: col[6] != 0)]
            readonly_columns = {col[1] for col in columns if col[6] != 0}
            declared = {col[1].lower() for col in columns}
            rowid_name = next((name for name in ("_rowid_", "rowid", "oid")
                               if name not in declared), None)
            if rowid_name is None:
                _record_sanitize_error(result, "row_addressing", table)
                continue

            for col_name in text_cols:
                result["columns_scanned"] += 1
                col_lower = col_name.lower()
                qcol = quote_identifier(col_name)

                if col_name in readonly_columns:
                    rows = _column_rows(conn, table, col_name, rowid_name, result)
                    try:
                        for _, value in rows:
                            sensitive = col_lower in SENSITIVE_COLUMNS and value not in (None, "")
                            if sensitive or any(_redact_cell(value, pattern, name)[1]
                                                for name, pattern in PII_PATTERNS.items()):
                                _record_sanitize_error(result, "read_only_column", table, col_name)
                                break
                    finally:
                        rows.close()
                    continue

                # Direct redact columns with sensitive names
                if col_lower in SENSITIVE_COLUMNS:
                    try:
                        expected = cursor.execute(
                            f"SELECT count(*) FROM {qtable} "
                            f"WHERE {qcol} IS NOT NULL AND {qcol} != ''"
                        ).fetchone()[0]
                        cursor.execute(
                            f"UPDATE {qtable} SET {qcol} = '[REDACTED]' "
                            f"WHERE {qcol} IS NOT NULL AND {qcol} != ''"
                        )
                        affected = cursor.rowcount if cursor.rowcount > 0 else 0
                        if affected != expected:
                            raise sqlite3.IntegrityError("redaction update skipped rows")
                        residual = cursor.execute(
                            f"SELECT 1 FROM {qtable} WHERE {qcol} IS NOT NULL "
                            f"AND {qcol} != '' AND {qcol} != '[REDACTED]' LIMIT 1"
                        ).fetchone()
                        if residual is not None:
                            raise sqlite3.IntegrityError("redaction update not retained")
                        if affected:
                            result["rows_redacted"] += affected
                            pii_found.add(f"sensitive_column:{col_lower}")
                    except sqlite3.Error:
                        # UNIQUE/PK constraint — use per-row unique values
                        for i, (rowid, value) in enumerate(
                            _column_rows(conn, table, col_name, rowid_name, result)
                        ):
                            if value == "":
                                continue
                            try:
                                cursor.execute(
                                    f"UPDATE {qtable} SET {qcol} = ? WHERE {rowid_name} = ?",
                                    (f"[REDACTED_{i}]", rowid),
                                )
                                if cursor.rowcount != 1 or not _redaction_retained(
                                    conn, qtable, qcol, rowid_name, rowid, f"[REDACTED_{i}]"
                                ):
                                    _record_sanitize_error(result, "redact_cell", table, col_name)
                                    continue
                            except sqlite3.Error:
                                _record_sanitize_error(result, "redact_cell", table, col_name)
                                continue
                            result["rows_redacted"] += 1
                            pii_found.add(f"sensitive_column:{col_lower}")
                    continue

                # Regex scan other columns (incl. BLOB / mistyped) for PII
                for pii_name, pattern in PII_PATTERNS.items():
                    for rowid, value in _column_rows(conn, table, col_name, rowid_name, result):
                        new_value, matched = _redact_cell(value, pattern, pii_name)
                        if not matched:
                            continue
                        try:
                            cursor.execute(
                                f"UPDATE {qtable} SET {qcol} = ? WHERE {rowid_name} = ?",
                                (new_value, rowid),
                            )
                            if cursor.rowcount != 1 or not _redaction_retained(
                                conn, qtable, qcol, rowid_name, rowid, new_value
                            ):
                                _record_sanitize_error(result, "redact_cell", table, col_name)
                                continue
                        except sqlite3.Error:
                            _record_sanitize_error(result, "redact_cell", table, col_name)
                            continue
                        result["rows_redacted"] += 1
                        pii_found.add(pii_name)

        # Multi-pass: keep scanning until no new PII found (URLs embed emails, etc.)
        pass_count = 1
        for pass_num in range(2, 6):
            pass_redacted = 0
            for table in tables:
                if inventory[table].derived or table in fts_sources or table.lower() in PII_TABLES:
                    continue
                qtable = quote_identifier(table)
                try:
                    columns = column_info(conn, table)
                except sqlite3.Error:
                    _record_sanitize_error(result, "read_schema", table)
                    continue
                declared = {col[1].lower() for col in columns}
                rowid_name = next((name for name in ("_rowid_", "rowid", "oid")
                                   if name not in declared), None)
                if rowid_name is None:
                    continue  # recorded in the first pass
                text_cols = [c[1] for c in columns
                             if c[1].lower() not in SAFE_COLUMNS and c[6] == 0]
                for col_name in text_cols:
                    if col_name.lower() in SENSITIVE_COLUMNS:
                        continue
                    qcol = quote_identifier(col_name)
                    for pii_name, pattern in PII_PATTERNS.items():
                        for rowid, value in _column_rows(
                            conn, table, col_name, rowid_name, result, exclude_redacted=True
                        ):
                            new_value, matched = _redact_cell(value, pattern, pii_name)
                            if not matched:
                                continue
                            try:
                                cursor.execute(
                                    f"UPDATE {qtable} SET {qcol} = ? WHERE {rowid_name} = ?",
                                    (new_value, rowid),
                                )
                                if cursor.rowcount != 1 or not _redaction_retained(
                                    conn, qtable, qcol, rowid_name, rowid, new_value
                                ):
                                    _record_sanitize_error(result, "redact_cell", table, col_name)
                                    continue
                            except sqlite3.Error:
                                _record_sanitize_error(result, "redact_cell", table, col_name)
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
        # Contentless/external-content bases (fts_uncleanable) skip the rebuild
        # shortcut entirely — that decision is structural (from the DDL), not
        # dependent on whether rebuild happens to raise on this SQLite version.
        fts_ok = _clean_fts_shadow_tables(conn, cursor, fts_bases, table_set, result,
                                           fts_uncleanable, external_fts5, fts_shadow)
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
            with closing(sqlite3.connect(str(db_path))) as post_conn:
                integrity = post_conn.execute("PRAGMA integrity_check").fetchone()
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
    finally:
        if conn is not None:
            conn.close()

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
