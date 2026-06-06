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

    # Delete WAL/SHM/journal files (retry on Windows file lock)
    for suffix in WAL_SUFFIXES:
        wal_file = Path(str(db_path) + suffix)
        if wal_file.exists():
            try:
                wal_file.unlink()
                log.debug(f"Deleted {wal_file.name}")
            except PermissionError:
                import time
                time.sleep(0.1)
                try:
                    wal_file.unlink()
                    log.debug(f"Deleted {wal_file.name} (retry)")
                except PermissionError:
                    log.warning(f"Could not delete {wal_file.name} (file locked)")


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
