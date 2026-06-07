"""
HYGEIA Forensic Cleaner -- anti-forensic hardening module.

Removes artifacts that survive standard file deletion and can be
recovered by forensic tools: LevelDB stores, thumbnail/browser caches,
swap/temp files, and file-system timestamps.
"""

import hashlib
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("hygeia.forensic_cleaner")


def _sha256(filepath: Path) -> str:
    """Return the SHA256 hex digest of a file's contents."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# LevelDB

# Directory name suffixes that unambiguously identify a LevelDB store,
# even when no CURRENT file is present (e.g. mid-write Electron apps).
_LEVELDB_NAME_SUFFIXES = ("leveldb", "_leveldb")


def _has_leveldb_data_files(path):
    """Return True if path contains at least one LevelDB data file."""
    return (
        any(path.glob("*.ldb"))
        or any(path.glob("*.sst"))
        or any(path.glob("MANIFEST-*"))
        or any(path.glob("*.log"))
    )


def _is_leveldb_dir(path):
    """Return True if path looks like a LevelDB store directory.

    Detection criteria (any one is sufficient):
    1. Contains a CURRENT file AND at least one data file (*.ldb, *.sst,
       MANIFEST-*, *.log) — the classic LevelDB layout.
    2. Directory name ends with "leveldb" or "_leveldb" — covers
       Electron ``LocalStorage_leveldb``, ``IndexedDB/foo.leveldb``, etc.
    3. Path contains an ``IndexedDB`` component and the directory name
       ends with ``.leveldb`` — belt-and-suspenders for Chrome/Electron.
    """
    if not path.is_dir():
        return False

    name_lower = path.name.lower()

    # Criterion 2: name-based detection (case-insensitive suffix match)
    for suffix in _LEVELDB_NAME_SUFFIXES:
        if name_lower.endswith(suffix):
            return True

    # Criterion 3: inside IndexedDB and name ends with .leveldb
    parts_lower = [p.lower() for p in path.parts]
    if "indexeddb" in parts_lower and name_lower.endswith(".leveldb"):
        return True

    # Criterion 1: CURRENT file + at least one data file
    if (path / "CURRENT").is_file() and _has_leveldb_data_files(path):
        return True

    return False


def _collect_leveldb_dirs(dump_path):
    """Walk dump_path and return all LevelDB store directories.

    Uses two complementary strategies:
    - CURRENT-file walk: fast for classic layouts.
    - Name-pattern walk: catches stores without a CURRENT file.

    Deduplicates so a directory matched by both is only returned once.
    Skips directories that are already inside a previously found store.
    """
    found = []
    seen = set()

    def _add(store_dir):
        key = store_dir.resolve()
        if key in seen:
            return
        # Skip if already inside a store we found (e.g. nested LevelDB)
        for existing in found:
            try:
                store_dir.relative_to(existing)
                return  # store_dir is inside an already-queued store
            except ValueError:
                pass
        seen.add(key)
        found.append(store_dir)

    # Strategy A: walk every directory, check name patterns and CURRENT
    for dirpath in dump_path.rglob("*"):
        if not dirpath.is_dir():
            continue
        if _is_leveldb_dir(dirpath):
            _add(dirpath)

    return found


def clean_leveldb_stores(dump_path, dry_run=False):
    actions = []
    for store_dir in _collect_leveldb_dirs(dump_path):
        rel = str(store_dir.relative_to(dump_path))
        if dry_run:
            actions.append({"action": "delete_leveldb_store", "path": rel, "dry_run": True})
        else:
            shutil.rmtree(store_dir, ignore_errors=True)
            actions.append({"action": "delete_leveldb_store", "path": rel})
            log.info(f"Deleted LevelDB store: {rel}")
    log.debug(f"LevelDB cleanup: {len(actions)} stores found")
    return actions


# Thumbnail / browser cache cleanup

_CACHE_DIR_NAMES_LOWER = frozenset({
    "thumbnails", "cache", "gpucache", "code cache", "service worker",
    "com.apple.uikit.pboardpersistentitems",
})
_IOS_CACHE_SUFFIX = "library/caches"
_CACHE_FILE_NAMES_LOWER = frozenset({
    "thumbnails-journal", "thumbnails.db", "thumbnails.db-wal", "thumbnails.db-shm",
})


def _is_cache_dir(path, dump_path):
    name_lower = path.name.lower()
    if name_lower in _CACHE_DIR_NAMES_LOWER:
        return True
    if "cache" in name_lower:
        return True
    rel_lower = str(path.relative_to(dump_path)).replace("\\\\", "/").lower()
    if rel_lower.endswith(_IOS_CACHE_SUFFIX):
        return True
    return False


def clean_thumbnail_caches(dump_path, dry_run=False):
    actions = []
    deleted_dirs = []

    def _inside_deleted(p):
        for d in deleted_dirs:
            try:
                p.relative_to(d)
                return True
            except ValueError:
                pass
        return False

    all_paths = sorted(dump_path.rglob("*"), key=lambda x: len(x.parts))
    for dirpath in all_paths:
        if not dirpath.is_dir():
            continue
        if _inside_deleted(dirpath):
            continue
        if _is_cache_dir(dirpath, dump_path):
            rel = str(dirpath.relative_to(dump_path))
            if dry_run:
                actions.append({"action": "delete_cache_dir", "path": rel, "dry_run": True})
            else:
                shutil.rmtree(dirpath, ignore_errors=True)
                deleted_dirs.append(dirpath)
                actions.append({"action": "delete_cache_dir", "path": rel})
                log.info(f"Deleted cache dir: {rel}")
    for fp in list(dump_path.rglob("*")):
        if not fp.is_file():
            continue
        if _inside_deleted(fp):
            continue
        if fp.name.lower() in _CACHE_FILE_NAMES_LOWER:
            rel = str(fp.relative_to(dump_path))
            if dry_run:
                actions.append({"action": "delete_cache_file", "path": rel, "dry_run": True})
            else:
                action = {"action": "delete_cache_file", "path": rel, "hash_before": _sha256(fp)}
                fp.unlink(missing_ok=True)
                actions.append(action)
                log.info(f"Deleted cache file: {rel}")
    log.debug(f"Thumbnail/cache cleanup: {len(actions)} items found")
    return actions


# Swap / temp file cleanup

_SWAP_EXACT_LOWER = frozenset({"pagefile.sys", "swapfile.sys", "hiberfil.sys"})
_SWAP_SUFFIXES = (".swp", ".swo", ".tmp")
_SWAP_PREFIXES = ("~$",)
_SWAP_DOTLOCK_PREFIX = ".~lock."


def _is_swap_file(name):
    name_lower = name.lower()
    if name_lower in _SWAP_EXACT_LOWER:
        return True
    for suf in _SWAP_SUFFIXES:
        if name_lower.endswith(suf):
            return True
    for pre in _SWAP_PREFIXES:
        if name.startswith(pre):
            return True
    if name.startswith(_SWAP_DOTLOCK_PREFIX):
        return True
    return False


def clean_swap_temp_files(dump_path, dry_run=False):
    actions = []
    for fp in list(dump_path.rglob("*")):
        if not fp.is_file():
            continue
        if _is_swap_file(fp.name):
            rel = str(fp.relative_to(dump_path))
            if dry_run:
                actions.append({"action": "delete_swap_file", "path": rel, "dry_run": True})
            else:
                action = {"action": "delete_swap_file", "path": rel, "hash_before": _sha256(fp)}
                fp.unlink(missing_ok=True)
                actions.append(action)
                log.info(f"Deleted swap/temp file: {rel}")
    log.debug(f"Swap/temp cleanup: {len(actions)} files found")
    return actions


# Timestamp normalization


def normalize_timestamps(dump_path, epoch="2000-01-01"):
    dt = datetime.strptime(epoch, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    epoch_ts = dt.timestamp()
    normalized = 0
    errors = 0
    for fp in list(dump_path.rglob("*")):
        try:
            os.utime(fp, (epoch_ts, epoch_ts))
            normalized += 1
        except OSError:
            errors += 1
    try:
        os.utime(dump_path, (epoch_ts, epoch_ts))
        normalized += 1
    except OSError:
        errors += 1
    action = {
        "action": "normalize_timestamps",
        "epoch": epoch,
        "epoch_ts": epoch_ts,
        "files_normalized": normalized,
    }
    if errors:
        action["errors"] = errors
    log.info(f"Timestamp normalization: {normalized} items set to {epoch}")
    return [action]


# Master function


def forensic_clean_all(dump_path, dry_run=False, workers=1):
    """Run all forensic cleaning sub-tasks.

    Args:
        dump_path: Root directory to clean.
        dry_run: Preview actions without executing.
        workers: Number of parallel workers for independent sub-tasks.
                 1 = sequential (default), 0 = auto-detect, >1 = explicit pool.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
    from pathlib import Path as _Path

    dump_path = _Path(dump_path)
    prefix = "DRY RUN " if dry_run else ""
    log.info(f"forensic_clean_all: {prefix}{dump_path} (workers={workers})")

    # Resolve auto-detect
    resolved_workers = workers if workers != 0 else (os.cpu_count() or 1)

    # The three scan/delete sub-tasks are independent of each other
    subtasks = [
        ("leveldb", clean_leveldb_stores),
        ("thumbnail_caches", clean_thumbnail_caches),
        ("swap_temp", clean_swap_temp_files),
    ]

    # Results keyed by subtask name so we can assemble in deterministic order
    subtask_results: dict[str, list] = {}

    if resolved_workers > 1 and not dry_run:
        futures_map = {}
        with ThreadPoolExecutor(max_workers=min(resolved_workers, len(subtasks))) as executor:
            for name, fn in subtasks:
                future = executor.submit(fn, dump_path, dry_run)
                futures_map[future] = name
            completed = 0
            for future in _as_completed(futures_map):
                name = futures_map[future]
                completed += 1
                subtask_results[name] = future.result()
                log.info(f"Forensic sub-task {completed}/{len(subtasks)} complete: {name}")
    else:
        for name, fn in subtasks:
            subtask_results[name] = fn(dump_path, dry_run)

    actions = []
    for name, _ in subtasks:
        actions.extend(subtask_results[name])

    if not dry_run:
        actions.extend(normalize_timestamps(dump_path))

    return actions
