"""
HYGEIA Forensic Cleaner -- anti-forensic hardening module.

Removes artifacts that survive standard file deletion and can be
recovered by forensic tools: LevelDB stores, thumbnail/browser caches,
swap/temp files, and file-system timestamps.
"""

import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("hygeia.forensic_cleaner")


# LevelDB


def _is_leveldb_dir(path):
    if not path.is_dir():
        return False
    if not (path / "CURRENT").is_file():
        return False
    return (
        any(path.glob("*.ldb"))
        or any(path.glob("*.sst"))
        or any(path.glob("MANIFEST-*"))
        or any(path.glob("*.log"))
    )


def clean_leveldb_stores(dump_path, dry_run=False):
    actions = []
    for current_file in list(dump_path.rglob("CURRENT")):
        store_dir = current_file.parent
        if not _is_leveldb_dir(store_dir):
            continue
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
                fp.unlink(missing_ok=True)
                actions.append({"action": "delete_cache_file", "path": rel})
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
                fp.unlink(missing_ok=True)
                actions.append({"action": "delete_swap_file", "path": rel})
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


def forensic_clean_all(dump_path, dry_run=False):
    from pathlib import Path as _Path
    dump_path = _Path(dump_path)
    actions = []
    prefix = "DRY RUN " if dry_run else ""
    log.info(f"forensic_clean_all: {prefix}{dump_path}")
    actions.extend(clean_leveldb_stores(dump_path, dry_run=dry_run))
    actions.extend(clean_thumbnail_caches(dump_path, dry_run=dry_run))
    actions.extend(clean_swap_temp_files(dump_path, dry_run=dry_run))
    if not dry_run:
        actions.extend(normalize_timestamps(dump_path))
    return actions
