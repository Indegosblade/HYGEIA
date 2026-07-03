"""
HYGEIA Filesystem Sanitizer — forensic artifact removal.

Targets data structures that survive file-level deletion:
LevelDB stores, thumbnail caches, swap/hibernation files,
Spotlight indexes, search databases, and credential stores.
"""

import logging
import os
import shutil
from pathlib import Path

from .utils import resolve_within, safe_utime

log = logging.getLogger("hygeia.filesystem")


def _safe_utime_any(path: Path, root: Path, times: tuple[float, float]) -> bool:
    """Symlink-safe utime for a file OR a directory.

    ``utils.safe_utime`` intentionally only permits regular files (it backs
    in-place content rewriters that must never write through a symlink).
    Timestamp normalization legitimately touches directory mtimes too (a
    dump's own subdirectories), so this mirrors the same symlink +
    containment guarantee for directories -- reusing ``resolve_within`` for
    the containment check -- without the regular-file restriction, and
    defers to ``safe_utime`` itself for anything that is not a directory.

    Finding #29: raw ``os.utime(f, times)`` defaults to
    ``follow_symlinks=True``, so a symlink preserved in the dump (copytree
    uses ``symlinks=True``) whose target lives outside ``root`` had its
    *target's* mtime rewritten to the normalization epoch -- corrupting
    timestamps on an arbitrary host file. Never following symlinks (for
    both files and directories) closes that hole.
    """
    try:
        if path.is_symlink():
            return False
        if not path.is_dir():
            return safe_utime(path, root, times)
        if resolve_within(path, root) is None:
            return False
        os.utime(path, times, follow_symlinks=False)
        return True
    except (OSError, NotImplementedError):
        return False


# Directories containing forensic artifacts — DELETE entire tree
FORENSIC_DIRECTORIES = {
    # Chrome/Chromium LevelDB stores
    "Local Storage/leveldb",
    "Session Storage",
    "IndexedDB",
    "Service Worker/CacheStorage",
    "Service Worker/ScriptCache",
    "GCM Store",
    "blob_storage",
    # Firefox equivalents
    "storage/default",
    "cache2",
    # iOS thumbnail caches
    "PhotoData/Thumbnails",
    "com.apple.photos.cpl.metadata",
    # macOS
    ".Spotlight-V100",
    ".fseventsd",
    ".Trashes",
    # Android
    "DCIM/.thumbnails",
    # Windows
    "Thumbcache",
    # General caches
    "__pycache__",
    ".cache/thumbnails",
}

# Individual files to delete
FORENSIC_FILES = {
    # macOS
    ".DS_Store",
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
    ".node_repl_history",
    ".irb_history",
    ".lesshst",
    ".sqlite_history",
    ".viminfo",
    ".wget-hsts",
    # Windows swap/hibernation
    "pagefile.sys",
    "swapfile.sys",
    "hiberfil.sys",
    # macOS swap
    "sleepimage",
    # Firefox session
    "sessionstore.jsonlz4",
    "sessionstore-backups",
    # Chrome
    "Visited Links",
    "Current Tabs",
    "Last Tabs",
    "Current Session",
    "Last Session",
    "Network Persistent State",
    "TransportSecurity",
}

FORENSIC_PATTERNS = [
    "*.ldb",
    "*.sst",
    "Thumbcache_*.db",
    "*.automaticDestinations-ms",
    "*.lnk",
    "*.pf",
    "*.evtx",
    "$I*",
    "$R*",
]


def sanitize_filesystem(dump_path: Path, dry_run: bool = False, normalize_timestamps: bool = False) -> list[dict]:
    actions = []

    # Delete forensic directories
    for forensic_dir in FORENSIC_DIRECTORIES:
        for found in dump_path.rglob(forensic_dir):
            rel = str(found.relative_to(dump_path))
            if found.is_symlink():
                # shutil.rmtree() refuses to operate on a symlink at all (it
                # raises, which ignore_errors=True then swallows), so nothing
                # is ever removed here. Finding #30: the code used to append
                # a "delete_forensic_dir" success action anyway -- a false
                # clean recorded for a store that was never touched. Refuse
                # up front instead of attempting and misreporting.
                actions.append({
                    "action": "delete_forensic_dir_failed",
                    "path": rel,
                    "error": "symlink - refused (rmtree would silently no-op; fail closed)",
                })
                log.warning(f"Forensic directory entry is a symlink, refusing to follow: {rel}")
                continue
            if found.is_dir():
                if dry_run:
                    actions.append({"action": "delete_forensic_dir", "path": rel, "dry_run": True})
                else:
                    shutil.rmtree(found, ignore_errors=True)
                    if found.exists():
                        # rmtree no-op'd for some other reason (e.g. a
                        # permission error swallowed by ignore_errors=True).
                        # Never claim success for a directory that is still
                        # there -- verify before recording the action.
                        actions.append({
                            "action": "delete_forensic_dir_failed",
                            "path": rel,
                            "error": "rmtree did not remove directory",
                        })
                        log.warning(f"Failed to delete forensic directory: {rel}")
                    else:
                        actions.append({"action": "delete_forensic_dir", "path": rel})
                        log.info(f"Deleted forensic directory: {rel}")

    # Delete forensic files
    for f in dump_path.rglob("*"):
        if not f.is_file():
            continue
        if f.name in FORENSIC_FILES:
            if dry_run:
                actions.append({"action": "delete_forensic_file", "path": str(f.relative_to(dump_path)), "dry_run": True})
            else:
                f.unlink(missing_ok=True)
                actions.append({"action": "delete_forensic_file", "path": str(f.relative_to(dump_path))})

    # Delete forensic file patterns
    for pattern in FORENSIC_PATTERNS:
        for f in dump_path.rglob(pattern):
            if f.is_file():
                if dry_run:
                    actions.append({"action": "delete_forensic_pattern", "path": str(f.relative_to(dump_path)), "dry_run": True})
                else:
                    f.unlink(missing_ok=True)
                    actions.append({"action": "delete_forensic_pattern", "path": str(f.relative_to(dump_path))})

    # Normalize timestamps
    if normalize_timestamps and not dry_run:
        epoch = 946684800  # 2000-01-01 00:00:00 UTC
        normalized = 0
        for f in dump_path.rglob("*"):
            if _safe_utime_any(f, dump_path, (epoch, epoch)):
                normalized += 1
        actions.append({"action": "normalize_timestamps", "files_normalized": normalized})
        log.info(f"Normalized timestamps on {normalized} files")

    log.info(f"Filesystem sanitization: {len(actions)} actions")
    return actions
