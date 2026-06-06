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

log = logging.getLogger("hygeia.filesystem")

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

# File patterns (glob) for forensic artifacts
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
            if found.is_dir():
                if dry_run:
                    actions.append({"action": "delete_forensic_dir", "path": str(found.relative_to(dump_path)), "dry_run": True})
                else:
                    shutil.rmtree(found, ignore_errors=True)
                    actions.append({"action": "delete_forensic_dir", "path": str(found.relative_to(dump_path))})
                    log.info(f"Deleted forensic directory: {found.relative_to(dump_path)}")

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
            try:
                os.utime(f, (epoch, epoch))
                normalized += 1
            except OSError:
                continue
        actions.append({"action": "normalize_timestamps", "files_normalized": normalized})
        log.info(f"Normalized timestamps on {normalized} files")

    log.info(f"Filesystem sanitization: {len(actions)} actions")
    return actions
