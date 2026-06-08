"""
HYGEIA Forensic Cleaner -- anti-forensic hardening module.

Removes artifacts that survive standard file deletion and can be
recovered by forensic tools: LevelDB stores, thumbnail/browser caches,
swap/temp files, file-system timestamps, macOS quarantine xattrs,
crash reporter data, and clipboard history.
"""

import logging
import os
import platform
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from .utils import sha256 as _sha256


def _inside_deleted(p: Path, deleted_dirs: list) -> bool:
    """Check if path is inside any already-deleted directory."""
    for d in deleted_dirs:
        try:
            p.relative_to(d)
            return True
        except ValueError:
            pass
    return False

log = logging.getLogger("hygeia.forensic_cleaner")


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

    all_paths = sorted(dump_path.rglob("*"), key=lambda x: len(x.parts))
    for dirpath in all_paths:
        if not dirpath.is_dir():
            continue
        if _inside_deleted(dirpath, deleted_dirs):
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
        if _inside_deleted(fp, deleted_dirs):
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


# macOS quarantine / extended attribute cleanup

# xattrs that encode download provenance or quarantine state
_MACOS_TRACKING_XATTRS = (
    "com.apple.quarantine",
    "com.apple.metadata:kMDItemWhereFroms",
    "com.apple.metadata:kMDItemDownloadedDate",
)


def clean_quarantine_xattrs(dump_path, dry_run=False):
    """
    Detect and remove macOS quarantine / download-tracking xattrs.

    Only executes on Darwin (macOS). On all other platforms the function
    returns an empty action list immediately.

    Uses os.listxattr() / os.removexattr() from the stdlib (Python 3.3+,
    available on macOS and Linux).
    """
    actions = []

    if platform.system() != "Darwin":
        log.debug("clean_quarantine_xattrs: non-Darwin platform, skipping")
        return actions

    listxattr = getattr(os, "listxattr", None)
    removexattr = getattr(os, "removexattr", None)
    if listxattr is None or removexattr is None:
        log.debug("clean_quarantine_xattrs: os.listxattr/removexattr not available, skipping")
        return actions

    for fp in list(dump_path.rglob("*")):
        try:
            xattrs = listxattr(str(fp), follow_symlinks=False)
        except (OSError, ValueError):
            continue

        for xattr_name in xattrs:
            if xattr_name in _MACOS_TRACKING_XATTRS:
                rel = str(fp.relative_to(dump_path))
                if dry_run:
                    actions.append({
                        "action": "remove_xattr",
                        "path": rel,
                        "xattr": xattr_name,
                        "dry_run": True,
                    })
                else:
                    try:
                        removexattr(str(fp), xattr_name, follow_symlinks=False)
                        actions.append({
                            "action": "remove_xattr",
                            "path": rel,
                            "xattr": xattr_name,
                        })
                        log.info(f"Removed xattr {xattr_name} from {rel}")
                    except OSError as exc:
                        log.warning(f"Failed to remove xattr {xattr_name} from {rel}: {exc}")

    log.debug(f"Quarantine xattr cleanup: {len(actions)} xattrs processed")
    return actions


# NTFS Alternate Data Streams detection

def detect_ntfs_ads(dump_path):
    """
    Detect NTFS Alternate Data Streams (ADS) in dump_path.

    Only runs on Windows. Uses PowerShell Get-Item -Stream * to enumerate
    ADS on each file. Logs warnings for any ADS found.

    Returns a list of warning dicts (never deletes — removal requires
    platform-specific APIs and can corrupt files if done carelessly).
    """
    warnings = []

    if platform.system() != "Windows":
        log.debug("detect_ntfs_ads: non-Windows platform, skipping")
        return warnings

    # Use PowerShell to enumerate ADS. -ErrorAction SilentlyContinue suppresses
    # access-denied noise on system files we can't read.
    ps_script = (
        "Get-ChildItem -Path '{path}' -Recurse -ErrorAction SilentlyContinue | "
        "ForEach-Object {{ Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue }} | "
        "Where-Object {{ $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }} | "
        "Select-Object -ExpandProperty FileName"
    ).format(path=str(dump_path).replace("'", "''"))

    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rel = str(Path(line).relative_to(dump_path))
                except ValueError:
                    rel = line
                warnings.append({
                    "action": "ads_detected",
                    "path": rel,
                    "warning": "NTFS Alternate Data Stream found — manual review required",
                })
                log.warning(f"NTFS ADS detected: {rel}")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.debug(f"detect_ntfs_ads: PowerShell enumeration failed: {exc}")

    log.debug(f"NTFS ADS detection: {len(warnings)} streams found")
    return warnings


# Crash reporter data cleanup

_CRASH_REPORTER_DIR_NAMES_LOWER = frozenset({
    "diagnosticmessages",
    "crashreporter",
    "reportcrash",
    "diagnosticreports",
})
_CRASH_FILE_SUFFIXES = frozenset({".ips", ".crash"})


def clean_crash_reporter_data(dump_path, dry_run=False):
    """
    Find and delete crash reporter artifacts.

    Targets:
    - Directories named DiagnosticMessages/, CrashReporter/, ReportCrash/,
      DiagnosticReports/ (case-insensitive) anywhere in the tree
    - Files with .ips or .crash extensions
    - Library/Logs/DiagnosticReports/ path component

    These artifacts contain usernames, full file paths, and occasionally
    stack frames with sensitive variable values.
    """
    actions = []
    deleted_dirs: list = []

    # Walk directories first (sorted by depth so parents are processed before children)
    all_dirs = sorted(
        (p for p in dump_path.rglob("*") if p.is_dir()),
        key=lambda x: len(x.parts),
    )
    for dirpath in all_dirs:
        if _inside_deleted(dirpath, deleted_dirs):
            continue
        name_lower = dirpath.name.lower()
        rel_lower = str(dirpath.relative_to(dump_path)).replace("\\", "/").lower()

        is_crash_dir = (
            name_lower in _CRASH_REPORTER_DIR_NAMES_LOWER
            or "library/logs/diagnosticreports" in rel_lower
        )
        if not is_crash_dir:
            continue

        rel = str(dirpath.relative_to(dump_path))
        if dry_run:
            actions.append({"action": "delete_crash_reporter_dir", "path": rel, "dry_run": True})
        else:
            shutil.rmtree(dirpath, ignore_errors=True)
            deleted_dirs.append(dirpath)
            actions.append({"action": "delete_crash_reporter_dir", "path": rel})
            log.info(f"Deleted crash reporter dir: {rel}")

    # Then individual .ips / .crash files
    for fp in list(dump_path.rglob("*")):
        if not fp.is_file():
            continue
        if _inside_deleted(fp, deleted_dirs):
            continue
        if fp.suffix.lower() in _CRASH_FILE_SUFFIXES:
            rel = str(fp.relative_to(dump_path))
            if dry_run:
                actions.append({"action": "delete_crash_file", "path": rel, "dry_run": True})
            else:
                action = {"action": "delete_crash_file", "path": rel, "hash_before": _sha256(fp)}
                fp.unlink(missing_ok=True)
                actions.append(action)
                log.info(f"Deleted crash file: {rel}")

    log.debug(f"Crash reporter cleanup: {len(actions)} items found")
    return actions


# Clipboard history cleanup

def clean_clipboard_history(dry_run=False):
    """
    Delete platform clipboard history artifacts.

    Windows: %LOCALAPPDATA%\\Microsoft\\Windows\\Clipboard\\
    macOS:   ~/Library/Application Support/com.apple.UIKit.pboard/

    Returns a list of action dicts. Silently skips platforms that have
    neither location or where the paths do not exist.
    """
    actions = []
    system = platform.system()

    candidate_dirs: list = []

    if system == "Windows":
        localappdata = os.environ.get("LOCALAPPDATA")
        if localappdata:
            candidate_dirs.append(Path(localappdata) / "Microsoft" / "Windows" / "Clipboard")
    elif system == "Darwin":
        home = Path.home()
        candidate_dirs.append(
            home / "Library" / "Application Support" / "com.apple.UIKit.pboard"
        )
        # Also check the clipboard pasteboard persistence path on macOS 13+
        candidate_dirs.append(
            home / "Library" / "Application Support" / "com.apple.clipboarduseragent"
        )

    for clip_dir in candidate_dirs:
        if not clip_dir.exists():
            continue
        rel = str(clip_dir)
        if dry_run:
            actions.append({
                "action": "delete_clipboard_history",
                "path": rel,
                "dry_run": True,
            })
        else:
            # Remove contents but keep the directory itself (system may recreate it)
            deleted_items = 0
            for item in list(clip_dir.iterdir()):
                try:
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        item.unlink(missing_ok=True)
                    deleted_items += 1
                except OSError as exc:
                    log.warning(f"Failed to delete clipboard item {item}: {exc}")
            actions.append({
                "action": "delete_clipboard_history",
                "path": rel,
                "items_deleted": deleted_items,
            })
            log.info(f"Cleared clipboard history: {rel} ({deleted_items} items)")

    log.debug(f"Clipboard cleanup: {len(actions)} locations processed")
    return actions


def forensic_clean_all(dump_path, dry_run=False, workers=1):
    dump_path = Path(dump_path)
    prefix = "DRY RUN " if dry_run else ""
    log.info(f"forensic_clean_all: {prefix}{dump_path} (workers={workers})")

    # Resolve auto-detect
    resolved_workers = workers if workers != 0 else (os.cpu_count() or 1)

    # Scan/delete sub-tasks (all operate on dump_path, all independent)
    subtasks = [
        ("leveldb", clean_leveldb_stores),
        ("thumbnail_caches", clean_thumbnail_caches),
        ("swap_temp", clean_swap_temp_files),
        ("crash_reporter", clean_crash_reporter_data),
        ("quarantine_xattrs", clean_quarantine_xattrs),
    ]

    # Results keyed by subtask name so we can assemble in deterministic order
    subtask_results: dict = {}

    if resolved_workers > 1 and not dry_run:
        futures_map = {}
        with ThreadPoolExecutor(max_workers=min(resolved_workers, len(subtasks))) as executor:
            for name, fn in subtasks:
                future = executor.submit(fn, dump_path, dry_run)
                futures_map[future] = name
            completed = 0
            for future in as_completed(futures_map):
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

    # NTFS ADS detection (Windows only, detect-only — no deletion)
    actions.extend(detect_ntfs_ads(dump_path))

    # Clipboard history cleanup (platform-aware, operates outside dump_path)
    actions.extend(clean_clipboard_history(dry_run=dry_run))

    if not dry_run:
        actions.extend(normalize_timestamps(dump_path))

    return actions
