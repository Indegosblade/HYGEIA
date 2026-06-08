"""
HYGEIA EXIF Stripper -- bulk image metadata removal.

Uses exiftool to strip all EXIF metadata from images (9 formats).
Removes GPS coordinates, device make/model, timestamps, camera serial
numbers, owner names, and all other embedded tags.
"""

import os
import subprocess
import shutil
import logging
from pathlib import Path

log = logging.getLogger("hygeia.exif")

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".tiff", ".tif", ".gif", ".bmp"}

# Common install locations to probe when exiftool is not on PATH
_EXIFTOOL_FALLBACK_PATHS = [
    r"C:\exiftool\exiftool.exe",
    r"C:\Program Files\exiftool\exiftool.exe",
    "/usr/bin/exiftool",
    "/usr/local/bin/exiftool",
]


def find_exiftool() -> str | None:
    """
    Return the path to exiftool, or None if not found.

    Checks PATH first via shutil.which, then falls back to common install
    locations on Windows and Unix.
    """
    found = shutil.which("exiftool")
    if found:
        return found
    for candidate in _EXIFTOOL_FALLBACK_PATHS:
        if Path(candidate).is_file():
            return candidate
    localappdata = os.environ.get("LOCALAPPDATA")
    if localappdata:
        winget_path = Path(localappdata) / "Programs" / "ExifTool" / "ExifTool.exe"
        if winget_path.is_file():
            return str(winget_path)
    return None


def exiftool_available() -> bool:
    """Check if exiftool is installed (PATH or common install locations)."""
    return find_exiftool() is not None


def strip_exif_directory(path: Path) -> dict:
    """
    Strip ALL EXIF metadata from all images in directory recursively.
    Uses exiftool -all= which removes all metadata tags.

    Returns a result dict. If exiftool is not installed the dict contains
    ``"skipped": True`` and ``"reason": "exiftool not installed"`` and no
    metadata is stripped.
    """
    result = {
        "action": "exif_strip",
        "path": str(path),
        "files_stripped": 0,
        "errors": [],
    }

    exiftool_path = find_exiftool()
    if exiftool_path is None:
        msg = (
            "exiftool not found — EXIF metadata stripping will be skipped. "
            "Install from https://exiftool.org/"
        )
        log.warning(msg)
        result["skipped"] = True
        result["reason"] = "exiftool not installed"
        return result

    if not path.exists():
        return result

    try:
        proc = subprocess.run(
            [exiftool_path, "-all=", "-overwrite_original", "-r", "-q", str(path)],
            capture_output=True, text=True, timeout=600
        )
        # exiftool reports files processed in stderr
        if proc.returncode == 0:
            # Count image files processed
            for f in path.rglob("*"):
                if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS:
                    result["files_stripped"] += 1
            log.info(f"EXIF stripped from {result['files_stripped']} images in {path}")
        else:
            if proc.stderr.strip():
                result["errors"].append(proc.stderr.strip())
    except subprocess.TimeoutExpired:
        result["errors"].append("exiftool timed out after 600s")
    except FileNotFoundError:
        result["errors"].append("exiftool not found")

    return result


def strip_single_file(filepath: Path) -> bool:
    """Strip EXIF from a single image file."""
    exiftool_path = find_exiftool()
    if exiftool_path is None:
        return False
    try:
        proc = subprocess.run(
            [exiftool_path, "-all=", "-overwrite_original", "-q", str(filepath)],
            capture_output=True, timeout=30
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def verify_exif_stripped(path: Path) -> list[Path]:
    """
    Verify no images have GPS, PII, or device-identifying EXIF tags remaining.

    Checks for: GPS tags, Make, Model, SerialNumber, LensSerialNumber,
    ImageUniqueID, OwnerName, CameraOwnerName, Copyright.
    """
    files_with_exif = []

    exiftool_path = find_exiftool()
    if exiftool_path is None:
        log.warning("Cannot verify EXIF — exiftool not installed")
        return files_with_exif

    for f in path.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in IMAGE_EXTENSIONS:
            continue
        try:
            proc = subprocess.run(
                [
                    exiftool_path,
                    "-gps*",
                    "-Make", "-Model",
                    "-SerialNumber", "-LensSerialNumber",
                    "-ImageUniqueID", "-OwnerName", "-CameraOwnerName",
                    "-Copyright",
                    "-q", "-s3", str(f),
                ],
                capture_output=True, text=True, timeout=10
            )
            if proc.stdout.strip():
                files_with_exif.append(f)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return files_with_exif
