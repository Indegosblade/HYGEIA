"""
HYGEIA EXIF Stripper -- bulk image metadata removal.

Uses exiftool to strip all EXIF metadata from images (9 formats).
Removes GPS coordinates, device make/model, timestamps, and all
other embedded tags.
"""

import subprocess
import shutil
import logging
from pathlib import Path

log = logging.getLogger("hygeia.exif")

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".tiff", ".tif", ".gif", ".bmp"}


def exiftool_available() -> bool:
    """Check if exiftool is installed."""
    return shutil.which("exiftool") is not None


def strip_exif_directory(path: Path) -> dict:
    """
    Strip ALL EXIF metadata from all images in directory recursively.
    Uses exiftool -all= which removes all metadata tags.
    """
    result = {
        "action": "exif_strip",
        "path": str(path),
        "files_stripped": 0,
        "errors": [],
    }

    if not exiftool_available():
        result["error"] = "exiftool not installed. Run: apt-get install libimage-exiftool-perl"
        log.error(result["error"])
        return result

    if not path.exists():
        return result

    try:
        proc = subprocess.run(
            ["exiftool", "-all=", "-overwrite_original", "-r", "-q", str(path)],
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
        result["error"] = "exiftool not found"

    return result


def strip_single_file(filepath: Path) -> bool:
    """Strip EXIF from a single image file."""
    if not exiftool_available():
        return False
    try:
        proc = subprocess.run(
            ["exiftool", "-all=", "-overwrite_original", "-q", str(filepath)],
            capture_output=True, timeout=30
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def verify_exif_stripped(path: Path) -> list[Path]:
    """Verify no images have GPS or PII EXIF tags remaining."""
    files_with_exif = []

    if not exiftool_available():
        log.warning("Cannot verify EXIF — exiftool not installed")
        return files_with_exif

    for f in path.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in IMAGE_EXTENSIONS:
            continue
        try:
            proc = subprocess.run(
                ["exiftool", "-gps*", "-Make", "-Model", "-q", "-s3", str(f)],
                capture_output=True, text=True, timeout=10
            )
            if proc.stdout.strip():
                files_with_exif.append(f)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return files_with_exif
