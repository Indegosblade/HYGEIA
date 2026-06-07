"""
HYGEIA PDF Stripper -- PDF metadata removal.

Strips Author, Creator, Producer, Title, Subject, Keywords, CreationDate,
and ModDate from PDF files. Uses exiftool if available (preferred), otherwise
falls back to a pure-Python PDF /Info dictionary rewriter.
"""

import logging
import re
import subprocess
from pathlib import Path

from .exif_stripper import find_exiftool

log = logging.getLogger("hygeia.pdf_stripper")

PDF_EXTENSIONS = {".pdf"}

# PDF metadata keys to strip (used in both exiftool and pure-Python paths)
_PDF_INFO_KEYS = [
    "Author", "Creator", "Producer", "Title", "Subject",
    "Keywords", "CreationDate", "ModDate", "Trapped",
]

# Regex to match a PDF string value: either (literal string) or <hex string>
_PDF_STRING_RE = re.compile(
    rb'\((?:[^()\\]|\\.|\((?:[^()\\]|\\.)*\))*\)'  # balanced parentheses
    rb'|<[0-9A-Fa-f\s]*>'                           # hex string
)

# Regex to find /Key value pairs in a /Info dict.
# Matches: /KeyName followed by whitespace and a string value.
_INFO_ENTRY_RE = re.compile(
    rb'/(' + b'|'.join(k.encode() for k in _PDF_INFO_KEYS) + rb')'
    rb'(\s*)'
    rb'(' + _PDF_STRING_RE.pattern + rb')',
    re.DOTALL,
)


def _strip_pdf_info_pure_python(pdf_path: Path) -> bool:
    """
    Pure-Python PDF /Info metadata stripper.

    Reads the raw PDF bytes, finds all /Key (value) pairs in /Info
    dictionary entries and replaces their string values with empty strings.
    Rewrites the file in place.

    Returns True if any replacements were made, False otherwise.
    Raises OSError on read/write failure.
    """
    data = pdf_path.read_bytes()

    replacements_made = 0

    def _replace_match(m: re.Match) -> bytes:
        nonlocal replacements_made
        key = m.group(1)
        whitespace = m.group(2)
        original_value = m.group(3)
        # Preserve the length of the value field to avoid invalidating
        # byte-offset cross-references in the PDF.  Pad with spaces inside
        # the parentheses to maintain the same byte count.
        if original_value.startswith(b"(") and original_value.endswith(b")"):
            inner_len = len(original_value) - 2  # chars between ( and )
            replacement_value = b"(" + b" " * inner_len + b")"
        elif original_value.startswith(b"<") and original_value.endswith(b">"):
            # Hex string: replace with hex-encoded spaces
            inner_len = len(original_value) - 2
            # Even number of hex chars required; use "20" (space) pairs
            pairs = inner_len // 2
            replacement_value = b"<" + b"20" * pairs + b">"
            # Adjust length if odd
            if len(replacement_value) != len(original_value):
                replacement_value = b"<" + (b"2" * (inner_len)) + b">"
                if len(replacement_value) != len(original_value):
                    replacement_value = original_value  # can't safely replace hex
        else:
            replacement_value = original_value  # unknown format, skip

        if replacement_value != original_value:
            replacements_made += 1

        return b"/" + key + whitespace + replacement_value

    new_data = _INFO_ENTRY_RE.sub(_replace_match, data)

    if replacements_made > 0:
        pdf_path.write_bytes(new_data)
        log.debug(f"{pdf_path.name}: {replacements_made} metadata fields cleared (pure-Python)")
        return True

    log.debug(f"{pdf_path.name}: no /Info metadata found (pure-Python)")
    return False


def strip_pdf_metadata(pdf_path: Path) -> dict:
    """
    Strip metadata from a single PDF file.

    Tries exiftool first (more thorough, handles XMP streams too).
    Falls back to pure-Python /Info dict rewriting if exiftool is absent.

    Returns an action dict with keys:
        action, path, method, success, [error]
    """
    result = {
        "action": "strip_pdf_metadata",
        "path": str(pdf_path),
    }

    exiftool_path = find_exiftool()
    if exiftool_path is not None:
        try:
            proc = subprocess.run(
                [exiftool_path, "-all=", "-overwrite_original", "-q", str(pdf_path)],
                capture_output=True, timeout=30,
            )
            if proc.returncode == 0:
                result["method"] = "exiftool"
                result["success"] = True
                log.info(f"PDF metadata stripped via exiftool: {pdf_path.name}")
                return result
            else:
                stderr = proc.stderr.decode(errors="replace").strip()
                log.warning(f"exiftool returned {proc.returncode} for {pdf_path.name}: {stderr}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            log.warning(f"exiftool failed for {pdf_path.name}: {exc}")

    # Fall back to pure Python
    try:
        changed = _strip_pdf_info_pure_python(pdf_path)
        result["method"] = "pure_python"
        result["success"] = True
        result["fields_modified"] = changed
        return result
    except OSError as exc:
        result["method"] = "pure_python"
        result["success"] = False
        result["error"] = str(exc)
        log.error(f"Failed to strip PDF metadata from {pdf_path}: {exc}")
        return result


def strip_pdf_directory(path: Path) -> dict:
    """
    Strip PDF metadata from all .pdf files under path recursively.

    Returns a summary dict:
        action, path, files_processed, files_modified, errors
    """
    result = {
        "action": "strip_pdf_metadata_directory",
        "path": str(path),
        "files_processed": 0,
        "files_modified": 0,
        "errors": [],
    }

    if not path.exists():
        return result

    for f in path.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in PDF_EXTENSIONS:
            continue
        action = strip_pdf_metadata(f)
        result["files_processed"] += 1
        if action.get("success"):
            result["files_modified"] += 1
        elif "error" in action:
            result["errors"].append(f"{f.name}: {action['error']}")

    log.info(
        f"PDF metadata stripping: {result['files_processed']} files processed, "
        f"{result['files_modified']} modified"
    )
    return result
