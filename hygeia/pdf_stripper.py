"""
HYGEIA PDF Stripper -- PDF metadata removal.

Strips Author, Creator, Producer, Title, Subject, Keywords, CreationDate,
and ModDate from PDF files. Uses exiftool if available (preferred), otherwise
falls back to a pure-Python stripper.

The pure-Python fallback removes PII from BOTH metadata carriers reachable
without a full PDF parser:
  - the plaintext ``/Info`` dictionary, and
  - the XMP metadata packet (``<x:xmpmeta>`` / ``<rdf:RDF>`` -- dc:creator,
    xmp:CreatorTool, GPS, xmpMM identifiers) -- edited length-preservingly so
    byte-offset cross-references stay valid.

Metadata can also hide inside a FlateDecode-compressed object stream (PDF 1.5+),
which a byte-level rewriter cannot reach. When such residual metadata is
detected the fallback reports ``success=False`` (fail closed) rather than
telling the operator the PDF is clean.

Every in-place rewrite is gated on ``is_safe_regular_file`` so a symlink
preserved in the dump cannot redirect the write onto a host file outside the
sanitized output tree.
"""

import logging
import re
import subprocess
import zlib
from pathlib import Path

from .exif_stripper import find_exiftool
from .utils import is_safe_regular_file

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

# ---------------------------------------------------------------------------
# XMP metadata packet stripping (length-preserving)
# ---------------------------------------------------------------------------

# Container properties whose values live in nested <rdf:li> elements.
_XMP_CONTAINER_TAGS = (
    b"dc:creator", b"dc:title", b"dc:description", b"dc:subject",
    b"dc:rights", b"dc:contributor", b"dc:publisher",
)

# Simple properties whose value is direct element text or a Description attribute.
_XMP_SIMPLE_TAGS = (
    b"xmp:CreatorTool", b"xmp:Author",
    b"pdf:Author", b"pdf:Keywords", b"pdf:Producer", b"pdf:Creator",
    b"pdf:Title", b"pdf:Subject",
    b"xmpMM:DocumentID", b"xmpMM:InstanceID", b"xmpMM:OriginalDocumentID",
    b"photoshop:AuthorsPosition", b"photoshop:CaptionWriter", b"photoshop:Credit",
    b"exif:GPSLatitude", b"exif:GPSLongitude", b"exif:GPSAltitude",
)

_TEXT_NODE_RE = re.compile(rb"(>)([^<]*)(<)")

# FlateDecode stream body: bytes between `stream`\n and \n`endstream`.
_FLATE_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)

# Strings whose presence in a *decompressed* stream means metadata is hiding in
# a compressed object we cannot rewrite in place.
_COMPRESSED_METADATA_INDICATORS = (
    b"<x:xmpmeta", b"<rdf:RDF", b"dc:creator", b"xmp:CreatorTool",
    b"GPSLatitude", b"GPSLongitude",
    b"/Author", b"/Producer", b"/Creator", b"/Title", b"/Keywords",
    b"/CreationDate", b"/ModDate",
)


def _blank_text_nodes(region: bytes) -> tuple[bytes, int]:
    """Replace every text node in ``region`` with equal-length spaces.

    Preserves total byte length (so a PDF's xref offsets stay valid) while
    erasing the character data inside nested elements. Returns
    (new_region, count_of_non_empty_text_nodes_blanked).
    """
    count = 0

    def _repl(m: "re.Match[bytes]") -> bytes:
        nonlocal count
        text = m.group(2)
        if text.strip():
            count += 1
        return m.group(1) + b" " * len(text) + m.group(3)

    return _TEXT_NODE_RE.sub(_repl, region), count


def _blank_xmp_metadata(data: bytes) -> tuple[bytes, int]:
    """Blank sensitive fields inside any XMP packet in ``data``.

    All replacements pad with spaces to preserve byte length, so the edit is
    safe to splice back into a PDF without breaking cross-reference offsets.
    Returns (new_data, count_of_values_blanked).
    """
    total = 0

    # 1. Container properties: blank the text nodes inside (rdf:li values),
    #    keeping the rdf:Seq/Alt/Bag structure intact.
    for tag in _XMP_CONTAINER_TAGS:
        pat = re.compile(
            rb"(<" + re.escape(tag) + rb"(?:\s[^>]*)?>)(.*?)(</" + re.escape(tag) + rb">)",
            re.DOTALL,
        )

        def _repl_container(m: "re.Match[bytes]") -> bytes:
            nonlocal total
            inner, c = _blank_text_nodes(m.group(2))
            total += c
            return m.group(1) + inner + m.group(3)

        data = pat.sub(_repl_container, data)

    # 2. Simple properties expressed as elements: <tag>value</tag>.
    for tag in _XMP_SIMPLE_TAGS:
        pat = re.compile(
            rb"(<" + re.escape(tag) + rb"(?:\s[^>]*)?>)([^<]*)(</" + re.escape(tag) + rb">)"
        )

        def _repl_elem(m: "re.Match[bytes]") -> bytes:
            nonlocal total
            val = m.group(2)
            if val.strip():
                total += 1
            return m.group(1) + b" " * len(val) + m.group(3)

        data = pat.sub(_repl_elem, data)

    # 3. Simple properties expressed as attributes on rdf:Description.
    for tag in _XMP_SIMPLE_TAGS:
        pat = re.compile(rb'(\b' + re.escape(tag) + rb'=")([^"]*)(")')

        def _repl_attr(m: "re.Match[bytes]") -> bytes:
            nonlocal total
            val = m.group(2)
            if val.strip():
                total += 1
            return m.group(1) + b" " * len(val) + m.group(3)

        data = pat.sub(_repl_attr, data)

    return data, total


def _detect_unreachable_pdf_metadata(data: bytes) -> str | None:
    """Return a reason string if PII metadata is present in a compressed object
    stream that the pure-Python rewriter cannot reach, else ``None``.

    PDF 1.5+ can store the /Info dictionary or the XMP packet inside a
    FlateDecode object stream (/ObjStm). A byte-level regex cannot see or edit
    those, so if we find metadata markers in a *decompressed* stream we must not
    claim the file was cleaned.
    """
    for m in _FLATE_STREAM_RE.finditer(data):
        raw = m.group(1)
        try:
            chunk = zlib.decompress(raw)
        except zlib.error:
            continue
        for indicator in _COMPRESSED_METADATA_INDICATORS:
            if indicator in chunk:
                return (
                    "residual metadata detected inside a compressed PDF object "
                    f"stream (marker {indicator.decode('latin-1')!r}); cannot be "
                    "stripped without exiftool"
                )
    return None


def _strip_pdf_info_pure_python(pdf_path: Path, dump_root: Path | None = None) -> bool:
    """
    Pure-Python PDF metadata stripper (plaintext /Info dict + XMP packet).

    Blanks /Info string values in place (padding to preserve length) and erases
    sensitive XMP fields, then rewrites the file. The write is gated on
    ``is_safe_regular_file`` so a symlinked ``pdf_path`` cannot redirect it onto
    a host file. ``dump_root`` defaults to ``pdf_path.parent`` (which still
    rejects a symlinked ``pdf_path``).

    Returns True if any replacements were made, False otherwise.
    Raises OSError on read/write failure or on a refused unsafe write.
    """
    root = dump_root if dump_root is not None else pdf_path.parent
    data = pdf_path.read_bytes()

    replacements_made = 0

    def _replace_match(m: "re.Match[bytes]") -> bytes:
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
    new_data, xmp_count = _blank_xmp_metadata(new_data)

    if replacements_made + xmp_count > 0:
        if not is_safe_regular_file(pdf_path, root):
            raise OSError(
                f"refusing in-place PDF rewrite of unsafe path "
                f"(symlink or outside dump root): {pdf_path}"
            )
        pdf_path.write_bytes(new_data)
        log.debug(
            f"{pdf_path.name}: {replacements_made} /Info + {xmp_count} XMP "
            f"fields cleared (pure-Python)"
        )
        return True

    log.debug(f"{pdf_path.name}: no plaintext /Info or XMP metadata found (pure-Python)")
    return False


def strip_pdf_metadata(pdf_path: Path, dump_root: Path | None = None) -> dict:
    """
    Strip metadata from a single PDF file.

    Tries exiftool first (more thorough, handles compressed streams too).
    Falls back to pure-Python /Info + XMP rewriting if exiftool is absent.

    ``dump_root`` is the sanitized output tree; any ``pdf_path`` that is a
    symlink or resolves outside it is refused (fail closed) rather than
    rewritten onto the host. When omitted it defaults to ``pdf_path.parent``.

    Returns an action dict with keys:
        action, path, method, success, [error]
    """
    result: dict = {
        "action": "strip_pdf_metadata",
        "path": str(pdf_path),
    }

    root = dump_root if dump_root is not None else pdf_path.parent
    if not is_safe_regular_file(pdf_path, root):
        result["method"] = "skipped"
        result["success"] = False
        result["error"] = (
            "unsafe path: symlink or outside dump root; not rewritten"
        )
        log.warning(f"Refusing to strip PDF via unsafe path: {pdf_path}")
        return result

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
        changed = _strip_pdf_info_pure_python(pdf_path, root)
        result["method"] = "pure_python"
        result["fields_modified"] = changed
    except OSError as exc:
        result["method"] = "pure_python"
        result["success"] = False
        result["error"] = str(exc)
        log.error(f"Failed to strip PDF metadata from {pdf_path}: {exc}")
        return result

    # Fail closed: if PII metadata survives in a compressed object stream we
    # could not reach, do NOT report the PDF clean.
    residual = _detect_unreachable_pdf_metadata(pdf_path.read_bytes())
    if residual is not None:
        result["success"] = False
        result["incomplete"] = True
        result["error"] = residual
        log.warning(f"{pdf_path.name}: {residual}")
        return result

    result["success"] = True
    return result


def strip_pdf_directory(path: Path) -> dict:
    """
    Strip PDF metadata from all .pdf files under path recursively.

    ``path`` is treated as the dump root: any .pdf that is a symlink (or
    otherwise not a regular file within ``path``) is skipped and surfaced in
    ``errors`` rather than followed onto a host file outside the tree.

    Returns a summary dict:
        action, path, files_processed, files_modified, errors
    """
    result: dict = {
        "action": "strip_pdf_metadata_directory",
        "path": str(path),
        "files_processed": 0,
        "files_modified": 0,
        "errors": [],
    }

    if not path.exists():
        return result

    for f in path.rglob("*"):
        if f.suffix.lower() not in PDF_EXTENSIONS:
            continue
        if not is_safe_regular_file(f, path):
            result["errors"].append(
                f"{f.name}: skipped unsafe path (symlink or outside dump); not sanitized"
            )
            continue
        action = strip_pdf_metadata(f, dump_root=path)
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
