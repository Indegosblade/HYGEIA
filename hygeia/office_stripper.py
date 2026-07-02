"""
HYGEIA Office Stripper -- metadata removal for Office and ODF documents.

.docx / .xlsx / .pptx are ZIP files containing XML. PII lives in:
  - docProps/core.xml     (dc:creator, cp:lastModifiedBy, dc:description, ...)
  - docProps/app.xml      (Application, Company, Manager, ...)
  - docProps/custom.xml   (arbitrary custom properties -- usernames, paths, ...)
  - word/document.xml     (w:author on w:ins/w:del tracked-changes markup)
  - word/comments.xml     (w:author / w:initials on comments)
  - word/people.xml       (w15:author -- reviewer identities)

.odt / .ods / .odp (OpenDocument Format) store metadata in:
  - meta.xml              (dc:creator, meta:initial-creator, dc:title, ...)

Simple metadata parts (core.xml/app.xml/meta.xml) are parsed with a hardened
xml.etree.ElementTree wrapper (``_safe_fromstring``) that refuses DTDs so a
malicious document cannot mount an entity-expansion (billion-laughs) DoS.

The tracked-changes / comment / custom-property parts carry namespace prefixes
(``w:``, ``w15:``, ``vt:``) whose *values* elsewhere reference those prefixes,
so they are edited with targeted byte-level regexes rather than re-serialised
through ElementTree (which would rename prefixes and can corrupt the part).
Byte-level editing is also inherently immune to entity expansion.

Every in-place ZIP rewrite is gated on ``is_safe_regular_file`` so a symlink
preserved inside the dump cannot redirect the write onto a file outside the
sanitized output tree (path-traversal write).
"""

import io
import logging
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .utils import is_safe_regular_file

log = logging.getLogger("hygeia.office_stripper")

OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}

# Upper bound on the *uncompressed* size of any single XML part we will read /
# parse. Protects against zip-decompression bombs and pathological XML. Real
# metadata parts are a few KB; document.xml is at most a few MB.
_MAX_XML_BYTES = 32 * 1024 * 1024

# A DOCTYPE is the only way to declare custom XML entities. Legitimate OOXML/ODF
# parts never contain one, so any DTD in untrusted input is treated as hostile.
_DOCTYPE_RE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)

# ---------------------------------------------------------------------------
# XML namespace registrations (prevents ns0: prefixes on re-serialisation)
# ---------------------------------------------------------------------------

_NAMESPACES = {
    # core.xml
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "dcmitype": "http://purl.org/dc/dcmitype/",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    # app.xml
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
    # ODF meta.xml
    "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
    "meta": "urn:oasis:names:tc:opendocument:xmlns:meta:1.0",
    "xlink": "http://www.w3.org/1999/xlink",
    "grddl": "http://www.w3.org/2003/g/data-view#",
}

for _prefix, _uri in _NAMESPACES.items():
    ET.register_namespace(_prefix, _uri)


def _safe_fromstring(xml_bytes: bytes) -> ET.Element:
    """Parse XML while refusing DTDs (entity-expansion / billion-laughs guard).

    Python's ElementTree is backed by expat, which expands internal general
    entities declared in a DTD -- the classic billion-laughs amplification that
    can exhaust memory from a tiny input. Office/ODF metadata parts never carry
    a DOCTYPE, so we reject any input that does rather than feed it to expat.
    Raises ``ET.ParseError`` (fail closed) instead of parsing hostile XML.
    """
    if len(xml_bytes) > _MAX_XML_BYTES:
        raise ET.ParseError("XML part exceeds safe size limit")
    if _DOCTYPE_RE.search(xml_bytes):
        raise ET.ParseError("XML DTD/DOCTYPE not permitted (entity-expansion guard)")
    return ET.fromstring(xml_bytes)


# ---------------------------------------------------------------------------
# OOXML (core.xml / app.xml) helpers
# ---------------------------------------------------------------------------

# Tags in core.xml that may contain PII
_CORE_PII_TAGS = {
    "{http://purl.org/dc/elements/1.1/}creator",
    "{http://purl.org/dc/elements/1.1/}description",
    "{http://purl.org/dc/elements/1.1/}subject",
    "{http://purl.org/dc/elements/1.1/}title",
    "{http://purl.org/dc/elements/1.1/}language",
    "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}lastModifiedBy",
    "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}lastPrinted",
    "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}keywords",
    "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}category",
    "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}contentStatus",
    "{http://purl.org/dc/terms/}created",
    "{http://purl.org/dc/terms/}modified",
}

# Tags in app.xml that may contain PII
_APP_PII_TAGS = {
    "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Application",
    "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Company",
    "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Manager",
    "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}AppVersion",
    "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Template",
    "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}HyperlinkBase",
}

# Tags in ODF meta.xml that may contain PII
_ODF_META_PII_TAGS = {
    "{http://purl.org/dc/elements/1.1/}creator",
    "{http://purl.org/dc/elements/1.1/}description",
    "{http://purl.org/dc/elements/1.1/}subject",
    "{http://purl.org/dc/elements/1.1/}title",
    "{http://purl.org/dc/elements/1.1/}language",
    "{urn:oasis:names:tc:opendocument:xmlns:meta:1.0}initial-creator",
    "{urn:oasis:names:tc:opendocument:xmlns:meta:1.0}printed-by",
    "{urn:oasis:names:tc:opendocument:xmlns:meta:1.0}creation-date",
    "{urn:oasis:names:tc:opendocument:xmlns:meta:1.0}date",
    "{urn:oasis:names:tc:opendocument:xmlns:meta:1.0}editing-duration",
    "{urn:oasis:names:tc:opendocument:xmlns:meta:1.0}generator",
    "{urn:oasis:names:tc:opendocument:xmlns:meta:1.0}keyword",
}

# OOXML parts whose *author identity* is carried in element attributes.
# These reviewer/author names (tracked changes, comments, people store) are a
# well-known Office PII leak vector ignored by core.xml/app.xml stripping.
_OOXML_ATTR_PARTS = ("word/document.xml", "word/comments.xml", "word/people.xml")

# docProps/custom.xml -- arbitrary custom document properties (values regularly
# hold usernames, file paths, matter numbers).
_OOXML_CUSTOM_PART = "docProps/custom.xml"

# Person-identifying attributes on tracked-changes / comment / people markup.
# The wordprocessingml namespace is conventionally bound to ``w`` and the 2012
# extensions to ``w15`` in every real-world .docx; we blank the *value* of these
# attributes (length of the file changes but the ZIP is rebuilt anyway).
_PERSON_ATTR_RE = re.compile(rb'\b((?:w15|w):(?:author|initials|userId))="([^"]*)"')

# Leaf value elements inside docProps/custom.xml, e.g. <vt:lpwstr>Jane</vt:lpwstr>.
_CUSTOM_VALUE_RE = re.compile(rb"(<vt:[A-Za-z0-9]+(?:\s[^>]*)?>)([^<]+)(</vt:[A-Za-z0-9]+>)")


def _blank_xml_tags(xml_bytes: bytes, pii_tags: set) -> tuple[bytes, int]:
    """
    Parse xml_bytes, set text of all matching tags to empty string.

    Returns (modified_bytes, count_of_blanked_tags).
    Raises ET.ParseError on malformed XML or on a rejected DTD.
    """
    root = _safe_fromstring(xml_bytes)
    count = 0
    for elem in root.iter():
        if elem.tag in pii_tags and elem.text:
            elem.text = ""
            count += 1
    # Re-serialise preserving the XML declaration if present
    declaration = b""
    if xml_bytes.lstrip().startswith(b"<?xml"):
        end = xml_bytes.index(b"?>") + 2
        declaration = xml_bytes[:end] + b"\n"
    new_bytes = declaration + ET.tostring(root, encoding="unicode").encode("utf-8")
    return new_bytes, count


def _blank_person_attrs_bytes(xml_bytes: bytes) -> tuple[bytes, int]:
    """Blank person-identifying attribute values (w:author, w:initials,
    w15:author, ...) in a WordprocessingML part.

    Operates on raw bytes so the surrounding markup -- including mc:Ignorable
    prefix lists that reference ``w``/``w15`` -- is preserved byte-for-byte.
    Returns (modified_bytes, count_of_non_empty_values_blanked).
    """
    count = 0

    def _repl(m: "re.Match[bytes]") -> bytes:
        nonlocal count
        if m.group(2):  # only count when there was a real value to remove
            count += 1
        return m.group(1) + b'=""'

    return _PERSON_ATTR_RE.sub(_repl, xml_bytes), count


def _blank_custom_props_bytes(xml_bytes: bytes) -> tuple[bytes, int]:
    """Blank the text of custom-property value elements in docProps/custom.xml.

    Returns (modified_bytes, count_of_values_blanked).
    """
    count = 0

    def _repl(m: "re.Match[bytes]") -> bytes:
        nonlocal count
        if m.group(2).strip():
            count += 1
        return m.group(1) + m.group(3)

    return _CUSTOM_VALUE_RE.sub(_repl, xml_bytes), count


def _rewrite_zip_entries(
    src_path: Path,
    updates: dict[str, bytes],
    dump_root: Path,
) -> None:
    """
    Rewrite one or more entries in a ZIP file in-place.

    Reads all entries, replaces the bytes for each name in ``updates``, writes
    back. Preserves the compression method of untouched entries.

    The write is gated on ``is_safe_regular_file(src_path, dump_root)``: if
    ``src_path`` is a symlink (or resolves outside ``dump_root``) the rewrite is
    refused with ``OSError`` so a crafted link in the dump cannot truncate a file
    on the operator's host. Raising surfaces as a stripper error (fail closed).
    """
    if not is_safe_regular_file(src_path, dump_root):
        raise OSError(
            f"refusing in-place ZIP rewrite of unsafe path "
            f"(symlink or outside dump root): {src_path}"
        )

    entries: dict[str, tuple[bytes, int]] = {}
    with zipfile.ZipFile(src_path, "r") as zf:
        for info in zf.infolist():
            with zf.open(info) as f:
                entries[info.filename] = (f.read(), info.compress_type)

    for name, content in updates.items():
        entries[name] = (content, zipfile.ZIP_DEFLATED)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf_out:
        for name, (content, compress_type) in entries.items():
            zf_out.writestr(
                zipfile.ZipInfo(name),
                content,
                compress_type=compress_type,
            )
    src_path.write_bytes(buf.getvalue())


def _read_ooxml_parts(doc_path: Path, wanted: list[str]) -> tuple[dict[str, bytes], list[str]]:
    """Read the requested ZIP entries, refusing oversized (bomb) parts.

    Returns (raw_bytes_by_entry, errors). A ``zipfile.BadZipFile`` propagates
    to the caller via the returned errors list is NOT used here; the caller
    handles the not-a-zip case separately.
    """
    raw: dict[str, bytes] = {}
    errors: list[str] = []
    with zipfile.ZipFile(doc_path, "r") as zf:
        names = set(zf.namelist())
        for entry in wanted:
            if entry not in names:
                continue
            info = zf.getinfo(entry)
            if info.file_size > _MAX_XML_BYTES:
                errors.append(
                    f"{entry}: uncompressed size {info.file_size} exceeds safe "
                    f"limit; not processed"
                )
                continue
            raw[entry] = zf.read(entry)
    return raw, errors


def _strip_ooxml_metadata(doc_path: Path, dump_root: Path) -> tuple[int, list[str]]:
    """
    Strip PII from an OOXML file: core.xml, app.xml, custom.xml, and the
    tracked-changes / comment / people author attributes in the document body.

    Returns (total_fields_blanked, list_of_errors).
    """
    total = 0
    tag_text_parts = [
        ("docProps/core.xml", _CORE_PII_TAGS),
        ("docProps/app.xml", _APP_PII_TAGS),
    ]
    wanted = (
        [e for e, _ in tag_text_parts]
        + list(_OOXML_ATTR_PARTS)
        + [_OOXML_CUSTOM_PART]
    )

    try:
        raw, errors = _read_ooxml_parts(doc_path, wanted)
    except zipfile.BadZipFile as exc:
        return 0, [f"Not a valid ZIP/OOXML file: {exc}"]

    updates: dict[str, bytes] = {}

    # core.xml / app.xml -- tag-text blanking via hardened ElementTree
    for entry, pii_tags in tag_text_parts:
        if entry not in raw:
            continue
        try:
            new_xml, count = _blank_xml_tags(raw[entry], pii_tags)
            if count > 0:
                updates[entry] = new_xml
                total += count
        except ET.ParseError as exc:
            errors.append(f"{entry}: XML parse error: {exc}")

    # document.xml / comments.xml / people.xml -- author attribute blanking
    for entry in _OOXML_ATTR_PARTS:
        if entry not in raw:
            continue
        new_xml, count = _blank_person_attrs_bytes(raw[entry])
        if count > 0:
            updates[entry] = new_xml
            total += count

    # custom.xml -- custom-property value blanking
    if _OOXML_CUSTOM_PART in raw:
        new_xml, count = _blank_custom_props_bytes(raw[_OOXML_CUSTOM_PART])
        if count > 0:
            updates[_OOXML_CUSTOM_PART] = new_xml
            total += count

    if updates:
        try:
            _rewrite_zip_entries(doc_path, updates, dump_root)
        except (OSError, zipfile.BadZipFile) as exc:
            errors.append(f"zip rewrite failed: {exc}")
            # Nothing was safely written -- report zero blanked, fail closed.
            return 0, errors

    return total, errors


def _strip_odf_metadata(doc_path: Path, dump_root: Path) -> tuple[int, list[str]]:
    """
    Strip PII from meta.xml inside an ODF file.

    Returns (total_fields_blanked, list_of_errors).
    """
    errors: list[str] = []

    try:
        with zipfile.ZipFile(doc_path, "r") as zf:
            if "meta.xml" not in zf.namelist():
                return 0, []
            if zf.getinfo("meta.xml").file_size > _MAX_XML_BYTES:
                return 0, ["meta.xml: uncompressed size exceeds safe limit; not processed"]
            xml_bytes = zf.read("meta.xml")
    except zipfile.BadZipFile as exc:
        return 0, [f"Not a valid ZIP/ODF file: {exc}"]

    try:
        new_xml, count = _blank_xml_tags(xml_bytes, _ODF_META_PII_TAGS)
        if count > 0:
            _rewrite_zip_entries(doc_path, {"meta.xml": new_xml}, dump_root)
            log.debug(f"{doc_path.name}/meta.xml: {count} fields blanked")
            return count, errors
    except ET.ParseError as exc:
        errors.append(f"meta.xml: XML parse error: {exc}")
    except (OSError, zipfile.BadZipFile) as exc:
        errors.append(f"meta.xml: {exc}")

    return 0, errors


def strip_office_metadata(doc_path: Path, dump_root: Path | None = None) -> dict:
    """
    Strip metadata from a single Office or ODF document.

    ``dump_root`` is the sanitized output tree; in-place ZIP rewrites are refused
    for any ``doc_path`` that is a symlink or resolves outside it. When omitted it
    defaults to ``doc_path.parent`` (which still rejects a symlinked ``doc_path``).

    Returns an action dict with keys:
        action, path, format, fields_blanked, success, [errors]
    """
    result: dict = {
        "action": "strip_office_metadata",
        "path": str(doc_path),
        "fields_blanked": 0,
        "success": False,
        "errors": [],
    }

    root = dump_root if dump_root is not None else doc_path.parent

    ext = doc_path.suffix.lower()
    if ext not in OFFICE_EXTENSIONS:
        result["errors"].append(f"Unsupported extension: {ext}")
        return result

    is_odf = ext in {".odt", ".ods", ".odp"}
    result["format"] = "odf" if is_odf else "ooxml"

    if is_odf:
        blanked, errors = _strip_odf_metadata(doc_path, root)
    else:
        blanked, errors = _strip_ooxml_metadata(doc_path, root)

    result["fields_blanked"] = blanked
    result["errors"] = errors
    result["success"] = not errors

    if blanked:
        log.info(f"Office metadata stripped from {doc_path.name}: {blanked} fields blanked")
    else:
        log.debug(f"Office metadata: no PII fields found in {doc_path.name}")

    return result


def strip_office_directory(path: Path) -> dict:
    """
    Strip Office/ODF metadata from all matching files under path recursively.

    ``path`` is treated as the dump root: any Office-suffixed entry that is a
    symlink (or otherwise not a regular file within ``path``) is skipped and
    surfaced in ``errors`` rather than followed, so a crafted link in the dump
    cannot make an in-place rewrite land on a host file outside the tree.

    Returns a summary dict:
        action, path, files_processed, files_modified, errors
    """
    result: dict = {
        "action": "strip_office_metadata_directory",
        "path": str(path),
        "files_processed": 0,
        "files_modified": 0,
        "errors": [],
    }

    if not path.exists():
        return result

    for f in path.rglob("*"):
        if f.suffix.lower() not in OFFICE_EXTENSIONS:
            continue
        if not is_safe_regular_file(f, path):
            # Do NOT follow: a symlink here could point outside the dump. Surface
            # it so an unfollowed Office file is never mistaken for "clean".
            result["errors"].append(
                f"{f.name}: skipped unsafe path (symlink or outside dump); not sanitized"
            )
            continue
        action = strip_office_metadata(f, dump_root=path)
        result["files_processed"] += 1
        if action.get("success") and action.get("fields_blanked", 0) > 0:
            result["files_modified"] += 1
        result["errors"].extend(action.get("errors", []))

    log.info(
        f"Office metadata stripping: {result['files_processed']} files processed, "
        f"{result['files_modified']} modified"
    )
    return result
