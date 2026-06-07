"""
HYGEIA Office Stripper -- metadata removal for Office and ODF documents.

.docx / .xlsx / .pptx are ZIP files containing XML. PII lives in:
  - docProps/core.xml  (dc:creator, cp:lastModifiedBy, dc:description, ...)
  - docProps/app.xml   (Application, Company, Manager, ...)

.odt / .ods / .odp (OpenDocument Format) store metadata in:
  - meta.xml           (dc:creator, meta:initial-creator, dc:title, ...)

All three use the same strategy: open the ZIP, parse XML with
xml.etree.ElementTree, blank the PII fields, rewrite the ZIP in-place.
"""

import io
import logging
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

log = logging.getLogger("hygeia.office_stripper")

OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}

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


def _blank_xml_tags(xml_bytes: bytes, pii_tags: set) -> tuple[bytes, int]:
    """
    Parse xml_bytes, set text of all matching tags to empty string.

    Returns (modified_bytes, count_of_blanked_tags).
    Raises ET.ParseError on malformed XML.
    """
    root = ET.fromstring(xml_bytes)
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


def _rewrite_zip_entry(
    src_path: Path,
    entry_name: str,
    new_content: bytes,
) -> None:
    """
    Rewrite a single entry in a ZIP file in-place.

    Reads all entries, replaces the bytes for entry_name, writes back.
    Preserves compression method and all other entries unchanged.
    """
    entries: dict[str, tuple[bytes, int]] = {}
    with zipfile.ZipFile(src_path, "r") as zf:
        for info in zf.infolist():
            with zf.open(info) as f:
                entries[info.filename] = (f.read(), info.compress_type)

    entries[entry_name] = (new_content, zipfile.ZIP_DEFLATED)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf_out:
        for name, (content, compress_type) in entries.items():
            zf_out.writestr(
                zipfile.ZipInfo(name),
                content,
                compress_type=compress_type,
            )
    src_path.write_bytes(buf.getvalue())


def _strip_ooxml_metadata(doc_path: Path) -> tuple[int, list[str]]:
    """
    Strip PII from docProps/core.xml and docProps/app.xml inside an OOXML file.

    Returns (total_fields_blanked, list_of_errors).
    """
    total = 0
    errors = []

    try:
        with zipfile.ZipFile(doc_path, "r") as zf:
            names = set(zf.namelist())
    except zipfile.BadZipFile as exc:
        return 0, [f"Not a valid ZIP/OOXML file: {exc}"]

    for entry, pii_tags in [
        ("docProps/core.xml", _CORE_PII_TAGS),
        ("docProps/app.xml", _APP_PII_TAGS),
    ]:
        if entry not in names:
            continue
        try:
            with zipfile.ZipFile(doc_path, "r") as zf:
                xml_bytes = zf.read(entry)
            new_xml, count = _blank_xml_tags(xml_bytes, pii_tags)
            if count > 0:
                _rewrite_zip_entry(doc_path, entry, new_xml)
                total += count
                log.debug(f"{doc_path.name}/{entry}: {count} fields blanked")
        except ET.ParseError as exc:
            errors.append(f"{entry}: XML parse error: {exc}")
        except (OSError, zipfile.BadZipFile) as exc:
            errors.append(f"{entry}: {exc}")

    return total, errors


def _strip_odf_metadata(doc_path: Path) -> tuple[int, list[str]]:
    """
    Strip PII from meta.xml inside an ODF file.

    Returns (total_fields_blanked, list_of_errors).
    """
    total = 0
    errors = []

    try:
        with zipfile.ZipFile(doc_path, "r") as zf:
            names = set(zf.namelist())
    except zipfile.BadZipFile as exc:
        return 0, [f"Not a valid ZIP/ODF file: {exc}"]

    if "meta.xml" not in names:
        return 0, []

    try:
        with zipfile.ZipFile(doc_path, "r") as zf:
            xml_bytes = zf.read("meta.xml")
        new_xml, count = _blank_xml_tags(xml_bytes, _ODF_META_PII_TAGS)
        if count > 0:
            _rewrite_zip_entry(doc_path, "meta.xml", new_xml)
            total += count
            log.debug(f"{doc_path.name}/meta.xml: {count} fields blanked")
    except ET.ParseError as exc:
        errors.append(f"meta.xml: XML parse error: {exc}")
    except (OSError, zipfile.BadZipFile) as exc:
        errors.append(f"meta.xml: {exc}")

    return total, errors


def strip_office_metadata(doc_path: Path) -> dict:
    """
    Strip metadata from a single Office or ODF document.

    Returns an action dict with keys:
        action, path, format, fields_blanked, success, [errors]
    """
    result = {
        "action": "strip_office_metadata",
        "path": str(doc_path),
        "fields_blanked": 0,
        "success": False,
        "errors": [],
    }

    ext = doc_path.suffix.lower()
    if ext not in OFFICE_EXTENSIONS:
        result["errors"].append(f"Unsupported extension: {ext}")
        return result

    is_odf = ext in {".odt", ".ods", ".odp"}
    result["format"] = "odf" if is_odf else "ooxml"

    if is_odf:
        blanked, errors = _strip_odf_metadata(doc_path)
    else:
        blanked, errors = _strip_ooxml_metadata(doc_path)

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

    Returns a summary dict:
        action, path, files_processed, files_modified, errors
    """
    result = {
        "action": "strip_office_metadata_directory",
        "path": str(path),
        "files_processed": 0,
        "files_modified": 0,
        "errors": [],
    }

    if not path.exists():
        return result

    for f in path.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in OFFICE_EXTENSIONS:
            continue
        action = strip_office_metadata(f)
        result["files_processed"] += 1
        if action.get("success") and action.get("fields_blanked", 0) > 0:
            result["files_modified"] += 1
        result["errors"].extend(action.get("errors", []))

    log.info(
        f"Office metadata stripping: {result['files_processed']} files processed, "
        f"{result['files_modified']} modified"
    )
    return result
