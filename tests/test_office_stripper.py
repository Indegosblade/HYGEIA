"""
Behavioural tests for hygeia.office_stripper covering audit findings:

  #10 / #35 -- tracked-changes authors, comment authors, word/people.xml
               reviewers and docProps/custom.xml values must be removed
               (they were previously ignored, leaving recoverable PII while the
               file was reported "success").
  #9        -- an in-place ZIP rewrite must be refused for a symlink preserved
               inside the dump, so it cannot overwrite a file on the host
               outside the sanitized output tree.
  billion-laughs -- ET.fromstring hardening: a DTD entity-expansion payload
               inside an Office XML part must fail closed, not exhaust memory.

Fixtures use only bogus/documentation values (example.com, reserved names).
"""

import io
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.office_stripper import (
    strip_office_metadata,
    strip_office_directory,
    _blank_xml_tags,
    _safe_fromstring,
    _CORE_PII_TAGS,
)

# WordprocessingML namespaces
_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_W15 = "http://schemas.microsoft.com/office/word/2012/wordml"
_CUSTOM = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
_VT = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"

# PII values embedded in the fixture -- all bogus. Each is unique so a survivor
# can be pinpointed to its part.
CORE_CREATOR = "Alice Author"
INS_AUTHOR = "Jane Inserter"
DEL_AUTHOR = "Mike Deleter"
COMMENT_AUTHOR = "Carol Commenter"
COMMENT_INITIALS = "CC"
PEOPLE_AUTHOR = "Dave People"
CUSTOM_VALUE = "Secret Matter 98765"

_ALL_NAMES = [
    CORE_CREATOR, INS_AUTHOR, DEL_AUTHOR, COMMENT_AUTHOR,
    PEOPLE_AUTHOR, CUSTOM_VALUE,
]


def _make_docx_with_authors(path: Path) -> Path:
    """A .docx carrying reviewer/author PII in every known Office carrier:
    core.xml, tracked changes (w:ins/w:del), comments, people store, custom
    properties.
    """
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '</Types>'
        ),
        "docProps/core.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties '
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            f'<dc:creator>{CORE_CREATOR}</dc:creator>'
            '</cp:coreProperties>'
        ),
        "word/document.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:document xmlns:w="{_W}"><w:body><w:p>'
            f'<w:ins w:id="1" w:author="{INS_AUTHOR}" w:date="2020-01-01T00:00:00Z">'
            '<w:r><w:t>added text</w:t></w:r></w:ins>'
            f'<w:del w:id="2" w:author="{DEL_AUTHOR}" w:date="2020-01-02T00:00:00Z">'
            '<w:r><w:delText>removed text</w:delText></w:r></w:del>'
            '</w:p></w:body></w:document>'
        ),
        "word/comments.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:comments xmlns:w="{_W}">'
            f'<w:comment w:id="1" w:author="{COMMENT_AUTHOR}" '
            f'w:date="2020-01-03T00:00:00Z" w:initials="{COMMENT_INITIALS}">'
            '<w:p><w:r><w:t>a review note</w:t></w:r></w:p></w:comment>'
            '</w:comments>'
        ),
        "word/people.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w15:people xmlns:w15="{_W15}" xmlns:w="{_W}">'
            f'<w15:person w15:author="{PEOPLE_AUTHOR}">'
            f'<w15:presenceInfo w15:providerId="None" w15:userId="{PEOPLE_AUTHOR}"/>'
            '</w15:person></w15:people>'
        ),
        "docProps/custom.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<Properties xmlns="{_CUSTOM}" xmlns:vt="{_VT}">'
            '<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Matter">'
            f'<vt:lpwstr>{CUSTOM_VALUE}</vt:lpwstr></property>'
            '</Properties>'
        ),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in parts.items():
            zf.writestr(name, content)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())
    return path


def _all_bytes(docx: Path) -> bytes:
    """Concatenate every entry's bytes so a survivor anywhere is caught."""
    out = bytearray()
    with zipfile.ZipFile(docx, "r") as zf:
        for name in zf.namelist():
            out += zf.read(name)
    return bytes(out)


def _read(docx: Path, entry: str) -> bytes:
    with zipfile.ZipFile(docx, "r") as zf:
        return zf.read(entry)


# ---------------------------------------------------------------------------
# #10 / #35 -- tracked changes / comments / people / custom properties
# ---------------------------------------------------------------------------

class TestAuthorAndCustomStripping:

    def test_all_author_names_removed(self, tmp_path):
        docx = _make_docx_with_authors(tmp_path / "report.docx")
        result = strip_office_metadata(docx, dump_root=tmp_path)

        assert result["success"] is True, result
        # core(1) + ins + del + comment author + comment initials + people
        # author + people userId + custom value  -> comfortably > 5
        assert result["fields_blanked"] >= 6

        blob = _all_bytes(docx)
        for name in _ALL_NAMES:
            assert name.encode() not in blob, f"{name!r} survived stripping"
        # Comment initials are PII too.
        assert b'w:initials="CC"' not in _read(docx, "word/comments.xml")

    def test_tracked_change_markup_preserved_only_author_blanked(self, tmp_path):
        docx = _make_docx_with_authors(tmp_path / "doc.docx")
        strip_office_metadata(docx, dump_root=tmp_path)

        document = _read(docx, "word/document.xml")
        # The tracked-change elements themselves must remain (we only blank the
        # author identity, not the edit); the file must still be a valid zip.
        assert b"w:ins" in document and b"w:del" in document
        assert b'w:author=""' in document
        assert INS_AUTHOR.encode() not in document
        assert zipfile.is_zipfile(docx)

    def test_people_userid_blanked(self, tmp_path):
        docx = _make_docx_with_authors(tmp_path / "p.docx")
        strip_office_metadata(docx, dump_root=tmp_path)
        people = _read(docx, "word/people.xml")
        assert PEOPLE_AUTHOR.encode() not in people
        assert b'w15:author=""' in people
        assert b'w15:userId=""' in people

    def test_custom_property_value_blanked_key_kept(self, tmp_path):
        docx = _make_docx_with_authors(tmp_path / "c.docx")
        strip_office_metadata(docx, dump_root=tmp_path)
        custom = _read(docx, "docProps/custom.xml")
        assert CUSTOM_VALUE.encode() not in custom
        # The property name/structure is retained, only the value emptied.
        assert b'name="Matter"' in custom
        assert b"<vt:lpwstr></vt:lpwstr>" in custom


# ---------------------------------------------------------------------------
# #9 -- symlink in the dump must not redirect the in-place rewrite onto a host
#       file outside the sanitized output tree.
# ---------------------------------------------------------------------------

class TestSymlinkTraversalWrite:

    def test_directory_skips_symlink_and_leaves_target_untouched(self, tmp_path):
        # A real Office doc OUTSIDE the dump, on the "host".
        host = tmp_path / "host"
        host.mkdir()
        external = _make_docx_with_authors(host / "quarterly.docx")
        before = external.read_bytes()

        # The dump the operator sanitizes.
        dump = tmp_path / "dump"
        dump.mkdir()
        (dump / "report.docx").symlink_to(external)

        result = strip_office_directory(dump)

        # The external file must be byte-for-byte unchanged (not truncated /
        # rewritten), and its PII must still be present -- proving we refused to
        # follow the link rather than silently overwriting the host file.
        assert external.read_bytes() == before
        assert CORE_CREATOR.encode() in external.read_bytes()
        assert result["files_processed"] == 0
        assert any("symlink" in e.lower() or "unsafe" in e.lower() for e in result["errors"])

    def test_metadata_refuses_symlink_and_reports_failure(self, tmp_path):
        host = tmp_path / "host"
        host.mkdir()
        external = _make_docx_with_authors(host / "real.docx")
        before = external.read_bytes()

        dump = tmp_path / "dump"
        dump.mkdir()
        link = dump / "evil.docx"
        link.symlink_to(external)

        result = strip_office_metadata(link, dump_root=dump)

        assert result["success"] is False
        assert result["errors"]
        assert external.read_bytes() == before


# ---------------------------------------------------------------------------
# billion-laughs -- entity-expansion DoS hardening on ET.fromstring
# ---------------------------------------------------------------------------

# A DTD that would expand &d; to 10^4 'A's if a naive parser processed it. The
# guard must reject it BEFORE expat expands anything.
_BILLION_LAUGHS = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE cp:coreProperties ['
    b'<!ENTITY a "AAAAAAAAAA">'
    b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
    b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
    b'<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
    b']>'
    b'<cp:coreProperties '
    b'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    b'xmlns:dc="http://purl.org/dc/elements/1.1/">'
    b'<dc:creator>&d;</dc:creator>'
    b'</cp:coreProperties>'
)


class TestBillionLaughsHardening:

    def test_safe_fromstring_rejects_dtd(self):
        with pytest.raises(ET.ParseError):
            _safe_fromstring(_BILLION_LAUGHS)

    def test_blank_xml_tags_rejects_dtd_fast(self):
        start = time.monotonic()
        with pytest.raises(ET.ParseError):
            _blank_xml_tags(_BILLION_LAUGHS, _CORE_PII_TAGS)
        # Rejection is O(len) -- must not expand entities.
        assert time.monotonic() - start < 2.0

    def test_docx_with_bomb_core_fails_closed(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("docProps/core.xml", _BILLION_LAUGHS)
        docx = tmp_path / "bomb.docx"
        docx.write_bytes(buf.getvalue())

        start = time.monotonic()
        result = strip_office_metadata(docx, dump_root=tmp_path)
        assert time.monotonic() - start < 2.0

        # Fail closed: the parse was refused, so the document is NOT reported
        # clean and the reason surfaces.
        assert result["success"] is False
        joined = " ".join(result["errors"]).lower()
        assert "doctype" in joined or "entity" in joined or "parse" in joined

    def test_oversized_part_fails_closed(self, tmp_path):
        # A part whose declared uncompressed size exceeds the cap must surface,
        # not be silently skipped as "clean".
        import hygeia.office_stripper as osmod

        big = b"<a>" + b"x" * (osmod._MAX_XML_BYTES + 1) + b"</a>"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("docProps/core.xml", big)
        docx = tmp_path / "big.docx"
        docx.write_bytes(buf.getvalue())

        result = strip_office_metadata(docx, dump_root=tmp_path)
        assert result["success"] is False
        assert any("size" in e.lower() for e in result["errors"])
