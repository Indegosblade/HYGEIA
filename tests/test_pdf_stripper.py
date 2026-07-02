"""
Behavioural tests for hygeia.pdf_stripper covering audit finding #11 and the
symlink-traversal write (#9) as it applies to PDFs.

  #11 (XMP)        -- the pure-Python fallback must strip the XMP metadata packet
                      (dc:creator / xmp:CreatorTool / GPS), not just the /Info
                      dict; the edit is length-preserving.
  #11 (compressed) -- if author/GPS metadata lives in a FlateDecode object
                      stream the fallback cannot reach, it must NOT report
                      success=True (fail closed).
  #9               -- an in-place PDF rewrite must be refused for a symlink
                      inside the dump.

All embedded values are bogus (documentation names).
"""

import sys
import zlib
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.pdf_stripper import (
    strip_pdf_metadata,
    strip_pdf_directory,
    _strip_pdf_info_pure_python,
    _detect_unreachable_pdf_metadata,
    _blank_xmp_metadata,
)

XMP_CREATOR = "Jane Analyst"
XMP_TOOL = "Microsoft Word 16.0"
INFO_AUTHOR = "John Doe"
COMPRESSED_AUTHOR = "Grace Hopper"


def _pdf_with_xmp(path: Path) -> Path:
    """A minimal PDF whose XMP /Metadata stream (uncompressed) carries a
    dc:creator and xmp:CreatorTool, plus a plaintext /Info /Author.
    """
    xmp = (
        '<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description rdf:about="" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:xmp="http://ns.adobe.com/xap/1.0/">'
        f'<dc:creator><rdf:Seq><rdf:li>{XMP_CREATOR}</rdf:li></rdf:Seq></dc:creator>'
        f'<xmp:CreatorTool>{XMP_TOOL}</xmp:CreatorTool>'
        '</rdf:Description></rdf:RDF></x:xmpmeta>'
        '<?xpacket end="w"?>'
    ).encode("utf-8")

    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"4 0 obj\n<< /Author (" + INFO_AUTHOR.encode() + b") /Creator (Word) >>\nendobj\n"
        b"5 0 obj\n<< /Type /Metadata /Subtype /XML /Length "
        + str(len(xmp)).encode() + b" >>\nstream\n" + xmp + b"\nendstream\nendobj\n"
        b"trailer\n<< /Size 6 /Root 1 0 R /Info 4 0 R >>\n%%EOF\n"
    )
    path.write_bytes(body)
    return path


def _pdf_with_compressed_metadata(path: Path) -> Path:
    """A PDF where the /Info-style metadata lives ONLY inside a FlateDecode
    object stream -- unreachable by the plaintext rewriter.
    """
    inner = b"4 0 << /Author (" + COMPRESSED_AUTHOR.encode() + b") /Producer (Acme) >>"
    compressed = zlib.compress(inner)
    body = (
        b"%PDF-1.5\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"6 0 obj\n<< /Type /ObjStm /N 1 /First 8 /Filter /FlateDecode /Length "
        + str(len(compressed)).encode() + b" >>\nstream\n" + compressed
        + b"\nendstream\nendobj\n"
        b"trailer\n<< /Size 7 /Root 1 0 R >>\n%%EOF\n"
    )
    path.write_bytes(body)
    return path


def _plain_pdf(path: Path) -> Path:
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Author (" + INFO_AUTHOR.encode() + b") >>\nendobj\n"
        b"trailer\n<< /Size 5 /Root 1 0 R /Info 4 0 R >>\n%%EOF\n"
    )
    return path


# ---------------------------------------------------------------------------
# #11 -- XMP packet stripping
# ---------------------------------------------------------------------------

class TestXMPStripping:

    def test_blank_xmp_metadata_removes_creator_and_tool(self):
        xmp = (
            b'<rdf:Description xmlns:dc="x" xmlns:xmp="y">'
            b'<dc:creator><rdf:Seq><rdf:li>' + XMP_CREATOR.encode() + b'</rdf:li></rdf:Seq></dc:creator>'
            b'<xmp:CreatorTool>' + XMP_TOOL.encode() + b'</xmp:CreatorTool>'
            b'</rdf:Description>'
        )
        out, count = _blank_xmp_metadata(xmp)
        assert count >= 2
        assert XMP_CREATOR.encode() not in out
        assert XMP_TOOL.encode() not in out
        # Length preserved (spaces), structure intact.
        assert len(out) == len(xmp)
        assert b"<dc:creator>" in out and b"<xmp:CreatorTool>" in out

    def test_strip_pdf_metadata_removes_xmp_when_exiftool_absent(self, tmp_path):
        pdf = _pdf_with_xmp(tmp_path / "doc.pdf")
        before_len = pdf.stat().st_size
        with patch("hygeia.pdf_stripper.find_exiftool", return_value=None):
            result = strip_pdf_metadata(pdf, dump_root=tmp_path)

        assert result["success"] is True, result
        content = pdf.read_bytes()
        assert XMP_CREATOR.encode() not in content
        assert XMP_TOOL.encode() not in content
        assert INFO_AUTHOR.encode() not in content  # /Info also cleared
        # XMP structure remains and byte length is preserved (xref-safe).
        assert b"<x:xmpmeta" in content
        assert pdf.stat().st_size == before_len

    def test_pure_python_helper_strips_xmp(self, tmp_path):
        pdf = _pdf_with_xmp(tmp_path / "h.pdf")
        changed = _strip_pdf_info_pure_python(pdf)
        assert changed is True
        assert XMP_CREATOR.encode() not in pdf.read_bytes()


# ---------------------------------------------------------------------------
# #11 -- compressed object stream => fail closed
# ---------------------------------------------------------------------------

class TestCompressedMetadataFailClosed:

    def test_detector_flags_compressed_author(self, tmp_path):
        pdf = _pdf_with_compressed_metadata(tmp_path / "c.pdf")
        reason = _detect_unreachable_pdf_metadata(pdf.read_bytes())
        assert reason is not None
        assert "compressed" in reason.lower()

    def test_strip_reports_failure_for_compressed_metadata(self, tmp_path):
        pdf = _pdf_with_compressed_metadata(tmp_path / "c.pdf")
        # The author is genuinely NOT recoverable from plaintext -- proving the
        # tool would otherwise have wrongly reported "clean".
        assert COMPRESSED_AUTHOR.encode() not in pdf.read_bytes()

        with patch("hygeia.pdf_stripper.find_exiftool", return_value=None):
            result = strip_pdf_metadata(pdf, dump_root=tmp_path)

        assert result["success"] is False
        assert result.get("incomplete") is True
        assert "compressed" in result["error"].lower()

    def test_directory_surfaces_compressed_failure(self, tmp_path):
        _pdf_with_compressed_metadata(tmp_path / "c.pdf")
        with patch("hygeia.pdf_stripper.find_exiftool", return_value=None):
            result = strip_pdf_directory(tmp_path)
        assert result["files_processed"] == 1
        assert result["files_modified"] == 0
        assert result["errors"]

    def test_plain_pdf_still_succeeds(self, tmp_path):
        # No compressed streams -> detector must not false-positive.
        pdf = _plain_pdf(tmp_path / "plain.pdf")
        with patch("hygeia.pdf_stripper.find_exiftool", return_value=None):
            result = strip_pdf_metadata(pdf, dump_root=tmp_path)
        assert result["success"] is True
        assert INFO_AUTHOR.encode() not in pdf.read_bytes()


# ---------------------------------------------------------------------------
# #9 -- symlink traversal write
# ---------------------------------------------------------------------------

class TestSymlinkTraversalWrite:

    def test_metadata_refuses_symlink(self, tmp_path):
        host = tmp_path / "host"
        host.mkdir()
        external = _pdf_with_xmp(host / "real.pdf")
        before = external.read_bytes()

        dump = tmp_path / "dump"
        dump.mkdir()
        link = dump / "evil.pdf"
        link.symlink_to(external)

        with patch("hygeia.pdf_stripper.find_exiftool", return_value=None):
            result = strip_pdf_metadata(link, dump_root=dump)

        assert result["success"] is False
        assert result["method"] == "skipped"
        # Host file untouched and its PII intact.
        assert external.read_bytes() == before
        assert XMP_CREATOR.encode() in external.read_bytes()

    def test_directory_skips_symlink_and_leaves_target_untouched(self, tmp_path):
        host = tmp_path / "host"
        host.mkdir()
        external = _pdf_with_xmp(host / "real.pdf")
        before = external.read_bytes()

        dump = tmp_path / "dump"
        dump.mkdir()
        (dump / "report.pdf").symlink_to(external)

        with patch("hygeia.pdf_stripper.find_exiftool", return_value=None):
            result = strip_pdf_directory(dump)

        assert result["files_processed"] == 0
        assert external.read_bytes() == before
        assert any("symlink" in e.lower() or "unsafe" in e.lower() for e in result["errors"])
