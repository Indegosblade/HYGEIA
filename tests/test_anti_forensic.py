"""
Tests for anti-forensic hardening features:
- PDF metadata stripping
- Office document metadata stripping
- Extended EXIF verification tags
- Crash reporter data cleanup
- macOS quarantine xattr detection (mocked)
- NTFS ADS detection (mocked)
- Clipboard history cleanup (mocked)
"""

import io
import logging
import os
import shutil
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.pdf_stripper import (
    strip_pdf_metadata,
    strip_pdf_directory,
    _strip_pdf_info_pure_python,
)
from hygeia.office_stripper import (
    strip_office_metadata,
    strip_office_directory,
    _blank_xml_tags,
    _CORE_PII_TAGS,
)
from hygeia.forensic_cleaner import (
    clean_crash_reporter_data,
    clean_quarantine_xattrs,
    clean_clipboard_history,
)
from hygeia.exif_stripper import verify_exif_stripped
from hygeia.sqlite_sanitizer import delete_database, _secure_overwrite


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tmp() -> Path:
    return Path(tempfile.mkdtemp())


def _touch(path: Path, content: bytes = b"") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _make_minimal_pdf(path: Path, with_metadata: bool = True) -> Path:
    """Create a minimal valid PDF file, optionally with /Info metadata."""
    if with_metadata:
        # A real minimal PDF with /Info dictionary
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n"
            b"<< /Type /Catalog /Pages 2 0 R >>\n"
            b"endobj\n"
            b"2 0 obj\n"
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
            b"endobj\n"
            b"3 0 obj\n"
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
            b"endobj\n"
            b"4 0 obj\n"
            b"<< /Author (John Doe) /Creator (Word) /Producer (Adobe) "
            b"/Title (Secret Report) /Subject (PII Test) "
            b"/CreationDate (D:20240101120000) /ModDate (D:20240101130000) >>\n"
            b"endobj\n"
            b"xref\n"
            b"0 5\n"
            b"0000000000 65535 f \n"
            b"0000000009 00000 n \n"
            b"0000000058 00000 n \n"
            b"0000000115 00000 n \n"
            b"0000000206 00000 n \n"
            b"trailer\n"
            b"<< /Size 5 /Root 1 0 R /Info 4 0 R >>\n"
            b"startxref\n"
            b"400\n"
            b"%%EOF\n"
        )
    else:
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n"
            b"<< /Type /Catalog /Pages 2 0 R >>\n"
            b"endobj\n"
            b"%%EOF\n"
        )
    path.write_bytes(pdf_content)
    return path


def _make_docx(path: Path, creator: str = "Alice Smith", company: str = "ACME Corp") -> Path:
    """Create a minimal .docx file with PII in core.xml and app.xml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # [Content_Types].xml (required)
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/docProps/core.xml" '
            'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
            '</Types>',
        )
        # core.xml with PII
        core_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties '
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:dcterms="http://purl.org/dc/terms/">'
            f'<dc:creator>{creator}</dc:creator>'
            '<cp:lastModifiedBy>Bob Jones</cp:lastModifiedBy>'
            '<dc:description>Confidential document</dc:description>'
            '</cp:coreProperties>'
        )
        zf.writestr("docProps/core.xml", core_xml)
        # app.xml with PII
        app_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            f'<Company>{company}</Company>'
            '<Manager>Carol White</Manager>'
            '<Application>Microsoft Word 16.0</Application>'
            '</Properties>'
        )
        zf.writestr("docProps/app.xml", app_xml)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())
    return path


def _make_odt(path: Path, creator: str = "Alice Smith") -> Path:
    """Create a minimal .odt file with PII in meta.xml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        meta_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<office:document-meta '
            'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            '<office:meta>'
            f'<dc:creator>{creator}</dc:creator>'
            '<meta:initial-creator>Initial Person</meta:initial-creator>'
            '<dc:title>My ODF Document</dc:title>'
            '<meta:generator>LibreOffice/7.0</meta:generator>'
            '</office:meta>'
            '</office:document-meta>'
        )
        zf.writestr("meta.xml", meta_xml)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())
    return path


def _read_docx_xml(doc_path: Path, entry: str) -> str:
    """Read an XML entry from a docx ZIP and return as string."""
    with zipfile.ZipFile(doc_path, "r") as zf:
        return zf.read(entry).decode("utf-8")


# ---------------------------------------------------------------------------
# 1. PDF metadata stripping tests
# ---------------------------------------------------------------------------

class TestPDFMetadataStripping:

    def test_pure_python_strips_author(self):
        """Pure-Python path should blank /Author field in PDF /Info dict."""
        d = _make_tmp()
        try:
            pdf = _make_minimal_pdf(d / "test.pdf", with_metadata=True)
            result = strip_pdf_metadata(pdf)
            assert result["success"] is True
            content = pdf.read_bytes()
            # Author value should be blanked (spaces) but key still present
            assert b"/Author" in content
            # The original value "(John Doe)" should be gone
            assert b"John Doe" not in content
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_strip_pdf_metadata_returns_action_dict(self):
        """strip_pdf_metadata must return a dict with action and success keys."""
        d = _make_tmp()
        try:
            pdf = _make_minimal_pdf(d / "doc.pdf")
            result = strip_pdf_metadata(pdf)
            assert "action" in result
            assert result["action"] == "strip_pdf_metadata"
            assert "success" in result
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_strip_pdf_directory_processes_all_pdfs(self):
        """strip_pdf_directory should find and process all .pdf files."""
        d = _make_tmp()
        try:
            _make_minimal_pdf(d / "a.pdf")
            (d / "sub").mkdir(exist_ok=True)
            _make_minimal_pdf(d / "sub" / "b.pdf")
            _touch(d / "readme.txt", b"not a pdf")
            result = strip_pdf_directory(d)
            assert result["action"] == "strip_pdf_metadata_directory"
            assert result["files_processed"] == 2
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_strip_pdf_directory_empty_dir(self):
        """strip_pdf_directory on an empty directory returns zero processed."""
        d = _make_tmp()
        try:
            result = strip_pdf_directory(d)
            assert result["files_processed"] == 0
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_pure_python_strips_multiple_fields(self):
        """All recognised metadata fields should be blanked."""
        d = _make_tmp()
        try:
            pdf = _make_minimal_pdf(d / "multi.pdf", with_metadata=True)
            _strip_pdf_info_pure_python(pdf)
            content = pdf.read_bytes()
            for pii_value in [b"John Doe", b"Word", b"Adobe", b"Secret Report", b"PII Test"]:
                assert pii_value not in content, f"{pii_value} should be stripped"
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_strip_pdf_uses_exiftool_when_available(self):
        """When exiftool is on PATH, strip_pdf_metadata should call it."""
        d = _make_tmp()
        try:
            pdf = _make_minimal_pdf(d / "doc.pdf")
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            with patch("hygeia.pdf_stripper.find_exiftool", return_value="/usr/bin/exiftool"), \
                 patch("subprocess.run", return_value=mock_proc) as mock_run:
                result = strip_pdf_metadata(pdf)
            assert result["method"] == "exiftool"
            assert result["success"] is True
            mock_run.assert_called_once()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_strip_pdf_fallback_when_exiftool_absent(self):
        """When exiftool is absent, strip_pdf_metadata falls back to pure Python."""
        d = _make_tmp()
        try:
            pdf = _make_minimal_pdf(d / "doc.pdf")
            with patch("hygeia.pdf_stripper.find_exiftool", return_value=None):
                result = strip_pdf_metadata(pdf)
            assert result["method"] == "pure_python"
            assert result["success"] is True
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# 2. Office document metadata stripping tests
# ---------------------------------------------------------------------------

class TestOfficeMetadataStripping:

    def test_docx_creator_stripped(self):
        """dc:creator in core.xml should be blanked after stripping."""
        d = _make_tmp()
        try:
            docx = _make_docx(d / "report.docx", creator="Alice Smith")
            result = strip_office_metadata(docx)
            assert result["success"] is True
            assert result["fields_blanked"] > 0
            core_xml = _read_docx_xml(docx, "docProps/core.xml")
            assert "Alice Smith" not in core_xml
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_docx_company_stripped(self):
        """Company in app.xml should be blanked."""
        d = _make_tmp()
        try:
            docx = _make_docx(d / "doc.docx", company="ACME Corp")
            strip_office_metadata(docx)
            app_xml = _read_docx_xml(docx, "docProps/app.xml")
            assert "ACME Corp" not in app_xml
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_odt_creator_stripped(self):
        """dc:creator in meta.xml of .odt should be blanked."""
        d = _make_tmp()
        try:
            odt = _make_odt(d / "notes.odt", creator="Alice Smith")
            result = strip_office_metadata(odt)
            assert result["success"] is True
            with zipfile.ZipFile(odt, "r") as zf:
                meta_xml = zf.read("meta.xml").decode("utf-8")
            assert "Alice Smith" not in meta_xml
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_strip_office_directory_counts(self):
        """strip_office_directory should count processed and modified files."""
        d = _make_tmp()
        try:
            _make_docx(d / "a.docx")
            _make_docx(d / "sub" / "b.docx")
            (d / "sub").mkdir(exist_ok=True)
            _make_docx(d / "sub" / "b.docx")
            _touch(d / "readme.txt", b"not office")
            result = strip_office_directory(d)
            assert result["files_processed"] == 2
            assert result["files_modified"] == 2
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_unsupported_extension_returns_error(self):
        """Passing a non-Office file should return an error dict, not raise."""
        d = _make_tmp()
        try:
            txt = _touch(d / "notes.txt", b"hello")
            result = strip_office_metadata(txt)
            assert result["success"] is False
            assert result["errors"]
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_blank_xml_tags_helper(self):
        """_blank_xml_tags should blank the matched tags and return count."""
        xml_bytes = (
            b'<?xml version="1.0"?>'
            b'<cp:coreProperties '
            b'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            b'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            b'<dc:creator>Jane Doe</dc:creator>'
            b'</cp:coreProperties>'
        )
        new_bytes, count = _blank_xml_tags(xml_bytes, _CORE_PII_TAGS)
        assert count == 1
        # Verify PII value is not in the serialised output
        assert b"Jane Doe" not in new_bytes

    def test_odf_initial_creator_stripped(self):
        """meta:initial-creator in ODF meta.xml should be blanked."""
        d = _make_tmp()
        try:
            odt = _make_odt(d / "doc.odt")
            strip_office_metadata(odt)
            with zipfile.ZipFile(odt, "r") as zf:
                meta_xml = zf.read("meta.xml").decode("utf-8")
            assert "Initial Person" not in meta_xml
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# 3. Extended EXIF verification
# ---------------------------------------------------------------------------

class TestExtendedExifVerification:

    def test_verify_exif_skipped_no_exiftool(self, caplog):
        """verify_exif_stripped returns [] and warns when exiftool absent."""
        d = _make_tmp()
        try:
            (d / "photo.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 16)
            with patch("shutil.which", return_value=None), \
                 patch("pathlib.Path.is_file", return_value=False), \
                 caplog.at_level(logging.WARNING, logger="hygeia.exif"):
                result = verify_exif_stripped(d)
            assert result == []
            assert any("exiftool" in r.message for r in caplog.records
                       if r.levelno == logging.WARNING)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_verify_exif_calls_serial_and_owner_tags(self):
        """verify_exif_stripped should check SerialNumber, OwnerName, etc."""
        import subprocess as sp
        import hygeia.exif_stripper as exif_mod
        d = _make_tmp()
        try:
            img = d / "photo.jpg"
            img.write_bytes(b"\xff\xd8\xff" + b"\x00" * 16)
            mock_proc = MagicMock()
            mock_proc.stdout = ""
            mock_proc.returncode = 0
            with patch.object(exif_mod, "find_exiftool", return_value="/usr/bin/exiftool"), \
                 patch.object(sp, "run", return_value=mock_proc) as mock_run:
                verify_exif_stripped(d)
            # Verify the call includes the new tags
            call_args = mock_run.call_args[0][0]
            assert "-SerialNumber" in call_args
            assert "-LensSerialNumber" in call_args
            assert "-ImageUniqueID" in call_args
            assert "-OwnerName" in call_args
            assert "-CameraOwnerName" in call_args
            assert "-Copyright" in call_args
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# 4. Crash reporter cleanup tests
# ---------------------------------------------------------------------------

class TestCrashReporterCleanup:

    def test_ips_files_deleted(self):
        """clean_crash_reporter_data should delete .ips files."""
        d = _make_tmp()
        try:
            ips = _touch(d / "crash.ips", b"username: alice\npath: /Users/alice/Documents")
            actions = clean_crash_reporter_data(d)
            assert not ips.exists()
            assert any(a["action"] == "delete_crash_file" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_crash_files_deleted(self):
        """clean_crash_reporter_data should delete .crash files."""
        d = _make_tmp()
        try:
            crash = _touch(d / "MyApp.crash", b"user: bob")
            actions = clean_crash_reporter_data(d)
            assert not crash.exists()
            assert any(a["action"] == "delete_crash_file" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_crashreporter_dir_deleted(self):
        """Directory named CrashReporter should be removed entirely."""
        d = _make_tmp()
        try:
            crash_dir = d / "CrashReporter"
            crash_dir.mkdir()
            _touch(crash_dir / "report.ips", b"user: alice")
            actions = clean_crash_reporter_data(d)
            assert not crash_dir.exists()
            assert any(a["action"] == "delete_crash_reporter_dir" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_diagnosticreports_dir_deleted(self):
        """Directory named DiagnosticReports should be removed."""
        d = _make_tmp()
        try:
            dr = d / "DiagnosticReports"
            dr.mkdir()
            _touch(dr / "myapp.ips", b"data")
            actions = clean_crash_reporter_data(d)
            assert not dr.exists()
            assert any(a["action"] == "delete_crash_reporter_dir" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dry_run_preserves_crash_files(self):
        """dry_run=True should not delete any crash files."""
        d = _make_tmp()
        try:
            ips = _touch(d / "app.ips", b"pii data")
            actions = clean_crash_reporter_data(d, dry_run=True)
            assert ips.exists()
            assert all(a.get("dry_run") for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_regular_files_not_deleted(self):
        """Normal files should not be touched by crash reporter cleanup."""
        d = _make_tmp()
        try:
            safe = _touch(d / "notes.txt", b"hello")
            clean_crash_reporter_data(d)
            assert safe.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_nested_ips_file_deleted(self):
        """Nested .ips files should also be deleted."""
        d = _make_tmp()
        try:
            sub = d / "logs" / "sub"
            sub.mkdir(parents=True)
            nested = _touch(sub / "deep.ips", b"pii")
            clean_crash_reporter_data(d)
            assert not nested.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# 4b. Secure database deletion (finding #45)
# ---------------------------------------------------------------------------

class TestSecureDatabaseDeletion:

    def _make_db(self, path: Path, marker: str) -> Path:
        conn = sqlite3.connect(str(path))
        conn.execute("CREATE TABLE t (id INTEGER, email TEXT)")
        conn.execute("INSERT INTO t VALUES (1, ?)", (f"victim-{marker}@example.com",))
        conn.commit()
        conn.close()
        return path

    def test_delete_database_overwrites_bytes_before_unlink(self):
        """#45: delete_database's 'securely delete' contract requires overwriting
        the file's bytes BEFORE unlink. Capture the on-disk bytes at the moment
        unlink is called and assert the PII marker is already destroyed — a plain
        unlink would leave it carvable in the free blocks."""
        d = _make_tmp()
        try:
            db = self._make_db(d / "secret.db", "UNIQUEMARKER123")
            assert b"UNIQUEMARKER123" in db.read_bytes()  # present before deletion

            captured = {}
            real_unlink = Path.unlink

            def capturing_unlink(self_path, *a, **k):
                if self_path == db and self_path.exists():
                    captured["at_unlink"] = self_path.read_bytes()
                return real_unlink(self_path, *a, **k)

            with patch.object(Path, "unlink", capturing_unlink):
                result = delete_database(db)

            assert not db.exists()
            assert "at_unlink" in captured, "unlink was never called on the database"
            assert b"UNIQUEMARKER123" not in captured["at_unlink"], \
                "file bytes were NOT overwritten before unlink — PII remains carvable"
            assert db.name in result.get("secure_overwrite", [])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_secure_overwrite_destroys_bytes(self):
        """#45: _secure_overwrite (used on the DB and its -wal/-shm/-journal
        companions, which hold 50-95% of deleted-record PII) must replace the
        whole extent with random bytes so the original PII is unrecoverable."""
        d = _make_tmp()
        try:
            f = d / "companion.db-wal"
            original = b"deleted rows victim-WALMARK@example.com in wal frames " * 100
            f.write_bytes(original)
            size = f.stat().st_size

            ok = _secure_overwrite(f)

            assert ok is True
            after = f.read_bytes()
            assert len(after) == size, "overwrite must cover the entire extent"
            assert b"WALMARK" not in after, "PII bytes not destroyed by secure overwrite"
            assert after != original
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_secure_overwrite_refuses_symlink(self):
        """#45 safety: the overwrite must never follow a symlink, or it would
        clobber a host file the dump points at (outside the output tree)."""
        d = _make_tmp()
        try:
            target = d / "host_file.bin"
            target.write_bytes(b"IMPORTANT-HOST-DATA")
            link = d / "link.db"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                pytest.skip("symlinks not supported on this platform")
            assert _secure_overwrite(link) is False
            assert target.read_bytes() == b"IMPORTANT-HOST-DATA", "symlink target was clobbered"
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# 5. macOS quarantine xattr (mocked — runs everywhere)
# ---------------------------------------------------------------------------

class TestQuarantineXattr:

    def test_skips_on_non_darwin(self):
        """clean_quarantine_xattrs returns empty list on non-Darwin platforms."""
        d = _make_tmp()
        try:
            _touch(d / "file.txt", b"data")
            with patch("platform.system", return_value="Windows"):
                actions = clean_quarantine_xattrs(d)
            assert actions == []
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_removes_quarantine_xattr_on_darwin(self):
        """On Darwin, quarantine xattr should be detected and removed."""
        import hygeia.forensic_cleaner as fc_mod
        d = _make_tmp()
        try:
            _touch(d / "downloaded.dmg", b"data")
            mock_listxattr = MagicMock(return_value=["com.apple.quarantine"])
            mock_removexattr = MagicMock()
            with patch("platform.system", return_value="Darwin"), \
                 patch.object(fc_mod.os, "listxattr", mock_listxattr, create=True), \
                 patch.object(fc_mod.os, "removexattr", mock_removexattr, create=True):
                actions = clean_quarantine_xattrs(d)
            mock_removexattr.assert_called()
            assert any(a["xattr"] == "com.apple.quarantine" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dry_run_does_not_remove_xattr(self):
        """dry_run=True should not call os.removexattr."""
        import hygeia.forensic_cleaner as fc_mod
        d = _make_tmp()
        try:
            _touch(d / "file.txt", b"data")
            mock_listxattr = MagicMock(return_value=["com.apple.quarantine"])
            mock_removexattr = MagicMock()
            with patch("platform.system", return_value="Darwin"), \
                 patch.object(fc_mod.os, "listxattr", mock_listxattr, create=True), \
                 patch.object(fc_mod.os, "removexattr", mock_removexattr, create=True):
                actions = clean_quarantine_xattrs(d, dry_run=True)
            mock_removexattr.assert_not_called()
            assert any(a.get("dry_run") for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# 6. Clipboard history cleanup (mocked)
# ---------------------------------------------------------------------------

class TestClipboardHistoryCleanup:

    def test_skips_when_no_clipboard_dir(self):
        """clean_clipboard_history returns empty list when clipboard dir absent."""
        with patch("platform.system", return_value="Windows"), \
             patch.dict(os.environ, {"LOCALAPPDATA": "/nonexistent"}, clear=False):
            actions = clean_clipboard_history()
        assert actions == []

    def test_windows_clipboard_cleared(self):
        """On Windows, clipboard contents should be deleted."""
        d = _make_tmp()
        try:
            clip_dir = d / "Clipboard"
            clip_dir.mkdir()
            _touch(clip_dir / "item1.dat", b"copied text")
            _touch(clip_dir / "item2.dat", b"more text")

            expected_path = d / "Microsoft" / "Windows" / "Clipboard"
            expected_path.mkdir(parents=True)
            _touch(expected_path / "item.dat", b"clipboard data")

            with patch("platform.system", return_value="Windows"), \
                 patch.dict(os.environ, {"LOCALAPPDATA": str(d)}, clear=False):
                actions = clean_clipboard_history()

            assert any(a["action"] == "delete_clipboard_history" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dry_run_does_not_delete_clipboard(self):
        """dry_run=True should not delete clipboard contents."""
        d = _make_tmp()
        try:
            clip_dir = d / "Microsoft" / "Windows" / "Clipboard"
            clip_dir.mkdir(parents=True)
            item = _touch(clip_dir / "item.dat", b"sensitive data")

            with patch("platform.system", return_value="Windows"), \
                 patch.dict(os.environ, {"LOCALAPPDATA": str(d)}, clear=False):
                actions = clean_clipboard_history(dry_run=True)

            assert item.exists()
            assert all(a.get("dry_run") for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)
