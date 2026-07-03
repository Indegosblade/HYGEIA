"""Tests for post-sanitization PII verifier."""

import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hygeia.verifier as V
from hygeia.verifier import (
    verify_sanitization, scan_text_files, scan_sqlite_content,
    scan_sqlite_freelist, _is_false_positive,
)


def test_clean_directory_passes():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "safe.txt").write_text("No personal data here at all")
    result = verify_sanitization(root)
    assert result.passed, f"Clean dir should pass, got {result.total_findings} findings"
    shutil.rmtree(d)


def test_email_detected_in_text():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "leak.txt").write_text("Contact user@example.com for info")
    result = verify_sanitization(root)
    assert not result.passed, "Email should be detected"
    assert any(m.pattern_name == "email" for m in result.pii_matches)
    shutil.rmtree(d)


def test_phone_detected_in_text():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "leak.txt").write_text("Call (555) 123-4567 for help")
    result = verify_sanitization(root)
    assert not result.passed
    shutil.rmtree(d)


def test_ssn_detected_in_text():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "leak.txt").write_text("SSN: 123-45-6789")
    result = verify_sanitization(root)
    assert not result.passed
    shutil.rmtree(d)


def test_email_detected_in_sqlite():
    d = tempfile.mkdtemp()
    root = Path(d)
    db = root / "test.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE users (id INTEGER, info TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'user@leaked.com')")
    conn.commit()
    conn.close()
    matches = scan_sqlite_content(root)
    assert len(matches) >= 1
    assert any("email" in m.pattern_name for m in matches)
    shutil.rmtree(d)


def test_freelist_detection():
    """INVERTED (#4/#26/#40): free pages hold recoverable deleted-row bytes.
    Verification is READ-ONLY and no longer VACUUMs, so a non-empty freelist is
    a FINDING even while another connection holds the database open — it is
    never suppressed as 'expected for locked databases'."""
    d = tempfile.mkdtemp()
    db = Path(d) / "test.db"
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (id INTEGER, data TEXT)")
    for i in range(1000):
        conn.execute("INSERT INTO t VALUES (?, ?)", (i, f"data_{i}"))
    conn.commit()
    conn.execute("DELETE FROM t WHERE id > 5")
    conn.commit()
    # Hold an open read transaction on the same file (used to block VACUUM in
    # the old fail-open path); the read-only inspection must still see the
    # freelist.
    conn.execute("BEGIN")
    conn.execute("SELECT * FROM t LIMIT 1")
    incomplete: list = []
    findings = scan_sqlite_freelist(db, incomplete=incomplete)
    conn.rollback()
    conn.close()
    assert len(findings) >= 1, f"Locked-DB freelist must be reported, got: {findings}"
    assert incomplete == [], f"Readable freelist is a finding, not incomplete: {incomplete}"
    shutil.rmtree(d, ignore_errors=True)


def test_false_positive_url_column():
    assert _is_false_positive("db:table.url", "phone_us", "5551234567") is True
    assert _is_false_positive("db:table.url", "ssn", "123-45-6789") is True


def test_false_positive_system_path():
    assert _is_false_positive("System/Library/file.txt", "email", "test@test.com") is True


def test_false_positive_redacted():
    assert _is_false_positive("any.txt", "email", "[REDACTED_EMAIL]") is True


def test_not_false_positive_real_pii():
    assert _is_false_positive("data/notes.txt", "email", "user@real.com") is False


def test_system_dir_skip():
    d = tempfile.mkdtemp()
    root = Path(d)
    sys_dir = root / "System" / "Library"
    sys_dir.mkdir(parents=True)
    (sys_dir / "framework.txt").write_text("admin@apple.com internal")
    matches = scan_text_files(root)
    assert len(matches) == 0, "System paths should be skipped"
    shutil.rmtree(d)


# ── False-positive fix tests (fix/false-positives-vacuum) ────────────────────

def test_gps_coord_above_180_is_false_positive():
    """Memory sizes / version strings like 387.19343805 must not flag as GPS."""
    assert _is_false_positive("data/bag_cache.plist", "gps_coord", "387.19343805") is True
    assert _is_false_positive("data/bag_cache.plist", "gps_coord", "1024.00000000") is True


def test_gps_coord_valid_range_is_not_false_positive():
    """Real GPS coordinates within -180..180 must still be flagged."""
    assert _is_false_positive("data/photos.db:ZASSET.ZLATITUDE", "gps_coord", "37.3382") is False
    assert _is_false_positive("data/photos.db:ZASSET.ZLONGITUDE", "gps_coord", "-122.0322") is False


def test_coredata_zpk_ssn_is_false_positive():
    """CoreData Z_PK / ROWID sequence numbers that match SSN pattern are not SSNs."""
    assert _is_false_positive("Calendar/Calendar.sqlitedb:CalendarItem.Z_PK", "ssn", "123456789") is True
    assert _is_false_positive("Calendar/Calendar.sqlitedb:CalendarItem.Z_ENT", "ssn", "234567890") is True
    assert _is_false_positive("Calendar/Calendar.sqlitedb:CalendarItem.Z_OPT", "ssn", "345678901") is True
    assert _is_false_positive("Calendar/Calendar.sqlitedb:CalendarItem.rowid", "ssn", "456789012") is True


def test_coredata_ssn_in_real_column_is_not_false_positive():
    """An SSN-shaped value in a non-system column must still be flagged."""
    assert _is_false_positive("data/contacts.db:Person.social_security", "ssn", "123-45-6789") is False


def test_apple_ip_is_false_positive_in_verifier():
    """Apple's 17/8 block should not fire as residual PII in the verifier."""
    assert _is_false_positive("data/bag_cache.plist", "ip_v4", "17.188.141.22") is True
    assert _is_false_positive("data/bag_cache.plist", "ip_v4", "17.0.0.1") is True


def test_rfc1918_ip_is_false_positive_in_verifier():
    """Private / loopback ranges should not fire in the verifier either."""
    assert _is_false_positive("data/wifi_history.log", "ip_v4", "10.0.0.1") is True
    assert _is_false_positive("data/wifi_history.log", "ip_v4", "172.16.5.3") is True
    assert _is_false_positive("data/wifi_history.log", "ip_v4", "172.31.255.255") is True
    assert _is_false_positive("data/wifi_history.log", "ip_v4", "192.168.1.100") is True


def test_public_user_ip_is_not_false_positive():
    """A non-Apple, non-private IP must still be flagged."""
    assert _is_false_positive("data/cookies.db", "ip_v4", "93.184.216.34") is False


# ── Residual false-positive fixes (fix/verification-residuals) ────────────────

def test_manifest_files_skipped_by_scanner():
    """manifest.json and MANIFEST.txt are HYGEIA output files — the scanner
    must skip them to avoid the manifest self-reporting loop."""
    d = tempfile.mkdtemp()
    root = Path(d)
    # Write a manifest.json that contains phone numbers that were logged
    (root / "manifest.json").write_text('{"phone": "1-604-555-0142", "found": true}')
    (root / "MANIFEST.txt").write_text("phone=16045550142 found=1")
    matches = scan_text_files(root)
    assert len(matches) == 0, (
        f"manifest files should be skipped, got {len(matches)} matches: "
        + ", ".join(f"{m.path}:{m.pattern_name}" for m in matches)
    )
    shutil.rmtree(d)


def test_bare_9digit_ssn_in_plist_is_now_flagged():
    """INVERTED (#25): the blanket extension-based suppression is removed. A bare
    9-digit SSN in a .plist/.json is a real finding — only CoreData COLUMN names
    (Z_PK/Z_ENT/timestamp cols) may suppress a bare-9-digit match, never the file
    extension."""
    assert _is_false_positive("Preferences/cloud.quota.plist", "ssn", "777777789") is False
    assert _is_false_positive("Preferences/facetime.bag.plist", "ssn", "201326586") is False
    assert _is_false_positive("Preferences/routined.plist", "ssn", "013456789") is False
    assert _is_false_positive("Preferences/tipsd.plist", "ssn", "012345678") is False


def test_bare_9digit_ssn_in_json_is_flagged():
    """The audit's exact scenario: a JSON export field "ssn":"123456789" must be
    flagged, not suppressed because the file ends in .json (#25)."""
    assert _is_false_positive("export/userdata.json", "ssn", "123456789") is False


def test_formatted_ssn_in_plist_is_not_false_positive():
    """A properly formatted SSN (XXX-XX-XXXX) must still be flagged even in a .plist."""
    assert _is_false_positive("Preferences/some.plist", "ssn", "123-45-6789") is False


def test_bare_9digit_ssn_in_sqlite_is_now_flagged():
    """INVERTED (#25): a bare 9-digit SSN in a .sqlitedb/.db with no CoreData
    column qualifier is a finding. Real CoreData sequence integers are still
    suppressed elsewhere by COLUMN NAME (Z_PK/ZDATE/…), never by extension."""
    assert _is_false_positive("data/Calendar.sqlitedb", "ssn", "802498179") is False
    assert _is_false_positive("data/Extras.db", "ssn", "803772792") is False


def test_leading_zero_gps_is_false_positive():
    """Values with a leading zero before the decimal (07.6100) are version
    numbers, not GPS coordinates."""
    assert _is_false_positive("data/some.plist", "gps_coord", "07.6100") is True
    assert _is_false_positive("data/some.plist", "gps_coord", "00.1234") is True


def test_4decimal_gps_in_plist_is_false_positive():
    """Version-like floats with exactly 4 decimal places in a plist are not GPS."""
    assert _is_false_positive("Preferences/tipsd.plist", "gps_coord", "11.5600") is True
    assert _is_false_positive("Preferences/some.plist", "gps_coord", "22.0598") is True


def test_real_gps_6decimal_not_false_positive():
    """GPS coordinates with 6+ decimal places in non-plist files remain flagged."""
    assert _is_false_positive("data/photos.db:ZASSET.ZLATITUDE", "gps_coord", "37.338200") is False


def test_external_mod_tag_gps_is_false_positive():
    """external_mod_tag column in SQLite databases is a sync tag, not GPS."""
    assert _is_false_positive("data/Calendar.sqlitedb:Event.external_mod_tag", "gps_coord", "179.100725") is True


def test_single_digit_octet_ip_is_false_positive():
    """All-single-digit-octet IPs like 2.3.5.8 are version numbers, not user IPs."""
    assert _is_false_positive("Preferences/SpeakSelection.plist", "ip_v4", "2.3.5.8") is True
    assert _is_false_positive("data/config.json", "ip_v4", "1.2.3.4") is True


def test_double_digit_octet_ip_not_false_positive():
    """IPs with multi-digit octets in the public range must still be flagged."""
    assert _is_false_positive("data/network.log", "ip_v4", "23.5.8.9") is False


def test_repeated_digit_phone_is_false_positive():
    """Phone numbers with 7+ repeated digits are Apple demo/placeholder data."""
    assert _is_false_positive("Preferences/tipsd.plist", "phone_us", "3333333334") is True
    assert _is_false_positive("Preferences/tipsd.plist", "phone_us", "5555555555") is True


def test_real_phone_not_repeated_digits():
    """A real phone number without repeated-digit pattern must still be flagged."""
    assert _is_false_positive("data/contacts.db", "phone_us", "6044192133") is False


def test_known_test_credit_cards_are_false_positives():
    """Mastercard/Visa/Stripe test card numbers are demo data, not real PII."""
    assert _is_false_positive("Preferences/tipsd.plist", "credit_card", "5555555555555556") is True
    assert _is_false_positive("data/any.json", "credit_card", "4111111111111111") is True
    assert _is_false_positive("data/any.json", "credit_card", "4242424242424242") is True


def test_real_credit_card_not_false_positive():
    """A credit card number that is not a known test card must still be flagged."""
    assert _is_false_positive("data/wallet.db", "credit_card", "4532015112830366") is False


# ── Final residual fixes (fix/final-residuals) ───────────────────────────────

def test_high_precision_binary_fraction_gps_in_plist_is_false_positive():
    """CSS/layout values like 11.56494140625 (power-of-2 fractions, 11 decimal
    places) in plist files must not be flagged as GPS coordinates."""
    assert _is_false_positive(
        "ios/Preferences/com.apple.mobileSMS.plist", "gps_coord", "11.56494140625"
    ) is True
    assert _is_false_positive(
        "ios/Preferences/com.apple.mobileSMS.plist", "gps_coord", "11.45703125"
    ) is True


def test_normal_precision_gps_in_plist_not_false_positive():
    """GPS coordinates with 4-7 decimal places in plist files are still flagged
    (the >=8-digit rule should not suppress them)."""
    # 6 decimal places — real GPS, must flag
    assert _is_false_positive(
        "ios/Preferences/some.plist", "gps_coord", "37.338200"
    ) is False
    # 7 decimal places — still real GPS precision, must flag
    assert _is_false_positive(
        "ios/Preferences/some.plist", "gps_coord", "37.3382001"
    ) is False


def test_coredata_zvalue_ssn_is_false_positive():
    """ZVALUE in CoreData tables holds heterogeneous data including timestamps —
    bare 9-digit integers there are not SSNs."""
    assert _is_false_positive(
        "ios/Calendar/Extras.db:ZSETTING.ZVALUE", "ssn", "803772792"
    ) is True


def test_coredata_timestamp_cols_ssn_is_false_positive():
    """ZDATE, ZTIMESTAMP, ZMODIFIEDDATE, ZCREATIONDATE are CoreData epoch offsets,
    not SSNs."""
    assert _is_false_positive("db:Table.ZDATE", "ssn", "803772792") is True
    assert _is_false_positive("db:Table.ZTIMESTAMP", "ssn", "803772792") is True
    assert _is_false_positive("db:Table.ZMODIFIEDDATE", "ssn", "803772792") is True
    assert _is_false_positive("db:Table.ZCREATIONDATE", "ssn", "803772792") is True
    assert _is_false_positive("db:Table.ZSETTING", "ssn", "803772792") is True


def test_freelist_suppressed_when_vacuum_fails():
    """INVERTED (#4/#26): a locked 'Login Data' copy with deleted rows in free
    pages must NOT be reported clean. The read-only inspection reads the
    freelist and reports the finding; the lock never suppresses it."""
    d = tempfile.mkdtemp()
    db_path = Path(d) / "Login Data"
    # Create a database with free pages
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE t (id INTEGER, data TEXT)")
    for i in range(500):
        conn.execute("INSERT INTO t VALUES (?, ?)", (i, f"data_{i}"))
    conn.commit()
    conn.execute("DELETE FROM t WHERE id > 5")
    conn.commit()
    # Keep the connection open to simulate a WAL/Chrome lock.
    conn.execute("BEGIN")
    conn.execute("SELECT * FROM t LIMIT 1")
    findings = scan_sqlite_freelist(db_path)
    conn.rollback()
    conn.close()
    assert len(findings) >= 1, (
        f"Locked-DB freelist with recoverable deleted rows must be reported, got: {findings}"
    )
    shutil.rmtree(d, ignore_errors=True)


def test_freelist_cleared_by_verification_vacuum():
    """INVERTED (#40): verification is READ-ONLY and must NOT VACUUM. Free pages
    from deleted rows therefore remain and are reported as a finding — the
    verifier can never mask a sanitizer gap by 'cleaning on the spot'. Also
    asserts the artifact is not mutated by verification."""
    d = tempfile.mkdtemp()
    db_path = Path(d) / "test_clearable.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE t (id INTEGER, data TEXT)")
    for i in range(500):
        conn.execute("INSERT INTO t VALUES (?, ?)", (i, f"data_{i}"))
    conn.commit()
    conn.execute("DELETE FROM t WHERE id > 5")
    conn.commit()
    conn.close()
    before = db_path.stat().st_size
    free_before = sqlite3.connect(str(db_path)).execute("PRAGMA freelist_count").fetchone()[0]
    findings = scan_sqlite_freelist(db_path)
    free_after = sqlite3.connect(str(db_path)).execute("PRAGMA freelist_count").fetchone()[0]
    assert len(findings) >= 1, (
        f"Free pages must be reported, not silently cleared, got: {findings}"
    )
    # Read-only verification must not have vacuumed the file.
    assert free_after == free_before > 0, "verification must not clear the freelist"
    assert db_path.stat().st_size == before, "verification must not rewrite the artifact"
    shutil.rmtree(d, ignore_errors=True)


# ── Fail-closed core: incomplete concept (#4/#22/#23/#24/#40/#41) ─────────────

def test_freelist_unreadable_db_is_incomplete():
    """A database that cannot be inspected read-only must be recorded as
    incomplete (fail closed) — never treated as a clean, empty freelist (#41)."""
    d = tempfile.mkdtemp()
    bad = Path(d) / "corrupt.db"
    bad.write_bytes(b"this is definitely not a sqlite database " * 4)
    incomplete: list = []
    findings = scan_sqlite_freelist(bad, incomplete=incomplete)
    assert findings == []
    assert any(i["check"] == "sqlite_freelist" for i in incomplete), incomplete
    shutil.rmtree(d, ignore_errors=True)


def test_content_scan_reads_all_rows_not_just_first_1000():
    """#22: PII stored past the old LIMIT 1000 window must still be found."""
    d = tempfile.mkdtemp()
    root = Path(d)
    db = root / "big.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE t (id INTEGER, note TEXT)")
    for i in range(2500):
        conn.execute("INSERT INTO t VALUES (?, ?)", (i, f"row {i} nothing here"))
    # Well past row 1000:
    conn.execute("INSERT INTO t VALUES (?, ?)", (99999, "leak victim@example.com"))
    conn.commit()
    conn.close()
    matches = scan_sqlite_content(root)
    assert any(m.pattern_name == "email" and "victim@example.com" in m.match_text
               for m in matches), "PII beyond the first 1000 rows must be scanned"
    shutil.rmtree(d, ignore_errors=True)


def test_content_scan_reads_blob_and_nontext_columns():
    """#23: text PII stored in a BLOB column and in an INTEGER-declared column
    must be decoded/scanned — declared affinity must not gate scanning."""
    d = tempfile.mkdtemp()
    root = Path(d)
    db = root / "blob.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE t (id INTEGER, payload BLOB, tag INTEGER)")
    conn.execute(
        "INSERT INTO t VALUES (?, ?, ?)",
        (1, b"contact agent@example.com asap", "SSN 123-45-6789"),
    )
    conn.commit()
    conn.close()
    matches = scan_sqlite_content(root)
    names = {m.pattern_name for m in matches}
    assert "email" in names, f"email in BLOB column was missed: {names}"
    assert "ssn" in names, f"SSN text in INTEGER-declared column was missed: {names}"
    shutil.rmtree(d, ignore_errors=True)


def test_content_scan_unreadable_db_is_incomplete():
    """#41: an unopenable/encrypted database contributes an incomplete entry,
    not a silent clean pass."""
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "encrypted.db").write_bytes(b"SQLCipher\x00garbage\x01\x02" * 8)
    incomplete: list = []
    scan_sqlite_content(root, incomplete=incomplete)
    assert any(i["check"] == "sqlite_content" for i in incomplete), incomplete
    shutil.rmtree(d, ignore_errors=True)


def test_oversized_text_file_is_incomplete():
    """#24: a file over max_file_size is surfaced as incomplete, and its PII is
    NOT silently reported clean."""
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "huge.log").write_text("PII here: user@example.com " * 4)
    incomplete: list = []
    matches = scan_text_files(root, max_file_size=10, incomplete=incomplete)
    assert any(i["check"] == "text_scan" for i in incomplete), incomplete
    assert not any(m.pattern_name == "email" for m in matches), (
        "oversized file must not be scanned-and-passed; it is surfaced as incomplete"
    )
    shutil.rmtree(d, ignore_errors=True)


def test_bare_9digit_ssn_in_json_flagged_end_to_end():
    """#25 end-to-end: a JSON export with a bare 9-digit SSN must FAIL verification."""
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "userdata.json").write_text('{"name": "Test User", "ssn": "123456789"}')
    result = verify_sanitization(root)
    assert not result.passed, "bare 9-digit SSN in JSON must be flagged"
    assert any(m.pattern_name == "ssn" for m in result.pii_matches)
    shutil.rmtree(d, ignore_errors=True)


# ── EXIF fail-closed (#1/#8/#42) ─────────────────────────────────────────────

def test_exif_incomplete_when_exiftool_absent_with_images():
    """#1/#8/#42: with images present but exiftool missing, EXIF can be neither
    stripped nor verified — verification must record incomplete and NOT pass."""
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "IMG_0001.jpg").write_bytes(b"\xff\xd8\xff\xe1\x00\x10Exif\x00\x00GPSdata")
    with patch("hygeia.exif_stripper.find_exiftool", return_value=None):
        result = verify_sanitization(root)
    assert any(i["check"] == "exif" for i in result.incomplete), result.incomplete
    assert result.passed is False, "must not report clean when EXIF was never verified"
    shutil.rmtree(d, ignore_errors=True)


def test_exif_no_incomplete_when_no_images_present():
    """No images means nothing to strip/verify — a missing exiftool is not an
    incomplete in that case."""
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "notes.txt").write_text("nothing sensitive here")
    with patch("hygeia.exif_stripper.find_exiftool", return_value=None):
        result = verify_sanitization(root)
    assert not any(i["check"] == "exif" for i in result.incomplete)
    assert result.passed is True
    shutil.rmtree(d, ignore_errors=True)


def test_verify_fails_closed_on_unreadable_database():
    """End-to-end fail-closed: an unreadable DB in the dump yields zero findings
    but blocks `passed` via an incomplete entry (#41)."""
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "corrupt.db").write_bytes(b"not a database " * 16)
    result = verify_sanitization(root)
    assert result.total_findings == 0
    assert result.incomplete, "corrupt DB must be recorded incomplete"
    assert result.passed is False, "must fail closed on an unreadable database"
    shutil.rmtree(d, ignore_errors=True)


# ── Scoped verification is never an unqualified clean (#43) ───────────────────

def test_scoped_verification_records_scope():
    """#43: --only/--skip narrows the verifier; the scope is recorded so a
    partial verify is never presented as a full clean."""
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "clean.txt").write_text("nothing sensitive here")
    V.configure(only=["financial"])
    try:
        result = verify_sanitization(root)
        assert result.scope is not None
        assert "financial" in result.scope
    finally:
        V.configure()  # reset global registry + scope state
    shutil.rmtree(d, ignore_errors=True)


def test_full_verification_has_no_scope():
    """An unscoped verify records scope=None (a genuine full-clean candidate)."""
    V.configure()  # ensure unscoped
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "clean.txt").write_text("nothing sensitive here")
    result = verify_sanitization(root)
    assert result.scope is None
    assert result.passed is True
    shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__} — {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
