"""
Deep compliance test suite — HIPAA Safe Harbor 18 identifiers, GDPR Article 9,
CCPA, and cross-compliance stacking tests.

Each test creates a real SQLite database, runs the sanitizer, then re-opens
the database to verify the data is gone / redacted.
"""

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.sqlite_sanitizer import sanitize_database_generic
from hygeia.compliance import (
    generalize_date,
    generate_compliance_report,
    get_compliance_profile,
    truncate_zip,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_db(schema_sql: str, rows: list[tuple], insert_sql: str) -> Path:
    """Create a temp SQLite db, insert rows, return path. Caller must unlink."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path = Path(tmp.name)
    tmp.close()
    conn = sqlite3.connect(str(db_path))
    conn.execute(schema_sql)
    conn.executemany(insert_sql, rows)
    conn.commit()
    conn.close()
    return db_path


def read_all(db_path: Path, query: str) -> list:
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute(query).fetchall()
    conn.close()
    return rows


def run_hipaa(db_path: Path) -> dict:
    profile = get_compliance_profile("hipaa")
    return sanitize_database_generic(
        db_path,
        extra_columns=profile.extra_sensitive_columns,
        extra_tables=profile.extra_pii_tables,
    )


def run_gdpr(db_path: Path) -> dict:
    profile = get_compliance_profile("gdpr")
    return sanitize_database_generic(
        db_path,
        extra_columns=profile.extra_sensitive_columns,
        extra_tables=profile.extra_pii_tables,
    )


def run_ccpa(db_path: Path) -> dict:
    profile = get_compliance_profile("ccpa")
    return sanitize_database_generic(
        db_path,
        extra_columns=profile.extra_sensitive_columns,
        extra_tables=profile.extra_pii_tables,
    )


def run_all(db_path: Path) -> dict:
    profile = get_compliance_profile("all")
    return sanitize_database_generic(
        db_path,
        extra_columns=profile.extra_sensitive_columns,
        extra_tables=profile.extra_pii_tables,
    )


# ---------------------------------------------------------------------------
# HIPAA Safe Harbor — 18 Identifiers
# ---------------------------------------------------------------------------

# 1. Names (first, last, full)
def test_hipaa_names_redacted():
    db = make_db(
        "CREATE TABLE patients (id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT, full_name TEXT)",
        [(1, "John", "Doe", "John Doe"), (2, "Jane", "Smith", "Jane Smith")],
        "INSERT INTO patients VALUES (?, ?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT first_name, last_name, full_name FROM patients")
        for first, last, full in rows:
            assert first == "[REDACTED]", f"first_name not redacted: {first!r}"
            assert last == "[REDACTED]", f"last_name not redacted: {last!r}"
            assert full == "[REDACTED]", f"full_name not redacted: {full!r}"
    finally:
        db.unlink(missing_ok=True)


# 2. Geographic data smaller than state — street address, city, zip
def test_hipaa_geographic_data_redacted():
    db = make_db(
        "CREATE TABLE records (id INTEGER PRIMARY KEY, street_address TEXT, city TEXT, zip TEXT)",
        [(1, "123 Main St", "Springfield", "62701"), (2, "456 Oak Ave", "Shelbyville", "62565")],
        "INSERT INTO records VALUES (?, ?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT street_address, city, zip FROM records")
        for street, city, zip_code in rows:
            assert street == "[REDACTED]", f"street_address not redacted: {street!r}"
            assert city == "[REDACTED]", f"city not redacted: {city!r}"
            assert zip_code == "[REDACTED]", f"zip not redacted: {zip_code!r}"
    finally:
        db.unlink(missing_ok=True)


# 3. Dates — DOB, admission, discharge (except year — column-name driven)
def test_hipaa_dob_redacted():
    db = make_db(
        "CREATE TABLE patients (id INTEGER PRIMARY KEY, date_of_birth TEXT, dob TEXT, birthdate TEXT)",
        [(1, "1985-03-15", "1985-03-15", "March 15, 1985")],
        "INSERT INTO patients VALUES (?, ?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT date_of_birth, dob, birthdate FROM patients")
        for dob1, dob2, bdate in rows:
            assert dob1 == "[REDACTED]", f"date_of_birth not redacted: {dob1!r}"
            assert dob2 == "[REDACTED]", f"dob not redacted: {dob2!r}"
            assert bdate == "[REDACTED]", f"birthdate not redacted: {bdate!r}"
    finally:
        db.unlink(missing_ok=True)


# 4. Phone numbers
def test_hipaa_phone_numbers_redacted():
    db = make_db(
        "CREATE TABLE contacts (id INTEGER PRIMARY KEY, phone TEXT, phone_number TEXT)",
        [(1, "555-867-5309", "555-867-5309"), (2, "(312) 555-0100", "(312) 555-0100")],
        "INSERT INTO contacts VALUES (?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT phone, phone_number FROM contacts")
        for phone, phone_number in rows:
            assert phone == "[REDACTED]", f"phone not redacted: {phone!r}"
            assert phone_number == "[REDACTED]", f"phone_number not redacted: {phone_number!r}"
    finally:
        db.unlink(missing_ok=True)


# 5. Fax numbers
def test_hipaa_fax_numbers_redacted():
    db = make_db(
        "CREATE TABLE providers (id INTEGER PRIMARY KEY, fax TEXT, fax_number TEXT)",
        [(1, "312-555-0199", "312-555-0199")],
        "INSERT INTO providers VALUES (?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT fax, fax_number FROM providers")
        for fax, fax_num in rows:
            assert fax == "[REDACTED]", f"fax not redacted: {fax!r}"
            assert fax_num == "[REDACTED]", f"fax_number not redacted: {fax_num!r}"
    finally:
        db.unlink(missing_ok=True)


# 6. Email addresses
def test_hipaa_email_addresses_redacted():
    db = make_db(
        "CREATE TABLE patients (id INTEGER PRIMARY KEY, email TEXT)",
        [(1, "patient@hospital.org"), (2, "john.doe@example.com")],
        "INSERT INTO patients VALUES (?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT email FROM patients")
        for (email,) in rows:
            assert email == "[REDACTED]", f"email not redacted: {email!r}"
    finally:
        db.unlink(missing_ok=True)


# 7. SSN
def test_hipaa_ssn_redacted():
    db = make_db(
        "CREATE TABLE patients (id INTEGER PRIMARY KEY, ssn TEXT, social_security TEXT)",
        [(1, "123-45-6789", "123-45-6789")],
        "INSERT INTO patients VALUES (?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT ssn, social_security FROM patients")
        for ssn, ss in rows:
            assert ssn == "[REDACTED]", f"ssn not redacted: {ssn!r}"
            assert ss == "[REDACTED]", f"social_security not redacted: {ss!r}"
    finally:
        db.unlink(missing_ok=True)


# 8. Medical Record Numbers (MRN)
def test_hipaa_mrn_redacted():
    db = make_db(
        "CREATE TABLE records (id INTEGER PRIMARY KEY, mrn TEXT, medical_record TEXT, patient_id TEXT)",
        [(1, "MRN-00123456", "00123456", "PT-987654")],
        "INSERT INTO records VALUES (?, ?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT mrn, medical_record, patient_id FROM records")
        for mrn, med_rec, pat_id in rows:
            assert mrn == "[REDACTED]", f"mrn not redacted: {mrn!r}"
            assert med_rec == "[REDACTED]", f"medical_record not redacted: {med_rec!r}"
            assert pat_id == "[REDACTED]", f"patient_id not redacted: {pat_id!r}"
    finally:
        db.unlink(missing_ok=True)


# 9. Health plan beneficiary numbers
def test_hipaa_health_plan_beneficiary_redacted():
    db = make_db(
        "CREATE TABLE insurance (id INTEGER PRIMARY KEY, health_plan_id TEXT, beneficiary_id TEXT, member_id TEXT)",
        [(1, "HP-12345678", "BEN-98765", "MBR-11223344")],
        "INSERT INTO insurance VALUES (?, ?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT health_plan_id, beneficiary_id, member_id FROM insurance")
        for hp_id, ben_id, mem_id in rows:
            assert hp_id == "[REDACTED]", f"health_plan_id not redacted: {hp_id!r}"
            assert ben_id == "[REDACTED]", f"beneficiary_id not redacted: {ben_id!r}"
            assert mem_id == "[REDACTED]", f"member_id not redacted: {mem_id!r}"
    finally:
        db.unlink(missing_ok=True)


# 10. Account numbers
def test_hipaa_account_numbers_redacted():
    db = make_db(
        "CREATE TABLE billing (id INTEGER PRIMARY KEY, account_number TEXT, account TEXT)",
        [(1, "ACC-0099887766", "0099887766")],
        "INSERT INTO billing VALUES (?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT account_number, account FROM billing")
        for acc_num, acc in rows:
            assert acc_num == "[REDACTED]", f"account_number not redacted: {acc_num!r}"
            assert acc == "[REDACTED]", f"account not redacted: {acc!r}"
    finally:
        db.unlink(missing_ok=True)


# 11. Certificate/license numbers
def test_hipaa_license_numbers_redacted():
    db = make_db(
        "CREATE TABLE providers (id INTEGER PRIMARY KEY, license_number TEXT, drivers_license TEXT)",
        [(1, "LIC-A1B2C3D4", "D12345678")],
        "INSERT INTO providers VALUES (?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT license_number, drivers_license FROM providers")
        for lic, drv in rows:
            assert lic == "[REDACTED]", f"license_number not redacted: {lic!r}"
            assert drv == "[REDACTED]", f"drivers_license not redacted: {drv!r}"
    finally:
        db.unlink(missing_ok=True)


# 12. Vehicle identifiers (VIN)
def test_hipaa_vin_redacted():
    db = make_db(
        "CREATE TABLE vehicles (id INTEGER PRIMARY KEY, vin TEXT, vehicle_vin TEXT, license_plate TEXT)",
        [(1, "1HGCM82633A123456", "1HGCM82633A123456", "ABC1234")],
        "INSERT INTO vehicles VALUES (?, ?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT vin, vehicle_vin, license_plate FROM vehicles")
        for vin, vvin, plate in rows:
            assert vin == "[REDACTED]", f"vin not redacted: {vin!r}"
            assert vvin == "[REDACTED]", f"vehicle_vin not redacted: {vvin!r}"
            assert plate == "[REDACTED]", f"license_plate not redacted: {plate!r}"
    finally:
        db.unlink(missing_ok=True)


# 13. Device identifiers — serial numbers, IMEI
def test_hipaa_device_identifiers_redacted():
    db = make_db(
        "CREATE TABLE devices (id INTEGER PRIMARY KEY, serial_number TEXT, device_serial TEXT, imei TEXT, udid TEXT)",
        [(1, "C02XG2JHJGH5", "C02XG2JHJGH5", "490154203237518", "00000000-0000-0000-0000-000000000000")],
        "INSERT INTO devices VALUES (?, ?, ?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT serial_number, device_serial, imei, udid FROM devices")
        for serial, dev_serial, imei, udid in rows:
            assert serial == "[REDACTED]", f"serial_number not redacted: {serial!r}"
            assert dev_serial == "[REDACTED]", f"device_serial not redacted: {dev_serial!r}"
            assert imei == "[REDACTED]", f"imei not redacted: {imei!r}"
            assert udid == "[REDACTED]", f"udid not redacted: {udid!r}"
    finally:
        db.unlink(missing_ok=True)


# 14. Web URLs — stored in a text column (not a named PII table)
def test_hipaa_web_urls_pattern_redacted():
    db = make_db(
        "CREATE TABLE activity (id INTEGER PRIMARY KEY, notes TEXT)",
        [(1, "Patient visited https://user:pass@myhealth.example.com/portal?token=abc123")],
        "INSERT INTO activity VALUES (?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT notes FROM activity")
        for (notes,) in rows:
            # url_creds pattern should strip the embedded credentials
            assert "user:pass@" not in notes, f"URL credentials not redacted: {notes!r}"
    finally:
        db.unlink(missing_ok=True)


# 15. IP addresses
def test_hipaa_ip_addresses_redacted():
    db = make_db(
        "CREATE TABLE logs (id INTEGER PRIMARY KEY, ip_address TEXT, remote_addr TEXT)",
        [(1, "192.168.1.100", "10.0.0.1")],
        "INSERT INTO logs VALUES (?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT ip_address, remote_addr FROM logs")
        for ip, remote in rows:
            assert ip == "[REDACTED]", f"ip_address not redacted: {ip!r}"
            assert remote == "[REDACTED]", f"remote_addr not redacted: {remote!r}"
    finally:
        db.unlink(missing_ok=True)


# 16. Biometric identifiers
def test_hipaa_biometric_identifiers_redacted():
    db = make_db(
        "CREATE TABLE biometrics (id INTEGER PRIMARY KEY, biometric TEXT, fingerprint TEXT, voiceprint TEXT)",
        [(1, "hex:aabbcc001122", "hex:ddeeff334455", "hex:112233445566")],
        "INSERT INTO biometrics VALUES (?, ?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT biometric, fingerprint, voiceprint FROM biometrics")
        for bio, fp, vp in rows:
            assert bio == "[REDACTED]", f"biometric not redacted: {bio!r}"
            assert fp == "[REDACTED]", f"fingerprint not redacted: {fp!r}"
            assert vp == "[REDACTED]", f"voiceprint not redacted: {vp!r}"
    finally:
        db.unlink(missing_ok=True)


# 17. Full-face photographs — test that face data columns are sanitized
def test_hipaa_face_data_redacted():
    db = make_db(
        "CREATE TABLE facial_data (id INTEGER PRIMARY KEY, face_data TEXT, face_scan TEXT)",
        [(1, "base64:AAAA/face-encoding-data==", "iris-scan-data")],
        "INSERT INTO facial_data VALUES (?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT face_data, face_scan FROM facial_data")
        for face, scan in rows:
            assert face == "[REDACTED]", f"face_data not redacted: {face!r}"
            assert scan == "[REDACTED]", f"face_scan not redacted: {scan!r}"
    finally:
        db.unlink(missing_ok=True)


# 18. Any other unique identifying number — NPI, DEA number (regex patterns)
def test_hipaa_unique_identifying_numbers_redacted():
    db = make_db(
        "CREATE TABLE providers (id INTEGER PRIMARY KEY, npi TEXT, dea_number TEXT)",
        [(1, "1234567893", "AB1234567")],
        "INSERT INTO providers VALUES (?, ?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT npi, dea_number FROM providers")
        for npi, dea in rows:
            assert npi == "[REDACTED]", f"npi not redacted: {npi!r}"
            assert dea == "[REDACTED]", f"dea_number not redacted: {dea!r}"
    finally:
        db.unlink(missing_ok=True)


# HIPAA: SSN in free-text column caught by regex pattern
def test_hipaa_ssn_in_freetext_redacted():
    db = make_db(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, note TEXT)",
        [(1, "Patient SSN is 123-45-6789 per intake form")],
        "INSERT INTO notes VALUES (?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT note FROM notes")
        for (note,) in rows:
            assert "123-45-6789" not in note, f"SSN not redacted in free text: {note!r}"
    finally:
        db.unlink(missing_ok=True)


# HIPAA: IMEI in free-text caught by regex
def test_hipaa_imei_in_freetext_redacted():
    db = make_db(
        "CREATE TABLE logs (id INTEGER PRIMARY KEY, log_text TEXT)",
        [(1, "Device check-in IMEI: 49-015420-323751-8 registered")],
        "INSERT INTO logs VALUES (?, ?)",
    )
    try:
        run_hipaa(db)
        rows = read_all(db, "SELECT log_text FROM logs")
        for (log_text,) in rows:
            assert "490154203237518" not in log_text.replace("-", "").replace(" ", ""), \
                f"IMEI not redacted in free text: {log_text!r}"
    finally:
        db.unlink(missing_ok=True)


# HIPAA: profile has date_generalization and zip_truncation set
def test_hipaa_profile_date_and_zip_flags():
    profile = get_compliance_profile("hipaa")
    assert profile.date_generalization is True, "HIPAA profile must set date_generalization=True"
    assert profile.zip_truncation == 3, "HIPAA profile must set zip_truncation=3 (Safe Harbor)"


# HIPAA: profile contains all key medical columns
def test_hipaa_profile_medical_columns_complete():
    profile = get_compliance_profile("hipaa")
    required = {"mrn", "medical_record", "patient_id", "health_plan_id",
                "beneficiary_id", "fax", "fax_number", "vin", "biometric",
                "fingerprint", "serial_number", "device_serial", "udid",
                "face_scan", "iris_scan"}
    missing = required - profile.extra_sensitive_columns
    assert not missing, f"HIPAA profile missing columns: {missing}"


# HIPAA: all 18 identifier keys present in HIPAA_18_IDENTIFIERS constant
def test_hipaa_18_identifiers_list_complete():
    from hygeia.compliance import HIPAA_18_IDENTIFIERS
    assert len(HIPAA_18_IDENTIFIERS) == 18, \
        f"Expected 18 HIPAA Safe Harbor identifiers, got {len(HIPAA_18_IDENTIFIERS)}"
    required_keys = {
        "names", "geographic_subdivisions", "dates", "phone_numbers",
        "fax_numbers", "email_addresses", "ssn", "medical_record_numbers",
        "health_plan_beneficiary_numbers", "account_numbers",
        "certificate_license_numbers", "vehicle_identifiers",
        "device_identifiers", "web_urls", "ip_addresses",
        "biometric_identifiers", "face_photographs", "unique_identifying_codes",
    }
    missing = required_keys - set(HIPAA_18_IDENTIFIERS)
    assert not missing, f"HIPAA_18_IDENTIFIERS missing: {missing}"


# ---------------------------------------------------------------------------
# GDPR Article 9 — Special Category Data
# ---------------------------------------------------------------------------

# Racial/ethnic origin
def test_gdpr_racial_ethnic_origin_redacted():
    db = make_db(
        "CREATE TABLE profiles (id INTEGER PRIMARY KEY, race TEXT, ethnicity TEXT, ethnic_origin TEXT)",
        [(1, "Asian", "Chinese", "East Asian")],
        "INSERT INTO profiles VALUES (?, ?, ?, ?)",
    )
    try:
        run_gdpr(db)
        rows = read_all(db, "SELECT race, ethnicity, ethnic_origin FROM profiles")
        for race, eth, eo in rows:
            assert race == "[REDACTED]", f"race not redacted: {race!r}"
            assert eth == "[REDACTED]", f"ethnicity not redacted: {eth!r}"
            assert eo == "[REDACTED]", f"ethnic_origin not redacted: {eo!r}"
    finally:
        db.unlink(missing_ok=True)


# Political opinions
def test_gdpr_political_opinions_redacted():
    db = make_db(
        "CREATE TABLE profiles (id INTEGER PRIMARY KEY, political_opinion TEXT, political_party TEXT, political_affiliation TEXT)",
        [(1, "Progressive", "Green Party", "Left-leaning")],
        "INSERT INTO profiles VALUES (?, ?, ?, ?)",
    )
    try:
        run_gdpr(db)
        rows = read_all(db, "SELECT political_opinion, political_party, political_affiliation FROM profiles")
        for opinion, party, affil in rows:
            assert opinion == "[REDACTED]", f"political_opinion not redacted: {opinion!r}"
            assert party == "[REDACTED]", f"political_party not redacted: {party!r}"
            assert affil == "[REDACTED]", f"political_affiliation not redacted: {affil!r}"
    finally:
        db.unlink(missing_ok=True)


# Religious/philosophical beliefs
def test_gdpr_religious_beliefs_redacted():
    db = make_db(
        "CREATE TABLE profiles (id INTEGER PRIMARY KEY, religion TEXT, religious_belief TEXT, faith TEXT)",
        [(1, "Islam", "Sunni Muslim", "Muslim")],
        "INSERT INTO profiles VALUES (?, ?, ?, ?)",
    )
    try:
        run_gdpr(db)
        rows = read_all(db, "SELECT religion, religious_belief, faith FROM profiles")
        for rel, belief, faith in rows:
            assert rel == "[REDACTED]", f"religion not redacted: {rel!r}"
            assert belief == "[REDACTED]", f"religious_belief not redacted: {belief!r}"
            assert faith == "[REDACTED]", f"faith not redacted: {faith!r}"
    finally:
        db.unlink(missing_ok=True)


# Trade union membership
def test_gdpr_trade_union_membership_redacted():
    db = make_db(
        "CREATE TABLE employment (id INTEGER PRIMARY KEY, trade_union TEXT, union_membership TEXT)",
        [(1, "UNITE", "Active member")],
        "INSERT INTO employment VALUES (?, ?, ?)",
    )
    try:
        run_gdpr(db)
        rows = read_all(db, "SELECT trade_union, union_membership FROM employment")
        for union, membership in rows:
            assert union == "[REDACTED]", f"trade_union not redacted: {union!r}"
            assert membership == "[REDACTED]", f"union_membership not redacted: {membership!r}"
    finally:
        db.unlink(missing_ok=True)


# Genetic/biometric data
def test_gdpr_genetic_biometric_data_redacted():
    db = make_db(
        "CREATE TABLE biodata (id INTEGER PRIMARY KEY, genetic_data TEXT, dna TEXT, biometric_data TEXT)",
        [(1, "ATCGATCG...", "rs123456:AA", "template:0xDEADBEEF")],
        "INSERT INTO biodata VALUES (?, ?, ?, ?)",
    )
    try:
        run_gdpr(db)
        rows = read_all(db, "SELECT genetic_data, dna, biometric_data FROM biodata")
        for genetic, dna, bio in rows:
            assert genetic == "[REDACTED]", f"genetic_data not redacted: {genetic!r}"
            assert dna == "[REDACTED]", f"dna not redacted: {dna!r}"
            assert bio == "[REDACTED]", f"biometric_data not redacted: {bio!r}"
    finally:
        db.unlink(missing_ok=True)


# Health data
def test_gdpr_health_data_redacted():
    db = make_db(
        "CREATE TABLE health (id INTEGER PRIMARY KEY, health_data TEXT, medical_condition TEXT, disability TEXT)",
        [(1, "hypertension, T2D", "diabetes mellitus type 2", "mobility impairment")],
        "INSERT INTO health VALUES (?, ?, ?, ?)",
    )
    try:
        run_gdpr(db)
        rows = read_all(db, "SELECT health_data, medical_condition, disability FROM health")
        for hd, mc, dis in rows:
            assert hd == "[REDACTED]", f"health_data not redacted: {hd!r}"
            assert mc == "[REDACTED]", f"medical_condition not redacted: {mc!r}"
            assert dis == "[REDACTED]", f"disability not redacted: {dis!r}"
    finally:
        db.unlink(missing_ok=True)


# Sex life / sexual orientation
def test_gdpr_sexual_orientation_redacted():
    db = make_db(
        "CREATE TABLE profiles (id INTEGER PRIMARY KEY, sexual_orientation TEXT, sex_life TEXT, gender_identity TEXT)",
        [(1, "bisexual", "not disclosed", "non-binary")],
        "INSERT INTO profiles VALUES (?, ?, ?, ?)",
    )
    try:
        run_gdpr(db)
        rows = read_all(db, "SELECT sexual_orientation, sex_life, gender_identity FROM profiles")
        for so, sl, gi in rows:
            assert so == "[REDACTED]", f"sexual_orientation not redacted: {so!r}"
            assert sl == "[REDACTED]", f"sex_life not redacted: {sl!r}"
            assert gi == "[REDACTED]", f"gender_identity not redacted: {gi!r}"
    finally:
        db.unlink(missing_ok=True)


# GDPR: delete_all_user_content flag is set
def test_gdpr_delete_all_user_content_flag():
    profile = get_compliance_profile("gdpr")
    assert profile.delete_all_user_content is True, "GDPR profile must set delete_all_user_content=True"


# GDPR: all Article 9 special categories present in profile columns
def test_gdpr_special_category_columns_complete():
    profile = get_compliance_profile("gdpr")
    required = {
        "race", "ethnicity", "ethnic_origin",
        "political_opinion", "political_party",
        "religion", "religious_belief",
        "trade_union", "union_membership",
        "genetic_data", "dna",
        "biometric_data", "fingerprint",
        "health_data", "medical_condition",
        "sexual_orientation", "sex_life", "gender_identity",
    }
    missing = required - profile.extra_sensitive_columns
    assert not missing, f"GDPR profile missing Article 9 columns: {missing}"


# GDPR: extra_pii_tables is empty (GDPR uses delete_all_user_content, not table nukes)
def test_gdpr_no_extra_pii_tables():
    profile = get_compliance_profile("gdpr")
    assert len(profile.extra_pii_tables) == 0, \
        "GDPR profile should not define extra_pii_tables (uses delete_all_user_content)"


# ---------------------------------------------------------------------------
# CCPA Tests
# ---------------------------------------------------------------------------

# Purchase history tables nuked
def test_ccpa_purchase_history_table_nuked():
    db = make_db(
        "CREATE TABLE purchase_history (id INTEGER PRIMARY KEY, item TEXT, amount REAL, user_id INTEGER)",
        [(1, "iPhone 15 Pro", 1199.99, 42), (2, "AirPods Pro", 249.00, 42)],
        "INSERT INTO purchase_history VALUES (?, ?, ?, ?)",
    )
    try:
        run_ccpa(db)
        rows = read_all(db, "SELECT COUNT(*) FROM purchase_history")
        count = rows[0][0]
        assert count == 0, f"purchase_history table not nuked: {count} rows remain"
    finally:
        db.unlink(missing_ok=True)


# Browsing history tables nuked
def test_ccpa_browsing_history_table_nuked():
    db = make_db(
        "CREATE TABLE browsing_history (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visited_at TEXT)",
        [(1, "https://example.com", "Example", "2024-01-01"), (2, "https://bank.com/login", "Bank Login", "2024-01-02")],
        "INSERT INTO browsing_history VALUES (?, ?, ?, ?)",
    )
    try:
        run_ccpa(db)
        rows = read_all(db, "SELECT COUNT(*) FROM browsing_history")
        count = rows[0][0]
        assert count == 0, f"browsing_history table not nuked: {count} rows remain"
    finally:
        db.unlink(missing_ok=True)


# Geolocation data tables nuked
def test_ccpa_geolocation_table_nuked():
    db = make_db(
        "CREATE TABLE geolocation (id INTEGER PRIMARY KEY, lat REAL, lng REAL, timestamp TEXT)",
        [(1, 37.7749, -122.4194, "2024-01-01T12:00:00"), (2, 34.0522, -118.2437, "2024-01-02T08:00:00")],
        "INSERT INTO geolocation VALUES (?, ?, ?, ?)",
    )
    try:
        run_ccpa(db)
        rows = read_all(db, "SELECT COUNT(*) FROM geolocation")
        count = rows[0][0]
        assert count == 0, f"geolocation table not nuked: {count} rows remain"
    finally:
        db.unlink(missing_ok=True)


# CCPA: geolocation in column form is also redacted
def test_ccpa_geolocation_columns_redacted():
    db = make_db(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, geolocation TEXT, gps TEXT)",
        [(1, "user1", "37.7749,-122.4194", "lat=37.7749 lng=-122.4194")],
        "INSERT INTO users VALUES (?, ?, ?, ?)",
    )
    try:
        run_ccpa(db)
        rows = read_all(db, "SELECT geolocation, gps FROM users")
        for geo, gps in rows:
            assert geo == "[REDACTED]", f"geolocation column not redacted: {geo!r}"
            assert gps == "[REDACTED]", f"gps column not redacted: {gps!r}"
    finally:
        db.unlink(missing_ok=True)


# CCPA: orders table nuked
def test_ccpa_orders_table_nuked():
    db = make_db(
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, product TEXT, price REAL)",
        [(1, "Widget A", 9.99), (2, "Widget B", 14.99)],
        "INSERT INTO orders VALUES (?, ?, ?)",
    )
    try:
        run_ccpa(db)
        rows = read_all(db, "SELECT COUNT(*) FROM orders")
        count = rows[0][0]
        assert count == 0, f"orders table not nuked: {count} rows remain"
    finally:
        db.unlink(missing_ok=True)


# CCPA: employment columns redacted
def test_ccpa_employment_data_redacted():
    db = make_db(
        "CREATE TABLE profiles (id INTEGER PRIMARY KEY, employer TEXT, occupation TEXT, salary TEXT, income TEXT)",
        [(1, "Acme Corp", "Software Engineer", "150000", "150000")],
        "INSERT INTO profiles VALUES (?, ?, ?, ?, ?)",
    )
    try:
        run_ccpa(db)
        rows = read_all(db, "SELECT employer, occupation, salary, income FROM profiles")
        for emp, occ, sal, inc in rows:
            assert emp == "[REDACTED]", f"employer not redacted: {emp!r}"
            assert occ == "[REDACTED]", f"occupation not redacted: {occ!r}"
            assert sal == "[REDACTED]", f"salary not redacted: {sal!r}"
            assert inc == "[REDACTED]", f"income not redacted: {inc!r}"
    finally:
        db.unlink(missing_ok=True)


# CCPA: education data redacted
def test_ccpa_education_data_redacted():
    db = make_db(
        "CREATE TABLE profiles (id INTEGER PRIMARY KEY, school TEXT, university TEXT, degree TEXT, gpa TEXT)",
        [(1, "Lincoln High", "MIT", "BSc Computer Science", "3.9")],
        "INSERT INTO profiles VALUES (?, ?, ?, ?, ?)",
    )
    try:
        run_ccpa(db)
        rows = read_all(db, "SELECT school, university, degree, gpa FROM profiles")
        for school, uni, deg, gpa in rows:
            assert school == "[REDACTED]", f"school not redacted: {school!r}"
            assert uni == "[REDACTED]", f"university not redacted: {uni!r}"
            assert deg == "[REDACTED]", f"degree not redacted: {deg!r}"
            assert gpa == "[REDACTED]", f"gpa not redacted: {gpa!r}"
    finally:
        db.unlink(missing_ok=True)


# CCPA: delete_browsing_history flag is set
def test_ccpa_delete_browsing_history_flag():
    profile = get_compliance_profile("ccpa")
    assert profile.delete_browsing_history is True, "CCPA profile must set delete_browsing_history=True"


# CCPA: extra_pii_tables includes all required tables
def test_ccpa_pii_tables_complete():
    profile = get_compliance_profile("ccpa")
    required = {"purchase_history", "browsing_history", "geolocation", "orders", "transactions"}
    missing = required - profile.extra_pii_tables
    assert not missing, f"CCPA profile missing PII tables: {missing}"


# CCPA: transactions table nuked
def test_ccpa_transactions_table_nuked():
    db = make_db(
        "CREATE TABLE transactions (id INTEGER PRIMARY KEY, amount REAL, merchant TEXT)",
        [(1, 50.00, "Amazon"), (2, 12.99, "Spotify")],
        "INSERT INTO transactions VALUES (?, ?, ?)",
    )
    try:
        run_ccpa(db)
        rows = read_all(db, "SELECT COUNT(*) FROM transactions")
        count = rows[0][0]
        assert count == 0, f"transactions table not nuked: {count} rows remain"
    finally:
        db.unlink(missing_ok=True)


# CCPA: location_history table nuked
def test_ccpa_location_history_table_nuked():
    db = make_db(
        "CREATE TABLE location_history (id INTEGER PRIMARY KEY, lat REAL, lng REAL, accuracy REAL)",
        [(1, 40.7128, -74.0060, 5.0)],
        "INSERT INTO location_history VALUES (?, ?, ?, ?)",
    )
    try:
        run_ccpa(db)
        rows = read_all(db, "SELECT COUNT(*) FROM location_history")
        count = rows[0][0]
        assert count == 0, f"location_history table not nuked: {count} rows remain"
    finally:
        db.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Cross-Compliance Tests
# ---------------------------------------------------------------------------

# --compliance all: union of HIPAA + GDPR + CCPA columns
def test_all_compliance_column_union():
    all_profile = get_compliance_profile("all")
    hipaa_profile = get_compliance_profile("hipaa")
    gdpr_profile = get_compliance_profile("gdpr")
    ccpa_profile = get_compliance_profile("ccpa")

    expected_union = (
        hipaa_profile.extra_sensitive_columns |
        gdpr_profile.extra_sensitive_columns |
        ccpa_profile.extra_sensitive_columns
    )
    missing = expected_union - all_profile.extra_sensitive_columns
    assert not missing, f"'all' profile missing columns from union: {missing}"


# --compliance all: extra_pii_tables includes CCPA tables
def test_all_compliance_pii_tables():
    all_profile = get_compliance_profile("all")
    ccpa_profile = get_compliance_profile("ccpa")
    missing = ccpa_profile.extra_pii_tables - all_profile.extra_pii_tables
    assert not missing, f"'all' profile missing CCPA PII tables: {missing}"


# --compliance all: all boolean flags set
def test_all_compliance_flags_all_set():
    p = get_compliance_profile("all")
    assert p.date_generalization is True, "all profile must have date_generalization=True"
    assert p.zip_truncation == 3, "all profile must have zip_truncation=3"
    assert p.delete_all_user_content is True, "all profile must have delete_all_user_content=True"
    assert p.delete_browsing_history is True, "all profile must have delete_browsing_history=True"


# --compliance all: name contains all three frameworks
def test_all_compliance_name_includes_all_frameworks():
    p = get_compliance_profile("all")
    name_upper = p.name.upper()
    assert "HIPAA" in name_upper, f"'all' profile name must mention HIPAA: {p.name!r}"
    assert "GDPR" in name_upper, f"'all' profile name must mention GDPR: {p.name!r}"
    assert "CCPA" in name_upper, f"'all' profile name must mention CCPA: {p.name!r}"


# HIPAA + GDPR stacking: database with both HIPAA and GDPR columns — all redacted
def test_hipaa_gdpr_stack_both_column_sets_redacted():
    """
    Simulate a medical app database that has HIPAA (mrn, patient_id) and
    GDPR Article 9 (race, religion) columns — pass extra_columns from both.
    """
    db = make_db(
        "CREATE TABLE patients (id INTEGER PRIMARY KEY, mrn TEXT, patient_id TEXT, race TEXT, religion TEXT)",
        [(1, "MRN-001", "PT-001", "Hispanic", "Catholic")],
        "INSERT INTO patients VALUES (?, ?, ?, ?, ?)",
    )
    try:
        hipaa_p = get_compliance_profile("hipaa")
        gdpr_p = get_compliance_profile("gdpr")
        combined_cols = hipaa_p.extra_sensitive_columns | gdpr_p.extra_sensitive_columns
        sanitize_database_generic(db, extra_columns=combined_cols)
        rows = read_all(db, "SELECT mrn, patient_id, race, religion FROM patients")
        for mrn, pat_id, race, religion in rows:
            assert mrn == "[REDACTED]", f"mrn not redacted: {mrn!r}"
            assert pat_id == "[REDACTED]", f"patient_id not redacted: {pat_id!r}"
            assert race == "[REDACTED]", f"race not redacted (GDPR): {race!r}"
            assert religion == "[REDACTED]", f"religion not redacted (GDPR): {religion!r}"
    finally:
        db.unlink(missing_ok=True)


# --compliance all: database with purchase_history + mrn + race all handled
def test_all_compliance_cross_framework_database():
    db = make_db(
        "CREATE TABLE mixed (id INTEGER PRIMARY KEY, mrn TEXT, race TEXT)",
        [(1, "MRN-999", "Asian")],
        "INSERT INTO mixed VALUES (?, ?, ?)",
    )
    try:
        run_all(db)
        rows = read_all(db, "SELECT mrn, race FROM mixed")
        for mrn, race in rows:
            assert mrn == "[REDACTED]", f"mrn not redacted under 'all' mode: {mrn!r}"
            assert race == "[REDACTED]", f"race not redacted under 'all' mode: {race!r}"
    finally:
        db.unlink(missing_ok=True)


# --compliance all: purchase_history table nuked (CCPA via all)
def test_all_compliance_purchase_history_nuked():
    db = make_db(
        "CREATE TABLE purchase_history (id INTEGER PRIMARY KEY, item TEXT, amount REAL)",
        [(1, "Widget", 9.99)],
        "INSERT INTO purchase_history VALUES (?, ?, ?)",
    )
    try:
        run_all(db)
        rows = read_all(db, "SELECT COUNT(*) FROM purchase_history")
        assert rows[0][0] == 0, "purchase_history not nuked under 'all' mode"
    finally:
        db.unlink(missing_ok=True)


# Compliance report: HIPAA report covers expected identifiers
def test_compliance_report_hipaa_identifiers_covered():
    actions = [
        {"action": "generic_sanitize", "pii_types_found": [
            "email", "phone_us", "ssn", "ip_v4", "mac_addr",
            "sensitive_column:name", "sensitive_column:mrn",
        ]},
    ]
    report = generate_compliance_report("hipaa", actions, verification_passed=True)
    assert report["compliance_framework"] == "HIPAA Safe Harbor"
    assert "email_addresses" in report["identifiers_covered"]
    assert "phone_numbers" in report["identifiers_covered"]
    assert "ssn" in report["identifiers_covered"]
    assert "ip_addresses" in report["identifiers_covered"]
    assert "names" in report["identifiers_covered"]


# Compliance report: empty actions → gaps reported
def test_compliance_report_gaps_when_no_pii_found():
    actions = [{"action": "generic_sanitize", "pii_types_found": []}]
    report = generate_compliance_report("hipaa", actions, verification_passed=False)
    assert len(report["gaps"]) > 0, "Should report gaps when no PII actions recorded"
    assert "email_addresses" in report["gaps"]


# Compliance report: GDPR mode returns correct framework name
def test_compliance_report_gdpr_framework_name():
    actions = []
    report = generate_compliance_report("gdpr", actions, verification_passed=True)
    assert "GDPR" in report["compliance_framework"]


# Compliance report: CCPA mode returns correct framework name
def test_compliance_report_ccpa_framework_name():
    actions = []
    report = generate_compliance_report("ccpa", actions, verification_passed=False)
    assert "CCPA" in report["compliance_framework"]
    assert report["verification_passed"] is False


# Cross: extra_tables parameter takes effect — custom table nuked
def test_extra_tables_parameter_respected():
    db = make_db(
        "CREATE TABLE custom_health_records (id INTEGER PRIMARY KEY, data TEXT)",
        [(1, "sensitive medical note"), (2, "another record")],
        "INSERT INTO custom_health_records VALUES (?, ?)",
    )
    try:
        sanitize_database_generic(db, extra_tables={"custom_health_records"})
        rows = read_all(db, "SELECT COUNT(*) FROM custom_health_records")
        assert rows[0][0] == 0, "custom extra_table not nuked"
    finally:
        db.unlink(missing_ok=True)


# Cross: extra_columns parameter takes effect — custom column redacted
def test_extra_columns_parameter_respected():
    db = make_db(
        "CREATE TABLE records (id INTEGER PRIMARY KEY, patient_secret_code TEXT)",
        [(1, "SECRET-ABC-123")],
        "INSERT INTO records VALUES (?, ?)",
    )
    try:
        sanitize_database_generic(db, extra_columns={"patient_secret_code"})
        rows = read_all(db, "SELECT patient_secret_code FROM records")
        for (val,) in rows:
            assert val == "[REDACTED]", f"custom extra_column not redacted: {val!r}"
    finally:
        db.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Finding #5 — HIPAA Safe Harbor date generalization + ZIP truncation are now
# real, tested transforms (previously date_generalization/zip_truncation were
# dead flags that never touched the data).
# ---------------------------------------------------------------------------

def test_truncate_zip_keeps_first_three_digits():
    assert truncate_zip("90210") == "902"
    assert truncate_zip("94103") == "941"


def test_truncate_zip_restricted_prefix_becomes_000():
    # 036 / 059 are among the 17 low-population prefixes -> must generalize to 000.
    assert truncate_zip("03601") == "000"
    assert truncate_zip("036") == "000"
    assert truncate_zip("05901") == "000"


def test_truncate_zip_plus_four_form():
    assert truncate_zip("90210-1234") == "902"


def test_truncate_zip_fail_closed_when_no_zip_digits():
    # A helper that de-identifies must never return the original on failure.
    assert truncate_zip("N/A") == "000"
    assert truncate_zip("") == "000"


def test_generalize_date_iso_drops_month_and_day():
    out = generalize_date("2019-03-14")
    assert out == "2019"
    assert "03" not in out and "14" not in out


def test_generalize_date_us_slash_form():
    assert generalize_date("03/14/2019") == "2019"


def test_generalize_date_textual_form():
    assert generalize_date("March 15, 1985") == "1985"


def test_generalize_date_compact_eight_digit_forms():
    assert generalize_date("20190314") == "2019"   # YYYYMMDD
    assert generalize_date("03142019") == "2019"   # MMDDYYYY


def test_generalize_date_fail_closed_on_two_digit_year():
    # Cannot confidently recover a 4-digit year -> redact, never leak day/month.
    out = generalize_date("03/14/85")
    assert out == "[REDACTED]"
    assert "14" not in out and "85" not in out


def test_generalize_date_empty_is_redacted():
    assert generalize_date("") == "[REDACTED]"


def test_hipaa_profile_transform_value_applies_safe_harbor():
    # Audit scenario values: encounter_date='2019-03-14', zip='90210'.
    profile = get_compliance_profile("hipaa")
    assert profile.transform_value("encounter_date", "2019-03-14") == "2019"
    assert profile.transform_value("zip", "90210") == "902"
    assert profile.transform_value("date_of_birth", "1985-03-15") == "1985"
    assert profile.transform_value("postal_code", "03601") == "000"
    # Columns that are neither dates nor ZIPs pass through untouched.
    assert profile.transform_value("notes", "hello world") == "hello world"


def test_non_hipaa_profile_transform_value_is_noop():
    # date_generalization / zip_truncation are HIPAA-only; other profiles leave
    # the flags off, so transform_value must not mutate values.
    profile = get_compliance_profile("gdpr")
    assert profile.transform_value("zip", "90210") == "90210"
    assert profile.transform_value("date_of_birth", "1985-03-15") == "1985-03-15"


def test_all_profile_transform_value_applies_safe_harbor():
    profile = get_compliance_profile("all")
    assert profile.transform_value("dob", "12/25/1990") == "1990"
    assert profile.transform_value("zipcode", "90210") == "902"


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
            import traceback
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    import sys
    sys.exit(1 if failed else 0)
