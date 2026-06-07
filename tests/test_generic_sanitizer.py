"""Tests for generic SQLite PII sanitizer — the core of v2.0.0."""

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.sqlite_sanitizer import sanitize_database_generic


def _make_db(tables_and_data: dict) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path = Path(f.name)
    f.close()
    conn = sqlite3.connect(str(db_path))
    for table, (schema, rows) in tables_and_data.items():
        conn.execute(f"CREATE TABLE {table} ({schema})")
        if rows:
            placeholders = ", ".join("?" * len(rows[0]))
            conn.executemany(f"INSERT INTO {table} VALUES ({placeholders})", rows)
    conn.commit()
    conn.close()
    return db_path


def test_email_detection():
    db = _make_db({"notes": ("id INTEGER, content TEXT", [
        (1, "Contact support@example.com for help"),
        (2, "No PII here"),
        (3, "user@icloud.com is my apple id"),
    ])})
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 2, f"Expected 2+ redacted, got {result['rows_redacted']}"
    conn = sqlite3.connect(str(db))
    rows = conn.execute("SELECT content FROM notes WHERE content LIKE '%@%' AND content NOT LIKE '%REDACTED%'").fetchall()
    conn.close()
    assert len(rows) == 0, f"Emails survived: {rows}"
    db.unlink()


def test_phone_us_detection():
    db = _make_db({"logs": ("id INTEGER, msg TEXT", [
        (1, "Call me at (555) 123-4567"),
        (2, "Phone: +1-800-555-0199"),
        (3, "No numbers here"),
    ])})
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 2
    conn = sqlite3.connect(str(db))
    for row in conn.execute("SELECT msg FROM logs").fetchall():
        assert "555" not in row[0] or "REDACTED" in row[0], f"Phone survived: {row[0]}"
    conn.close()
    db.unlink()


def test_phone_intl_detection():
    db = _make_db({"contacts": ("id INTEGER, phone TEXT", [
        (1, "+44 20 7946 0958"),
        (2, "+49 30 123456789"),
        (3, "+91 98765 43210"),
    ])})
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 2
    db.unlink()


def test_ssn_detection():
    db = _make_db({"records": ("id INTEGER, info TEXT", [
        (1, "SSN: 123-45-6789"),
        (2, "Regular text"),
    ])})
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 1
    conn = sqlite3.connect(str(db))
    vals = [r[0] for r in conn.execute("SELECT info FROM records").fetchall()]
    conn.close()
    assert not any("123-45-6789" in v for v in vals), "SSN survived"
    db.unlink()


def test_credit_card_detection():
    db = _make_db({"payments": ("id INTEGER, note TEXT", [
        (1, "Card: 4111 1111 1111 1111"),
        (2, "Amex: 3782-822463-10005"),
        (3, "No card here"),
    ])})
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 1
    db.unlink()


def test_ip_v4_detection():
    db = _make_db({"access": ("id INTEGER, addr TEXT", [
        (1, "Login from 192.168.1.100"),
        (2, "Server at 10.0.0.1"),
    ])})
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 1
    db.unlink()


def test_iban_detection():
    db = _make_db({"bank": ("id INTEGER, account TEXT", [
        (1, "IBAN: DE89370400440532013000"),
        (2, "No IBAN"),
    ])})
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 1
    db.unlink()


def test_mac_address_detection():
    db = _make_db({"devices": ("id INTEGER, mac TEXT", [
        (1, "Device: AA:BB:CC:DD:EE:FF"),
        (2, "No MAC"),
    ])})
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 1
    db.unlink()


def test_sensitive_column_redaction():
    db = _make_db({"users": ("id INTEGER, email TEXT, password TEXT, username TEXT, display_name TEXT", [
        (1, "test@test.com", "secret123", "jdoe", "John Doe"),
        (2, "admin@corp.com", "hunter2", "admin", "Admin User"),
    ])})
    result = sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    rows = conn.execute("SELECT email, password, username FROM users").fetchall()
    conn.close()
    for row in rows:
        for val in row:
            assert val == "[REDACTED]", f"Sensitive column not redacted: {val}"
    db.unlink()


def test_pii_table_nuking():
    db = _make_db({
        "autofill": ("id INTEGER, name TEXT, value TEXT", [
            (1, "email", "user@test.com"),
            (2, "address", "123 Main St"),
        ]),
        "system_config": ("id INTEGER, key TEXT, value TEXT", [
            (1, "version", "1.0"),
        ]),
    })
    result = sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    autofill_count = conn.execute("SELECT COUNT(*) FROM autofill").fetchone()[0]
    config_count = conn.execute("SELECT COUNT(*) FROM system_config").fetchone()[0]
    conn.close()
    assert autofill_count == 0, "autofill table should be empty"
    assert config_count == 1, "system_config should be preserved"
    db.unlink()


def test_wal_cleanup():
    db = _make_db({"t": ("id INTEGER, val TEXT", [(1, "test@test.com")])})
    wal = Path(str(db) + "-wal")
    shm = Path(str(db) + "-shm")
    wal.write_bytes(b"fake wal")
    shm.write_bytes(b"fake shm")
    sanitize_database_generic(db)
    assert not wal.exists(), "WAL should be deleted"
    assert not shm.exists(), "SHM should be deleted"
    db.unlink()


def test_freelist_zero_after_vacuum():
    db = _make_db({"data": ("id INTEGER, val TEXT", [(i, f"row{i}") for i in range(1000)])})
    conn = sqlite3.connect(str(db))
    conn.execute("DELETE FROM data WHERE id > 10")
    conn.commit()
    conn.close()
    sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    conn.close()
    assert free == 0, f"Freelist should be 0, got {free}"
    db.unlink()


def test_fts_shadow_table_cleanup():
    db = _make_db({})
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE VIRTUAL TABLE search USING fts5(title, body)")
    conn.execute("INSERT INTO search VALUES ('Secret Email', 'Contact user@secret.com')")
    conn.execute("INSERT INTO search VALUES ('Password', 'My password is hunter2')")
    conn.commit()
    conn.close()
    sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    content = conn.execute("SELECT * FROM search_content").fetchall()
    conn.close()
    for row in content:
        row_str = str(row)
        assert "user@secret.com" not in row_str, f"FTS content survived: {row}"
    db.unlink()


def test_multi_pass_catches_embedded_email():
    db = _make_db({"urls": ("id INTEGER, data TEXT", [
        (1, "Visit https://example.com/profile?email=user@hidden.com&token=abc"),
    ])})
    sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    val = conn.execute("SELECT data FROM urls").fetchone()[0]
    conn.close()
    assert "user@hidden.com" not in val, f"Embedded email survived: {val}"
    db.unlink()


def test_compliance_extra_columns():
    db = _make_db({"patients": ("id INTEGER, patient_id TEXT, mrn TEXT, diagnosis TEXT", [
        (1, "P12345", "MRN-001", "Type 2 Diabetes"),
    ])})
    extra_cols = {"patient_id", "mrn", "diagnosis"}
    result = sanitize_database_generic(db, extra_columns=extra_cols)
    conn = sqlite3.connect(str(db))
    row = conn.execute("SELECT patient_id, mrn, diagnosis FROM patients").fetchone()
    conn.close()
    for val in row:
        assert val == "[REDACTED]", f"HIPAA column not redacted: {val}"
    db.unlink()


def test_compliance_extra_tables():
    db = _make_db({
        "purchase_history": ("id INTEGER, item TEXT, amount TEXT", [
            (1, "Widget", "$49.99"),
        ]),
    })
    extra_tbls = {"purchase_history"}
    result = sanitize_database_generic(db, extra_tables=extra_tbls)
    conn = sqlite3.connect(str(db))
    count = conn.execute("SELECT COUNT(*) FROM purchase_history").fetchone()[0]
    conn.close()
    assert count == 0, "CCPA table should be nuked"
    db.unlink()


def test_varchar_and_clob_types():
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db = Path(f.name)
    f.close()
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE chrome_data (id INTEGER, value LONGVARCHAR, memo CLOB)")
    conn.execute("INSERT INTO chrome_data VALUES (1, 'user@chrome.com', 'call 555-123-4567')")
    conn.commit()
    conn.close()
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 1
    db.unlink()


def test_empty_database():
    db = _make_db({"empty_table": ("id INTEGER, val TEXT", [])})
    result = sanitize_database_generic(db)
    assert result["tables_scanned"] >= 1
    assert result["rows_redacted"] == 0
    db.unlink()


def test_non_sqlite_file():
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.write(b"not a sqlite database")
    f.close()
    result = sanitize_database_generic(Path(f.name))
    assert "error" in result
    Path(f.name).unlink()


def test_jwt_detection():
    db = _make_db({"tokens": ("id INTEGER, data TEXT", [
        (1, "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
        (2, "No token here"),
    ])})
    result = sanitize_database_generic(db)
    assert result["rows_redacted"] >= 1
    conn = sqlite3.connect(str(db))
    val = conn.execute("SELECT data FROM tokens WHERE id=1").fetchone()[0]
    conn.close()
    assert "eyJhbGci" not in val, f"JWT survived: {val}"
    db.unlink()


def test_aws_key_detection():
    db = _make_db({"configs": ("id INTEGER, value TEXT", [
        (1, "aws_key=AKIAIOSFODNN7EXAMPLE"),
        (2, "safe value"),
    ])})
    result = sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    val = conn.execute("SELECT value FROM configs WHERE id=1").fetchone()[0]
    conn.close()
    assert "AKIAIOSFODNN7EXAMPLE" not in val, f"AWS key survived: {val}"
    db.unlink()


def test_eth_wallet_detection():
    db = _make_db({"wallets": ("id INTEGER, addr TEXT", [
        (1, "Send to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"),
    ])})
    result = sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    val = conn.execute("SELECT addr FROM wallets WHERE id=1").fetchone()[0]
    conn.close()
    assert "0x742d35Cc6634" not in val, f"ETH wallet survived: {val}"
    db.unlink()


def test_url_credentials_detection():
    db = _make_db({"urls": ("id INTEGER, link TEXT", [
        (1, "Connect to ftp://admin:secret@192.168.1.1/files"),
    ])})
    result = sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    val = conn.execute("SELECT link FROM urls WHERE id=1").fetchone()[0]
    conn.close()
    assert "admin:secret@" not in val, f"URL creds survived: {val}"
    db.unlink()


def test_uk_nino_detection():
    db = _make_db({"records": ("id INTEGER, info TEXT", [
        (1, "NI number: AB123456C"),
    ])})
    result = sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    val = conn.execute("SELECT info FROM records WHERE id=1").fetchone()[0]
    conn.close()
    assert "AB123456C" not in val, f"UK NINO survived: {val}"
    db.unlink()


def test_vin_detection():
    db = _make_db({"vehicles": ("id INTEGER, vin_num TEXT", [
        (1, "VIN: 1HGBH41JXMN109186"),
    ])})
    result = sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    val = conn.execute("SELECT vin_num FROM vehicles WHERE id=1").fetchone()[0]
    conn.close()
    assert "1HGBH41JXMN109186" not in val, f"VIN survived: {val}"
    db.unlink()


def test_expanded_pii_tables():
    db = _make_db({
        "moz_formhistory": ("id INTEGER, fieldname TEXT, value TEXT", [
            (1, "email", "user@test.com"),
        ]),
        "downloads": ("id INTEGER, url TEXT", [
            (1, "https://example.com/file.pdf"),
        ]),
        "safe_table": ("id INTEGER, val TEXT", [
            (1, "keep me"),
        ]),
    })
    result = sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    ff_count = conn.execute("SELECT COUNT(*) FROM moz_formhistory").fetchone()[0]
    dl_count = conn.execute("SELECT COUNT(*) FROM downloads").fetchone()[0]
    safe_count = conn.execute("SELECT COUNT(*) FROM safe_table").fetchone()[0]
    conn.close()
    assert ff_count == 0, "moz_formhistory should be nuked"
    assert dl_count == 0, "downloads should be nuked"
    assert safe_count == 1, "safe_table should be preserved"
    db.unlink()


def test_expanded_sensitive_columns():
    db = _make_db({"profiles": (
        "id INTEGER, passport TEXT, drivers_license TEXT, salary TEXT, imei TEXT, ssid TEXT",
        [(1, "C12345678", "D1234567", "$85000", "353456789012345", "MyHomeWifi"),]
    )})
    result = sanitize_database_generic(db)
    conn = sqlite3.connect(str(db))
    row = conn.execute("SELECT passport, drivers_license, salary, imei, ssid FROM profiles").fetchone()
    conn.close()
    for val in row:
        assert val == "[REDACTED]", f"Sensitive column not redacted: {val}"
    db.unlink()


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
