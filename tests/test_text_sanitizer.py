"""Tests for text file sanitization — JSON, logs, CSV, shell history."""

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.text_sanitizer import (
    sanitize_json, sanitize_log_file, sanitize_csv,
    delete_shell_history, sanitize_all_text_files,
    _redact_pii_in_string, _partition_by_size,
)


def test_json_sensitive_key_redaction():
    d = tempfile.mkdtemp()
    f = Path(d) / "config.json"
    f.write_text(json.dumps({
        "username": "jdoe",
        "password": "hunter2",
        "api_key": "sk-abc123",
        "version": "1.0",
    }))
    result = sanitize_json(f)
    assert result["keys_redacted"] >= 3
    data = json.loads(f.read_text())
    assert data["username"] == "[REDACTED]"
    assert data["password"] == "[REDACTED]"
    assert data["api_key"] == "[REDACTED]"
    assert data["version"] == "1.0"
    shutil.rmtree(d)


def test_json_nested_sensitive_keys():
    d = tempfile.mkdtemp()
    f = Path(d) / "nested.json"
    f.write_text(json.dumps({
        "app": {
            "auth": {"token": "eyJhbGciOiJIUzI1NiJ9", "refresh_token": "rt_abc"},
            "settings": {"theme": "dark"},
        }
    }))
    sanitize_json(f)
    data = json.loads(f.read_text())
    assert data["app"]["auth"]["token"] == "[REDACTED]"
    assert data["app"]["auth"]["refresh_token"] == "[REDACTED]"
    assert data["app"]["settings"]["theme"] == "dark"
    shutil.rmtree(d)


def test_json_pii_in_values():
    d = tempfile.mkdtemp()
    f = Path(d) / "data.json"
    f.write_text(json.dumps({
        "message": "Contact user@example.com for details",
        "note": "Call (555) 123-4567",
    }))
    sanitize_json(f)
    data = json.loads(f.read_text())
    assert "user@example.com" not in data["message"]
    assert "REDACTED" in data["message"]
    shutil.rmtree(d)


def test_log_file_email_redaction():
    d = tempfile.mkdtemp()
    f = Path(d) / "app.log"
    f.write_text("2024-01-01 Login from admin@company.com succeeded\n"
                 "2024-01-01 System startup complete\n"
                 "2024-01-02 Error for user@test.org at 192.168.1.50\n")
    result = sanitize_log_file(f)
    assert result["lines_redacted"] >= 2
    content = f.read_text()
    assert "admin@company.com" not in content
    assert "user@test.org" not in content
    assert "System startup complete" in content
    shutil.rmtree(d)


def test_log_file_phone_redaction():
    d = tempfile.mkdtemp()
    f = Path(d) / "sms.log"
    f.write_text("Sent to +1-555-123-4567\nReceived from (800) 555-0199\n")
    result = sanitize_log_file(f)
    assert result["lines_redacted"] >= 1
    content = f.read_text()
    assert "555-123-4567" not in content or "REDACTED" in content
    shutil.rmtree(d)


def test_csv_header_based_redaction():
    d = tempfile.mkdtemp()
    f = Path(d) / "users.csv"
    f.write_text("id,email,name,phone,role\n"
                 "1,alice@test.com,Alice Smith,(555) 111-2222,admin\n"
                 "2,bob@test.com,Bob Jones,(555) 333-4444,user\n")
    result = sanitize_csv(f)
    assert result["cells_redacted"] >= 4
    content = f.read_text()
    assert "alice@test.com" not in content
    assert "bob@test.com" not in content
    shutil.rmtree(d)


def test_csv_pii_in_non_header_cells():
    d = tempfile.mkdtemp()
    f = Path(d) / "notes.csv"
    f.write_text("id,notes\n"
                 "1,Contact user@hidden.com for help\n"
                 "2,Nothing special here\n")
    sanitize_csv(f)
    content = f.read_text()
    assert "user@hidden.com" not in content
    shutil.rmtree(d)


## ─────────────────────────────────────────────────────────────────────────
## #19: _redact_pii_in_string ignored reg.context_patterns entirely, so
## date_of_birth/password_kv/drivers_license/us_passport/aws_secret_key/npi/
## etc. (detectors that live ONLY in context_patterns) were never redacted
## from JSON, log, or CSV output.
## ─────────────────────────────────────────────────────────────────────────

def test_context_pattern_dob_and_password_redacted_in_log():
    """Exact audit failure scenario: a log line with a labeled DOB and a
    plaintext password= must have BOTH redacted. Neither date_of_birth nor
    password_kv has a standalone regex_patterns counterpart, so before the
    fix this line passed through completely untouched."""
    d = tempfile.mkdtemp()
    f = Path(d) / "app.log"
    f.write_text("User record: DOB: 03/14/1985  password=hunter2 for user jdoe\n")
    result = sanitize_log_file(f)
    content = f.read_text()
    assert "03/14/1985" not in content, "DOB must be redacted"
    assert "hunter2" not in content, "plaintext password must be redacted"
    assert result["lines_redacted"] >= 1
    assert "date_of_birth" in result["pii_types"]
    assert "password_kv" in result["pii_types"]
    shutil.rmtree(d)


def test_context_pattern_password_redacted_in_json_value():
    """A plaintext password embedded in a JSON string VALUE under a
    non-sensitive key name must be caught by the password_kv context
    pattern, not only by key-name-based redaction."""
    d = tempfile.mkdtemp()
    f = Path(d) / "notes.json"
    f.write_text(json.dumps({
        "note": "login uses password=hunter2 for the shared account",
    }))
    sanitize_json(f)
    data = json.loads(f.read_text())
    assert "hunter2" not in data["note"]
    assert "REDACTED" in data["note"]
    shutil.rmtree(d)


def test_context_pattern_dob_redacted_in_csv_cell():
    """A DOB inside a free-text CSV cell (not a dedicated 'dob' column) must
    be redacted via the date_of_birth context pattern."""
    d = tempfile.mkdtemp()
    f = Path(d) / "notes.csv"
    f.write_text("id,notes\n"
                 "1,Patient DOB: 03/14/1985 admitted for follow-up\n")
    sanitize_csv(f)
    content = f.read_text()
    assert "03/14/1985" not in content
    shutil.rmtree(d)


def test_context_pattern_requires_keyword_gating():
    """Context patterns must stay keyword-gated, not fire unconditionally:
    the exact same 40-char token is left alone with no nearby keyword, and
    redacted once an 'aws secret key' keyword is nearby. This guards against
    a regression that treats every context-pattern regex hit as an
    unconditional match (which would reintroduce false positives on ordinary
    identifiers the context gate is meant to filter out)."""
    token = "Qk9ndXM5eEp2WjNyVGZLbDJtSGRQY1lXaU5vQXpS"  # 40 base64-alphabet chars
    no_keyword = f"Backup blob {token} stored on the volume"
    redacted, found = _redact_pii_in_string(no_keyword)
    assert redacted == no_keyword, "no nearby keyword -> must not be redacted"
    assert found == []

    with_keyword = f"AWS secret key {token} rotated last night"
    redacted2, found2 = _redact_pii_in_string(with_keyword)
    assert token not in redacted2
    assert "aws_secret_key" in found2


## ─────────────────────────────────────────────────────────────────────────
## #20: 'address' was absent from sensitive_json_keys, so CSV columns and
## JSON keys literally named address/city/zip/employer passed through
## unredacted. The registry now carries the 'address' category; these tests
## prove sanitize_csv/sanitize_json actually honor it end to end.
## ─────────────────────────────────────────────────────────────────────────

def test_csv_address_city_zip_redacted():
    """Exact audit failure scenario: a CSV headed name,address,city,zip must
    have the address/city/zip values redacted, not just 'name'."""
    d = tempfile.mkdtemp()
    f = Path(d) / "contacts.csv"
    f.write_text("name,address,city,zip\n"
                 "John Doe,742 Evergreen Terrace,Springfield,62704\n")
    result = sanitize_csv(f)
    content = f.read_text()
    assert "742 Evergreen Terrace" not in content, "street address must be redacted"
    assert "Springfield" not in content, "city must be redacted"
    assert "62704" not in content, "zip must be redacted"
    assert "John Doe" not in content, "name must still be redacted (regression guard)"
    assert result["cells_redacted"] >= 4
    shutil.rmtree(d)


def test_json_address_keys_redacted():
    """A JSON key named 'home_address'/'city'/'zip'/'employer' must be
    redacted via the 'address' sensitive_json_keys category, while an
    unrelated key is left alone."""
    d = tempfile.mkdtemp()
    f = Path(d) / "profile.json"
    f.write_text(json.dumps({
        "home_address": "221B Baker Street",
        "city": "London",
        "zip": "NW16XE",
        "employer": "Scotland Yard",
        "hobby": "violin",
    }))
    sanitize_json(f)
    data = json.loads(f.read_text())
    assert data["home_address"] == "[REDACTED]"
    assert data["city"] == "[REDACTED]"
    assert data["zip"] == "[REDACTED]"
    assert data["employer"] == "[REDACTED]"
    assert data["hobby"] == "violin", "unrelated key must survive (regression guard)"
    shutil.rmtree(d)


## ─────────────────────────────────────────────────────────────────────────
## #21: files over the size limit were filtered out of the workload with no
## record anywhere -- neither sanitized nor flagged, a silent PII
## passthrough. Every excluded file must now be recorded as a residual
## action, fail closed, so the run can never be mistaken for having fully
## processed the dump.
## ─────────────────────────────────────────────────────────────────────────

def test_oversize_log_file_skipped_is_recorded_not_silently_dropped():
    """A log file over its size limit must be left completely unsanitized
    (its PII survives on disk) AND recorded as an explicit skipped action --
    never just absent from both the file and the action list."""
    d = tempfile.mkdtemp()
    root = Path(d)
    f = root / "huge.log"
    pii_line = "Contact admin@company.com about the outage\n"
    f.write_text(pii_line)

    # A tiny limit stands in for a real >10MB oversize file without writing
    # tens of MB to disk in a test.
    actions = sanitize_all_text_files(root, log_size_limit=10)

    content = f.read_text()
    assert content == pii_line, "oversize file must be left untouched, not partially processed"
    assert "admin@company.com" in content, "PII survives because the file was never sanitized"

    skipped = [a for a in actions
               if a.get("action") == "text_sanitize_skipped" and a.get("path") == str(f)]
    assert skipped, "an oversize file must be recorded as skipped, never silently dropped"
    assert "error" in skipped[0]
    assert skipped[0]["file_type"] == "log"
    shutil.rmtree(d)


def test_oversize_json_file_skipped_is_recorded():
    """Same fail-closed guarantee for the JSON workload: an oversize JSON
    file keeps its PII on disk and is recorded as skipped."""
    d = tempfile.mkdtemp()
    root = Path(d)
    f = root / "big.json"
    f.write_text(json.dumps({"email": "user@example.com"}))

    actions = sanitize_all_text_files(root, json_size_limit=5)

    data = json.loads(f.read_text())
    assert data["email"] == "user@example.com", "oversize JSON must be left unsanitized"

    skipped = [a for a in actions
               if a.get("action") == "text_sanitize_skipped" and a.get("path") == str(f)]
    assert skipped
    assert skipped[0]["file_type"] == "json"
    shutil.rmtree(d)


def test_oversize_csv_file_skipped_is_recorded():
    """Same fail-closed guarantee for the CSV workload."""
    d = tempfile.mkdtemp()
    root = Path(d)
    f = root / "big.csv"
    f.write_text("email\nuser@example.com\n")

    actions = sanitize_all_text_files(root, csv_size_limit=5)

    content = f.read_text()
    assert "user@example.com" in content, "oversize CSV must be left unsanitized"
    skipped = [a for a in actions
               if a.get("action") == "text_sanitize_skipped" and a.get("path") == str(f)]
    assert skipped
    assert skipped[0]["file_type"] == "csv"
    shutil.rmtree(d)


def test_partition_by_size_records_unstatable_file():
    """A file that vanishes/cannot be stat'd must also be recorded as a
    residual -- never silently excluded with zero trace."""
    ghost_root = Path(tempfile.mkdtemp())
    ghost = ghost_root / "does" / "not" / "exist.log"
    within, residual = _partition_by_size([ghost], 1024, "log")
    assert within == []
    assert len(residual) == 1
    assert residual[0]["action"] == "text_sanitize_skipped"
    assert "error" in residual[0]
    shutil.rmtree(ghost_root)


def test_within_limit_files_are_still_sanitized():
    """Regression guard: files within the size limit must still go through
    normal sanitization and produce zero residual entries for them."""
    d = tempfile.mkdtemp()
    root = Path(d)
    f = root / "small.log"
    f.write_text("Contact admin@company.com about the outage\n")

    actions = sanitize_all_text_files(root)

    content = f.read_text()
    assert "admin@company.com" not in content
    residual = [a for a in actions if a.get("action") == "text_sanitize_skipped"]
    assert residual == []
    shutil.rmtree(d)


def test_shell_history_deletion():
    d = tempfile.mkdtemp()
    hist = Path(d) / ".bash_history"
    hist.write_text("ssh root@192.168.1.1\nmysql -u admin -p secret\n")
    delete_shell_history(hist)
    assert not hist.exists(), ".bash_history should be deleted"
    shutil.rmtree(d)


def test_sanitize_all_text_files():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "config.json").write_text(json.dumps({"password": "secret"}))
    (root / "app.log").write_text("Login from admin@test.com\n")
    (root / ".zsh_history").write_text("curl -u user:pass http://api.com\n")
    actions = sanitize_all_text_files(root)
    assert len(actions) >= 3
    assert not (root / ".zsh_history").exists()
    shutil.rmtree(d)


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
