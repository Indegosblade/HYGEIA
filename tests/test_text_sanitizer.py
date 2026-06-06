"""Tests for text file sanitization — JSON, logs, CSV, shell history."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.text_sanitizer import (
    sanitize_json, sanitize_log_file, sanitize_csv,
    delete_shell_history, sanitize_all_text_files,
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
    import shutil; shutil.rmtree(d)


def test_json_nested_sensitive_keys():
    d = tempfile.mkdtemp()
    f = Path(d) / "nested.json"
    f.write_text(json.dumps({
        "app": {
            "auth": {"token": "eyJhbGciOiJIUzI1NiJ9", "refresh_token": "rt_abc"},
            "settings": {"theme": "dark"},
        }
    }))
    result = sanitize_json(f)
    data = json.loads(f.read_text())
    assert data["app"]["auth"]["token"] == "[REDACTED]"
    assert data["app"]["auth"]["refresh_token"] == "[REDACTED]"
    assert data["app"]["settings"]["theme"] == "dark"
    import shutil; shutil.rmtree(d)


def test_json_pii_in_values():
    d = tempfile.mkdtemp()
    f = Path(d) / "data.json"
    f.write_text(json.dumps({
        "message": "Contact user@example.com for details",
        "note": "Call (555) 123-4567",
    }))
    result = sanitize_json(f)
    data = json.loads(f.read_text())
    assert "user@example.com" not in data["message"]
    assert "REDACTED" in data["message"]
    import shutil; shutil.rmtree(d)


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
    import shutil; shutil.rmtree(d)


def test_log_file_phone_redaction():
    d = tempfile.mkdtemp()
    f = Path(d) / "sms.log"
    f.write_text("Sent to +1-555-123-4567\nReceived from (800) 555-0199\n")
    result = sanitize_log_file(f)
    assert result["lines_redacted"] >= 1
    content = f.read_text()
    assert "555-123-4567" not in content or "REDACTED" in content
    import shutil; shutil.rmtree(d)


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
    import shutil; shutil.rmtree(d)


def test_csv_pii_in_non_header_cells():
    d = tempfile.mkdtemp()
    f = Path(d) / "notes.csv"
    f.write_text("id,notes\n"
                 "1,Contact user@hidden.com for help\n"
                 "2,Nothing special here\n")
    result = sanitize_csv(f)
    content = f.read_text()
    assert "user@hidden.com" not in content
    import shutil; shutil.rmtree(d)


def test_shell_history_deletion():
    d = tempfile.mkdtemp()
    hist = Path(d) / ".bash_history"
    hist.write_text("ssh root@192.168.1.1\nmysql -u admin -p secret\n")
    result = delete_shell_history(hist)
    assert not hist.exists(), ".bash_history should be deleted"
    import shutil; shutil.rmtree(d)


def test_sanitize_all_text_files():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "config.json").write_text(json.dumps({"password": "secret"}))
    (root / "app.log").write_text("Login from admin@test.com\n")
    (root / ".zsh_history").write_text("curl -u user:pass http://api.com\n")
    actions = sanitize_all_text_files(root)
    assert len(actions) >= 3
    assert not (root / ".zsh_history").exists()
    import shutil; shutil.rmtree(d)


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
