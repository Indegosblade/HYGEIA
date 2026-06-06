"""Basic tests for HYGEIA plist sanitizer module."""

import plistlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.plist_sanitizer import sanitize_plist, _is_sensitive_key


def test_sensitive_key_detection():
    assert _is_sensitive_key("UserEmail") is True
    assert _is_sensitive_key("AuthToken") is True
    assert _is_sensitive_key("password") is True
    assert _is_sensitive_key("iCloudAccount") is True
    assert _is_sensitive_key("BundleVersion") is False
    assert _is_sensitive_key("HardwareModel") is False


def test_plist_sanitization():
    with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as f:
        plist_path = Path(f.name)

    data = {
        "UserEmail": "test@icloud.com",
        "AuthToken": "abc123secret",
        "BundleVersion": "1.0.0",
        "nested": {
            "password": "hunter2",
            "systemversion": "15.5",
        }
    }
    with open(plist_path, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)

    result = sanitize_plist(plist_path)
    assert len(result["keys_redacted"]) >= 3

    with open(plist_path, "rb") as f:
        sanitized = plistlib.load(f)

    assert sanitized["UserEmail"] == "[REDACTED]"
    assert sanitized["AuthToken"] == "[REDACTED]"
    assert sanitized["BundleVersion"] == "1.0.0"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["nested"]["systemversion"] == "15.5"

    plist_path.unlink()


if __name__ == "__main__":
    test_sensitive_key_detection()
    test_plist_sanitization()
    print("All tests passed.")
