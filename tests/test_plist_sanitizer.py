"""Tests for HYGEIA plist sanitizer module."""

import plistlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.plist_sanitizer import (
    sanitize_plist,
    _is_sensitive_key,
    _is_redact_all_file,
)


# ---------------------------------------------------------------------------
# Existing tests — sensitive key detection + selective sanitization
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# New tests — redact_all_values_files detection
# ---------------------------------------------------------------------------

def test_redact_all_file_detection():
    """Files in redact_all_values_files list are recognised correctly."""
    assert _is_redact_all_file("data_ark.plist") is True
    assert _is_redact_all_file("com.apple.MobileGestalt.plist") is True
    assert _is_redact_all_file("com.apple.purplebuddy.plist") is True
    assert _is_redact_all_file("com.apple.mobileactivationd.plist") is True
    # Normal plists should NOT trigger redact-all
    assert _is_redact_all_file("com.apple.settings.plist") is False
    assert _is_redact_all_file("preferences.plist") is False


# ---------------------------------------------------------------------------
# data_ark.plist: ALL values redacted
# ---------------------------------------------------------------------------

def _write_plist(path: Path, data: dict) -> None:
    with open(path, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)


def _read_plist(path: Path) -> dict:
    with open(path, "rb") as f:
        return plistlib.load(f)


def test_data_ark_all_values_redacted():
    """data_ark.plist: every string and number is wiped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "data_ark.plist"
        data = {
            "SerialNumber": "C3Q9XXXXXXXX",
            "UniqueChipID": 123456789,
            "WiFiAddress": "aa:bb:cc:dd:ee:ff",
            "BluetoothAddress": "aa:bb:cc:dd:ee:00",
            "DeviceName": "Kevin's iPhone",
            "ProductType": "iPhone12,8",
            "MLBSerialNumber": "FAKEMLBSERIAL",
            "activation-state": "Activated",
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert result.get("mode") == "redact_all_values", (
            f"Expected mode=redact_all_values, got {result.get('mode')}"
        )
        assert len(result["keys_redacted"]) == len(data), (
            f"Expected {len(data)} keys redacted, got {len(result['keys_redacted'])}"
        )

        sanitized = _read_plist(plist_path)

        for key, original in data.items():
            value = sanitized[key]
            if isinstance(original, str):
                assert value == "[REDACTED]", (
                    f"Key '{key}': expected '[REDACTED]', got {value!r}"
                )
            elif isinstance(original, int):
                assert value == 0, (
                    f"Key '{key}': expected 0, got {value!r}"
                )


def test_data_ark_structure_preserved():
    """data_ark.plist: keys and plist structure are intact after redaction."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "data_ark.plist"
        data = {
            "SerialNumber": "C3Q9XXXXXXXX",
            "UniqueChipID": 987654321,
            "FlagEnabled": True,    # bool — should be preserved
            "nested": {
                "SubKey": "some_value",
                "SubNum": 42,
            },
        }
        _write_plist(plist_path, data)
        sanitize_plist(plist_path)
        sanitized = _read_plist(plist_path)

        # All original keys must still exist
        assert set(sanitized.keys()) == set(data.keys()), (
            f"Key set changed: {set(sanitized.keys())} != {set(data.keys())}"
        )
        # Nested dict structure preserved
        assert isinstance(sanitized["nested"], dict), "Nested dict lost"
        assert "SubKey" in sanitized["nested"]
        assert "SubNum" in sanitized["nested"]
        # Bool preserved unchanged
        assert sanitized["FlagEnabled"] is True, "Boolean value should not be redacted"
        # Strings and ints redacted
        assert sanitized["SerialNumber"] == "[REDACTED]"
        assert sanitized["UniqueChipID"] == 0
        assert sanitized["nested"]["SubKey"] == "[REDACTED]"
        assert sanitized["nested"]["SubNum"] == 0


def test_data_ark_bytes_cleared():
    """data_ark.plist: bytes values are cleared to empty bytes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "data_ark.plist"
        data = {
            "CertBlob": b"\xde\xad\xbe\xef" * 16,
            "SerialNumber": "ABC123",
        }
        _write_plist(plist_path, data)
        sanitize_plist(plist_path)
        sanitized = _read_plist(plist_path)

        assert sanitized["CertBlob"] == b"", (
            f"bytes should be cleared, got {sanitized['CertBlob']!r}"
        )
        assert sanitized["SerialNumber"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# Other redact-all files behave the same way
# ---------------------------------------------------------------------------

def test_mobile_gestalt_redact_all():
    """com.apple.MobileGestalt.plist triggers redact-all mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "com.apple.MobileGestalt.plist"
        data = {
            "UniqueDeviceID": "DEADBEEF000000000000000000000000DEADBEEF",
            "SerialNumber": "XXXXXXXXXXX",
            "CPUArchitecture": "arm64e",
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert result.get("mode") == "redact_all_values"
        sanitized = _read_plist(plist_path)
        for key in data:
            assert sanitized[key] == "[REDACTED]", (
                f"Key '{key}' not redacted in MobileGestalt"
            )


def test_purplebuddy_redact_all():
    """com.apple.purplebuddy.plist triggers redact-all mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "com.apple.purplebuddy.plist"
        data = {
            "SetupDone": True,
            "ActivationToken": "tok_abc123",
            "ActivationCount": 3,
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert result.get("mode") == "redact_all_values"
        sanitized = _read_plist(plist_path)
        assert sanitized["SetupDone"] is True       # bool preserved
        assert sanitized["ActivationToken"] == "[REDACTED]"
        assert sanitized["ActivationCount"] == 0


def test_mobileactivationd_redact_all():
    """com.apple.mobileactivationd.plist triggers redact-all mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "com.apple.mobileactivationd.plist"
        data = {
            "ActivationRecord": "base64stuff==",
            "DeviceClass": "iPhone",
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert result.get("mode") == "redact_all_values"
        sanitized = _read_plist(plist_path)
        assert sanitized["ActivationRecord"] == "[REDACTED]"
        assert sanitized["DeviceClass"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# Normal plists are NOT affected by redact-all mode
# ---------------------------------------------------------------------------

def test_normal_plist_not_redact_all():
    """An ordinary .plist uses selective (sensitive key) mode, not redact-all."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "com.apple.settings.plist"
        data = {
            "UserEmail": "test@example.com",   # sensitive key → redacted
            "SystemVersion": "15.5",            # safe key → preserved
            "BuildNumber": 19,                  # safe key → preserved
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert result.get("mode") == "sensitive_keys", (
            f"Normal plist should use sensitive_keys mode, got {result.get('mode')}"
        )
        sanitized = _read_plist(plist_path)
        assert sanitized["UserEmail"] == "[REDACTED]"
        assert sanitized["SystemVersion"] == "15.5"   # NOT redacted
        assert sanitized["BuildNumber"] == 19          # NOT redacted


def test_normal_plist_non_sensitive_keys_untouched():
    """A normal plist with no sensitive keys is written back unchanged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "preferences.plist"
        data = {
            "DarkMode": True,
            "FontSize": 14,
            "Language": "en-US",
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert result.get("mode") == "sensitive_keys"
        assert result["keys_redacted"] == [], "No keys should be redacted"

        sanitized = _read_plist(plist_path)
        assert sanitized["DarkMode"] is True
        assert sanitized["FontSize"] == 14
        assert sanitized["Language"] == "en-US"


if __name__ == "__main__":
    test_sensitive_key_detection()
    test_plist_sanitization()
    test_redact_all_file_detection()
    test_data_ark_all_values_redacted()
    test_data_ark_structure_preserved()
    test_data_ark_bytes_cleared()
    test_mobile_gestalt_redact_all()
    test_purplebuddy_redact_all()
    test_mobileactivationd_redact_all()
    test_normal_plist_not_redact_all()
    test_normal_plist_non_sensitive_keys_untouched()
    print("All tests passed.")
