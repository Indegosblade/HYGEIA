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


# ---------------------------------------------------------------------------
# Regex PII scan — universal second pass
# ---------------------------------------------------------------------------

def test_regex_scan_email_in_arbitrary_key():
    """An email address buried under a non-sensitive key gets regex-redacted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "cloud.quota.plist"
        data = {
            "CloudStorageCapacity": 5368709120,    # int — untouched
            "CloudContactInfo": "drvged@gmail.com",  # non-sensitive key name, email value
            "CloudEnabled": True,               # bool — untouched
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert any(t == "email" for _, t in result["regex_hits"]), (
            f"Expected email hit in regex_hits, got: {result['regex_hits']}"
        )
        sanitized = _read_plist(plist_path)
        assert "drvged@gmail.com" not in sanitized["CloudContactInfo"], (
            f"Raw email should be gone, got: {sanitized['CloudContactInfo']!r}"
        )
        assert "[REDACTED_EMAIL]" in sanitized["CloudContactInfo"]
        # Non-string values untouched
        assert sanitized["CloudStorageCapacity"] == 5368709120
        assert sanitized["CloudEnabled"] is True


def test_regex_scan_phone_in_nested_dict():
    """A phone number buried in a nested dict is found and redacted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "itunescloud.plist"
        data = {
            "StorefrontInfo": {
                "Region": "US",
                "ContactNumber": "+1 (555) 867-5309",
            },
            "Version": "4.2",
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        hits_flat = [t for _, t in result["regex_hits"]]
        assert "phone_us" in hits_flat, (
            f"Expected phone_us hit, got: {result['regex_hits']}"
        )
        sanitized = _read_plist(plist_path)
        assert "+1 (555) 867-5309" not in sanitized["StorefrontInfo"]["ContactNumber"]
        assert sanitized["Version"] == "4.2"  # non-sensitive string, no PII → unchanged


def test_regex_scan_binary_plist():
    """A binary plist with PII in an arbitrary key gets regex-scanned."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "apsd.plist"
        data = {
            "ServerAddress": "192.168.1.100",   # IP address — should be redacted
            "Port": 443,                          # int — untouched
            "Enabled": True,                      # bool — untouched
        }
        # Write as binary plist
        with open(plist_path, "wb") as f:
            plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)

        # Verify it really is binary
        with open(plist_path, "rb") as f:
            assert f.read(6) == b"bplist", "Test fixture must be a binary plist"

        result = sanitize_plist(plist_path)

        assert any(t == "ip_v4" for _, t in result["regex_hits"]), (
            f"Expected ip_v4 regex hit, got: {result['regex_hits']}"
        )
        sanitized = _read_plist(plist_path)
        assert "192.168.1.100" not in sanitized["ServerAddress"]
        assert "[REDACTED_IP_V4]" in sanitized["ServerAddress"]
        assert sanitized["Port"] == 443
        assert sanitized["Enabled"] is True

        # Verify output is still binary plist
        with open(plist_path, "rb") as f:
            assert f.read(6) == b"bplist", "Output should remain a binary plist"


def test_regex_scan_mac_address():
    """A MAC address in a plist value gets regex-redacted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "Accessibility.plist"
        data = {
            "NetworkInterface": "en0",
            "HardwareAddress": "aa:bb:cc:dd:ee:ff",
            "AutoConnect": True,
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert any(t == "mac_addr" for _, t in result["regex_hits"]), (
            f"Expected mac_addr hit, got: {result['regex_hits']}"
        )
        sanitized = _read_plist(plist_path)
        assert "aa:bb:cc:dd:ee:ff" not in sanitized["HardwareAddress"]
        assert "[REDACTED_MAC_ADDR]" in sanitized["HardwareAddress"]
        assert sanitized["NetworkInterface"] == "en0"  # no PII — untouched


def test_regex_scan_imei():
    """An IMEI in a plist value gets regex-redacted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "cmfsyncagent.plist"
        data = {
            "DeviceIMEI": "35-123456-123456-7",
            "SyncEnabled": True,
            "SyncCount": 12,
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert any(t == "imei" for _, t in result["regex_hits"]), (
            f"Expected imei hit, got: {result['regex_hits']}"
        )
        sanitized = _read_plist(plist_path)
        assert "35-123456-123456-7" not in sanitized["DeviceIMEI"]
        assert sanitized["SyncCount"] == 12
        assert sanitized["SyncEnabled"] is True


def test_non_string_values_untouched():
    """Integers, floats, booleans, bytes, and dates are not modified by regex scan."""
    import datetime
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "test.plist"
        now = datetime.datetime(2024, 1, 1, 12, 0, 0)
        data = {
            "IntVal": 42,
            "FloatVal": 3.14,
            "BoolTrue": True,
            "BoolFalse": False,
            "BytesVal": b"\xde\xad\xbe\xef",
            "DateVal": now,
            "SafeString": "hello world",  # no PII
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        # No regex hits and no key-based redactions expected
        assert result["regex_hits"] == [], f"Unexpected regex hits: {result['regex_hits']}"
        assert result["keys_redacted"] == [], f"Unexpected key redactions: {result['keys_redacted']}"

        sanitized = _read_plist(plist_path)
        assert sanitized["IntVal"] == 42
        assert abs(sanitized["FloatVal"] - 3.14) < 1e-9
        assert sanitized["BoolTrue"] is True
        assert sanitized["BoolFalse"] is False
        assert sanitized["BytesVal"] == b"\xde\xad\xbe\xef"
        assert sanitized["SafeString"] == "hello world"


def test_key_based_and_regex_scan_together():
    """A plist with both a 'password' key AND an email in another value: both get redacted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "facetime.bag.plist"
        data = {
            "password": "supersecret",           # key-based hit (sensitive key)
            "ContactBackup": "user@example.com", # non-sensitive key, regex hit
            "Version": "2.0",                    # no PII
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        # Key-based redaction should catch 'password'
        assert "password" in result["keys_redacted"], (
            f"'password' should be in keys_redacted: {result['keys_redacted']}"
        )
        # Regex scan should catch the email in 'ContactBackup'
        assert any(t == "email" for _, t in result["regex_hits"]), (
            f"Expected email regex hit, got: {result['regex_hits']}"
        )

        sanitized = _read_plist(plist_path)
        assert sanitized["password"] == "[REDACTED]"
        assert "user@example.com" not in sanitized["ContactBackup"]
        assert "[REDACTED_EMAIL]" in sanitized["ContactBackup"]
        assert sanitized["Version"] == "2.0"




# ---------------------------------------------------------------------------
# Nested plist detection -- bytes values containing embedded XML/binary plists
# ---------------------------------------------------------------------------

def test_nested_xml_plist_bytes_email_redacted():
    """bytes value containing an XML plist with an email -> email gets redacted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "com.apple.facetime.bag.plist"

        # Build the nested XML plist that lives inside the bytes value.
        nested = {
            "AccountInfo": "user@icloud.com",
            "ServerIP": "17.32.0.1",
        }
        nested_bytes = plistlib.dumps(nested, fmt=plistlib.FMT_XML)
        assert nested_bytes.startswith(b"<?xml"), "fixture must be XML plist bytes"

        data = {
            "CachedBag": nested_bytes,
            "Version": "1.0",
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        hit_types = [t for _, t in result["regex_hits"]]
        assert "email" in hit_types, (
            f"Expected email hit from nested plist bytes, got: {result['regex_hits']}"
        )

        sanitized = _read_plist(plist_path)
        cached = sanitized["CachedBag"]
        assert isinstance(cached, bytes), "CachedBag should still be bytes after sanitization"
        inner = plistlib.loads(cached)
        assert "user@icloud.com" not in inner["AccountInfo"], (
            f"Raw email still present: {inner['AccountInfo']!r}"
        )
        assert "[REDACTED_EMAIL]" in inner["AccountInfo"]
        # Non-nested string unchanged
        assert sanitized["Version"] == "1.0"


def test_nested_binary_plist_bytes_phone_redacted():
    """bytes value containing a binary plist with a phone number -> phone gets redacted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "contactscache.plist"

        nested = {
            "PhoneNumber": "+1 (555) 867-5309",
            "Label": "mobile",
        }
        nested_bytes = plistlib.dumps(nested, fmt=plistlib.FMT_BINARY)
        assert nested_bytes.startswith(b"bplist"), "fixture must be binary plist bytes"

        data = {
            "CachedContact": nested_bytes,
            "SyncToken": "abc123",
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        hit_types = [t for _, t in result["regex_hits"]]
        assert "phone_us" in hit_types, (
            f"Expected phone_us hit from nested binary plist bytes, got: {result['regex_hits']}"
        )

        sanitized = _read_plist(plist_path)
        cached = sanitized["CachedContact"]
        assert isinstance(cached, bytes)
        inner = plistlib.loads(cached)
        assert "+1 (555) 867-5309" not in inner["PhoneNumber"], (
            f"Raw phone still present: {inner['PhoneNumber']!r}"
        )
        # Output should remain a binary plist
        assert cached.startswith(b"bplist"), "nested plist should remain binary format"


def test_bytes_with_certificate_left_untouched():
    """bytes value containing random/certificate binary data -> left untouched."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "keychain.plist"

        # Simulate a DER certificate blob -- starts with 0x30 (ASN.1 SEQUENCE)
        cert_blob = b"\x30\x82\x04\x00" + b"\xde\xad\xbe\xef" * 256

        data = {
            "CertificateData": cert_blob,
            "Label": "My Cert",
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        assert result["regex_hits"] == [], (
            f"No regex hits expected for cert blob, got: {result['regex_hits']}"
        )
        sanitized = _read_plist(plist_path)
        assert sanitized["CertificateData"] == cert_blob, (
            "Certificate bytes should be left completely untouched"
        )


def test_nested_plist_bytes_multiple_pii_types():
    """Nested plist bytes containing multiple PII types -- all caught.

    Uses key name 'CachedBag' (non-sensitive) to mirror the real-world
    com.apple.facetime.bag.plist structure that triggered this fix.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "com.apple.facetime.bag.plist"

        nested = {
            "ContactEmail": "victim@example.com",
            "ContactPhone": "+1 (800) 555-1234",
            "ServerIP": "203.0.113.42",
            "DeviceMAC": "de:ad:be:ef:00:01",
        }
        nested_bytes = plistlib.dumps(nested, fmt=plistlib.FMT_XML)

        data = {
            "CachedBag": nested_bytes,
            "Enabled": True,
        }
        _write_plist(plist_path, data)

        result = sanitize_plist(plist_path)

        hit_types = {t for _, t in result["regex_hits"]}
        assert "email" in hit_types, f"Missing email hit: {result['regex_hits']}"
        assert "phone_us" in hit_types, f"Missing phone_us hit: {result['regex_hits']}"
        assert "ip_v4" in hit_types, f"Missing ip_v4 hit: {result['regex_hits']}"
        assert "mac_addr" in hit_types, f"Missing mac_addr hit: {result['regex_hits']}"

        sanitized = _read_plist(plist_path)
        inner = plistlib.loads(sanitized["CachedBag"])
        assert "victim@example.com" not in inner["ContactEmail"]
        assert "+1 (800) 555-1234" not in inner["ContactPhone"]
        assert "203.0.113.42" not in inner["ServerIP"]
        assert "de:ad:be:ef:00:01" not in inner["DeviceMAC"]
        # Non-PII structure preserved
        assert sanitized["Enabled"] is True

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
    test_regex_scan_email_in_arbitrary_key()
    test_regex_scan_phone_in_nested_dict()
    test_regex_scan_binary_plist()
    test_regex_scan_mac_address()
    test_regex_scan_imei()
    test_non_string_values_untouched()
    test_key_based_and_regex_scan_together()
    test_nested_xml_plist_bytes_email_redacted()
    test_nested_binary_plist_bytes_phone_redacted()
    test_bytes_with_certificate_left_untouched()
    test_nested_plist_bytes_multiple_pii_types()
    print("All tests passed.")
