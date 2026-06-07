"""
HYGEIA Plist Sanitizer -- recursive credential redaction for binary plists.

Walks nested plist structures and redacts values whose keys match
sensitive patterns (email, token, auth, password, etc.) while
preserving safe system identifiers.

For high-risk device identity files (data_ark.plist, MobileGestalt, etc.)
a "redact all values" mode is available that zeros every string and numeric
value regardless of key name, preserving only the plist structure.
"""

import json
import plistlib
import logging
from pathlib import Path

log = logging.getLogger("hygeia.plist")

SENSITIVE_KEY_PATTERNS = [
    "email", "token", "auth", "password", "phone",
    "login", "user", "account", "credential",
    "oauth", "bearer", "session", "cookie",
    "secret", "apikey", "api_key", "refresh",
    "access_token", "id_token", "username",
    "firstname", "lastname", "fullname",
    "icloud", "appleid",
]

# Keys that look sensitive but are safe system identifiers
SAFE_KEY_PATTERNS = [
    "entitlement", "bundle", "version", "build",
    "systemversion", "productname", "hardwaremodel",
]

# Loaded once on first use
_PATTERNS_CACHE: dict | None = None


def _load_patterns() -> dict:
    """Load plist_patterns.json, caching the result."""
    global _PATTERNS_CACHE
    if _PATTERNS_CACHE is None:
        rules_path = Path(__file__).parent / "rules" / "plist_patterns.json"
        try:
            with open(rules_path, "r") as f:
                _PATTERNS_CACHE = json.load(f)
        except Exception:
            _PATTERNS_CACHE = {}
    return _PATTERNS_CACHE


def _is_redact_all_file(filename: str) -> bool:
    """Return True if the filename is in the redact_all_values_files list."""
    patterns = _load_patterns()
    redact_all = patterns.get("redact_all_values_files", [])
    return filename in redact_all


def _is_sensitive_key(key: str) -> bool:
    """Check if a plist key matches sensitive patterns."""
    key_lower = key.lower()
    # Skip safe system keys
    if any(safe in key_lower for safe in SAFE_KEY_PATTERNS):
        return False
    return any(pattern in key_lower for pattern in SENSITIVE_KEY_PATTERNS)


def _redact_all_values(obj, redacted_keys: list):
    """
    Recursively walk plist structure and redact ALL string and numeric values.

    - str  → "[REDACTED]"
    - int  → 0
    - float → 0.0
    - bool is left as-is (boolean flags are not identifying)
    - bytes → b"" (cleared)
    - dict/list structure is preserved; only leaf values are replaced
    """
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            value = obj[key]
            if isinstance(value, bool):
                # bool subclasses int — check before int
                pass
            elif isinstance(value, str):
                obj[key] = "[REDACTED]"
                redacted_keys.append(key)
            elif isinstance(value, int):
                obj[key] = 0
                redacted_keys.append(key)
            elif isinstance(value, float):
                obj[key] = 0.0
                redacted_keys.append(key)
            elif isinstance(value, bytes):
                obj[key] = b""
                redacted_keys.append(key)
            elif isinstance(value, (dict, list)):
                _redact_all_values(value, redacted_keys)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, bool):
                pass
            elif isinstance(item, str):
                obj[i] = "[REDACTED]"
                redacted_keys.append(f"[{i}]")
            elif isinstance(item, int):
                obj[i] = 0
                redacted_keys.append(f"[{i}]")
            elif isinstance(item, float):
                obj[i] = 0.0
                redacted_keys.append(f"[{i}]")
            elif isinstance(item, bytes):
                obj[i] = b""
                redacted_keys.append(f"[{i}]")
            elif isinstance(item, (dict, list)):
                _redact_all_values(item, redacted_keys)


def _redact_recursive(obj, redacted_keys: list):
    """Recursively walk dict/list and redact sensitive keys."""
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            if _is_sensitive_key(key):
                obj[key] = "[REDACTED]"
                redacted_keys.append(key)
            else:
                _redact_recursive(obj[key], redacted_keys)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _redact_recursive(item, redacted_keys)


def sanitize_plist(filepath: Path) -> dict:
    """
    Sanitize a binary plist file by redacting sensitive keys.

    For files listed in redact_all_values_files (e.g. data_ark.plist,
    com.apple.MobileGestalt.plist), ALL string/numeric values are replaced
    regardless of key name.  For all other plists, only keys matching
    SENSITIVE_KEY_PATTERNS are redacted.

    Returns action result dict.
    """
    result = {
        "action": "plist_sanitize",
        "path": str(filepath),
        "keys_redacted": [],
    }

    try:
        with open(filepath, "rb") as f:
            data = plistlib.load(f)
    except Exception as e:
        result["error"] = f"Failed to parse: {e}"
        return result

    redacted: list = []
    if _is_redact_all_file(filepath.name):
        result["mode"] = "redact_all_values"
        _redact_all_values(data, redacted)
    else:
        result["mode"] = "sensitive_keys"
        _redact_recursive(data, redacted)

    result["keys_redacted"] = redacted

    if redacted:
        try:
            with open(filepath, "wb") as f:
                plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)
            log.info(
                f"Sanitized {filepath.name} ({result['mode']}): "
                f"{len(redacted)} values redacted"
            )
        except Exception as e:
            result["error"] = f"Failed to write: {e}"

    return result
