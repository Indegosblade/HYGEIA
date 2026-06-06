"""
HYGEIA Plist Sanitizer -- recursive credential redaction for binary plists.

Walks nested plist structures and redacts values whose keys match
sensitive patterns (email, token, auth, password, etc.) while
preserving safe system identifiers.
"""

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


def _is_sensitive_key(key: str) -> bool:
    """Check if a plist key matches sensitive patterns."""
    key_lower = key.lower()
    # Skip safe system keys
    if any(safe in key_lower for safe in SAFE_KEY_PATTERNS):
        return False
    return any(pattern in key_lower for pattern in SENSITIVE_KEY_PATTERNS)


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

    redacted = []
    _redact_recursive(data, redacted)
    result["keys_redacted"] = redacted

    if redacted:
        try:
            with open(filepath, "wb") as f:
                plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)
            log.info(f"Sanitized {filepath.name}: {len(redacted)} keys redacted")
        except Exception as e:
            result["error"] = f"Failed to write: {e}"

    return result
