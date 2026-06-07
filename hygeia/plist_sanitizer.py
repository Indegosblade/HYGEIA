"""
HYGEIA Plist Sanitizer -- recursive credential redaction for binary plists.

Walks nested plist structures and redacts values whose keys match
sensitive patterns (email, token, auth, password, etc.) while
preserving safe system identifiers.

For high-risk device identity files (data_ark.plist, MobileGestalt, etc.)
a "redact all values" mode is available that zeros every string and numeric
value regardless of key name, preserving only the plist structure.

After key-based sanitization, ALL plists undergo a universal PII regex scan
(same patterns as text_sanitizer and sqlite_sanitizer) that catches PII
buried in arbitrary keys — emails in cloud.quota.plist, phone numbers,
MAC addresses, IMEI, IP addresses, etc.
"""

import json
import plistlib
import logging
from pathlib import Path

from hygeia.text_sanitizer import _redact_pii_in_string
from .utils import sha256 as _sha256

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


def _try_scan_nested_plist_bytes(value: bytes, found_types: list, path: str):
    """
    If *value* looks like an embedded XML or binary plist, parse it,
    recursively scan it for PII, and return the re-serialised bytes.

    Returns None when the bytes are not a plist (certificates, raw binary,
    etc.) so the caller can leave them untouched.
    """
    # Quick header check — avoid plistlib overhead on random binary blobs.
    if not (value.startswith(b"<?xml") or value.startswith(b"bplist")):
        return None
    try:
        nested = plistlib.loads(value)
    except Exception:
        return None

    # Determine original format so we serialise back in the same way.
    nested_fmt = plistlib.FMT_BINARY if value.startswith(b"bplist") else plistlib.FMT_XML

    hits_before = len(found_types)
    _regex_scan_plist(nested, found_types, path)
    if len(found_types) == hits_before:
        # No PII found — return None to leave the original bytes unchanged.
        return None

    try:
        return plistlib.dumps(nested, fmt=nested_fmt)
    except Exception:
        return None


# Key-name fragments that strongly suggest an integer value encodes a phone
# number rather than a size, count, or other non-PII numeric field.
_PHONE_KEY_HINTS = frozenset({
    "phone", "mobile", "cell", "msisdn", "phonenumber", "phoneno",
    "mdn", "callerid", "contactnumber",
})


def _key_suggests_phone(key: str) -> bool:
    """Return True if the plist key name suggests the integer value is a phone number."""
    k = key.lower().replace("_", "").replace("-", "").replace(" ", "")
    return any(hint in k for hint in _PHONE_KEY_HINTS)


def _regex_scan_plist(obj, found_types: list, path: str = ""):
    """
    Recursively walk ALL string values in a plist structure and apply
    PII_PATTERNS regex scanning.  String values are the primary target.

    Also handles two edge cases that naive string-only scanning misses:

    1. Integer values stored under phone-hint keys (e.g. 16044192133 under a
       key containing "phone" in com.apple.itunescloud.plist).  The integer is
       converted to its decimal string, scanned against phone PII_PATTERNS, and
       if a match is found the integer is replaced with 0.  Only phone-hint
       keys are checked — generic integers (sizes, counts, capacities) are left
       untouched to avoid false positives.

    2. Dictionary keys that ARE the PII (e.g. Bluetooth device addresses like
       "50:57:8A:E4:47:FD" used as keys in com.apple.Accessibility.plist).
       When a key matches a MAC address pattern the entire key+value subtree is
       replaced with a redacted key name.

    bytes values are inspected for embedded XML or binary plists (e.g. the
    CachedBag key in com.apple.facetime.bag.plist).  If the bytes parse as a
    plist, the nested plist is scanned recursively and the value is replaced
    with the sanitised re-serialised bytes.  Non-plist binary data
    (certificates, raw blobs, etc.) is left untouched.

    Values already replaced by pass 1 key-based sanitization (i.e. equal to
    "[REDACTED]" or starting with "[REDACTED_") are skipped to avoid double-
    processing and false BIC/NPI matches on the replacement token.

    Mutates obj in place.  Appends (path, pii_type) tuples to found_types.
    """
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            value = obj[key]
            child_path = f"{path}.{key}" if path else key

            # --- Key PII scan: catch MAC addresses (and similar) used as keys ---
            # current_key tracks the actual key name after any potential rename.
            current_key = key
            key_redacted, key_types = _redact_pii_in_string(key)
            if key_types:
                # Rename the key so the PII no longer appears in the plist
                current_key = key_redacted
                obj[current_key] = obj.pop(key)
                for t in key_types:
                    found_types.append((f"{path}[key:{t}]", t))
                # Continue scanning the value under the new key name
                value = obj[current_key]
                child_path = f"{path}.{current_key}" if path else current_key

            if isinstance(value, str):
                # Skip values already sanitized by pass 1
                if value == "[REDACTED]" or value.startswith("[REDACTED_"):
                    continue
                redacted, types = _redact_pii_in_string(value)
                if types:
                    obj[current_key] = redacted
                    for t in types:
                        found_types.append((child_path, t))
            elif isinstance(value, int) and not isinstance(value, bool):
                # Integer values under phone-hint keys may encode bare phone
                # numbers (e.g. 16044192133 stored as <integer> in binary
                # plists).  Generic integers (sizes, counts, capacities) are
                # deliberately excluded — only phone-hint key names are checked.
                if _key_suggests_phone(current_key):
                    int_str = str(value)
                    _, types = _redact_pii_in_string(int_str)
                    if types:
                        obj[current_key] = 0
                        for t in types:
                            found_types.append((child_path, t))
            elif isinstance(value, bytes):
                sanitised = _try_scan_nested_plist_bytes(value, found_types, child_path)
                if sanitised is not None:
                    obj[current_key] = sanitised
            elif isinstance(value, (dict, list)):
                _regex_scan_plist(value, found_types, child_path)
            # bool, float, datetime — leave untouched
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            child_path = f"{path}[{i}]"
            if isinstance(item, str):
                # Skip values already sanitized by pass 1
                if item == "[REDACTED]" or item.startswith("[REDACTED_"):
                    continue
                redacted, types = _redact_pii_in_string(item)
                if types:
                    obj[i] = redacted
                    for t in types:
                        found_types.append((child_path, t))
            elif isinstance(item, bytes):
                sanitised = _try_scan_nested_plist_bytes(item, found_types, child_path)
                if sanitised is not None:
                    obj[i] = sanitised
            elif isinstance(item, (dict, list)):
                _regex_scan_plist(item, found_types, child_path)


def _detect_plist_fmt(filepath: Path) -> object:
    """Return plistlib.FMT_BINARY if the file starts with 'bplist', else FMT_XML."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(8)
        if header.startswith(b"bplist"):
            return plistlib.FMT_BINARY
    except OSError:
        pass
    return plistlib.FMT_XML


def sanitize_plist(filepath: Path) -> dict:
    """
    Sanitize a plist file (binary or XML) in two passes:

    Pass 1 — key-based:
      * redact_all_values_files  → zero every string/numeric value
      * all other plists          → redact values whose keys match SENSITIVE_KEY_PATTERNS

    Pass 2 — universal PII regex scan:
      * Walk ALL string values in the entire plist structure
      * Apply PII_PATTERNS (email, phone, MAC, IMEI, IP, …) to every string
      * Replaces matches with [REDACTED_<TYPE>]
      * Does NOT touch booleans, integers, floats, bytes, or dates

    The file is written back in its original format (binary → binary, XML → XML).

    Returns action result dict with keys_redacted and regex_hits fields.
    """
    result = {
        "action": "plist_sanitize",
        "path": str(filepath),
        "keys_redacted": [],
        "regex_hits": [],
    }

    try:
        result["hash_before"] = _sha256(filepath)
        fmt = _detect_plist_fmt(filepath)
        with open(filepath, "rb") as f:
            data = plistlib.load(f)
    except Exception as e:
        result["error"] = f"Failed to parse: {e}"
        return result

    # Pass 1: key-based sanitization
    redacted: list = []
    if _is_redact_all_file(filepath.name):
        result["mode"] = "redact_all_values"
        _redact_all_values(data, redacted)
    else:
        result["mode"] = "sensitive_keys"
        _redact_recursive(data, redacted)

    result["keys_redacted"] = redacted

    # Pass 2: universal PII regex scan on all string values
    regex_hits: list = []
    _regex_scan_plist(data, regex_hits)
    result["regex_hits"] = regex_hits

    changed = bool(redacted or regex_hits)
    if changed:
        try:
            with open(filepath, "wb") as f:
                plistlib.dump(data, f, fmt=fmt)
            log.info(
                f"Sanitized {filepath.name} ({result['mode']}): "
                f"{len(redacted)} key-based redactions, "
                f"{len(regex_hits)} regex PII hits"
            )
        except Exception as e:
            result["error"] = f"Failed to write: {e}"

    result["hash_after"] = _sha256(filepath)
    return result
