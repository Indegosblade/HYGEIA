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
from .patterns import _load_raw as _load_pii_registry_raw
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

    If PII IS found in the nested structure but the sanitized copy cannot be
    re-serialised (plistlib.dumps raising -- e.g. a value shape that only
    round-trips in one plist format), the caller will keep the ORIGINAL,
    un-redacted bytes. In that case the hits already recorded above must not
    be left in *found_types* looking like a normal, successfully-handled PII
    hit -- that would let the manifest/verifier accounting claim the PII was
    removed when it demonstrably was not (#12). They are rolled back and
    replaced with a single explicit failure marker so the failure is
    surfaced (fail closed) instead of silently counted as "handled".
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
    except Exception as e:
        del found_types[hits_before:]
        found_types.append((path, "nested_plist_reserialize_failed"))
        log.error(
            f"Nested plist at {path!r} contained PII that could not be "
            f"re-serialised after redaction ({e}); original un-redacted "
            f"bytes were retained"
        )
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


# Location key-name hints, loaded from the shared PII pattern registry
# (rules/pii_patterns.json: sensitive_columns.location) instead of a second
# hardcoded list. That list already covers latitude/longitude/lat/lng/lon/
# geolocation/coordinates/gps AND the CoreData Z-prefixed names (zlatitude/
# zlongitude/zlocation/zaltitude/zcoordinate), so a name added there for the
# SQLite sanitizer is automatically honoured here too (#13).
_LOCATION_KEY_HINTS_CACHE: frozenset | None = None


def _load_location_key_hints() -> frozenset:
    """Load+cache the 'location' sensitive-column vocabulary from the
    registry. Falls back to an empty set (never raises) so a missing/corrupt
    registry file degrades to "no key-name hint available" rather than
    crashing plist sanitization -- the content-based gps_coord regex scan
    still runs independently of this.
    """
    global _LOCATION_KEY_HINTS_CACHE
    if _LOCATION_KEY_HINTS_CACHE is None:
        try:
            raw = _load_pii_registry_raw()
            hints = raw.get("sensitive_columns", {}).get("location", [])
            _LOCATION_KEY_HINTS_CACHE = frozenset(h.lower() for h in hints)
        except Exception:
            log.warning("Could not load location key hints from pii_patterns.json registry")
            _LOCATION_KEY_HINTS_CACHE = frozenset()
    return _LOCATION_KEY_HINTS_CACHE


def _key_suggests_location(key: str) -> bool:
    """Return True if the plist key name suggests a numeric value encodes
    GPS/location data (latitude, longitude, altitude, coordinate, ...)."""
    hints = _load_location_key_hints()
    if not hints:
        return False
    k = key.lower().replace("_", "").replace("-", "").replace(" ", "")
    return any(hint in k for hint in hints)


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

    3. Float values (e.g. <real>37.7749</real> under lastKnownLatitude in
       locationd/routined/Maps state caches).  Floats used to be excluded from
       every PII check ("bool, float, datetime — leave untouched"), so GPS
       coordinates stored this way — a routine occurrence, since CoreLocation
       serialises lat/lng as doubles — survived sanitization untouched
       regardless of key name (#13).  The float's decimal string form is
       scanned with the same PII_PATTERNS used for strings/ints (this is what
       catches gps_coord regardless of key), and — because a coordinate
       rounded to only a couple of decimal places can be too short for
       gps_coord to match on content alone — a value under a key the shared
       registry already treats as location-sensitive (sensitive_columns.location,
       which also covers CoreData's Z-prefixed zlatitude/zlongitude/zlocation)
       is zeroed unconditionally as a fallback.  On a match the float is
       replaced with 0.0.

    4. Integer values under a location-hint key (e.g. a fixed-point/scaled
       coordinate such as latitude*1e7) are zeroed the same way as (3) — a
       scaled integer has no decimal point for gps_coord to match against, so
       the key name is the only usable signal, mirroring the phone-hint
       integer handling in (1) but for location instead of phone (#13).

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
                elif value != 0 and _key_suggests_location(current_key):
                    # Fixed-point/scaled coordinate (e.g. an E7-format
                    # latitude*1e7 int) — no decimal point for gps_coord to
                    # match, so the location-hint key name is the only
                    # available signal (#13).
                    obj[current_key] = 0
                    found_types.append((child_path, "gps_coord"))
            elif isinstance(value, float):
                # GPS/location floats (#13) — see docstring case 3. Content
                # scan first (catches coordinates regardless of key name);
                # fall back to the location-hint key name for coordinates
                # too short/rounded for gps_coord to match on content alone.
                float_str = str(value)
                _, types = _redact_pii_in_string(float_str)
                if types:
                    obj[current_key] = 0.0
                    for t in types:
                        found_types.append((child_path, t))
                elif value != 0.0 and _key_suggests_location(current_key):
                    obj[current_key] = 0.0
                    found_types.append((child_path, "gps_coord"))
            elif isinstance(value, bytes):
                sanitised = _try_scan_nested_plist_bytes(value, found_types, child_path)
                if sanitised is not None:
                    obj[current_key] = sanitised
            elif isinstance(value, (dict, list)):
                _regex_scan_plist(value, found_types, child_path)
            # bool, datetime — leave untouched
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
            elif isinstance(item, float):
                # Array-form coordinate pairs (e.g. [lat, lng]) get the same
                # content scan as dict-value floats (#13). List items have no
                # key name, so only the content-based check applies here.
                item_str = str(item)
                _, types = _redact_pii_in_string(item_str)
                if types:
                    obj[i] = 0.0
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
      * Also scans float values and phone/location-hint-keyed integer values
        for numeric PII (e.g. GPS coordinates, #13) — see _regex_scan_plist.
      * Does NOT touch booleans, bytes, or dates

    The file is written back in its original format (binary → binary, XML → XML).

    If a nested plist embedded as a bytes value contains PII that could not
    be re-serialised after redaction (#12), the failure is surfaced in
    result["error"] and as a "nested_plist_reserialize_failed" entry in
    regex_hits rather than silently counted as a normal, successfully
    redacted hit — see _try_scan_nested_plist_bytes.

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

    # #12: a nested-plist re-serialization failure leaves the ORIGINAL,
    # un-redacted bytes in place for that value. Surface it at the top level
    # (fail closed) instead of letting the run report success while PII the
    # tool itself found remains recoverable in the output.
    nested_failures = [p for p, t in regex_hits if t == "nested_plist_reserialize_failed"]
    if nested_failures:
        result["error"] = (
            f"{len(nested_failures)} embedded nested plist value(s) contained PII "
            f"that could not be re-serialised and remain un-redacted in the output: "
            f"{nested_failures}"
        )

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
            # Do not clobber an already-recorded nested-reserialize failure
            # (#12) -- append so both fail-closed signals survive.
            write_err = f"Failed to write: {e}"
            result["error"] = f"{result['error']}; {write_err}" if result.get("error") else write_err

    result["hash_after"] = _sha256(filepath)
    return result
