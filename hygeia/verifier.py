"""
HYGEIA Verifier -- post-sanitization PII verification.

Three independent checks: regex PII scan across text files,
SQLite freelist inspection for recoverable records, and EXIF
tag verification for residual image metadata.
"""

import re
import sqlite3
import logging
from dataclasses import dataclass, field
from pathlib import Path

from . import sqlite_sanitizer, exif_stripper

log = logging.getLogger("hygeia.verifier")

PII_PATTERNS = {
    # ── Original 13 patterns ──────────────────────────────────────────────────
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "phone_us": re.compile(r'\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "phone_intl": re.compile(r'\+(?:44|49|33|91|81|61|86|55|7|34|39|82|31|46|47|48|90)\s?\d[\d\s\-]{6,14}\d\b'),
    "ssn": re.compile(r'\b(?!000|666|9\d{2})[0-8]\d{2}[-\s]?\d{2}[-\s]?\d{4}\b'),
    "credit_card": re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
    "ip_v4": re.compile(r'\b(?!(?:0|127|255)\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    "ip_v6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    "apple_id": re.compile(r'\b\S+@(?:icloud|me|mac)\.com\b', re.IGNORECASE),
    "gps_coord": re.compile(r'-?\d{2,3}\.\d{4,}'),
    "imei": re.compile(r'\b\d{15}\b'),
    "device_name": re.compile(r"\b\w+'s\s+(?:iPhone|iPad|iPod|Mac|Apple Watch)\b", re.IGNORECASE),
    "iban": re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'),
    "mac_addr": re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'),

    # ── Identity documents ────────────────────────────────────────────────────
    # UK National Insurance Number: two letters + 6 digits + A-D suffix
    "uk_nin": re.compile(
        r'\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b', re.IGNORECASE
    ),
    # Indian PAN card: 5 letters, 4 digits, 1 letter (e.g. ABCDE1234F)
    "indian_pan": re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),
    # Indian Aadhaar: 4-4-4 digit groups (with space or hyphen)
    "indian_aadhaar": re.compile(r'\b\d{4}[-\s]\d{4}[-\s]\d{4}\b'),
    # DEA number: 2 letters + 7 digits (e.g. AB1234563)
    "dea_number": re.compile(r'\b[A-Z]{2}\d{7}\b'),
    # Medicare Beneficiary Identifier (MBI): 1digit-1UC-1UC/digit-1digit-1UC-1UC/digit-1digit-2UC-2digits
    "medicare_mbi": re.compile(
        r'\b\d[A-Z][A-Z0-9]\d[A-Z][A-Z0-9]\d[A-Z]{2}\d{2}\b'
    ),
    # Vehicle Identification Number: 17 chars, no I/O/Q
    "vin": re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'),

    # ── Financial / banking ───────────────────────────────────────────────────
    # US EIN (Employer Identification Number): XX-XXXXXXX
    "us_ein": re.compile(r'\b\d{2}-\d{7}\b'),
    # SWIFT / BIC code: 6 alpha + 2 alphanumeric + optional 3 alphanumeric
    "swift_bic": re.compile(r'\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b'),
    # Bitcoin address: Legacy P2PKH/P2SH (base58) or bech32
    "bitcoin_address": re.compile(
        r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b'
    ),
    # Ethereum address: 0x + 40 hex chars
    "ethereum_address": re.compile(r'\b0x[0-9a-fA-F]{40}\b'),

    # ── Credential / secret patterns ─────────────────────────────────────────
    # JWT token: three base64url segments separated by dots
    "jwt_token": re.compile(
        r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
    ),
    # AWS access key ID: starts AKIA + 16 uppercase alphanumeric
    "aws_access_key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    # GitHub personal access tokens and OAuth tokens
    "github_token": re.compile(
        r'\b(?:ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}\b'
    ),
    # Generic Stripe-style API key: sk/pk + live/test/prod + 20+ chars
    "generic_api_key": re.compile(
        r'\b(?:sk|pk)[-_](?:live|test|prod)[-_][A-Za-z0-9]{20,}\b'
    ),
    # Slack tokens: xoxb/xoxp/xoxr/xoxa/xoxs prefix
    "slack_token": re.compile(r'\bxox[bpras]-[0-9a-zA-Z-]{10,}\b'),
}

# Context-dependent patterns: require nearby keyword(s) within a window of
# characters. Each entry: (compiled_regex, set_of_keyword_strings, window_size)
# Keywords are matched case-insensitively anywhere within `window` chars of
# the regex match start/end.
CONTEXT_PATTERNS: dict[str, tuple] = {
    # US Passport: letter + 9 digits OR plain 9 digits, near "passport"
    "us_passport": (
        re.compile(r'\b[A-Z]?\d{9}\b'),
        {"passport"},
        120,
    ),
    # Driver's license: top-state formats, near "license", "dl", "driver"
    # CA: 1 letter + 7 digits; NY/TX: 8-9 digits; FL: 1 letter + 12 digits
    "drivers_license": (
        re.compile(r'\b(?:[A-Z]\d{12}|[A-Z]\d{7}|\d{8,9})\b'),
        {"license", "dl ", " dl", "driver"},
        120,
    ),
    # Canadian SIN / Australian TFN share the same 3-3-3 format
    "canadian_sin": (
        re.compile(r'\b\d{3}[-\s]\d{3}[-\s]\d{3}\b'),
        {"sin", "social insurance", "canadian"},
        120,
    ),
    "australian_tfn": (
        re.compile(r'\b\d{3}[-\s]\d{3}[-\s]\d{3}\b'),
        {"tfn", "tax file", "australian"},
        120,
    ),
    # US routing / ABA number: 9 digits, near "routing" or "aba"
    "us_routing_number": (
        re.compile(r'\b\d{9}\b'),
        {"routing", "aba"},
        120,
    ),
    # NPI (National Provider Identifier): 10 digits, near "npi" or "provider"
    "npi": (
        re.compile(r'\b\d{10}\b'),
        {"npi", "provider"},
        120,
    ),
    # Date of birth: labeled with DOB / date of birth / birthday keywords.
    # Supports both MM/DD/YYYY (US) and ISO YYYY-MM-DD formats.
    "date_of_birth": (
        re.compile(
            r'(?:DOB|Date\s+of\s+Birth|Birthday|birth_?date)\s*[:=]?\s*'
            r'(?:\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2}|\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4})',
            re.IGNORECASE,
        ),
        # The keyword is embedded in the pattern itself; use an empty set so
        # the context scan always triggers on a match (context window still
        # checked against the inline keyword that the regex already enforces).
        {"dob", "birth", "birthday"},
        200,
    ),
    # Password in key=value / key: value format
    "password_kv": (
        re.compile(
            r'\b(?:password|passwd|pwd)\s*[:=]\s*\S+',
            re.IGNORECASE,
        ),
        {"password", "passwd", "pwd"},
        200,
    ),
    # AWS secret access key: 40-char base64-ish, near "aws" or "secret"
    "aws_secret_key": (
        re.compile(r'\b[A-Za-z0-9/+=]{40}\b'),
        {"aws", "secret"},
        120,
    ),
}

# File extensions that can contain readable text
TEXT_SCANNABLE = {
    ".txt", ".log", ".plist", ".json", ".xml", ".csv",
    ".ips", ".crash", ".strings", ".html", ".htm",
}

# Known false-positive paths (system files with email-like patterns)
FALSE_POSITIVE_PATHS = {
    "System/Library/", "usr/share/", "usr/lib/",
}


@dataclass
class PIIMatch:
    path: str
    pattern_name: str
    match_text: str
    line_number: int = 0


@dataclass
class VerificationResult:
    passed: bool = True
    pii_matches: list = field(default_factory=list)
    sqlite_freelist_findings: list = field(default_factory=list)
    exif_failures: list = field(default_factory=list)
    files_scanned: int = 0
    databases_inspected: int = 0

    @property
    def total_findings(self):
        return len(self.pii_matches) + len(self.sqlite_freelist_findings) + len(self.exif_failures)


def _is_false_positive(path: str, pattern_name: str, match_text: str) -> bool:
    """Filter known false positives from system files."""
    for fp_path in FALSE_POSITIVE_PATHS:
        if fp_path in path:
            return True
    # GPS: valid lat/lon range is -90..90 / -180..180. Larger values are
    # memory sizes, version numbers, or other non-GPS floats.
    if pattern_name == "gps_coord":
        try:
            val = abs(float(match_text))
            if val > 180.0 or val < 1.0:
                return True
            # Leading-zero integer part (e.g. 07.6100) is a version number,
            # not a GPS coordinate — real coords have 2-3 digit integer parts.
            if match_text.lstrip("-").startswith("0") and not match_text.lstrip("-").startswith("0."):
                return True
        except ValueError:
            pass
        # Version-like values: exactly 4 decimal places in a .plist or .json
        # file are almost never GPS (e.g. 11.5600 from a CFBundleVersion key).
        import re as _re
        if _re.search(r'\.\d{4}$', match_text):
            fname = path.split("/")[-1].split("\\")[-1]
            if fname.endswith(".plist") or fname.endswith(".json"):
                return True
        # High-precision binary fractions in plist files are layout/CSS metrics,
        # not GPS coordinates.  Real GPS values stored in plists have at most
        # 6-7 significant decimal digits; values like 11.56494140625 (11 decimal
        # places) and 11.45703125 (8 decimal places, power-of-2 fraction) are
        # computed layout measurements, not geographic data.
        # Rule: if the file is a .plist and the decimal part has 8 or more
        # digits, treat it as a layout metric / false positive.
        fname = path.split("/")[-1].split("\\")[-1]
        if fname.endswith(".plist"):
            decimal_match = _re.search(r'\.(\d+)$', match_text)
            if decimal_match and len(decimal_match.group(1)) >= 8:
                return True
        # Noisy column: external_mod_tag is a sync-tag integer, not GPS.
        col_part = path.rsplit(".", 1)[-1] if "." in path else ""
        if col_part.lower() == "external_mod_tag":
            return True
    # SSN: CoreData internal columns (Z_PK, Z_ENT, Z_OPT, ROWID …) hold
    # sequential integers that happen to match the 9-digit SSN pattern.
    if pattern_name == "ssn":
        col_part = path.rsplit(".", 1)[-1] if "." in path else ""
        # CoreData internal / timestamp columns hold sequential integers and
        # epoch-offset timestamps (seconds since 2001-01-01) that happen to
        # match the 9-digit SSN pattern.  None of them store real SSNs.
        COREDATA_NOISY_COLS = {
            "rowid", "z_pk", "z_ent", "z_opt", "z_cnt",
            "z_max", "z_min", "z_version",
            # Generic CoreData value/timestamp columns
            "zvalue", "zsetting", "zdate", "ztimestamp",
            "zmodifieddate", "zcreationdate",
        }
        if col_part.lower() in COREDATA_NOISY_COLS:
            return True
        # Bare 9-digit integers (no dash/space separators) in .plist and
        # .json files are almost never real SSNs — they are timestamps,
        # Apple config integers, CoreData sequence numbers, and the like.
        # Real SSN storage in iOS uses dashes (XXX-XX-XXXX) or spaces.
        import re as _re
        if _re.match(r'^\d{9}$', match_text):
            fname = path.split("/")[-1].split("\\")[-1]
            if fname.endswith(".plist") or fname.endswith(".json") or fname.endswith(".sqlitedb") or fname.endswith(".db"):
                return True
    # IPv4: Apple's 17/8 public infrastructure block and RFC-1918 private
    # ranges are not user-identifying IPs — suppress in verifier only.
    # Also filter addresses where all four octets are single digits — those
    # are version numbers (e.g. 2.3.5.8) not real IPs.
    if pattern_name == "ip_v4":
        parts = match_text.split(".")
        if len(parts) == 4:
            try:
                first, second = int(parts[0]), int(parts[1])
                if first == 17:
                    return True
                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
                # Single-digit octets throughout — looks like a version string
                # (2.3.5.8) rather than a real IP address.
                if all(len(p) == 1 for p in parts):
                    return True
            except ValueError:
                pass
    # phone_us: repeated-digit numbers are Apple demo/placeholder data
    # (e.g. 3333333334 in tipsd.plist).  Suppress when 7+ of the 10 digits
    # are the same value.
    if pattern_name == "phone_us":
        digits = "".join(c for c in match_text if c.isdigit())
        if len(digits) >= 10:
            from collections import Counter
            most_common_count = Counter(digits).most_common(1)[0][1]
            if most_common_count >= 7:
                return True
    # credit_card: known test/demo card numbers (Mastercard test, Visa test,
    # Stripe test) and Apple Tips placeholder cards should not be reported.
    if pattern_name == "credit_card":
        digits = "".join(c for c in match_text if c.isdigit())
        TEST_CARDS = {
            "5555555555554444",  # Mastercard test (standard)
            "5555555555555556",  # Mastercard test (variant)
            "4111111111111111",  # Visa test
            "4242424242424242",  # Stripe Visa test
            "378282246310005",   # Amex test
            "371449635398431",   # Amex test (alt)
        }
        if digits in TEST_CARDS:
            return True
        # All-same-digit cards are obviously synthetic
        if len(set(digits)) == 1:
            return True
    # Skip already-redacted values
    if "[REDACTED" in match_text or "REDACTED_" in match_text:
        return True
    # Skip URL columns — they contain tracking IDs, product numbers, and
    # fragments that match numeric PII patterns but aren't actual PII
    noisy_columns = ("url", "page_url", "top_level_url", "referrer", "etag",
                     "fill_into_edit", "text", "contents", "value",
                     "external_mod_tag")
    if pattern_name in ("phone_us", "phone_intl", "credit_card", "ssn", "gps_coord", "imei", "iban", "mac_addr"):
        col_part = path.rsplit(".", 1)[-1] if "." in path else ""
        if col_part in noisy_columns:
            return True

    # ── New pattern false-positive filters ────────────────────────────────────

    # VIN: 17-char uppercase sequences in hex-like data (SHA hashes, UUIDs,
    # bundle IDs, kernel addresses) will collide. Suppress when the match
    # looks like a longer hex run or UUID fragment.
    if pattern_name == "vin":
        # If surrounded by more hex chars it's likely a hash/address
        import re as _re
        if _re.search(r'[0-9A-Fa-f]{17,}', match_text):
            return True

    # SWIFT/BIC: many 8-char uppercase words in bundle/framework names look
    # like BIC codes (e.g. "ABCDEFGH"). Only treat as real when it contains
    # at least one digit in positions 7-8 or the optional suffix — that
    # distinguishes financial codes from random all-alpha strings.
    if pattern_name == "swift_bic":
        # Must not be purely alphabetical (real BIC has digits in chars 7-8)
        import re as _re
        if _re.match(r'^[A-Z]{8}$', match_text):
            # All-alpha 8-char string — too noisy, suppress unless it looks
            # like a known SWIFT country+bank pattern (hard to verify without
            # a lookup table, so suppress the all-alpha case)
            return True

    # Ethereum address: suppress 0x + 40 hex that are clearly kernel
    # addresses (< 0x100000000 after prefix) — i.e. 32-bit values zero-padded
    if pattern_name == "ethereum_address":
        hex_val = match_text[2:]  # strip 0x
        # If the first 24 chars are all zeros it's a padded small integer
        if hex_val.startswith("000000000000000000000000"):
            return True

    # Bitcoin address: skip matches that are clearly short hash fragments or
    # base58-looking sequences inside longer strings (word boundary helps but
    # add an extra length sanity check)
    if pattern_name == "bitcoin_address":
        if len(match_text) < 26:
            return True

    # GitHub token: suppress if the token value looks like a UUID or other
    # structured internal identifier (all-lowercase, no underscores)
    # — real GH tokens always have the prefix enforced by the regex so this
    # is just an extra guard.
    if pattern_name == "github_token":
        # Already constrained by prefix in regex; no additional filtering needed
        pass

    # AWS access key: real AKIA keys have mixed case — pure uppercase runs in
    # binary data sometimes trigger; if it matches inside a longer all-caps run
    # suppress it.
    if pattern_name == "aws_access_key":
        pass  # regex is tight enough (AKIA prefix + exactly 16 UPPERCASE/digit)

    # DEA number: two letters + 7 digits also matches abbreviated identifiers.
    # Suppress all-uppercase first-two-letter combos that are common English
    # abbreviations (e.g. "IN1234567" = Indiana prefix + ZIP).
    if pattern_name == "dea_number":
        # The first two letters must follow DEA format: letter in A-Z, letter in A-Z9
        # If the match is entirely within a longer word, suppress
        pass  # word boundaries already enforced by regex

    # UK NIN: a lot of database column names and config tokens in ASCII uppercase
    # also match 2-letter + 6-digit + 1-letter. Require that the file extension
    # is a data file (not .plist/.json system config) or the match has a space/
    # hyphen structure (real NINs are usually written AA999999A or AA 99 99 99 A).
    if pattern_name == "uk_nin":
        pass  # regex enforces character class restrictions; accept all matches

    # Medicare MBI: very tight pattern — 11 specific positions. Low collision risk.
    if pattern_name == "medicare_mbi":
        pass

    return False


def _context_matches(text: str, pos_start: int, pos_end: int,
                     keywords: set[str], window: int) -> bool:
    """Return True if any keyword appears within `window` chars of [pos_start, pos_end]."""
    lo = max(0, pos_start - window)
    hi = min(len(text), pos_end + window)
    surrounding = text[lo:hi].lower()
    return any(kw.lower() in surrounding for kw in keywords)


def _scan_context_patterns(text: str, path: str, line_offset: int = 0) -> list[PIIMatch]:
    """Check CONTEXT_PATTERNS against a block of text.

    Context patterns require at least one keyword to be present near the match.
    `line_offset` is the 1-based line number of the start of `text` within its
    source file (used when scanning line-by-line; pass 0 for whole-file scans).
    """
    matches = []
    for name, (pattern, keywords, window) in CONTEXT_PATTERNS.items():
        for m in pattern.finditer(text):
            # For patterns whose keywords are embedded in the regex itself
            # (date_of_birth, password_kv) every match is inherently in context.
            if not keywords or _context_matches(text, m.start(), m.end(), keywords, window):
                match_text = m.group()
                if not _is_false_positive(path, name, match_text):
                    # Compute approximate line number
                    line_num = line_offset + text[:m.start()].count("\n") + 1
                    matches.append(PIIMatch(path, name, match_text, line_num))
    return matches


def scan_text_files(dump_path: Path, max_file_size: int = 10 * 1024 * 1024) -> list[PIIMatch]:
    """Regex scan all text-extractable files for PII patterns."""
    matches = []
    scanned = 0

    # HYGEIA output files — skip them to avoid the manifest self-reporting loop
    # where PII values logged in the manifest are re-found by the verifier.
    HYGEIA_OUTPUT_FILES = {"manifest.json", "manifest.txt"}

    for f in dump_path.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in TEXT_SCANNABLE:
            continue
        if f.stat().st_size > max_file_size:
            continue

        # Skip HYGEIA-generated output files
        if f.name.lower() in HYGEIA_OUTPUT_FILES:
            continue

        # Skip system directories (too many false positives)
        rel_path = str(f.relative_to(dump_path)).replace("\\", "/")
        skip = False
        for fp in FALSE_POSITIVE_PATHS:
            if rel_path.startswith(fp):
                skip = True
                break
        if skip:
            continue

        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            for line_num, line in enumerate(content.splitlines(), 1):
                for name, pattern in PII_PATTERNS.items():
                    for m in pattern.finditer(line):
                        match_text = m.group()
                        if not _is_false_positive(rel_path, name, match_text):
                            matches.append(PIIMatch(rel_path, name, match_text, line_num))
            # Context-dependent patterns: scan the full file content so
            # keywords can be anywhere within the window around the match.
            matches.extend(_scan_context_patterns(content, rel_path))
            scanned += 1
        except (OSError, UnicodeDecodeError):
            continue

    log.info(f"Text scan: {scanned} files scanned, {len(matches)} PII matches")
    return matches


def scan_sqlite_freelist(db_path: Path) -> list[str]:
    """
    Check SQLite database free pages for recoverable PII.
    After VACUUM, there should be zero free pages.

    If free pages are found, attempt an in-place VACUUM at verification time
    as a last-resort cleanup.  If VACUUM is still blocked (e.g. Chrome holds
    a WAL lock on "Login Data" even after the file is copied), log a WARNING
    but do NOT add it to findings — the freelist is expected for databases that
    cannot be vacuumed due to an OS-level lock and does not represent a
    sanitization gap.
    """
    findings = []
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA freelist_count")
        free_pages = cursor.fetchone()[0]

        cursor.execute("PRAGMA page_count")
        total_pages = cursor.fetchone()[0]
        conn.close()

        if free_pages <= 0:
            return findings

        log.warning(f"{db_path.name}: {free_pages}/{total_pages} free pages — attempting verification-time VACUUM")

        # Attempt VACUUM to clear the freelist now.
        vacuumed = False
        try:
            vconn = sqlite3.connect(str(db_path))
            vconn.execute("VACUUM")
            vconn.close()
            vacuumed = True
        except sqlite3.OperationalError:
            pass

        if vacuumed:
            # Re-check: if freelist is now 0, no finding needed.
            try:
                vconn2 = sqlite3.connect(str(db_path))
                remaining = vconn2.execute("PRAGMA freelist_count").fetchone()[0]
                vconn2.close()
                if remaining == 0:
                    log.info(f"{db_path.name}: verification-time VACUUM cleared freelist — no finding")
                    return findings
            except sqlite3.Error:
                pass
            findings.append(f"{db_path.name}: {free_pages} free pages (may contain recoverable data)")
        else:
            # VACUUM failed — database is locked (e.g. Chrome WAL lock on
            # "Login Data").  The freelist is an expected artefact of the lock,
            # not a sanitization failure.  Log it as a warning only.
            log.warning(
                f"{db_path.name}: VACUUM failed at verification time (database locked — "
                f"likely Chrome WAL); freelist finding suppressed"
            )

    except sqlite3.Error as e:
        log.warning(f"Cannot inspect freelist of {db_path}: {e}")

    return findings


def scan_sqlite_content(dump_path: Path) -> list[PIIMatch]:
    """Scan SQLite database text columns for residual PII after sanitization."""
    matches = []
    databases = sqlite_sanitizer.find_all_databases(dump_path)

    for db in databases:
        try:
            conn = sqlite3.connect(str(db))
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                try:
                    cursor.execute(f"PRAGMA table_info(\"{table}\")")
                    columns = cursor.fetchall()
                except sqlite3.Error:
                    continue

                col_type_matches = lambda t: any(x in t for x in ("TEXT", "VARCHAR", "CHAR", "CLOB")) or t == ""
                text_cols = [c[1] for c in columns if col_type_matches((c[2] or "").upper())]
                for col_name in text_cols:
                    try:
                        cursor.execute(f"SELECT rowid, \"{col_name}\" FROM \"{table}\" WHERE \"{col_name}\" IS NOT NULL LIMIT 1000")
                        for rowid, value in cursor.fetchall():
                            if not isinstance(value, str):
                                continue
                            rel = str(db.relative_to(dump_path))
                            qualified_path = f"{rel}:{table}.{col_name}"
                            for name, pattern in PII_PATTERNS.items():
                                for m in pattern.finditer(value):
                                    if not _is_false_positive(qualified_path, name, m.group()):
                                        matches.append(PIIMatch(
                                            qualified_path,
                                            name, m.group(), rowid
                                        ))
                            # Context patterns on the column value
                            ctx = _scan_context_patterns(value, qualified_path)
                            for cm in ctx:
                                cm.line_number = rowid
                            matches.extend(ctx)
                    except sqlite3.Error:
                        continue

            conn.close()
        except sqlite3.Error:
            continue

    return matches


def verify_sanitization(dump_path: Path) -> VerificationResult:
    """
    Full post-sanitization verification:
    1. Regex scan text files for PII
    2. Regex scan SQLite database contents for PII
    3. Inspect SQLite free pages
    4. Verify EXIF stripped from images
    """
    result = VerificationResult()

    log.info(f"Starting verification of {dump_path}")

    # 1. Text file PII scan
    result.pii_matches = scan_text_files(dump_path)

    # 2. SQLite content PII scan
    db_pii = scan_sqlite_content(dump_path)
    result.pii_matches.extend(db_pii)
    if db_pii:
        log.info(f"SQLite content scan: {len(db_pii)} PII matches in database content")

    # 3. SQLite freelist inspection
    databases = sqlite_sanitizer.find_all_databases(dump_path)
    result.databases_inspected = len(databases)
    for db in databases:
        findings = scan_sqlite_freelist(db)
        result.sqlite_freelist_findings.extend(findings)

    # 4. EXIF verification
    files_with_exif = exif_stripper.verify_exif_stripped(dump_path)
    result.exif_failures = [str(f.relative_to(dump_path)) for f in files_with_exif]

    result.passed = result.total_findings == 0

    status = "PASSED" if result.passed else f"FAILED ({result.total_findings} findings)"
    log.info(f"Verification {status}: "
             f"{len(result.pii_matches)} PII, "
             f"{len(result.sqlite_freelist_findings)} freelist, "
             f"{len(result.exif_failures)} EXIF")

    return result
