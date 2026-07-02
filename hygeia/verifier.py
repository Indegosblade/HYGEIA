"""
HYGEIA Verifier -- post-sanitization PII verification.

Three independent checks: regex PII scan across text files,
SQLite freelist inspection for recoverable records, and EXIF
tag verification for residual image metadata.

Patterns loaded from the central registry (rules/pii_patterns.json).
"""

import re
import sqlite3
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import sqlite_sanitizer, exif_stripper
from .patterns import load_patterns, get_default_registry, PatternRegistry
from .utils import quote_identifier

log = logging.getLogger("hygeia.verifier")

_registry: PatternRegistry | None = None

# Records whether the verifier was narrowed via --only/--skip. A narrowed
# verify can only see the selected categories, so it can NEVER certify a full
# clean — verify_sanitization surfaces this as result.scope and the CLI must
# print it so a scoped run is never mistaken for an unqualified PASSED (#43).
_scope_only: list[str] | None = None
_scope_skip: list[str] | None = None


def _get_registry() -> PatternRegistry:
    global _registry
    if _registry is None:
        _registry = get_default_registry()
    return _registry


def configure(only: list[str] | None = None, skip: list[str] | None = None):
    """Reconfigure the verifier with specific pattern categories."""
    global _registry, _scope_only, _scope_skip
    _registry = load_patterns(only=only, skip=skip)
    _scope_only = only
    _scope_skip = skip


# Default compiled patterns — exposed for tests and external consumers.
# Internal scan functions use _get_registry() which respects configure().
PII_PATTERNS = get_default_registry().regex_patterns
CONTEXT_PATTERNS = get_default_registry().context_patterns

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
    # Checks that could NOT be run to completion (missing tool, unreadable /
    # locked DB, oversized input). Each entry is {check, path, reason}. A
    # forensic sanitizer must FAIL CLOSED: an un-run check is not a clean
    # check, so any incomplete entry blocks `passed`.
    incomplete: list = field(default_factory=list)
    # When set, verification was narrowed to these pattern categories via
    # --only/--skip and therefore did NOT check for PII outside them (#43).
    scope: str | None = None
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

    # Common extractions used throughout this function
    fname = path.split("/")[-1].split("\\")[-1]
    col_part = path.rsplit(".", 1)[-1] if "." in path else ""
    # GPS: valid lat/lon range is -90..90 / -180..180. Larger values are
    # memory sizes, version numbers, or other non-GPS floats.
    if pattern_name == "gps_coord":
        val = None
        try:
            val = abs(float(match_text))
            # Out of the valid lat/long envelope, or an exact zero: not a real
            # coordinate (memory sizes, version numbers, padding).
            if val > 180.0 or val == 0.0:
                return True
            # NOTE (#37): the old `val < 1.0 -> False positive` rule is REMOVED.
            # Equatorial latitudes and prime-meridian longitudes (e.g. -0.1278,
            # 5.6231) legitimately have |val| < 1 and MUST still be flagged.
        except ValueError:
            pass
        # Leading-zero integer part (07.6100, 00.1234) is a version number, not
        # GPS. A genuine sub-1 coordinate is written "0.xxxx" and is exempt.
        stripped = match_text.lstrip("-")
        if stripped.startswith("0") and not stripped.startswith("0."):
            return True
        # Layout-metric heuristics apply only to |val| >= 1 magnitudes. A real
        # sub-1-degree coordinate must bypass them so it is never dropped (#37).
        if val is None or val >= 1.0:
            # High-precision floats ending in exactly 4 decimals inside PLIST
            # files are layout/CSS metrics (e.g. 11.5600, 22.0598), not GPS.
            # NOTE (#37): this is scoped to .plist ONLY — the old rule also
            # suppressed .json, which silently discarded real coordinates in
            # JSON location exports.
            if fname.endswith(".plist") and re.search(r'\.\d{4}$', match_text):
                return True
            # >=8 decimal digits in a plist = power-of-2 layout fraction
            # (11.56494140625, 11.45703125), not geographic data.
            if fname.endswith(".plist"):
                decimal_match = re.search(r'\.(\d+)$', match_text)
                if decimal_match and len(decimal_match.group(1)) >= 8:
                    return True
        # Noisy column: external_mod_tag is a sync-tag integer, not GPS.
        if col_part.lower() == "external_mod_tag":
            return True
    # SSN: CoreData internal columns (Z_PK, Z_ENT, Z_OPT, ROWID …) hold
    # sequential integers that happen to match the 9-digit SSN pattern.
    if pattern_name == "ssn":
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
        # NOTE (#25): the blanket "bare 9-digit SSN in a .json/.plist/.db/
        # .sqlitedb file is a false positive" suppression is REMOVED. It made a
        # real unformatted SSN like "123456789" in a JSON export invisible to
        # the verifier. Genuine CoreData sequence/timestamp integers are still
        # suppressed above, but ONLY by column name (Z_PK / Z_ENT / timestamp
        # cols) — never by file extension.
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
    # Vector/embedding database content columns store conversation text that
    # naturally contains keyword-triggered patterns (password_kv, etc.)
    if pattern_name == "password_kv":
        embedding_cols = ("string_value", "c0", "c1", "c2", "metadata",
                          "embedding_id", "document", "content")
        if col_part.lower() in embedding_cols:
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
        if col_part in noisy_columns:
            return True

    # ── New pattern false-positive filters ────────────────────────────────────

    if pattern_name == "vin":
        if re.search(r'[0-9A-Fa-f]{17,}', match_text):
            return True

    if pattern_name == "swift_bic":
        # 8-char all-uppercase or all-same-char strings are padding/test data
        if re.match(r'^[A-Z]{8}$', match_text):
            return True
        if len(set(match_text.replace(" ", ""))) <= 2:
            return True
        # Sequential/alphabetical runs in plist files are carrier bundle identifiers
        if fname.endswith(".plist"):
            return True

    if pattern_name == "ethereum_address":
        if match_text[2:].startswith("000000000000000000000000"):
            return True

    if pattern_name == "bitcoin_address":
        if len(match_text) < 26:
            return True
        # Hex-only strings (UUIDs, hashes, embedding IDs) are not bitcoin addresses.
        # Real bitcoin addresses use base58 (mixed case, no 0OIl).
        if re.fullmatch(r'[0-9a-fA-F]+', match_text[1:]):
            return True
        # Database columns that store internal IDs, not crypto
        if col_part.lower() in ("embedding_id", "id", "uuid", "guid", "hash", "checksum"):
            return True

    # Repeated/sequential digit strings in plists are binary padding, not real identifiers
    if pattern_name in ("us_routing", "us_routing_number", "cusip", "south_korean_rrn"):
        digits = "".join(c for c in match_text if c.isdigit())
        if digits and len(set(digits)) <= 2:
            return True
        # Sequential digits (012345678, 012345679) are test/padding data in plists
        if fname.endswith(".plist") and digits:
            return True

    # Ripple/Litecoin: all-same-char strings are binary plist padding
    if pattern_name in ("ripple", "litecoin"):
        if len(set(match_text)) <= 2:
            return True

    # DEA numbers in plist files: carrier bundle checksums look like DEA format
    if pattern_name == "dea_number":
        if fname.endswith(".plist"):
            return True

    # url_credentials: Apple CDN URLs (appldnld.apple.com, updates.cdn-apple.com)
    # are not credential-bearing URLs
    if pattern_name == "url_credentials":
        if "apple.com" in match_text or "cdn-apple.com" in match_text:
            return True

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
    reg = _get_registry()
    for name, (pattern, keywords, window) in reg.context_patterns.items():
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


def scan_text_files(dump_path: Path, max_file_size: int = 10 * 1024 * 1024,
                    incomplete: list | None = None) -> list[PIIMatch]:
    """Regex scan all text-extractable files for PII patterns.

    Files larger than ``max_file_size`` cannot be loaded for scanning, so —
    fail closed — they are recorded as an ``incomplete`` entry rather than
    silently skipped as if clean (#24).
    """
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

        # Skip HYGEIA-generated output files
        if f.name.lower() in HYGEIA_OUTPUT_FILES:
            continue

        # Skip system directories (too many false positives). Done BEFORE the
        # size check so an oversized system file is not spuriously flagged.
        rel_path = str(f.relative_to(dump_path)).replace("\\", "/")
        skip = False
        for fp in FALSE_POSITIVE_PATHS:
            if rel_path.startswith(fp):
                skip = True
                break
        if skip:
            continue

        # Oversized files cannot be loaded for scanning: fail closed by
        # recording an incomplete entry rather than silently passing them (#24).
        try:
            size = f.stat().st_size
        except OSError:
            size = -1
        if size > max_file_size:
            if incomplete is not None:
                incomplete.append({
                    "check": "text_scan",
                    "path": rel_path,
                    "reason": (
                        f"file is {size} bytes (> max_file_size {max_file_size}); "
                        f"NOT scanned for PII — cannot certify clean"
                    ),
                })
            log.warning(f"{rel_path}: {size} bytes exceeds scan cap — recorded incomplete")
            continue

        try:
            reg = _get_registry()
            content = f.read_text(encoding="utf-8", errors="ignore")
            for line_num, line in enumerate(content.splitlines(), 1):
                for name, pattern in reg.regex_patterns.items():
                    for m in pattern.finditer(line):
                        match_text = m.group()
                        if not _is_false_positive(rel_path, name, match_text):
                            matches.append(PIIMatch(rel_path, name, match_text, line_num))
            matches.extend(_scan_context_patterns(content, rel_path))
            scanned += 1
        except (OSError, UnicodeDecodeError):
            continue

    log.info(f"Text scan: {scanned} files scanned, {len(matches)} PII matches")
    return matches


def _ro_uri(db_path: Path) -> str:
    """Build a read-only SQLite URI for ``db_path``.

    Verification is a read-only audit of the delivered artifact — it must never
    mutate the file it is checking (#40). ``mode=ro`` enforces that at the SQLite
    layer, and ``Path.as_uri()`` percent-encodes spaces/specials (e.g. Chrome's
    "Login Data") so the URI is well-formed cross-platform.
    """
    return db_path.resolve().as_uri() + "?mode=ro"


def _coerce_to_text(value) -> str | None:
    """Best-effort decode of a SQLite cell value to text for PII matching.

    SQLite is dynamically typed, so a column of any declared affinity can hold
    strings or BLOBs that carry text PII (#23). BLOB/bytes values are decoded
    utf-8 (errors ignored) before matching. Pure numeric cells are not text and
    are not scanned.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("utf-8", errors="ignore")
        except Exception:
            return None
    return None


def scan_sqlite_freelist(db_path: Path, incomplete: list | None = None) -> list[str]:
    """
    Inspect SQLite free pages for recoverable (deleted-row) PII.

    Verification is READ-ONLY (#40): this opens the database ``mode=ro`` and
    does NOT run VACUUM. Free pages retain the byte images of deleted rows,
    directly carveable by forensic tools, so any non-empty freelist is a
    FINDING — it is never suppressed just because the database happens to be
    locked (#4/#26). If the database cannot even be opened/inspected read-only,
    that is recorded as an ``incomplete`` entry (fail closed, #41) — never
    silently treated as clean.
    """
    findings: list[str] = []

    try:
        conn = sqlite3.connect(_ro_uri(db_path), uri=True)
    except sqlite3.Error as e:
        log.warning(f"Cannot open {db_path} read-only for freelist inspection: {e}")
        if incomplete is not None:
            incomplete.append({
                "check": "sqlite_freelist",
                "path": str(db_path),
                "reason": f"database could not be opened read-only for freelist inspection: {e}",
            })
        return findings

    try:
        cursor = conn.cursor()
        free_pages = cursor.execute("PRAGMA freelist_count").fetchone()[0]
        total_pages = cursor.execute("PRAGMA page_count").fetchone()[0]
    except sqlite3.Error as e:
        log.warning(f"Cannot inspect freelist of {db_path}: {e}")
        if incomplete is not None:
            incomplete.append({
                "check": "sqlite_freelist",
                "path": str(db_path),
                "reason": f"freelist could not be read (locked/corrupt/encrypted): {e}",
            })
        return findings
    finally:
        conn.close()

    if free_pages and free_pages > 0:
        log.warning(f"{db_path.name}: {free_pages}/{total_pages} free pages — recoverable deleted-row PII")
        findings.append(
            f"{db_path.name}: {free_pages} free pages (may contain recoverable deleted-row data)"
        )

    return findings


def _scan_sqlite_column(cursor, db, dump_path, table, col_name,
                        matches: list, incomplete: list | None) -> None:
    """Scan every non-NULL value of one column for residual PII.

    Reads ALL rows in bounded ``fetchmany`` batches (#22 — no LIMIT window) and
    decodes BLOB/bytes values to text before matching (#23). Any read failure is
    surfaced as ``incomplete`` — never silently skipped.
    """
    rel = str(db.relative_to(dump_path))
    qualified_path = f"{rel}:{table}.{col_name}"
    qt, qc = quote_identifier(table), quote_identifier(col_name)

    # Prefer rowid for forensic locability; fall back for WITHOUT ROWID / virtual
    # tables that have no rowid.
    has_rowid = True
    try:
        cursor.execute(f"SELECT rowid, {qc} FROM {qt} WHERE {qc} IS NOT NULL")
    except sqlite3.Error:
        try:
            cursor.execute(f"SELECT {qc} FROM {qt} WHERE {qc} IS NOT NULL")
            has_rowid = False
        except sqlite3.Error as e:
            if incomplete is not None:
                incomplete.append({
                    "check": "sqlite_content",
                    "path": qualified_path,
                    "reason": f"column could not be read for PII scan: {e}",
                })
            return

    reg = _get_registry()
    row_index = 0
    while True:
        try:
            batch = cursor.fetchmany(1000)
        except sqlite3.Error as e:
            if incomplete is not None:
                incomplete.append({
                    "check": "sqlite_content",
                    "path": qualified_path,
                    "reason": f"row read failed partway through PII scan: {e}",
                })
            return
        if not batch:
            return
        for row in batch:
            row_index += 1
            if has_rowid:
                rowid, value = row[0], row[1]
            else:
                rowid, value = row_index, row[0]
            text = _coerce_to_text(value)
            if text is None:
                continue
            for name, pattern in reg.regex_patterns.items():
                for m in pattern.finditer(text):
                    if not _is_false_positive(qualified_path, name, m.group()):
                        matches.append(PIIMatch(qualified_path, name, m.group(), rowid))
            ctx = _scan_context_patterns(text, qualified_path)
            for cm in ctx:
                cm.line_number = rowid
            matches.extend(ctx)


def scan_sqlite_content(dump_path: Path, incomplete: list | None = None) -> list[PIIMatch]:
    """Scan SQLite database contents for residual PII after sanitization.

    Opens each database READ-ONLY (#40) and scans EVERY column regardless of
    declared affinity (#23) across ALL rows (#22). A database that cannot be
    opened or whose schema cannot be read is recorded as ``incomplete`` — an
    unreadable database is never reported clean (#41).
    """
    matches: list = []
    databases = sqlite_sanitizer.find_all_databases(dump_path)

    for db in databases:
        try:
            conn = sqlite3.connect(_ro_uri(db), uri=True)
        except sqlite3.Error as e:
            log.warning(f"Cannot open {db} read-only for content scan: {e}")
            if incomplete is not None:
                incomplete.append({
                    "check": "sqlite_content",
                    "path": str(db),
                    "reason": f"database could not be opened read-only for PII content scan: {e}",
                })
            continue

        try:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
                tables = [row[0] for row in cursor.fetchall()]
            except sqlite3.Error as e:
                if incomplete is not None:
                    incomplete.append({
                        "check": "sqlite_content",
                        "path": str(db),
                        "reason": f"table list could not be read (locked/corrupt/encrypted): {e}",
                    })
                continue

            for table in tables:
                try:
                    cursor.execute(f"PRAGMA table_info({quote_identifier(table)})")
                    columns = cursor.fetchall()
                except sqlite3.Error as e:
                    if incomplete is not None:
                        incomplete.append({
                            "check": "sqlite_content",
                            "path": f"{db}:{table}",
                            "reason": f"table schema could not be read: {e}",
                        })
                    continue

                # Scan ALL columns regardless of declared affinity (#23).
                for col in columns:
                    _scan_sqlite_column(cursor, db, dump_path, table, col[1],
                                        matches, incomplete)
        finally:
            conn.close()

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

    # A narrowed verify (--only/--skip) cannot see PII outside the selected
    # categories, so record the scope; the CLI must never present it as a full
    # clean (#43).
    if _scope_only or _scope_skip:
        result.scope = ", ".join(sorted(_get_registry().active_categories)) or "(none)"

    log.info(f"Starting verification of {dump_path}")

    # 1. Text file PII scan (oversized files -> incomplete)
    result.pii_matches = scan_text_files(dump_path, incomplete=result.incomplete)

    # 2. SQLite content PII scan (unreadable DBs -> incomplete)
    db_pii = scan_sqlite_content(dump_path, incomplete=result.incomplete)
    result.pii_matches.extend(db_pii)
    if db_pii:
        log.info(f"SQLite content scan: {len(db_pii)} PII matches in database content")

    # 3. SQLite freelist inspection (uninspectable DBs -> incomplete)
    databases = sqlite_sanitizer.find_all_databases(dump_path)
    result.databases_inspected = len(databases)
    for db in databases:
        findings = scan_sqlite_freelist(db, incomplete=result.incomplete)
        result.sqlite_freelist_findings.extend(findings)

    # 4. EXIF verification. Without exiftool the images can be neither stripped
    #    nor verified — surface that as incomplete instead of reporting a false
    #    clean (#1/#8/#42). With exiftool present, residual-EXIF images are
    #    ordinary findings.
    if exif_stripper.find_exiftool() is None:
        image_files = [
            f for f in dump_path.rglob("*")
            if f.is_file() and f.suffix.lower() in exif_stripper.IMAGE_EXTENSIONS
        ]
        if image_files:
            log.warning(
                f"exiftool not installed — {len(image_files)} image(s) could not be "
                f"verified for residual EXIF/GPS metadata"
            )
            result.incomplete.append({
                "check": "exif",
                "path": str(dump_path),
                "reason": (
                    f"exiftool not installed — {len(image_files)} image(s) were neither "
                    f"stripped nor verified for residual EXIF/GPS metadata"
                ),
            })
    else:
        files_with_exif = exif_stripper.verify_exif_stripped(dump_path)
        result.exif_failures = [str(f.relative_to(dump_path)) for f in files_with_exif]

    # FAIL CLOSED: a clean result requires zero findings AND that every check
    # actually ran to completion.
    result.passed = result.total_findings == 0 and not result.incomplete

    status = "PASSED" if result.passed else (
        f"FAILED ({result.total_findings} findings, {len(result.incomplete)} incomplete)"
    )
    log.info(f"Verification {status}: "
             f"{len(result.pii_matches)} PII, "
             f"{len(result.sqlite_freelist_findings)} freelist, "
             f"{len(result.exif_failures)} EXIF, "
             f"{len(result.incomplete)} incomplete"
             + (f", scope={result.scope}" if result.scope else ""))

    return result
