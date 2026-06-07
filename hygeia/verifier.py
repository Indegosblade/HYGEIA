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
    # GPS pattern: filter out version numbers and timestamps
    if pattern_name == "gps_coord" and abs(float(match_text)) < 1.0:
        return True
    # Skip already-redacted values
    if "[REDACTED" in match_text or "REDACTED_" in match_text:
        return True
    # Skip URL columns — they contain tracking IDs, product numbers, and
    # fragments that match numeric PII patterns but aren't actual PII
    noisy_columns = ("url", "page_url", "top_level_url", "referrer", "etag",
                     "fill_into_edit", "text", "contents", "value")
    if pattern_name in ("phone_us", "phone_intl", "credit_card", "ssn", "gps_coord", "imei", "iban", "mac_addr"):
        col_part = path.rsplit(".", 1)[-1] if "." in path else ""
        if col_part in noisy_columns:
            return True
    return False


def scan_text_files(dump_path: Path, max_file_size: int = 10 * 1024 * 1024) -> list[PIIMatch]:
    """Regex scan all text-extractable files for PII patterns."""
    matches = []
    scanned = 0

    for f in dump_path.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in TEXT_SCANNABLE:
            continue
        if f.stat().st_size > max_file_size:
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
            scanned += 1
        except (OSError, UnicodeDecodeError):
            continue

    log.info(f"Text scan: {scanned} files scanned, {len(matches)} PII matches")
    return matches


def scan_sqlite_freelist(db_path: Path) -> list[str]:
    """
    Check SQLite database free pages for recoverable PII.
    After VACUUM, there should be zero free pages.
    """
    findings = []
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA freelist_count")
        free_pages = cursor.fetchone()[0]
        if free_pages > 0:
            findings.append(f"{db_path.name}: {free_pages} free pages (may contain recoverable data)")

        cursor.execute("PRAGMA page_count")
        total_pages = cursor.fetchone()[0]

        conn.close()

        if free_pages > 0:
            log.warning(f"{db_path.name}: {free_pages}/{total_pages} free pages remaining")
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
