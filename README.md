# HYGEIA

[![CI](https://github.com/Indegosblade/HYGEIA/actions/workflows/ci.yml/badge.svg)](https://github.com/Indegosblade/HYGEIA/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Indegosblade/HYGEIA/branch/main/graph/badge.svg)](https://codecov.io/gh/Indegosblade/HYGEIA)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg)](https://github.com/Indegosblade/HYGEIA/actions/workflows/ci.yml)
[![License: PolyForm](https://img.shields.io/badge/license-PolyForm%20NC-green.svg)](LICENSE)

Forensic-grade PII sanitization that actually understands what it's looking at.

20 schema-aware handlers detect and surgically clean Chrome profiles, Firefox databases, iOS filesystem dumps, Android extractions, and Windows forensic artifacts — by table signature, not filename guessing. Everything else gets full regex + column-name scanning as a safety net. Zero external pip dependencies.

**Platforms tested in-house:** Chrome/Chromium (4 handlers) · Firefox (3) · iOS (8) · Android (3) · Windows (1 + filesystem rules) · macOS · Linux

**Compliance:** HIPAA Safe Harbor · GDPR Article 4/9 · CCPA — with per-run coverage reporting.

**Verification:** fail-closed — a run is only reported PASSED when there are zero PII findings *and* every check actually ran to completion. A missing tool, a locked database, an oversized file, or a narrowed `--only`/`--skip-patterns` scope makes HYGEIA exit non-zero and say so, instead of guessing clean.

---

## Why HYGEIA?

Existing tools either don't do this or solve a different problem:

- **Cellebrite UFED / Magnet AXIOM / EnCase** — $15K–$50K/seat forensic *acquisition* tools. They extract and present PII. They don't remove it. If you need to share a dump without leaking personal data, they have no answer.
- **Autopsy** — Free forensic analysis. Same problem: it finds PII, it doesn't sanitize it. There's no "redact and export clean" workflow.
- **Manual SQLite editing** — Misses WAL files (which contain 50–95% of "deleted" records), misses freelist pages, misses FTS shadow tables, misses LevelDB, misses thumbnail caches. One missed artifact and the data is recoverable.
- **Generic regex scrubbers** — Don't understand database schemas. Can't distinguish a Chrome Login Data table from a Firefox permissions table. Can't do WAL checkpointing or VACUUM. Can't handle platform-specific column semantics.

HYGEIA exists because no tool combines platform-aware surgical sanitization with anti-forensic hardening in a single pass. It's built for security researchers sharing device dumps, forensic analysts preparing court exhibits, red teams sanitizing test data, and compliance teams processing DSAR requests — anyone who needs the structural data without the personal data.

---

## Installation

```bash
pip install git+https://github.com/Indegosblade/HYGEIA.git
```

Requirements: Python 3.10+. Optional: [exiftool](https://exiftool.org/) for image metadata stripping.

---

## Usage

```bash
# Standard sanitization
hygeia --input /path/to/data --output /path/to/clean

# Preview without modifying anything
hygeia --input /path/to/data --output /unused --dry-run

# HIPAA-compliant sanitization
hygeia --input /path/to/data --output /path/to/clean --compliance hipaa

# Maximum sanitization: all compliance frameworks + timestamp normalization
hygeia --input /path/to/data --output /path/to/clean --compliance all --normalize-timestamps

# Verbose output with custom manifest path
hygeia --input /path/to/data --output /path/to/clean -v --manifest audit.json
```

### Pattern Selection

```bash
# Only strip image metadata (EXIF GPS, device identifiers)
hygeia --input /path/to/data --output /clean --only exif

# Only detect VINs and credit cards
hygeia --input /path/to/data --output /clean --only vin,credit_card

# Run everything except crypto wallet detection
hygeia --input /path/to/data --output /clean --skip-patterns crypto

# Only run identity + financial patterns (no credentials, no location, no healthcare)
hygeia --input /path/to/data --output /clean --only identity,financial

# List all available categories and patterns
hygeia --list-patterns
```

### Flags

| Flag | Description |
|------|-------------|
| `--input PATH`, `-i` | Source data directory |
| `--output PATH`, `-o` | Destination for sanitized copy |
| `--dry-run`, `-n` | Preview all actions without executing |
| `--compliance MODE` | Compliance mode: `hipaa`, `gdpr`, `ccpa`, or `all` |
| `--only PATTERNS` | Comma-separated categories or pattern names to activate exclusively |
| `--skip-patterns PATTERNS` | Comma-separated categories or pattern names to exclude |
| `--list-patterns` | Print all available categories and patterns, then exit |
| `--normalize-timestamps` | Set all file timestamps to epoch (defeats timeline analysis) |
| `--skip-verify` | Skip post-sanitization verification |
| `--skip-exif` | Skip EXIF metadata stripping |
| `--manifest PATH`, `-m` | Custom path for JSON audit manifest |
| `--verbose`, `-v` | Detailed logging |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Sanitization complete, verification passed (or skipped) |
| 1 | Input error (path not found, output already exists) |
| 2 | Verification failed — residual PII detected, and/or verification could not certify the dump clean (missing exiftool, a locked/unreadable/encrypted database, an oversized file, or a narrowed `--only`/`--skip-patterns` scope). HYGEIA never exits 0 when it can't back that up. |

---

## Pipeline

HYGEIA runs a deterministic 7-stage pipeline on every invocation:

```
[1/7] Scan          Classify every file by type. Auto-detect iOS or generic mode.
[2/7] Databases     Platform detection → WAL-checkpoint → secure_delete → regex scan → table nuke → FTS rebuild → VACUUM
[3/7] Text files    Redact PII in JSON, logs, CSV/TSV. Delete shell history files.
[4/7] Forensics     Delete LevelDB stores, thumbnail caches, swap files, search indexes, session data.
[5/7] Media         Strip EXIF from images, metadata from PDFs (author/creator/producer/XMP), Office docs (docx/xlsx/pptx properties + tracked-changes/comment authors).
[6/7] Verify        Read-only, fail-closed scan: every row and column (incl. BLOB) of every surviving database, plus every text file, checked for residual PII. Anything that couldn't be checked to completion is recorded as incomplete, never assumed clean.
[7/7] Manifest      Write JSON audit trail: actions taken, verification result, compliance report.
```

The pipeline is fail-closed: if verification finds residual PII — or cannot prove the output clean because some check didn't run to completion — HYGEIA exits with code 2 and reports exactly what was found, or what couldn't be checked, and where. A passing run means zero PII detections **and** zero incomplete checks across all scanned content.

---

## What It Detects

All patterns live in a single JSON source of truth (`hygeia/rules/pii_patterns.json`) organized into selectable categories. Each pattern can be activated individually or by category via `--only`/`--skip-patterns`.

### Pattern Categories

| Category | Patterns | Examples |
|----------|----------|----------|
| **Identity** | 12 | SSN, UK NIN, Indian PAN/Aadhaar, US passport, driver's license, Canadian SIN, Australian TFN, US ITIN, EIN |
| **Location** | 4 | GPS coordinates (incl. sub-1° values like `-0.1278`), IPv4, IPv6 (full + compressed `::` notation), MAC addresses |
| **Financial** | 6 | Credit cards (incl. spaced/hyphenated Amex), IBAN, SWIFT/BIC, US routing numbers, Bitcoin addresses, Ethereum addresses |
| **Credentials** | 8 | AWS access keys, AWS secret keys, GitHub tokens, Slack tokens, JWT tokens, generic API keys, private key headers, password key-value pairs |
| **Crypto** | 4 | Bitcoin (legacy + bech32), Ethereum, plus Monero/Solana/Cardano (context-dependent) |
| **Healthcare** | 3 | NPI (standalone + context), DEA numbers, Medicare MBI |
| **Vehicle** | 2 | VIN (17-char ISO 3779), UK license plates |

### Context-Dependent Patterns

These patterns only fire when a nearby keyword confirms the context — short digit sequences (9-10 digits), key=value pairs, and base64-looking strings are too ambiguous to flag on content alone. They're applied consistently in both directions: during sanitization (JSON/log/CSV redaction) and during verification (residual-PII scanning), so a match is redacted the same way it would otherwise be flagged as a leftover finding:

| Pattern | Keywords Required | Window |
|---------|-------------------|--------|
| US passport | "passport" | 120 chars |
| Driver's license | "license", "dl", "driver" | 120 chars |
| Canadian SIN | "sin", "social insurance" | 120 chars |
| Australian TFN | "tfn", "tax file" | 120 chars |
| US routing number | "routing", "aba", "bank" | 120 chars |
| Date of birth | "dob", "birth", "birthday" | 200 chars |
| Password (key=value) | "password", "passwd", "pwd" | 200 chars |
| AWS secret key | "aws", "secret", "AWS_SECRET" | 120 chars |
| NPI | "npi", "provider", "prescriber" | 120 chars |

### Column-Name Detection

60+ column names treated as inherently sensitive regardless of content — any non-empty value replaced with `[REDACTED]`:

`email`, `username`, `password`, `phone`, `address`, `street`, `city`, `zip`, `first_name`, `last_name`, `full_name`, `ssn`, `credit_card`, `latitude`, `longitude`, `api_key`, `token`, `cookie`, `session`, `encrypted_value`, `ip_address`, `remote_addr`, `mac_address`, `device_id`, `udid`, `serial_number`, `imei`, `account_number`, and more.

JSON/plist key-name detection additionally recognizes a dedicated `address` category (`street`, `city`, `zip`, `postal_code`, `employer`, `organization`, and more) and iOS CoreData location columns (`ZLATITUDE`, `ZLONGITUDE`, `ZLOCATION`, `ZALTITUDE`, `ZCOORDINATE`). The CoreData names also drive GPS detection in plist **float** and location-hint-keyed integer values (e.g. `lastKnownLatitude` stored as a `<real>`), which were previously left untouched regardless of key name.

### Table-Level Nuking

80+ table names across platforms — all rows deleted, schema preserved:

- **Chrome/Chromium**: `autofill`, `autofill_profiles`, `credit_cards`, `logins`, `cookies`, `omni_box_shortcuts`, `top_sites`, `keyword_search_terms`, `downloads`
- **Firefox**: `moz_formhistory`, `moz_cookies`, `moz_inputhistory`, `moz_perms`, `moz_hosts`, `moz_logins`, `webappsstore2`, `storage_sync_data`
- **Android**: `raw_contacts`, `data`, `calls`, `sms`, `threads`, `canonical_addresses`, `siminfo`, `carriers`
- **iOS**: `history_items`, `history_visits`, `zperson`, `zdetectedface`, `zdetectedfaceprint`, `zshare`, `zmemory`
- **Windows**: `notification`
- **Generic**: `contacts`, `messages`, `call_log`, `accounts`, `search_history`, `purchase_history`, `geolocation`, `location_history`

---

## Platform Coverage

Every platform listed below ships with tested handlers — not theoretical coverage. Auto-detection is by table signature (schema inspection), not filename or directory path.

### Chrome / Chromium (4 handlers)

History, Login Data, Web Data, Cookies, Shortcuts, Top Sites, Favicons, DIPS, Network Action Predictor, Extension Cookies, Affiliation Database, Media History. Auto-detected by table signature — Login Data is nuked differently than History. LevelDB localStorage and IndexedDB directory deletion. Session data cleanup.

### Firefox (3 handlers)

places.sqlite, cookies.sqlite, formhistory.sqlite, permissions.sqlite, content-prefs.sqlite, key4.db, cert9.db, signons.sqlite, webappsstore.sqlite. Auto-detected by `moz_*` table presence. IndexedDB storage directory deletion. Session restore file deletion. Cache cleanup.

### iOS (8 handlers)

Messages, Photos.sqlite, Health, Contacts, Safari History/Bookmarks, Notes, knowledgeC, Screen Time, TCC.db. Jailbreak-aware scanning with dynamic detection of Dopamine, palera1n, and RootHide. Preserves jailbreak infrastructure (`/var/jb/`, `/private/preboot/`, package databases) while removing user data. Column-level sanitization for knowledgeC.db (redacts third-party app names, preserves system app usage) and Photos.sqlite (NULLs GPS coordinates, deletes facial recognition data — detection now correctly matches both the pre-iOS-14 (`ZGENERICASSET`) and iOS 14+ (`ZASSET`) schema, either of which is sufficient on its own). SEGB biome stream deletion. Third-party app container cleanup with WAL handling.

### Android (3 handlers)

contacts2.db, mmssms.db, telephony.db, calendar.db, accounts.db, webview.db. Thumbnail cache deletion. Google Analytics database deletion.

### Windows (1 handler + filesystem rules)

WebCacheV01.dat (ESE-based). Prefetch files (.pf), jump lists (.automaticDestinations-ms), LNK files, event logs (.evtx), recycle bin markers ($I/$R files), swap/hibernation files (pagefile.sys, swapfile.sys, hiberfil.sys), thumbnail caches (Thumbcache_*.db).

### macOS

TCC.db permission grants, quarantine events database, Spotlight indexes (.Spotlight-V100), FSEvents logs (.fseventsd), shell history files, Accounts databases, unified log traces.

### Linux

Shell history files (.bash_history, .zsh_history, .python_history, etc.), GNOME Tracker databases, thumbnail caches, systemd journal artifacts.

### Generic (fallback for any unrecognized database)

Any directory containing SQLite databases: HYGEIA scans every column in every table — regardless of declared type, including BLOB/INTEGER/REAL columns holding text-as-bytes — for PII patterns, with no platform-specific knowledge required. This is the safety net — if your database isn't one of the 20 recognized types, it still gets sanitized.

---

## Compliance

### HIPAA Safe Harbor (45 CFR 164.514(b)(2))

The `--compliance hipaa` flag activates detection for all 18 Safe Harbor identifiers: names, geographic subdivisions below state level, dates (except year), phone numbers, fax numbers, email addresses, Social Security numbers, medical record numbers, health plan beneficiary numbers, account numbers, certificate/license numbers, vehicle identifiers, device identifiers, web URLs, IP addresses, biometric identifiers, photographs, and unique codes. Every run evaluates all 18 against the evidence the sanitizer actually produced (redacted columns, nuked tables, regex hits) — an identifier is reported `covered` only when there's positive evidence for it; otherwise it's a `gap` (fail closed: absence of evidence is never silently treated as removed).

Safe Harbor also calls for dates to be generalized to the year and ZIP codes truncated to 3 digits (`000` for the HHS-listed low-population prefixes). `generalize_date()`/`truncate_zip()` implement those transforms and are wired through `ComplianceProfile.transform_value()`, but the running pipeline itself only redacts date-of-birth/ZIP *columns* by name — it does not rewrite free-text dates or ZIP codes found elsewhere. The per-run report spells this out as a `limitations` entry rather than letting a `covered` dates/geography result imply more than was actually done.

### GDPR Article 4/9

The `--compliance gdpr` flag adds detection for special category data as defined in Article 9: racial/ethnic origin, political opinions, religious beliefs, trade union membership, genetic data, biometric data, health data, and sexual orientation. Column-name detection is extended with terms like `race`, `ethnicity`, `religion`, `political_opinion`, `genetic_data`, `health_data`. Like HIPAA, GDPR mode reports real per-identifier `covered`/`gaps` (previously the framework name was reported with no coverage detail behind it). Special-category detection is column-name-based only — free-text special-category data in a notes/bio/message column is not detected, and the report says so via a standing `limitations` entry and an explicit `free_text_special_categories` gap.

### CCPA

The `--compliance ccpa` flag treats browsing history, search history, geolocation data, and purchase/transaction records as mandatory-delete categories, reflecting the CCPA's broad definition of personal information that includes behavioral and commercial data. As with GDPR, CCPA mode reports identifier-level coverage/gaps rather than a bare framework label, and calls out when a `delete_browsing_history` request found no matching tables to delete in that particular dump.

### Combined Mode

`--compliance all` applies the union of all frameworks — the most aggressive sanitization profile available.

Every compliance run's report — any mode — includes `identifiers_covered`, `gaps`, and a `limitations` list. The named framework (`HIPAA Safe Harbor`, etc.) is only ever a label; those three fields are the honest, per-dataset account of what was actually delivered, and nothing is marked `covered` without positive evidence from that run.

---

## Anti-Forensic Hardening

HYGEIA is designed to produce output that withstands examination by forensic tools including Cellebrite UFED, Autopsy, EnCase, and Magnet AXIOM.

| Technique | What it defeats |
|-----------|----------------|
| WAL checkpoint + companion file deletion | WAL file carving for deleted records |
| `PRAGMA secure_delete = ON` | Deleted cell recovery within live database pages |
| VACUUM rebuild (failure surfaced, never silent) | Freelist page carving from unallocated database pages |
| FTS3/4/5 shadow table rebuild — fails closed on structurally contentless/external-content tables | Full-text search index data recovery (`*_content`, `*_segments`, `*_data`, `*_idx`) |
| Random-byte overwrite before unlink (databases + WAL/SHM/journal companions) | Forensic carving of deleted database bytes from unallocated disk blocks |
| LevelDB directory deletion | Chrome localStorage/IndexedDB content carving |
| Thumbnail cache deletion | Thumbnail persistence after source file deletion |
| Swap/hibernation file deletion | RAM artifact recovery from pagefile.sys, hiberfil.sys |
| Shell history deletion | Command-line credential and activity recovery |
| Spotlight/search index deletion | Indexed document content recovery |
| Timestamp normalization (symlink-safe — never follows a link off the dump) | MACB timeline reconstruction and activity correlation |

---

## Verification

Every sanitization run includes automatic verification (disable with `--skip-verify`). Verification is **fail-closed**: it never reports a dump clean when it could not actually prove that — a missing tool, a locked database, or a narrowed pattern selection blocks a PASSED result exactly like a residual PII match would.

1. **Content scan**: every surviving text file, and the full content of every SQLite database — all tables, all columns regardless of declared type (TEXT/BLOB/INTEGER/REAL), all rows, no row cap — is regex-scanned for the full set of PII patterns. BLOB/bytes cells are UTF-8 decoded before matching, so PII stored in a column typed as binary is still caught. Databases are opened strictly read-only (`mode=ro`); verification never writes to, VACUUMs, or otherwise mutates the artifact it's checking.
2. **Freelist inspection**: every SQLite database is opened read-only and checked for non-zero freelist page counts. Any non-zero freelist is always reported as a finding — verification no longer attempts its own VACUUM and silently drops the finding when that VACUUM is blocked by a lock (which used to happen for e.g. a Chrome WAL lock on "Login Data").
3. **EXIF check**: images are verified for residual GPS coordinates and device identifier tags — but only when exiftool is installed. Without it, images are neither stripped nor verified, and this is now reported as an **incomplete** check rather than a silent, unearned pass.
4. **False positive filtering**: URL columns, system framework paths, and already-redacted values are excluded to prevent noise.

A run ends in one of three states:

- **PASSED** — zero PII findings, zero freelist findings, zero EXIF failures, and every check ran to completion. Exit code 0.
- **FAILED (findings)** — one or more residual PII, freelist, or EXIF findings. Exit code 2.
- **FAILED (incomplete)** — every check that *did* run found nothing, but at least one check could not be completed at all: exiftool missing, a database locked/corrupt/encrypted and unreadable, a file or database too large to scan, or a `--only`/`--skip-patterns` run that narrowed the categories checked. HYGEIA prints exactly which checks are incomplete and why, and exits code 2 — it will not print "PASSED" when it cannot back that up.

A `--only`/`--skip-patterns` run also carries a **scope** annotation: since it only checked the selected categories, a pass is reported as "PASSED for scoped categories (...) only — NOT a full-clean certification," never as an unqualified clean bill of health.

A failing verification reports the exact file, table, column, row, and matched pattern for every finding — and the exact check, path, and reason for every incomplete item.

---

## Programmatic API

```python
from pathlib import Path

# Generic database sanitization
from hygeia.sqlite_sanitizer import sanitize_database_generic
result = sanitize_database_generic(Path("any_database.db"))
print(f"Redacted {result['rows_redacted']} rows, found: {result['pii_types_found']}")
# => Redacted 847 rows, found: ['email', 'phone', 'sensitive_column:username']

# Platform-aware database sanitization (auto-detects Chrome, Firefox, iOS, etc.)
from hygeia.platform_handlers import sanitize_with_platform_detection
result = sanitize_with_platform_detection(Path("Login Data"))
print(f"Platform: {result.get('platform', 'generic')}, deleted: {result['rows_deleted']}")
# => Platform: chrome_login_data, deleted: 34

# Text file sanitization
from hygeia.text_sanitizer import sanitize_json, sanitize_log_file, sanitize_csv
result = sanitize_json(Path("config.json"))
# => {'action': 'sanitize_json', 'fields_redacted': 3, 'path': 'config.json'}

# Pattern registry — configure which patterns are active
from hygeia.patterns import load_patterns, list_available
registry = load_patterns(only=["identity", "financial"])  # category filter
registry = load_patterns(skip=["crypto"])                 # exclude a category
print(list_available())
# => {'identity': ['ssn', 'uk_nin', 'pan_card', ...], 'financial': ['credit_card', 'iban', ...], ...}

# Forensic artifact cleanup
from hygeia.filesystem_sanitizer import sanitize_filesystem
actions = sanitize_filesystem(Path("/path/to/dump"), normalize_timestamps=True)
# => [{'action': 'delete', 'path': 'LocalStorage/leveldb/', 'reason': 'leveldb_store'}, ...]

# Post-sanitization verification (fail-closed: passed requires zero findings
# AND zero incomplete checks — see result.incomplete / result.scope)
from hygeia.verifier import verify_sanitization
result = verify_sanitization(Path("/path/to/clean"))
assert result.passed, f"{result.total_findings} findings, {len(result.incomplete)} incomplete checks"
# => VerificationResult(passed=True, total_findings=0, incomplete=[], scope=None)

# Compliance-driven sanitization
from hygeia.compliance import get_compliance_profile
profile = get_compliance_profile("hipaa")
sanitize_database_generic(Path("patient.db"),
    extra_columns=profile.extra_sensitive_columns,
    extra_tables=profile.extra_pii_tables)
# => {'rows_redacted': 2341, 'pii_types_found': ['sensitive_column:mrn', 'npi', 'email']}
```

---

## Optional Dependencies

### exiftool (image metadata stripping)

HYGEIA uses [exiftool](https://exiftool.org/) to strip EXIF metadata from images (GPS coordinates, device make/model, timestamps, and all other embedded tags). Without it, step [5/7] is silently skipped and image metadata is **not** removed.

If exiftool is missing at startup, HYGEIA prints:

```
WARNING: exiftool not installed. Image metadata will NOT be stripped.
         Install from https://exiftool.org/ to enable EXIF stripping.
```

Verification honors the same gap: if exiftool is missing and the dump contains images, step [6/7] reports those images as an **incomplete** check — neither stripped nor verified — instead of reporting a false PASSED. Install exiftool, or accept the incomplete result and its non-zero exit code, if the dump contains images.

**Installation:**

| Platform | Command |
|----------|---------|
| macOS | `brew install exiftool` |
| Debian/Ubuntu | `apt-get install libimage-exiftool-perl` |
| Windows | Download from [exiftool.org](https://exiftool.org/) and place `exiftool.exe` in `C:\exiftool\` or `C:\Program Files\exiftool\` |

HYGEIA probes `PATH` first, then checks `C:\exiftool\exiftool.exe` and `C:\Program Files\exiftool\exiftool.exe` on Windows and `/usr/bin/exiftool` and `/usr/local/bin/exiftool` on Unix — so a standalone Windows install works without adding it to `PATH`.

To skip EXIF stripping intentionally (e.g. in environments without exiftool), pass `--skip-exif`.

---

## Architecture

```
hygeia/
├── cli.py                   7-stage pipeline orchestrator + CLI argument handling
├── scanner.py               File classification engine (DELETE/PRESERVE/SELECTIVE_DB/PLIST/EXIF)
├── patterns.py              Central pattern registry — loads pii_patterns.json, compiles regexes, filters by --only/--skip
├── sqlite_sanitizer.py      WAL-aware database sanitization — checkpoint → secure_delete → scan → VACUUM; safe identifier quoting, BLOB scanning, FTS3/4/5 fail-closed cleanup, secure-overwrite delete
├── platform_handlers.py     20 tested schema-aware handlers (Chrome, Firefox, iOS, Android, Windows, macOS) with table-signature auto-detection
├── text_sanitizer.py        JSON, log, CSV/TSV sanitization + shell history deletion; context-pattern redaction (DOB, passwords, AWS keys, ...), fail-closed oversize handling
├── filesystem_sanitizer.py  Forensic artifact removal — LevelDB, caches, swap, indexes; symlink-safe timestamp normalization
├── forensic_cleaner.py      Anti-forensic hardening — slack space, ADS, extended attributes; symlink containment, concurrent-worker-safe cleanup
├── plist_sanitizer.py       Binary plist credential redaction (recursive key-walk, incl. float/GPS values and location-hint integers)
├── exif_stripper.py         Image metadata removal via exiftool (9 formats)
├── pdf_stripper.py          PDF metadata stripping (author, creator, producer, keywords, XMP packets); symlink-safe in-place rewrite
├── office_stripper.py       Office document metadata removal (docx/xlsx/pptx XML properties, tracked-changes/comment authors); DTD/entity-expansion guard
├── compliance.py            HIPAA/GDPR/CCPA compliance profiles + evidence-based coverage reporting with a `limitations` field
├── verifier.py              Post-sanitization PII verification (regex + freelist + EXIF) — read-only, fail-closed (`incomplete`/`scope`), exits 2 when it can't certify clean
├── manifest.py              JSON audit trail generation
├── utils.py                 Shared helpers — SQL identifier quoting, symlink containment (`resolve_within`, `is_safe_regular_file`, `safe_utime`)
└── rules/
    ├── pii_patterns.json          Single source of truth — 40+ regex patterns in 7 categories
    ├── delete_patterns.json       34 directory + 40 database + 10 extension patterns
    ├── preserve_patterns.json     18 directory + 5 file + 4 extension rules
    ├── selective_db_rules.json    Column-level SQL for knowledgeC, Photos.sqlite, TCC.db
    └── plist_patterns.json        29 sensitive key patterns + path-based rules
```

Zero external pip dependencies. Stdlib only. Optional system exiftool for image metadata.

---

## Limitations

Documenting what HYGEIA doesn't do is as important as what it does:

| Limitation | Detail |
|-----------|--------|
| **Encrypted databases** | HYGEIA cannot read or sanitize encrypted SQLite databases (e.g. Signal's sqlcipher, FileVault-encrypted volumes). If a database requires a key to open, it's skipped with a warning during sanitization — and because verification is fail-closed, that same unreadable database is reported as an **incomplete** check, so a dump containing one exits 2, not 0. |
| **Non-SQLite databases** | ESE databases (Windows WebCache, SRUM) are identified and flagged but not parsed internally. LevelDB stores are deleted entirely rather than selectively sanitized. |
| **Binary application data** | Proprietary binary formats (e.g. Chrome's SNSS session files, Firefox sessionstore.jsonlz4 internals) are deleted rather than surgically edited. |
| **Network captures** | PCAP/PCAPNG files are not parsed. If your dump contains packet captures, remove them separately. |
| **Disk-level artifacts** | HYGEIA operates at the filesystem level. It cannot wipe unallocated disk sectors, MFT entries, or journal data below the filesystem. For that, use a disk-level tool after HYGEIA cleans the logical files. |
| **Steganography** | Embedded data within image pixel values is not detected or removed. EXIF/XMP metadata is stripped; pixel content is untouched. |
| **Memory dumps** | Raw RAM dumps (.raw, .vmem, hibernation files) are deleted but not parsed for PII extraction. |
| **Language detection** | PII patterns are primarily English/Latin-script. CJK names, Arabic identifiers, and non-Latin personal data may not match regex patterns. Column-name and table-name detection still catches these in structured databases. |

### Verifier Suppressions (Known False Positive Filters)

The post-sanitization verifier intentionally suppresses certain pattern matches that are structurally identical to PII but are not personally identifiable in context. These are documented here because an overly aggressive filter could mask a real finding:

| Pattern | Suppressed When | Rationale |
|---------|----------------|-----------|
| `swift_bic` | 8-char all-uppercase string, or ≤2 unique characters, or inside `.plist` files | Apple plist binary data contains carrier bundle identifiers (e.g. `BUNDLEID`) that match SWIFT format but aren't bank codes. |
| `url_credentials` | URL contains `apple.com` or `cdn-apple.com` | Apple CDN download URLs use `user:token@host` format for authenticated firmware downloads — not user credentials. |
| `us_routing` / `cusip` / `south_korean_rrn` | All digits have ≤2 unique values, or inside `.plist` | Sequential/repeated digit strings (`012345678`, `111111111`) in binary plists are padding bytes, not financial identifiers. |
| `dea_number` | Inside `.plist` files | Carrier bundle checksums match DEA alphanumeric format by coincidence. |
| `bitcoin_address` | Match is purely hexadecimal (`[0-9a-f]` only) | Hex UUIDs and hash digests (ChromaDB embedding IDs, git SHAs) start with `1` and match the base58 length requirements but aren't crypto addresses. Real bitcoin uses base58 (mixed case, excludes 0/O/I/l). |
| `password_kv` | Column is a vector DB content column (`string_value`, `c0`, `metadata`, `document`) | Embedding databases store conversation text that naturally contains the word "password" in context — not actual credential key-value pairs. |
| `ssn` | Column is a CoreData internal (`z_pk`, `z_ent`, `zvalue`, `ztimestamp`, etc.) — **no longer suppressed merely for being inside a `.plist`/`.json`/`.db` file** | Sequential integers and epoch timestamps in Apple CoreData schemas match 9-digit SSN format by column name only. A bare unformatted SSN (`123456789`) in a JSON/plist/db export is a real finding and is no longer blanket-hidden by file extension. |
| `ip_v4` | Address is in RFC-1918 private range, Apple 17/8 block, or all single-digit octets | Private/internal IPs and version strings (e.g. `2.3.5.8`) aren't user-identifying. |
| `gps_coord` | Value > 180 or exactly `0`; a leading-zero integer part not written as `0.x` (version strings); a `.plist`-only value ending in exactly 4 decimals or with ≥8 decimal digits; or the `external_mod_tag` column | Layout metrics, version numbers, and sync tags match float format but aren't geographic coordinates. Sub-1° coordinates (e.g. `-0.1278`, `5.6231`) are **no longer suppressed** — equatorial latitudes and prime-meridian longitudes are real GPS data — and the 4-decimal/≥8-decimal layout-metric rules now apply to `.plist` only (previously also suppressed real GPS values in `.json` exports). |

**If you suspect a suppression is hiding real PII in your dataset**, run `hygeia --skip-verify` and then manually inspect the output with your own tooling. The suppressions exist to reduce noise on common data types — they are not guarantees.

HYGEIA reports what it skipped. Check the audit manifest (`deletion_manifest.json`) for any files that were classified but not processed — these may need manual review.

---

## License

PolyForm Noncommercial 1.0.0 — free for research, education, and personal use. Commercial use requires a separate license. See [LICENSE](LICENSE).

## Author

**Kevin Estrada** ([@Indegosblade](https://github.com/Indegosblade))
