# HYGEIA

[![CI](https://github.com/Indegosblade/HYGEIA/actions/workflows/ci.yml/badge.svg)](https://github.com/Indegosblade/HYGEIA/actions/workflows/ci.yml)

**Forensic-grade PII sanitization for filesystem dumps.**

HYGEIA is a data sanitization framework built for security researchers, forensic analysts, and compliance teams who need to strip personally identifiable information from filesystem dumps, application databases, configuration files, and media — without destroying the structural and system-level data that makes those artifacts useful.

It handles iOS filesystem dumps with specialized rules, but the core engine is platform-agnostic: point it at Chrome profiles, Android extractions, Windows artifacts, macOS system data, or any directory containing SQLite databases, JSON configs, logs, or images, and it will find and remove PII using the same forensic-grade pipeline.

Built-in compliance modes for **HIPAA Safe Harbor**, **GDPR Article 4/9**, and **CCPA** with per-run coverage reporting.

---

## Features

- **28+ PII regex patterns** — email, US/international phone, SSN, credit cards, JWT tokens, AWS access keys, GitHub tokens, API keys, Bitcoin/Ethereum wallets, IBAN, MAC addresses, IPv4/IPv6, IMEI, IMSI, VIN, UK NINO, Indian PAN, US EIN, DEA numbers, NPI, SWIFT/BIC, routing numbers, URL-embedded credentials, and more
- **Platform-agnostic database sanitization** — iOS, Android, Chrome, Firefox, Windows, macOS, and any generic SQLite database
- **95+ sensitive column name detection** — blanket redaction of any column named `email`, `password`, `token`, `api_key`, `latitude`, `encrypted_value`, and dozens more
- **60+ known PII table detection and nuking** — rows deleted, schema preserved, across Chrome, Firefox, Android, messaging apps, and macOS
- **Multi-pass regex engine** — every TEXT column in every SQLite table, every line in every JSON/log/CSV file
- **FTS shadow table cleanup** — full-text search indexes rebuilt after sanitization to eliminate indexed PII
- **Anti-forensic hardening** — LevelDB store deletion, thumbnail cache removal, swap/hibernation file deletion, Spotlight index removal, shell history deletion, optional timestamp normalization
- **EXIF metadata stripping** — GPS coordinates, device identifiers, and creation timestamps removed from all images via exiftool
- **HIPAA Safe Harbor / GDPR / CCPA compliance modes** — per-run coverage reporting against all 18 HIPAA identifiers, GDPR Article 9 special categories, and CCPA behavioral data definitions
- **Post-sanitization verification** — mandatory regex scan, SQLite freelist inspection, and EXIF check after every run; exits code 2 if anything remains
- **JSON audit manifests** — every action logged with path, reason, rows affected, and compliance coverage
- **Dry-run mode** — preview every action without modifying files

---

## Installation

```bash
pip install -e .
```

Requirements: Python 3.10+. Optional: [exiftool](https://exiftool.org/) for image metadata stripping.

---

## Quick Start

```bash
hygeia --input /path/to/dump --output /path/to/clean
hygeia --input dump/ --output clean/ --compliance hipaa
hygeia --input dump/ --output clean/ --dry-run
```

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

### CLI Flags

| Flag | Description |
|------|-------------|
| `--input PATH`, `-i` | Source data directory (required) |
| `--output PATH`, `-o` | Destination for sanitized copy (required; must not already exist) |
| `--dry-run`, `-n` | Preview all actions without executing |
| `--compliance MODE` | Compliance mode: `hipaa`, `gdpr`, `ccpa`, or `all` |
| `--normalize-timestamps` | Set all file timestamps to epoch (defeats timeline analysis) |
| `--skip-verify` | Skip post-sanitization verification |
| `--skip-exif` | Skip EXIF metadata stripping |
| `--skip-forensic` | Skip anti-forensic hardening (LevelDB, caches, swap, indexes) |
| `--optimize` | Remove localizations and caches to reduce output size |
| `--manifest PATH`, `-m` | Custom path for JSON audit manifest (default: `deletion_manifest.json`) |
| `--verbose`, `-v` | Detailed logging |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Sanitization complete, verification passed (or skipped) |
| 1 | Input error (path not found, output already exists, missing permissions) |
| 2 | Verification failed — residual PII detected post-sanitization |

---

## Pipeline

HYGEIA runs a deterministic 7-step pipeline on every invocation:

```
[1/7] Scan          Classify every file by type. Auto-detect iOS or generic mode.
[2/7] Databases     WAL-checkpoint -> secure_delete -> regex scan -> table nuke -> FTS rebuild -> VACUUM
[3/7] Text files    Redact PII in JSON, logs, CSV/TSV. Delete shell history files.
[4/7] Forensics     Delete LevelDB stores, thumbnail caches, swap files, search indexes, session data.
[5/7] EXIF          Strip GPS, device identifiers, and metadata from all images.
[6/7] Verify        Regex scan all surviving text and database content for residual PII.
[7/7] Manifest      Write JSON audit trail: actions taken, verification result, compliance report.
```

The pipeline is fail-safe: if verification finds residual PII, HYGEIA exits with code 2 and reports exactly what was found and where. A passing run means zero PII detections across all scanned content.

---

## What It Detects

### Regex Patterns (28+)

| Pattern | Coverage |
|---------|----------|
| Email addresses | RFC 5322 local-part + domain |
| US phone numbers | 10-digit with optional +1, parentheses, separators |
| International phone numbers | 20+ country codes (UK, DE, FR, IN, JP, AU, BR, CN, etc.) |
| Social Security numbers | 3-2-4 format with exclusion of known-invalid prefixes |
| Credit card numbers | Visa, Mastercard, Amex, Discover, UnionPay with optional separators |
| IPv4 addresses | Dotted quad, excluding localhost/broadcast |
| IPv6 addresses | Full 8-group colon-hex notation |
| IBAN | 2-letter country code + 2 check digits + 11-30 alphanumeric |
| MAC addresses | Colon or hyphen separated hex pairs |
| JWT tokens | `eyJ...eyJ...` three-part base64url structure |
| AWS access keys | `AKIA`/`ASIA` prefix + 16 uppercase alphanumeric characters |
| GitHub tokens | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefixed tokens |
| API keys | Stripe `sk_live_`/`pk_live_`, OpenAI `sk-`, Slack `xox*` patterns |
| Bitcoin wallets | Legacy (1.../3...) and bech32 (bc1...) address formats |
| Ethereum wallets | `0x` + 40 hex digits |
| URL-embedded credentials | `scheme://user:password@host` patterns |
| SIN / TFN | Canadian SIN and Australian TFN (3-3-3 digit format) |
| SWIFT / BIC codes | 8 or 11 character bank identifier codes |
| US routing numbers | 9-digit ABA routing numbers with prefix validation |
| IMEI | 15-digit device identifier with optional separators |
| IMSI | 15-digit subscriber identity |
| DEA registration numbers | Drug Enforcement Administration registrant codes |
| NPI numbers | National Provider Identifier (10-digit with NPI prefix) |
| UK National Insurance | NINO format with invalid prefix exclusion |
| Indian PAN | Permanent Account Number (10-character alphanumeric) |
| US EIN | Employer Identification Number (XX-XXXXXXX format) |
| VIN | Vehicle Identification Number (17-character) |
| ZIP / postal codes | Detected via column name (`zip`, `zipcode`, `postal_code`) |

### Column-Name Detection (95+)

Column names treated as inherently sensitive regardless of content — any matching column has all non-empty values replaced with `[REDACTED]`:

Identity: `email`, `username`, `password`, `phone`, `first_name`, `last_name`, `full_name`, `display_name`, `nickname`, `given_name`, `family_name`

Location: `address`, `street`, `city`, `state`, `zip`, `zipcode`, `postal_code`, `country`, `latitude`, `longitude`, `gps_lat`, `gps_lon`, `location`

Financial: `credit_card`, `card_number`, `cvv`, `account_number`, `routing_number`, `bank_account`, `iban`, `ssn`, `sin`, `tfn`, `tax_id`

Credentials: `api_key`, `secret_key`, `private_key`, `token`, `access_token`, `refresh_token`, `auth_token`, `session_token`, `cookie`, `session`, `password_hash`, `encrypted_value`, `oauth_token`

Device / network: `device_id`, `device_name`, `imei`, `imsi`, `mac_address`, `ip_address`, `user_agent`

Healthcare: `medical_record_number`, `health_plan_id`, `dea_number`, `npi`, `diagnosis`, `medication`

### Table-Level Nuking (60+)

Table names recognized as entirely PII — all rows deleted, schema preserved:

- **Chrome/Chromium**: `autofill`, `autofill_profiles`, `credit_cards`, `logins`, `cookies`, `omni_box_shortcuts`, `top_sites`, `keyword_search_terms`, `downloads`, `visits`, `urls`, `favicons`, `network_action_predictor`
- **Firefox**: `moz_formhistory`, `moz_cookies`, `moz_inputhistory`, `moz_perms`, `moz_places`, `moz_historyvisits`, `moz_bookmarks`, `moz_annos`
- **Android**: `raw_contacts`, `data`, `calls`, `sms`, `threads`, `canonical_addresses`, `events`, `calendars`
- **Messaging / social**: `chat_list`, `chat_view`, `message_thumbnails`, `messages`, `conversations`
- **macOS**: `access` (TCC.db), `quarantine_events`, `LSQuarantineEvents`
- **Generic**: `contacts`, `call_log`, `accounts`, `search_history`, `browsing_history`, `location_history`, `transaction_history`

---

## Platform Coverage

### iOS (Full Pipeline)

Jailbreak-aware scanning with dynamic detection of Dopamine, palera1n, and RootHide. Preserves jailbreak infrastructure (`/var/jb/`, `/private/preboot/`, package databases) while removing user data. Column-level sanitization for knowledgeC.db (redacts third-party app names, preserves system app usage) and Photos.sqlite (NULLs GPS coordinates, deletes facial recognition data). SEGB biome stream deletion. Third-party app container cleanup with WAL handling.

### Chrome / Chromium

History, Login Data, Web Data, Cookies, Shortcuts, Top Sites, Favicons, DIPS, Network Action Predictor, Extension Cookies. LevelDB localStorage and IndexedDB directory deletion. Session data cleanup.

### Firefox

places.sqlite, cookies.sqlite, formhistory.sqlite, permissions.sqlite, content-prefs.sqlite, webappsstore.sqlite. IndexedDB storage directory deletion. Session restore file deletion. Cache cleanup.

### Android

contacts2.db, mmssms.db, telephony.db, calendar.db, accounts.db, webview.db. Thumbnail cache deletion. Google Analytics database deletion.

### Windows

Prefetch files (.pf), jump lists (.automaticDestinations-ms), LNK files, event logs (.evtx), recycle bin markers ($I/$R files), swap/hibernation files (pagefile.sys, swapfile.sys, hiberfil.sys), thumbnail caches (Thumbcache_*.db).

### macOS

TCC.db permission grants, quarantine events database, Spotlight indexes (.Spotlight-V100), FSEvents logs (.fseventsd), shell history files, Accounts databases, unified log traces.

### Linux

Shell history files (.bash_history, .zsh_history, .python_history, etc.), GNOME Tracker databases, thumbnail caches, systemd journal artifacts.

### Generic

Any directory containing SQLite databases: HYGEIA scans every TEXT column in every table for PII patterns, with no platform-specific knowledge required.

---

## Compliance

### HIPAA Safe Harbor (45 CFR 164.514(b)(2))

The `--compliance hipaa` flag activates detection for all 18 Safe Harbor identifiers: names, geographic subdivisions below state level, dates (except year), phone numbers, fax numbers, email addresses, Social Security numbers, medical record numbers, health plan beneficiary numbers, account numbers, certificate/license numbers, vehicle identifiers, device identifiers, web URLs, IP addresses, biometric identifiers, photographs, and unique codes. HYGEIA's output summary reports which identifiers were covered and which have gaps for the specific dataset.

### GDPR Article 4/9

The `--compliance gdpr` flag adds detection for special category data as defined in Article 9: racial/ethnic origin, political opinions, religious beliefs, trade union membership, genetic data, biometric data, health data, and sexual orientation. Column-name detection is extended with terms like `race`, `ethnicity`, `religion`, `political_opinion`, `genetic_data`, `health_data`.

### CCPA

The `--compliance ccpa` flag treats browsing history, search history, geolocation data, and purchase/transaction records as mandatory-delete categories, reflecting the CCPA's broad definition of personal information that includes behavioral and commercial data.

### Combined Mode

`--compliance all` applies the union of all frameworks — the most aggressive sanitization profile available.

---

## Anti-Forensic Hardening

HYGEIA is designed to produce output that withstands examination by forensic tools including Cellebrite UFED, Autopsy, EnCase, and Magnet AXIOM.

| Technique | What it defeats |
|-----------|----------------|
| WAL checkpoint + companion file deletion | WAL file carving for deleted records |
| `PRAGMA secure_delete = ON` | Deleted cell recovery within live database pages |
| VACUUM rebuild | Freelist page carving from unallocated database pages |
| FTS shadow table rebuild | Full-text search index data recovery (`*_content`, `*_segments`) |
| LevelDB directory deletion | Chrome localStorage/IndexedDB content carving |
| Thumbnail cache deletion | Thumbnail persistence after source file deletion |
| Swap/hibernation file deletion | RAM artifact recovery from pagefile.sys, hiberfil.sys |
| Shell history deletion | Command-line credential and activity recovery |
| Spotlight/search index deletion | Indexed document content recovery |
| Timestamp normalization | MACB timeline reconstruction and activity correlation |

---

## Verification

Every sanitization run includes automatic verification (disable with `--skip-verify`):

1. **Content scan**: All surviving text files and SQLite database contents are regex-scanned for the full set of PII patterns.
2. **Freelist inspection**: Every SQLite database is checked for non-zero freelist page counts. After VACUUM, any remaining free pages indicate potential data recovery.
3. **EXIF check**: All images are verified for residual GPS coordinates and device identifier tags.
4. **False positive filtering**: URL columns, system framework paths, and already-redacted values are excluded to prevent noise.

A passing verification means zero PII detections across all scanned content. A failing verification reports the exact file, table, column, row, and matched pattern for every finding.

---

## Programmatic API

```python
from pathlib import Path

# Generic database sanitization
from hygeia.sqlite_sanitizer import sanitize_database_generic
result = sanitize_database_generic(Path("any_database.db"))
print(f"Redacted {result['rows_redacted']} rows, found: {result['pii_types_found']}")

# Text file sanitization
from hygeia.text_sanitizer import sanitize_json, sanitize_log_file, sanitize_csv
sanitize_json(Path("config.json"))
sanitize_log_file(Path("app.log"))

# iOS-specific database sanitization
from hygeia.sqlite_sanitizer import sanitize_knowledgec, sanitize_photos_sqlite
sanitize_knowledgec(Path("knowledgeC.db"))
sanitize_photos_sqlite(Path("Photos.sqlite"))

# Forensic artifact cleanup
from hygeia.filesystem_sanitizer import sanitize_filesystem
actions = sanitize_filesystem(Path("/path/to/dump"), normalize_timestamps=True)

# Post-sanitization verification
from hygeia.verifier import verify_sanitization
result = verify_sanitization(Path("/path/to/clean"))
assert result.passed, f"{result.total_findings} PII findings remain"

# Compliance-driven sanitization
from hygeia.compliance import get_compliance_profile
profile = get_compliance_profile("hipaa")
sanitize_database_generic(Path("patient.db"),
    extra_columns=profile.extra_sensitive_columns,
    extra_tables=profile.extra_pii_tables)
```

---

## Architecture

```
hygeia/
├── scanner.py               File classification engine (DELETE/PRESERVE/SELECTIVE_DB/PLIST/EXIF)
├── sqlite_sanitizer.py      WAL-aware database sanitization — iOS-specific + generic PII scanner
├── text_sanitizer.py        JSON, log, CSV/TSV sanitization + shell history deletion
├── filesystem_sanitizer.py  Forensic artifact removal — LevelDB, caches, swap, indexes
├── forensic_cleaner.py      Anti-forensic hardening — WAL, freelist, FTS, swap, timestamps
├── plist_sanitizer.py       Binary plist credential redaction (recursive key-walk)
├── exif_stripper.py         Image metadata removal via exiftool (9 formats)
├── compliance.py            HIPAA/GDPR/CCPA compliance profiles + coverage reporting
├── verifier.py              Post-sanitization PII verification (regex + freelist + EXIF)
├── manifest.py              JSON audit trail generation
└── rules/
    ├── delete_patterns.json       33 directory + 18 database + 10 extension patterns
    ├── preserve_patterns.json     18 directory + 5 file + 4 extension rules
    ├── selective_db_rules.json    Column-level SQL for knowledgeC, Photos.sqlite, TCC.db
    └── plist_patterns.json        29 sensitive key patterns + path-based rules
```

Zero external pip dependencies. Stdlib only. Optional system exiftool for image metadata.

---

## License

PolyForm Noncommercial 1.0.0 — free for research, education, and personal use. Commercial use requires a separate license. See [LICENSE](LICENSE).

## Author

**Kevin Estrada** ([@Indegosblade](https://github.com/Indegosblade))
