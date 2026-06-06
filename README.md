# HYGEIA

**Forensic-grade PII sanitization for any platform.**

Remove personal data from filesystem dumps, databases, configs, and logs. Works on iOS, Android, Chrome, Firefox, Windows, macOS, Linux — anything with SQLite databases, JSON configs, or text files. Ships with iOS-specific rules and a generic engine that handles any data source.

HIPAA Safe Harbor, GDPR Article 4/9, and CCPA compliance modes built in.

---

## Quick Start

```bash
# Requirements: Python 3.10+
pip install -e .

# Sanitize any data directory
hygeia --input /path/to/dump --output /path/to/clean

# With HIPAA compliance
hygeia --input /path/to/dump --output /path/to/clean --compliance hipaa

# Dry run (preview actions, no changes)
hygeia --input /path/to/dump --output /unused --dry-run

# Full anti-forensic mode
hygeia --input /path/to/dump --output /path/to/clean --compliance all --normalize-timestamps
```

---

## Architecture

```
hygeia/
├── __init__.py
├── scanner.py                # File classification (DELETE/PRESERVE/SELECTIVE_DB/PLIST/EXIF)
├── sqlite_sanitizer.py       # WAL-aware database sanitization (iOS + generic)
├── text_sanitizer.py          # JSON, log, CSV, shell history sanitization
├── filesystem_sanitizer.py    # LevelDB, thumbnail caches, swap files, forensic artifacts
├── plist_sanitizer.py         # Binary plist credential redaction
├── exif_stripper.py           # Image GPS/metadata removal via exiftool
├── compliance.py              # HIPAA/GDPR/CCPA compliance profiles
├── verifier.py                # Post-sanitization PII verification
├── manifest.py                # JSON audit trail generation
└── rules/
    ├── delete_patterns.json
    ├── preserve_patterns.json
    ├── selective_db_rules.json
    └── plist_patterns.json

hygeia_cli.py                  # 7-step CLI pipeline
```

---

## 7-Step Pipeline

| Step | What it does |
|------|-------------|
| 1. Scan | Classify all files by type (iOS-aware or generic auto-detect) |
| 2. Databases | WAL-checkpoint, secure_delete, regex scan all TEXT columns, nuke PII tables, FTS shadow table rebuild, VACUUM |
| 3. Text files | Redact PII in JSON configs, log files, CSV/TSV; delete shell history |
| 4. Forensic artifacts | Delete LevelDB stores, thumbnail caches, swap/hibernation files, Spotlight indexes, session data |
| 5. EXIF | Strip GPS coordinates, device identifiers, and metadata from images |
| 6. Verify | Regex scan all text files and database contents for residual PII; inspect SQLite freelists |
| 7. Manifest | Generate JSON audit trail with actions taken, verification results, compliance report |

---

## PII Detection

### Regex Patterns (10 types)
- Email addresses
- US phone numbers
- International phone numbers (20+ country codes)
- Social Security numbers
- Credit card numbers (Visa, Mastercard, Amex, Discover)
- IPv4 addresses
- IPv6 addresses
- IBAN (international bank account numbers)
- MAC addresses
- ZIP codes (via column-name detection)

### Sensitive Column Detection (50+ column names)
Names, addresses, credentials, payment info, GPS coordinates, cookies, tokens, API keys — any column with a sensitive name gets blanket-redacted regardless of content.

### PII Table Nuking (30+ table names)
Chrome autofill/logins/cookies/shortcuts, Firefox form history/cookies, Android contacts/SMS/call log, messaging app tables, macOS TCC — entire tables deleted, schema preserved.

---

## Platform Support

| Platform | What HYGEIA handles |
|----------|-------------------|
| **iOS** | Full pipeline: jailbreak-aware scanning, knowledgeC/Photos.sqlite column-level sanitization, app container cleanup, SEGB biome streams |
| **Chrome/Chromium** | History, Login Data, Web Data, Cookies, Shortcuts, Top Sites, Favicons, DIPS, Network Action Predictor, LevelDB localStorage/IndexedDB |
| **Firefox** | places.sqlite, cookies.sqlite, formhistory.sqlite, permissions.sqlite, content-prefs, cache, session data |
| **Android** | contacts2.db, mmssms.db, telephony.db, calendar.db, accounts.db, webview.db |
| **Windows** | Prefetch, jump lists, LNK files, event logs, recycle bin markers, swap/hibernation files, thumbnail caches |
| **macOS** | TCC.db, quarantine events, Spotlight indexes, shell history, Spotlight, .fseventsd |
| **Linux** | Shell history, GNOME tracker, thumbnail caches, systemd journal |
| **Any SQLite** | Generic mode: scans every TEXT column in every table for PII patterns |

---

## Compliance

```bash
# HIPAA Safe Harbor (18 identifiers)
hygeia --input ./dump --output ./clean --compliance hipaa

# GDPR Article 4/9 (special category data)
hygeia --input ./dump --output ./clean --compliance gdpr

# CCPA (browsing history, geolocation, purchase records)
hygeia --input ./dump --output ./clean --compliance ccpa

# All frameworks combined (most aggressive)
hygeia --input ./dump --output ./clean --compliance all
```

Each mode injects additional sensitive columns and PII tables into the sanitizer. The compliance report in output shows which identifiers were covered and any gaps.

---

## Anti-Forensic Features

| Feature | What it defeats |
|---------|----------------|
| WAL checkpoint + delete | WAL file carving (Cellebrite, Autopsy) |
| `secure_delete = ON` | Deleted cell recovery within SQLite pages |
| VACUUM rebuild | Freelist page carving |
| FTS shadow table cleanup | Full-text index data recovery |
| LevelDB directory deletion | Chrome localStorage/IndexedDB carving |
| Thumbnail cache deletion | Thumbnail survival after original file deletion |
| Swap/hibernation file deletion | RAM artifact recovery from disk |
| Timestamp normalization | Timeline analysis (MACB timestamps) |
| Shell history deletion | Command-line credential recovery |
| Spotlight index deletion | Indexed document content recovery |

---

## SQLite WAL Handling

WAL files contain 50-95% of recoverable PII. HYGEIA's pipeline:

1. `PRAGMA wal_checkpoint(TRUNCATE)` — flush WAL into main DB
2. `PRAGMA secure_delete = ON` — zero freed pages
3. Execute sanitization SQL (regex scan + column redaction + table nuke)
4. Rebuild FTS shadow tables
5. `VACUUM` — rebuild database, eliminate free pages
6. Delete `.db-wal`, `.db-shm`, `.db-journal`

---

## Verification

Post-sanitization checks (automatic unless `--skip-verify`):

1. **Regex PII scan** — 10 patterns across all text files and SQLite database contents
2. **SQLite freelist inspection** — zero free pages after VACUUM
3. **EXIF verification** — no GPS/device tags remaining
4. **False positive filtering** — URL columns, system paths, redacted tags excluded

---

## License

PolyForm Noncommercial 1.0.0 — free for research, education, and personal use. No commercial use. See [LICENSE](LICENSE).

## Authors

**Kevin Estrada** ([@Indegosblade](https://github.com/Indegosblade)) and **Limen**
