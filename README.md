# HYGEIA

**Forensic-grade PII sanitization engine for filesystem dumps.**

Classifies, sanitizes, verifies, and audits. Ships with iOS rules -- the engine works on any SQLite database, binary plist, or image regardless of platform.

---

## The Problem

Filesystem dumps from mobile devices and desktops contain everything: photos, messages, GPS history, health data, typed passwords in keyboard caches, OAuth tokens in plists, facial recognition clusters, browsing history. You can't share them. You can't publish them. You can't hand them to a collaborator.

Forensic extraction tools (iLEAPP, MVT, Cellebrite, Magnet AXIOM) are built to **find** personal data -- the opposite of what you need. HYGEIA does selective, verified removal.

## The Hard Part

**Deleting a database does not delete the data.** SQLite databases use Write-Ahead Logging (WAL). The `.db-wal` file contains uncommitted transactions and recently-deleted records -- 50-95% of recoverable PII lives here. Standard file deletion leaves WAL files intact. Most tools don't handle this at all.

HYGEIA's pipeline: WAL checkpoint, secure_delete, sanitize, VACUUM, companion file cleanup. Five steps, zero recoverable records.

---

## Quick Start

```bash
# Python 3.9+, optional: exiftool for image metadata stripping
# apt-get install libimage-exiftool-perl  (Linux)
# brew install exiftool                   (macOS)

git clone https://github.com/Indegosblade/HYGEIA.git
cd HYGEIA
pip install -e .

# Sanitize a filesystem dump
hygeia --input /path/to/dump --output /path/to/clean

# Preview what would happen (nothing touched)
hygeia --input /path/to/dump --output /unused --dry-run

# Full pipeline with verbose logging and custom manifest path
hygeia --input /path/to/dump --output /path/to/clean --manifest audit.json -v
```

---

## How It Works

```
Input ──> Scan & Classify ──> Sanitize ──> Verify ──> Manifest
               |                  |            |           |
         Rule-based file    WAL-aware DB   3 independent  JSON audit
         classification     surgery, plist  PII checks     trail with
         (JSON rulesets)    redaction, EXIF (regex, free-  compliance
                            stripping       list, EXIF)    alignment
```

**Six-stage pipeline:**

| Stage | What Happens |
|-------|-------------|
| **1. Copy** | Duplicate the input to preserve the original -- sanitization is destructive |
| **2. Scan** | Classify every file against rule patterns: DELETE, PRESERVE, SELECTIVE_DB, PLIST_SANITIZE, EXIF_STRIP |
| **3. Sanitize** | Execute classified actions -- WAL-aware database deletion, column-level SQL, plist key redaction |
| **4. EXIF strip** | Remove GPS coordinates, device model, timestamps from all images (9 formats) |
| **5. Verify** | Three independent checks: regex PII scan, SQLite freelist inspection, EXIF tag verification |
| **6. Manifest** | JSON audit trail documenting every action, for compliance and reproducibility |

---

## Sanitization Capabilities

### WAL-Aware SQLite Pipeline

Every database goes through five steps:

1. `PRAGMA wal_checkpoint(TRUNCATE)` -- flush WAL into main DB
2. `PRAGMA secure_delete = ON` -- zero freed pages on write
3. Execute sanitization SQL (DELETE, UPDATE, NULL)
4. `VACUUM` -- rebuild database file, eliminate all free pages
5. Delete `.db-wal`, `.db-shm`, `.db-journal` companion files

After this pipeline: zero free pages, zero WAL records, zero recoverable data.

### Column-Level Database Surgery

Not all databases should be deleted entirely. Some contain personal data and system metadata in the same tables. HYGEIA supports column-level SQL rules:

```json
{
  "name": "knowledgeC",
  "path_suffix": "CoreDuet/Knowledge/knowledgeC.db",
  "strategy": "selective",
  "sql_commands": [
    "UPDATE ZOBJECT SET ZVALUESTRING = '[REDACTED]' WHERE ZVALUESTRING NOT LIKE 'com.apple.%'",
    "DELETE FROM ZOBJECT WHERE ZSTREAMNAME LIKE '%safari%'"
  ]
}
```

### Binary Plist Redaction

Recursive key-pattern matching across nested plist structures. 29 sensitive key patterns (email, token, auth, password, OAuth, credential, etc.) with safe-key exclusions (bundle, version, build) to prevent false positives.

### EXIF Metadata Stripping

Bulk removal via exiftool across 9 image formats (JPEG, HEIC, HEIF, PNG, TIFF, GIF, BMP). Strips GPS coordinates, device make/model, timestamps, and all other EXIF tags.

### Post-Sanitization Verification

Three independent checks run automatically after every sanitization:

| Check | What It Catches |
|-------|----------------|
| **Regex PII scan** | Emails, phone numbers, SSNs, Apple IDs, GPS coordinates, IMEIs, device names |
| **SQLite freelist** | Non-zero free pages = recoverable records survived VACUUM |
| **EXIF tags** | GPS or device metadata that survived stripping |

If any check fails, HYGEIA exits with code 2 and flags the findings in the manifest.

---

## Architecture

Seven Python modules, four JSON rule files, zero pip dependencies (stdlib only + optional system exiftool).

```
hygeia/
├── scanner.py               # File classification engine (rule-driven, 6 action types)
├── sqlite_sanitizer.py      # WAL-aware 5-step database sanitization pipeline
├── plist_sanitizer.py       # Recursive binary plist credential redaction
├── exif_stripper.py         # Bulk image metadata removal (9 formats)
├── verifier.py              # 3-check post-sanitization PII verification
├── manifest.py              # JSON audit trail with compliance alignment
└── rules/
    ├── delete_patterns.json      # What to remove (directories, databases, scoped extensions)
    ├── preserve_patterns.json    # What to keep (system paths, critical files, extensions)
    ├── selective_db_rules.json   # Column-level SQL for mixed databases
    └── plist_patterns.json       # Sensitive key patterns for plist redaction
```

### Platform-Agnostic Engine

Each module operates independently of the rule files:

| Module | Works On | Platform Dependency |
|--------|----------|-------------------|
| `sqlite_sanitizer.py` | Any SQLite database | None |
| `plist_sanitizer.py` | Any binary plist | None |
| `exif_stripper.py` | Any image (9 formats) | System exiftool |
| `verifier.py` | Any filesystem tree | None |
| `manifest.py` | Any sanitization run | None |
| `scanner.py` | Any filesystem dump | JSON rule files (swappable) |

The iOS rules in `hygeia/rules/` are the default ruleset. Replace them for Android, macOS, Windows, or any other filesystem.

---

## iOS Ruleset (Default)

The included rules cover iOS filesystem dumps with 33 delete patterns, 18 preserve paths, 29 sensitive plist keys, and column-level SQL for mixed databases.

### What Gets Removed

| Category | Target | Method |
|----------|--------|--------|
| Photos & Videos | DCIM/, PhotoData/, Recordings/ | Directory delete |
| Messages | sms.db + WAL + Attachments/ | WAL-aware delete |
| Contacts | AddressBook.sqlitedb | WAL-aware delete |
| Call History | CallHistory.storedata | WAL-aware delete |
| Safari | History.db, Cookies/ | WAL-aware delete |
| Health | healthdb_secure.sqlite | WAL-aware delete |
| Location | routined caches, locationd | WAL-aware delete |
| Accounts | Accounts3.sqlite, iCloud tokens | WAL-aware delete |
| Keyboard Cache | dynamic-text.dat | File delete |
| Biome Streams | iOS 16+ SEGB binary telemetry | Directory delete |
| Third-party Apps | All non-jailbreak app containers | Directory delete |
| Credentials | OAuth tokens, passwords in plists | Key-level redaction |
| Image EXIF | GPS coordinates, device model | Metadata strip |

### What Gets Preserved

| Category | Why |
|----------|-----|
| Kernelcache, kexts | Kernel research |
| dyld shared cache | Framework analysis, symbol resolution |
| System binaries | /System/, /usr/, /bin/, /sbin/ |
| Sandbox profiles | Security boundary mapping |
| Crash logs | Kernel panics, exception traces |
| TCC.db | Permission grants (research value) |
| Jailbreak infrastructure | /var/jb/, Dopamine, basebin, preboot |

### Jailbreak Detection

Automatic detection and preservation of three jailbreak families:

| Jailbreak | Detection Markers |
|-----------|------------------|
| Dopamine | `/var/jb/basebin/jailbreakd` + `libjailbreak.dylib` |
| palera1n | `/cores/jbinit.log` |
| RootHide | `/var/jb-*/` (randomized paths) |

---

## Custom Rules

To sanitize non-iOS dumps, create your own JSON rule files and point the scanner at them:

```python
from pathlib import Path
from hygeia.scanner import FileScanner

scanner = FileScanner(rules_dir=Path("my_rules/"))
result = scanner.scan_dump(Path("/path/to/dump"))
```

Rule file format follows the same structure as the iOS defaults in `hygeia/rules/`. See [docs/USAGE.md](docs/USAGE.md) for the full schema.

---

## Programmatic API

Every module is importable independently:

```python
from pathlib import Path
from hygeia.sqlite_sanitizer import sanitize_database, delete_database
from hygeia.plist_sanitizer import sanitize_plist
from hygeia.exif_stripper import strip_exif_directory
from hygeia.verifier import verify_sanitization

# Sanitize a single database with custom SQL
sanitize_database(
    Path("knowledgeC.db"),
    sql_commands=["DELETE FROM ZOBJECT WHERE ZSTREAMNAME LIKE '%safari%'"]
)

# Redact credentials from a plist
sanitize_plist(Path("com.example.app.plist"))

# Strip EXIF from all images in a directory
strip_exif_directory(Path("/path/to/images"))

# Verify a sanitized filesystem
result = verify_sanitization(Path("/path/to/clean"))
assert result.passed
```

---

## Compliance

HYGEIA generates JSON audit manifests aligned with:

| Standard | Coverage |
|----------|----------|
| **NIST SP 800-88 Rev. 2** | Clear-level: secure_delete + VACUUM + audit trail |
| **HIPAA Safe Harbor** | 13 of 18 identifiers covered |
| **GDPR Anonymization** | Irreversible: VACUUM rebuild, WAL deleted, verified |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (verification passed or skipped) |
| 1 | Input error (path not found, permissions, output exists) |
| 2 | Verification failed (PII found post-sanitization) |

---

## License

[PolyForm Noncommercial 1.0.0](LICENSE) -- free for research, education, and personal use. No commercial use.

## Author

[@Indegosblade](https://github.com/Indegosblade)
