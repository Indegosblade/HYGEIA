# HYGEIA Usage Guide

Forensic-grade PII sanitization engine for filesystem dumps. Ships with iOS rules -- the engine works on any SQLite database, binary plist, or image.

---

## Installation

### Requirements

- Python 3.10+
- exiftool (optional, for image metadata stripping)

```bash
# Install exiftool
apt-get install libimage-exiftool-perl    # Debian/Ubuntu
brew install exiftool                      # macOS
choco install exiftool                     # Windows

# Install HYGEIA
git clone https://github.com/Indegosblade/HYGEIA.git
cd HYGEIA
pip install -e .

# Verify
python -c "from hygeia.scanner import FileScanner; print('HYGEIA OK')"
exiftool -ver
```

---

## CLI Usage

### Basic Sanitization

```bash
# Sanitize a dump (copies to output, preserves original)
hygeia --input /path/to/dump --output /path/to/clean

# Preview what would be deleted (no changes made)
hygeia --input /path/to/dump --output /unused --dry-run

# Verbose logging
hygeia --input /path/to/dump --output /path/to/clean -v
```

### All Options

| Flag | Description |
|------|-------------|
| `--input PATH` / `-i` | Source filesystem dump directory (required) |
| `--output PATH` / `-o` | Destination for sanitized copy (required) |
| `--dry-run` / `-n` | Preview all actions without making changes |
| `--compliance MODE` | Compliance mode: `hipaa`, `gdpr`, `ccpa`, or `all` |
| `--normalize-timestamps` | Set all file timestamps to epoch (anti-forensic) |
| `--skip-verify` | Skip post-sanitization PII verification |
| `--skip-exif` | Skip EXIF metadata stripping |
| `--skip-forensic` | Skip anti-forensic hardening (LevelDB, caches, swap, indexes) |
| `--optimize` | Remove localizations and caches to reduce output size |
| `--manifest PATH` / `-m` | Write JSON audit manifest to custom path |
| `--verbose` / `-v` | Detailed logging output |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (verification passed or skipped) |
| 1 | Input error (path not found, permissions, output exists) |
| 2 | Verification failed (PII found post-sanitization) |

---

## What Gets Removed (iOS Default Rules)

| Category | Examples | Action |
|----------|----------|--------|
| Photos | DCIM/, PhotoData/ | DELETE entirely |
| Messages | SMS/sms.db + WAL | DELETE with WAL cleanup |
| Contacts | AddressBook.sqlitedb | DELETE with WAL cleanup |
| Safari | History.db, Cookies | DELETE with WAL cleanup |
| Health | healthdb_secure.sqlite | DELETE with WAL cleanup |
| Location | routined/Cache.sqlite, locationd/ | DELETE with WAL cleanup |
| Accounts | Accounts3.sqlite, iCloud tokens | DELETE with WAL cleanup |
| Keyboard | dynamic-text.dat, LocalDictionary | DELETE |
| App data | Third-party app containers | DELETE (preserve jailbreak apps) |
| Biome | iOS 16+ binary streams | DELETE entirely |
| Plists | OAuth tokens, credentials | REDACT sensitive keys |
| Images | GPS EXIF metadata | STRIP via exiftool |

## What Gets Preserved

| Category | Examples | Why |
|----------|----------|-----|
| Kernel | kernelcache, kexts | Security research target |
| System | /System/, /usr/, /bin/ | OS binaries and frameworks |
| Jailbreak | /var/jb/, Dopamine, Sileo | Research infrastructure |
| Crash logs | CrashReporter/*.ips | Kernel panic analysis |
| Sandbox | Profiles/*.sb | Attack surface mapping |
| TCC | TCC.db | Permission grants (research value) |
| dyld cache | dyld_shared_cache_arm64e | Framework analysis |
| Firmware | /usr/standalone/firmware/ | SEP, baseband research |

## Column-Level Sanitization

| Database | Preserved | Removed |
|----------|-----------|---------|
| knowledgeC.db | com.apple.* system app data | Third-party app names, Safari, Siri |
| Photos.sqlite | Schema, metadata | GPS coordinates, facial recognition |

---

## Custom Rules

HYGEIA's scanner uses JSON rule files for classification. The included iOS rules are in `hygeia/rules/`. To sanitize other platforms, create your own:

```python
from pathlib import Path
from hygeia.scanner import FileScanner

scanner = FileScanner(rules_dir=Path("my_android_rules/"))
result = scanner.scan_dump(Path("/path/to/android_dump"))
```

### Rule File Schema

**delete_patterns.json:**
```json
{
  "directory_patterns": ["/path/to/personal/data/"],
  "database_patterns": ["personal.db", "history.sqlite"],
  "extension_patterns": [{"ext": ".jpg", "scope": "/user/media/"}]
}
```

**preserve_patterns.json:**
```json
{
  "paths": ["system/", "usr/"],
  "files": ["kernelcache"],
  "extensions_always_preserve": [".framework", ".dylib"]
}
```

**selective_db_rules.json:**
```json
{
  "databases": [{
    "name": "usage_stats",
    "path_suffix": "stats/usage.db",
    "strategy": "selective",
    "sql_commands": ["DELETE FROM events WHERE type = 'personal'"]
  }]
}
```

**plist_patterns.json:**
```json
{
  "sanitize_paths": ["/user/preferences/"],
  "sensitive_key_patterns": ["email", "token", "password", "credential"]
}
```

---

## Programmatic API

### Scan a dump

```python
from pathlib import Path
from hygeia.scanner import FileScanner

scanner = FileScanner()
jailbreak = scanner.detect_jailbreak(Path("/mnt/dump"))
result = scanner.scan_dump(Path("/mnt/dump"))

print(f"Files: {result.total_files}")
print(f"Delete: {result.delete_count} files ({result.delete_size} bytes)")
```

### Sanitize a single database

```python
from pathlib import Path
from hygeia.sqlite_sanitizer import sanitize_database

sanitize_database(
    Path("knowledgeC.db"),
    sql_commands=[
        "UPDATE ZOBJECT SET ZVALUESTRING = '[REDACTED]' WHERE ZVALUESTRING NOT LIKE 'com.apple.%'",
        "DELETE FROM ZOBJECT WHERE ZSTREAMNAME LIKE '%safari%'",
    ]
)
```

### Strip EXIF from a directory

```python
from pathlib import Path
from hygeia.exif_stripper import strip_exif_directory

result = strip_exif_directory(Path("/path/to/images"))
print(f"Stripped {result['files_stripped']} images")
```

### Sanitize a plist

```python
from pathlib import Path
from hygeia.plist_sanitizer import sanitize_plist

result = sanitize_plist(Path("com.example.app.plist"))
print(f"Redacted keys: {result['keys_redacted']}")
```

### Verify sanitization

```python
from pathlib import Path
from hygeia.verifier import verify_sanitization

result = verify_sanitization(Path("/path/to/clean"))
if result.passed:
    print("Clean.")
else:
    print(f"FAILED: {result.total_findings} findings")
    for match in result.pii_matches:
        print(f"  {match.pattern_name}: {match.path}:{match.line_number}")
```

---

## Verification Details

### Automatic (runs after every sanitization)

1. **Regex PII scan** -- emails, phone numbers, SSNs, GPS coordinates, Apple IDs, IMEIs, device names
2. **SQLite freelist inspection** -- checks for recoverable records in free pages (should be zero after VACUUM)
3. **EXIF verification** -- confirms GPS/device metadata stripped from all images

### Manual

```bash
# Check for residual PII
grep -rn "@icloud.com\|@me.com" /path/to/clean/

# Check SQLite free pages
sqlite3 /path/to/db "PRAGMA freelist_count;"  # Should be 0

# Check EXIF
exiftool -gps* /path/to/clean/private/var/mobile/Media/
```

---

## Troubleshooting

### "exiftool not found"
```bash
apt-get install libimage-exiftool-perl   # Linux
brew install exiftool                     # macOS
```

### "VACUUM failed" on a database
The database may be corrupted or locked. HYGEIA logs a warning and continues. Check the manifest for affected databases.

### Verification fails with PII matches
Review the manifest `pii_matches` entries. Common false positives:
- Email-like patterns in system framework paths
- Version numbers matching GPS coordinate pattern

### Large dump takes too long
Use `--skip-exif` if exiftool is the bottleneck. EXIF stripping is the slowest operation on large photo libraries.
