# HYGEIA CLI Reference

## Installation

```bash
git clone https://github.com/Indegosblade/HYGEIA.git
cd HYGEIA
pip install -e .
```

After installation, HYGEIA is available as `hygeia` on the command line, or `python hygeia_cli.py` from the repo root.

---

## Synopsis

```
hygeia --input PATH --output PATH [OPTIONS]
```

## Required Arguments

| Flag | Description |
|------|-------------|
| `--input PATH`, `-i` | Source data directory (filesystem dump, app data, any directory) |
| `--output PATH`, `-o` | Destination for sanitized copy (must not already exist) |

## Options

| Flag | Description |
|------|-------------|
| `--dry-run`, `-n` | Preview all actions without modifying files |
| `--compliance MODE` | Compliance mode: `hipaa`, `gdpr`, `ccpa`, or `all` |
| `--normalize-timestamps` | Set all file timestamps to epoch (anti-forensic) |
| `--skip-verify` | Skip post-sanitization PII verification |
| `--skip-exif` | Skip EXIF metadata stripping |
| `--skip-forensic` | Skip anti-forensic hardening (LevelDB, caches, swap, indexes) |
| `--optimize` | Remove localizations and caches for smaller output |
| `--manifest PATH`, `-m` | Custom path for JSON audit manifest (default: `deletion_manifest.json`) |
| `--verbose`, `-v` | Enable detailed logging output |

---

## Examples

### Basic Sanitization

```bash
hygeia --input /mnt/dump --output /mnt/clean
```

Auto-detects input type (iOS or generic). Runs the full 7-step pipeline. Outputs verification result and audit manifest.

### Dry Run

```bash
hygeia --input /mnt/dump --output /tmp/unused --dry-run
```

Scans and classifies all files, reports what would happen, modifies nothing.

### HIPAA Compliance

```bash
hygeia --input /mnt/patient_device --output /mnt/clean --compliance hipaa
```

Activates HIPAA Safe Harbor identifier detection. Output includes coverage report showing which of the 18 identifier categories were addressed.

### Maximum Sanitization

```bash
hygeia --input /mnt/dump --output /mnt/clean --compliance all --normalize-timestamps -v
```

Union of all compliance frameworks. Timestamp normalization defeats timeline analysis. Verbose logging for audit trail.

### Chrome Profile Sanitization

```bash
hygeia --input ~/.config/google-chrome/Default --output ~/chrome_clean
```

Detects Chrome SQLite databases automatically. Nukes autofill, logins, cookies, browsing history, shortcuts, search terms. Deletes LevelDB localStorage/IndexedDB. Passes verification with zero findings.

### Custom Manifest Location

```bash
hygeia --input /mnt/dump --output /mnt/clean --manifest /var/log/hygeia_audit.json
```

---

## Pipeline Steps

```
[1/7] Scan              Classify files, detect iOS/generic mode, identify jailbreak
[2/7] Databases          SQLite: WAL checkpoint → secure_delete → scan → nuke → FTS rebuild → VACUUM
[3/7] Text files         JSON config redaction, log file PII removal, CSV sanitization, shell history deletion
[4/7] Forensic cleanup   LevelDB, thumbnail caches, swap/hibernation, Spotlight, session data
[5/7] EXIF               Strip GPS, device IDs, timestamps from images (requires exiftool)
[6/7] Verify             Regex scan all content for residual PII, inspect SQLite freelists
[7/7] Manifest           Write JSON audit trail with actions, verification, compliance report
```

---

## Programmatic API

### Generic Database Sanitization

```python
from pathlib import Path
from hygeia.sqlite_sanitizer import sanitize_database_generic

result = sanitize_database_generic(Path("any_database.db"))
print(f"Tables: {result['tables_scanned']}")
print(f"Columns: {result['columns_scanned']}")
print(f"Rows redacted: {result['rows_redacted']}")
print(f"PII types: {result['pii_types_found']}")
```

### Compliance-Driven Sanitization

```python
from pathlib import Path
from hygeia.sqlite_sanitizer import sanitize_database_generic
from hygeia.compliance import get_compliance_profile

profile = get_compliance_profile("hipaa")
result = sanitize_database_generic(
    Path("patient_records.db"),
    extra_columns=profile.extra_sensitive_columns,
    extra_tables=profile.extra_pii_tables,
)
```

### Text File Sanitization

```python
from pathlib import Path
from hygeia.text_sanitizer import sanitize_json, sanitize_log_file, sanitize_csv

sanitize_json(Path("config.json"))       # Redact sensitive keys + PII in values
sanitize_log_file(Path("server.log"))    # Replace PII patterns inline
sanitize_csv(Path("export.csv"))         # Redact sensitive columns + PII cells
```

### Forensic Artifact Cleanup

```python
from pathlib import Path
from hygeia.filesystem_sanitizer import sanitize_filesystem

actions = sanitize_filesystem(
    Path("/mnt/dump"),
    normalize_timestamps=True,    # Set all timestamps to epoch
)
print(f"Artifacts removed: {len(actions)}")
```

### iOS-Specific Database Sanitization

```python
from pathlib import Path
from hygeia.sqlite_sanitizer import sanitize_knowledgec, sanitize_photos_sqlite

# Column-level: preserves system app usage, redacts third-party
sanitize_knowledgec(Path("knowledgeC.db"))

# Column-level: NULLs GPS, deletes facial recognition
sanitize_photos_sqlite(Path("Photos.sqlite"))
```

### Verification

```python
from pathlib import Path
from hygeia.verifier import verify_sanitization

result = verify_sanitization(Path("/mnt/clean"))
if result.passed:
    print("Clean — zero PII findings")
else:
    print(f"FAILED: {result.total_findings} findings")
    for match in result.pii_matches:
        print(f"  [{match.pattern_name}] {match.path} line {match.line_number}: {match.match_text}")
    for finding in result.sqlite_freelist_findings:
        print(f"  [freelist] {finding}")
    for exif_fail in result.exif_failures:
        print(f"  [exif] {exif_fail}")
```

### Plist Sanitization

```python
from pathlib import Path
from hygeia.plist_sanitizer import sanitize_plist

result = sanitize_plist(Path("com.example.app.plist"))
print(f"Keys redacted: {result['keys_redacted']}")
```

### EXIF Stripping

```python
from pathlib import Path
from hygeia.exif_stripper import strip_exif_directory, verify_exif_stripped

result = strip_exif_directory(Path("/path/to/images"))
remaining = verify_exif_stripped(Path("/path/to/images"))
assert len(remaining) == 0, f"{len(remaining)} images still have EXIF"
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Sanitization complete, verification passed (or skipped) |
| 1 | Input error — path not found, output directory already exists, or missing permissions |
| 2 | Verification failed — residual PII detected after sanitization. Review manifest for details. |

---

## Environment

- **Python**: 3.10 or later
- **exiftool**: Optional. Required for EXIF metadata stripping (step 5). Install via package manager (`apt install libimage-exiftool-perl`, `brew install exiftool`) or from [exiftool.org](https://exiftool.org/).
- **Disk space**: Output directory requires approximately the same space as the input. VACUUM operations may temporarily require additional space equal to the largest database being processed.
- **Dependencies**: Zero external pip packages. Stdlib only.
