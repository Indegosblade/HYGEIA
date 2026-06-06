# HYGEIA Commands Reference

## CLI Usage

```bash
hygeia [OPTIONS]
# or: python hygeia_cli.py [OPTIONS]
```

## Required

| Flag | Description |
|------|-------------|
| `--input PATH` / `-i` | Source filesystem dump directory |
| `--output PATH` / `-o` | Destination for sanitized copy |

## Options

| Flag | Description |
|------|-------------|
| `--dry-run` / `-n` | Preview all actions without making changes |
| `--skip-verify` | Skip post-sanitization PII verification |
| `--skip-exif` | Skip EXIF metadata stripping (fastest skip if photos already deleted) |
| `--manifest PATH` / `-m` | Write JSON audit manifest to custom path |
| `--verbose` / `-v` | Detailed logging output |

## Examples

```bash
# Basic sanitization
hygeia --input /mnt/dump --output /mnt/clean

# Preview what happens (nothing touched)
hygeia --input /mnt/dump --output /tmp/unused --dry-run

# Full pipeline with manifest
hygeia --input /mnt/dump --output /mnt/clean --manifest audit.json -v

# Fast run (skip EXIF and verification)
hygeia --input /mnt/dump --output /mnt/clean --skip-exif --skip-verify
```

## Programmatic Usage

```python
from hygeia.scanner import FileScanner, FileAction
from hygeia.sqlite_sanitizer import sanitize_database, delete_database, find_all_databases
from hygeia.plist_sanitizer import sanitize_plist
from hygeia.exif_stripper import strip_exif_directory, verify_exif_stripped
from hygeia.verifier import verify_sanitization
from hygeia.manifest import generate_manifest
```

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

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (verification passed or skipped) |
| 1 | Input error (path not found, permissions, output exists) |
| 2 | Verification failed (PII found post-sanitization) |
