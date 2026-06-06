# About HYGEIA

**Named after the Greek goddess of cleanliness, hygiene, and sanitation.**

---

## Why This Exists

If you've ever pulled a filesystem dump from a personal device, you know the problem: that 30-60GB image has every photo you've taken, every message you've sent, your GPS history, health data, typed passwords sitting in keyboard caches, facial recognition clusters, OAuth tokens in plists, and browsing history going back years. You can't share it. You can't publish it. You can't hand it to a collaborator.

Forensic tools like iLEAPP, MVT, Magnet AXIOM, and Cellebrite are built to **extract** that personal data -- the opposite of what security researchers need. HYGEIA does selective, verified PII removal.

---

## What Makes It Different

### 1. WAL-Aware SQLite Sanitization

The single most important technical insight: **deleting a database does not delete the data.** Every SQLite database on iOS (and most mobile/desktop apps) uses Write-Ahead Logging. The `.db-wal` file contains uncommitted transactions and recently-deleted records -- 50-95% of recoverable PII lives here.

HYGEIA handles this with a five-step pipeline: WAL checkpoint, secure_delete, sanitize, VACUUM, companion file cleanup. No other sanitization tool does this correctly.

### 2. Column-Level Database Surgery

Databases like knowledgeC.db and Photos.sqlite have personal data and system metadata in the same tables. HYGEIA doesn't nuke the whole database -- it surgically NULLs GPS coordinates, deletes facial recognition clusters, and redacts third-party app names while keeping the system data that researchers need.

### 3. Platform-Agnostic Engine

Ships with iOS rules (33 delete patterns, 18 preserve paths, 29 sensitive plist keys), but the sanitization modules are generic:

- `sqlite_sanitizer.py` works on any SQLite database
- `plist_sanitizer.py` works on any binary plist
- `exif_stripper.py` works on any image (9 formats)
- `verifier.py` works on any filesystem tree

Swap the JSON rule files in `hygeia/rules/` for Android, macOS, or whatever you're sanitizing.

### 4. Jailbreak Preservation

Dynamic detection of three jailbreak families (Dopamine, palera1n, RootHide). When detected, the entire jailbreak tree is preserved: /var/jb/, /private/preboot/, /cores/, tweak preferences, package databases.

### 5. Mandatory Verification

A sanitization tool that doesn't verify its own output is worse than no tool. HYGEIA runs three independent checks after every sanitization: regex PII scan (7 pattern families), SQLite freelist inspection (zero free pages = no recoverable records), and EXIF tag verification.

### 6. Compliance-Ready Manifests

JSON audit manifests aligned with NIST SP 800-88 (media sanitization), HIPAA Safe Harbor (18 identifier coverage), and GDPR anonymization requirements.

---

## Architecture

Seven Python modules, four JSON rule files, zero external pip dependencies (stdlib + optional system exiftool).

| Module | What It Does | Scope |
|--------|-------------|-------|
| `scanner.py` | Classifies every file into 6 actions using JSON rules | Rule-driven (swappable) |
| `sqlite_sanitizer.py` | WAL-aware 5-step database sanitization pipeline | Any SQLite DB |
| `plist_sanitizer.py` | Recursive key-pattern matching, binary plist redaction | Any binary plist |
| `exif_stripper.py` | Bulk metadata removal via exiftool, 9 formats | Any image |
| `verifier.py` | 3 independent PII checks: regex, freelist, EXIF | Any filesystem |
| `manifest.py` | JSON audit trail with compliance alignment | Universal |
| `hygeia_cli.py` | Full pipeline orchestration: copy > scan > sanitize > verify | Universal |

### Rule Files

| File | Contents |
|------|----------|
| `delete_patterns.json` | 33 directory patterns, 18 database names, 10 extension-scoped patterns, app container rules |
| `preserve_patterns.json` | 18 directory paths, 5 critical files, 4 always-preserve extensions, jailbreak markers |
| `selective_db_rules.json` | Column-level SQL for 4 databases (knowledgeC, Photos.sqlite, TCC.db, applicationState.db) |
| `plist_patterns.json` | 4 sanitization paths, 5 always-sanitize files, 3 never-sanitize files, 29 sensitive keys |

---

## Performance

| Dump Size | Time (SSD) | Output Size |
|-----------|------------|-------------|
| 30 GB | 15-30 min | 10-15 GB |
| 60 GB | 30-60 min | 20-30 GB |

Bottlenecks: SQLite VACUUM (CPU-bound), EXIF stripping (I/O on large photo libraries).

---

## Integration

HYGEIA can integrate as a sanitization phase in other analysis pipelines. The standalone version (this repo) is rule-based and works immediately with no external dependencies beyond Python stdlib.

When integrated with an analysis database, HYGEIA can make intelligence-guided decisions about which artifacts to preserve vs delete based on prior analysis results.
