# About HYGEIA

**Named after the Greek goddess of cleanliness, hygiene, and sanitation.**

---

## Problem

Filesystem dumps from personal devices — phones, laptops, desktops — contain years of accumulated PII: passwords in database WAL files, GPS coordinates embedded in photo EXIF, OAuth tokens in configuration plists, browsing history in SQLite, typed passwords in keyboard caches, facial recognition clusters, search queries, call logs, and messages.

This data makes dumps unusable for sharing, collaboration, publication, or regulatory compliance. You cannot hand a filesystem dump to a colleague, submit it as evidence, publish it alongside research, or store it in a shared environment without first removing the personal data.

Existing forensic tools (iLEAPP, MVT, Magnet AXIOM, Cellebrite UFED, Autopsy) are built to **extract** personal data. HYGEIA does the opposite: selective, verified, forensic-grade removal.

---

## Design Principles

### Correctness Over Speed

HYGEIA runs a mandatory verification pass after every sanitization. A tool that reports "clean" when PII remains is worse than no tool. Every run either passes verification (zero findings) or fails with exact locations of every remaining PII match. There is no "probably clean" state.

### Structural Preservation

Sanitization preserves the structural and system-level data that makes artifacts useful for analysis. Database schemas survive intact. System binaries, framework metadata, daemon configurations, sandbox profiles, crash logs, and kernel artifacts are untouched. On iOS, jailbreak infrastructure is dynamically detected and preserved. The output is a working filesystem minus the personal data.

### Defense in Depth

PII can survive deletion through multiple mechanisms: SQLite WAL files, database free pages, FTS shadow tables, LevelDB logs, thumbnail caches, swap files, search indexes, and file timestamps. HYGEIA addresses each layer independently. A single missed vector means the data is recoverable. The pipeline assumes every vector is active and handles all of them.

### Platform Independence

The core engine operates on data formats (SQLite, JSON, CSV, binary plists, images), not platform assumptions. iOS-specific rules are loaded from JSON configuration files that can be replaced or extended for any platform. The generic mode requires zero platform knowledge — it scans every TEXT column in every SQLite table for PII patterns.

### Compliance Alignment

Regulatory frameworks (HIPAA, GDPR, CCPA) define specific categories of protected information. HYGEIA maps its detection capabilities to these categories and reports coverage gaps per run. This is not a checkbox exercise — the compliance report tells you exactly which identifier classes were addressed and which were not present or not covered in your specific dataset.

---

## Technical Foundation

### SQLite WAL Handling

The single most critical technical insight in data sanitization: **deleting rows from a SQLite database does not delete the data.** Write-Ahead Logging (WAL) is the default journal mode for SQLite on iOS, Android, Chrome, Firefox, and most modern applications. The `.db-wal` file contains uncommitted transactions, recently-deleted records, and overflow data. Forensic tools specifically target WAL files because they contain 50-95% of recoverable PII from a database.

HYGEIA's database pipeline:

1. `PRAGMA wal_checkpoint(TRUNCATE)` — Flush all WAL content into the main database file. This ensures the WAL is empty before sanitization begins.
2. `PRAGMA secure_delete = ON` — Force SQLite to overwrite deleted content with zeros instead of marking it as free. Without this, deleted cells remain readable within live pages.
3. Execute sanitization SQL — Regex-based scanning of TEXT columns, blanket redaction of sensitive column names, deletion of known PII tables.
4. Rebuild FTS shadow tables — Full-text search indexes (`*_content`, `*_segments`, `*_segdir`) retain indexed text even after the source table is emptied. Rebuild eliminates this.
5. `VACUUM` — Rebuild the entire database file from scratch. This eliminates free pages (where deleted records live), defragments the file, and produces a minimal-size output.
6. Delete companion files — Remove `.db-wal`, `.db-shm`, and `.db-journal` files.

No other sanitization tool implements this complete pipeline.

### Multi-Layer Detection

PII detection operates at three levels simultaneously:

**Regex patterns**: 28+ pattern families (email, phone US/intl, SSN, credit card, IPv4, IPv6, IBAN, MAC, JWT, AWS keys, GitHub tokens, API keys, Bitcoin/Ethereum wallets, IMEI, IMSI, SWIFT/BIC, routing numbers, DEA numbers, NPI, UK NINO, Indian PAN, US EIN, VIN, and more) applied to every TEXT column in every SQLite table and every line of every text file. Patterns are tuned to minimize false positives — SSN excludes known-invalid prefixes, IP excludes localhost/broadcast, phone requires area code validation.

**Column-name detection**: 50+ column names (email, username, password, phone, address, latitude, longitude, api_key, token, cookie, etc.) trigger blanket redaction regardless of content. This catches PII that doesn't match any regex pattern — a name in a `first_name` column, a street address in an `address` column.

**Table-level rules**: 30+ table names across Chrome, Firefox, Android, messaging apps, and macOS are recognized as entirely PII. All rows are deleted, schema is preserved. This is faster and more thorough than row-level scanning for tables that are definitionally personal data.

### Forensic Artifact Handling

Beyond databases, HYGEIA targets data structures that forensic examiners specifically look for:

- **LevelDB stores**: Chrome localStorage, IndexedDB, and Session Storage use LevelDB format. These contain arbitrary application data including tokens, user preferences, and cached content. Partial cleanup is unreliable — HYGEIA deletes the entire directory tree.
- **Thumbnail caches**: iOS PhotoData/Thumbnails, Android DCIM/.thumbnails, Windows Thumbcache_*.db, macOS ~/.cache/thumbnails. Thumbnails survive deletion of the original image and are specifically targeted by Cellebrite and Autopsy.
- **Swap and hibernation files**: pagefile.sys, swapfile.sys, hiberfil.sys, sleepimage. These contain RAM snapshots written to disk, which can include in-memory credentials, decrypted content, and session data.
- **Search indexes**: Spotlight (.Spotlight-V100), Windows Search (Windows.edb), iOS SearchHistory.db. These contain indexed text from documents, emails, and messages.
- **Session data**: Chrome Current Session/Last Session, Firefox sessionstore.jsonlz4. These contain open tab URLs, form data, and scroll positions.
- **File timestamps**: Modified/Accessed/Changed/Born timestamps enable timeline reconstruction. The `--normalize-timestamps` flag sets all timestamps to a uniform epoch value.

---

## Compliance Framework

### HIPAA Safe Harbor (45 CFR 164.514(b)(2))

HIPAA defines 18 categories of protected health information (PHI) identifiers that must be removed for Safe Harbor de-identification. HYGEIA tracks coverage against all 18:

1. Names — column-name detection
2. Geographic data below state level — column-name detection (address, city, zip, street)
3. Dates except year — configurable date generalization
4. Phone numbers — regex pattern
5. Fax numbers — column-name detection
6. Email addresses — regex pattern
7. SSN — regex pattern
8. Medical record numbers — column-name detection
9. Health plan beneficiary numbers — column-name detection
10. Account numbers — column-name detection
11. Certificate/license numbers — column-name detection
12. Vehicle identifiers — column-name detection
13. Device identifiers — regex pattern (MAC, IMEI) + column-name detection
14. Web URLs — table-level deletion (browsing history tables)
15. IP addresses — regex pattern (v4 + v6)
16. Biometric identifiers — table-level deletion (face data tables)
17. Photographs — EXIF stripping (metadata removal, not content deletion)
18. Unique codes — column-name detection

### GDPR Article 4/9

GDPR special category data includes racial/ethnic origin, political opinions, religious beliefs, trade union membership, genetic data, biometric data, health data, and sexual orientation. HYGEIA extends column-name detection with these categories when `--compliance gdpr` is active.

### CCPA

CCPA's definition of personal information explicitly includes browsing history, search history, geolocation data, and commercial information (purchase records). HYGEIA treats these as mandatory-delete categories when `--compliance ccpa` is active.

---

## Performance

| Input Size | Pipeline Time (SSD) | Primary Bottleneck |
|-----------|---------------------|-------------------|
| 100 MB | 2-5 seconds | SQLite VACUUM |
| 1 GB | 10-30 seconds | SQLite VACUUM |
| 10 GB | 2-5 minutes | EXIF stripping (large photo libraries) |
| 30 GB | 15-30 minutes | Copy + VACUUM + EXIF |
| 60 GB | 30-60 minutes | Copy + VACUUM + EXIF |

The copy step (input to output) dominates wall-clock time for large dumps. Sanitization and verification are CPU-bound on SQLite VACUUM operations. EXIF stripping is I/O-bound and scales with image count.

---

## Integration

HYGEIA operates as a standalone CLI tool or as a Python library. All sanitization modules expose functions that accept `Path` objects and return structured result dictionaries, making integration into larger pipelines straightforward.

When paired with an intelligence database (such as ICARUS), HYGEIA can make analysis-informed decisions about which artifacts to preserve based on prior classification results.
