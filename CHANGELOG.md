# Changelog

All notable changes to HYGEIA are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.15.0] - 2026-07-03

45-finding forensic-correctness audit remediation. The core guarantee — HYGEIA never reports a dump clean when it can't prove that — is now actually enforced by the verifier and the CLI, not just asserted in prose.

### Changed
- **Fail-closed verification**: `VerificationResult` gained `incomplete` (checks that could not be run to completion) and `scope` (set when `--only`/`--skip-patterns` narrowed what was checked). `passed` now requires zero findings *and* zero incomplete checks. The CLI prints every incomplete/scoped item and exits 2 whenever it cannot certify a file or database clean — missing exiftool, a locked/unreadable/encrypted database, an oversized file, or a narrowed pattern selection all now block a PASSED result instead of being silently skipped.
- **Verifier internals**: SQLite databases are opened `mode=ro` and are never mutated by verification (previously, freelist inspection ran its own VACUUM at verification time and silently dropped the finding if that VACUUM failed or the DB was locked). Content scanning covers every column regardless of declared type — including BLOB and mistyped columns, decoded to text — across all rows; the old 1000-row-per-column cap and TEXT-only column filter are gone.
- **Detection coverage**: compressed (`::`) IPv6 notation; GPS coordinates with a single or zero leading digit (equatorial/prime-meridian values like `-0.1278` are no longer suppressed as false positives, and the old blanket "`.plist`/`.json` value ending in 4 decimals" suppression is now `.plist`-only); spaced/hyphenated Amex card grouping; a dedicated `address` sensitive-key category (street/city/zip/postal_code/employer/organization/...); CoreData `Z`-prefixed location columns (`ZLATITUDE`, `ZLONGITUDE`, `ZLOCATION`, `ZALTITUDE`, `ZCOORDINATE`). Context-gated patterns (date of birth, password key/value pairs, driver's license, passport, AWS secret keys, NPI) are now actually redacted during JSON/log/CSV sanitization instead of only being flagged after the fact by the verifier. The blanket "bare SSN in a `.json`/`.plist`/`.db` file is a false positive" verifier suppression is removed — it was hiding real unformatted SSNs; CoreData-internal-column suppression (`Z_PK`, `Z_ENT`, etc.) still applies.
- **SQLite / anti-forensic hardening**: every identifier is safely quoted (`utils.quote_identifier`) before interpolation into SQL; FTS3/4/5 shadow-table cleanup rebuilds the index from redacted content where possible and, for structurally contentless/external-content FTS5 tables, fails closed instead of trusting a version-dependent "rebuild didn't raise"; deleted databases and their WAL/SHM/journal companions are overwritten with random bytes before unlink; a persistent VACUUM failure is now surfaced (`vacuum_failed`) instead of silently leaving freelist pages behind; the WAL-orphan finder no longer mis-resolves the parent database path when a directory name itself contains `-wal`/`-shm`/`-journal`.
- **Path safety**: every in-place rewriter (office, PDF, text, plist) and both timestamp-normalization passes now refuse to follow a symlink or write outside the dump root (`utils.resolve_within` / `is_safe_regular_file` / `safe_utime`); forensic directory/cache/crash-file cleanup no longer reports success when a symlink `rmtree` silently no-oped, and tolerates files a concurrent `--workers` task already removed instead of crashing; thumbnail/cache matching is exact-name (or `Library/Caches`-suffix) instead of "any name containing *cache*", so folders like `DocumentCache` are no longer wiped; `clean_clipboard_history()` is no longer called from the automatic per-dump pipeline — it targets the *operator's own host* clipboard, not the dump, and was clearing the analyst's live clipboard on every real run.
- **Compliance honesty**: all 18 HIPAA Safe Harbor identifiers are evaluated every run against the evidence the sanitizer actually produced — an identifier is `covered` only with positive evidence, otherwise it's a `gap`. GDPR and CCPA modes report real identifier-level `covered`/`gaps` instead of a bare framework name with nothing behind it. Every compliance report now includes a `limitations` list spelling out what wasn't done (e.g. free-text dates/ZIPs are not generalized by the running pipeline even though new `generalize_date`/`truncate_zip` helpers exist for it; free-text GDPR special-category data isn't detected). The `delete_all_user_content` / `delete_browsing_history` profile flags are now read instead of being dead fields.
- **Cross-platform CI**: Windows-safe secure-overwrite (no CRLF translation on `os.write`), symlink-aware `os.utime` fallbacks on platforms lacking `follow_symlinks=False`, and tolerant companion-file cleanup when a sibling process holds a lock — the full Windows/macOS/Python 3.10 matrix is green.

### Fixed
- iOS `photos_ios` handler now matches on `ZASSET` **or** `ZGENERICASSET` — the old signature required both, which no real device ever has, so the handler never fired and Photos.sqlite GPS/face data fell through to the generic sanitizer (which skips FLOAT columns entirely).
- plist float values (GPS coordinates stored as CoreLocation doubles) and scaled-integer coordinates under location-hint keys are now scanned and zeroed; previously every float was left untouched regardless of key name.
- Office tracked-changes and comment author identities (`word/document.xml`, `comments.xml`, `people.xml`) and `docProps/custom.xml` custom properties are now stripped, with a DTD/entity-expansion ("billion laughs") guard on every parsed XML part.
- PDF XMP metadata packets are now stripped (not just the plaintext `/Info` dict); residual metadata hidden in a compressed object stream is detected and reported instead of silently missed.
- Oversized JSON/log/CSV files are no longer dropped from a run with no trace — each is recorded as an explicit `text_sanitize_skipped` action.

## [3.14.0] - 2026-06-07

### Changed
- Final DRY pass: deduplicated helpers, consolidated ZIP opens, hardened CI.
- mypy typecheck now enforced (no `continue-on-error`), config centralized in pyproject.toml.
- Bandit security scan installs from `.[dev]` (single dependency source).
- `.ruff_cache/` and `.mypy_cache/` added to `.gitignore`.

### Fixed
- `_inside_deleted()` extracted to module level — was duplicated as nested function in two places.
- ZIP file opens consolidated: 3→1 for OOXML metadata strip, 2→1 for ODF.
- `_get_existing_tables()` helper extracted — sqlite_master query was duplicated.
- `fname`/`col_part` path parsing deduplicated in verifier (13 instances → 1 each).
- Manifest `platform_sanitize` action now counted in `databases_sanitized`.
- GPS redaction counted correctly as redaction, not deletion.
- Dead `--optimize` CLI flag removed.
- exif_stripper error key unified to list pattern.
- CLI indentation fix after dead flag removal.

## [3.1.0] - 2026-06-07

### Added
- Typed exception hierarchy (`hygeia/exceptions.py`): `HygeiaError`, `DatabaseLockError`, `DatabaseCorruptionError`, `VerificationFailedError`.
- `PRAGMA integrity_check` pre- and post-sanitization in `sanitize_database_generic()`. Corrupted databases are rejected before sanitization; post-sanitization corruption is logged.
- Module-level pattern singleton (`get_default_registry()`) — patterns compiled once, shared across text_sanitizer, sqlite_sanitizer, and verifier.

### Changed
- `find_all_databases()` now filters by extension first, only opening files for magic-byte checks when the extension is unrecognized. Reduces I/O on large directory trees.
- VACUUM retry uses exponential backoff (0.1s → 0.3s → 0.9s) instead of hardcoded sleep(0.1) + sleep(0.5).

### Fixed
- Pattern registry no longer recompiled independently in each module — eliminates redundant JSON parsing and regex compilation on first use.

## [3.0.0] - 2026-06-06

### Added
- Cross-platform positioning: 20 schema-aware handlers across Chrome, Firefox, iOS, Android, Windows, macOS, Linux.
- XML file sanitization (`.xml` added to text sanitizer discovery).
- Vector database false-positive suppression (bitcoin_address hex filter, password_kv embedding column filter).
- Verifier Suppressions table in README and wiki documenting 9 known false-positive filters.
- "Why HYGEIA?" competitive analysis section in README.
- Limitations table (8 entries) in README and Architecture wiki.
- Expected output comments in all Programmatic API examples.

### Changed
- README rewritten: one-sentence hook, platform list, split wall-of-text intro.
- Wiki synced with README content (Home.md, Architecture.md).

### Fixed
- iPodDevices.xml with real IMEIs was passing through unsanitized.
- ChromaDB embedding IDs (32-char hex) matching bitcoin_address regex.

## [2.0.0] - 2026-05-28

### Added
- DRY refactor: extracted `sha256` utility, data-driven platform handlers.
- PK/UNIQUE constraint bypass in sensitive column redaction.
- Plist false-positive suppression in verifier.

## [1.0.0] - 2026-05-15

### Added
- Initial release: 7-stage pipeline, 20 platform handlers, WAL-aware SQLite sanitization.
- HIPAA/GDPR/CCPA compliance modes.
- Post-sanitization verification (regex + freelist + EXIF).
- CLI with `--dry-run`, `--only`, `--skip-patterns`, `--compliance` flags.
- JSON audit manifest generation.
