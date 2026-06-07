# Changelog

All notable changes to HYGEIA are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
