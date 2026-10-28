# HYGEIA

[![CI](https://github.com/Indegosblade/HYGEIA/actions/workflows/ci.yml/badge.svg)](https://github.com/Indegosblade/HYGEIA/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: PolyForm NC](https://img.shields.io/badge/license-PolyForm%20NC-green.svg)](LICENSE)

HYGEIA sanitizes copies of filesystem datasets using schema-aware SQLite handlers,
PII patterns, file removal rules, and metadata cleanup. It prepares research
artifacts for review and sharing, with a record of actions and verification gaps.

**Current package: 3.15.2.** Python 3.10 or later; no runtime Python dependencies.
Image metadata processing additionally requires [ExifTool](https://exiftool.org/).

## Install

Use a virtual environment and Git:

```bash
git clone https://github.com/Indegosblade/HYGEIA.git
cd HYGEIA
python -m venv .venv
# Activate: source .venv/bin/activate (macOS/Linux)
# Activate: .venv\Scripts\Activate.ps1 (PowerShell)
python -m pip install .
hygeia --help
```

For reproducible deployments, check out a reviewed commit before installation and
record that revision alongside the package version.

## Run

Use a stable, offline dataset and a new output directory outside the input tree.
The CLI refuses an output directory that already exists.

```bash
# Preview actions; no sanitized output or verification is produced.
hygeia --input ./data --output ./clean --dry-run

# Copy, sanitize, verify, and write a private audit manifest.
hygeia --input ./data --output ./clean --manifest ./audit.json
```

Review verification and action records before sharing output. The manifest can
contain sensitive paths: keep it private. A zero exit code alone is insufficient
when verification was skipped or the pattern scope was narrowed.

## Capabilities

| Component | Behavior |
|---|---|
| SQLite | Schema-specific and generic scanning, selected row deletion/redaction, WAL handling, FTS cleanup, and VACUUM |
| Text and plists | Pattern and key-based processing for supported JSON, logs, CSV/TSV, and plist content |
| Filesystem | Rule-based removal of selected histories, caches, browser stores, and artifacts |
| Metadata | Image metadata via ExifTool; supported PDF and Office metadata cleanup |
| Verification | Separate content pass, SQLite freelist and image metadata checks, and explicit incomplete results |

SQLite coverage includes readable values regardless of declared affinity,
generated/hidden columns, and UTF-8/UTF-16 interpretations of BLOBs. Sanitization
and verification share a table inventory; the latter is a separate pass, not an
independently implemented inventory. See [SQLite coverage](docs/SQLITE.md).

## Verification and limits

`PASSED` means no findings under the configured policy and no recorded incomplete
checks. It does not prove arbitrary personal data is absent. Patterns, contextual
suppressions, supported formats, and available tools bound the result. Unsupported
binary formats, encrypted content, image pixels, packet captures, and disk sectors
are outside general content sanitization coverage.

HIPAA, GDPR, and CCPA options select additional rules and report coverage; they do
not certify legal compliance. Review their gaps and limitations.

## Documentation

- [Getting started](docs/GETTING_STARTED.md)
- [CLI reference](docs/CLI.md)
- [Python API](docs/API.md)
- [SQLite coverage](docs/SQLITE.md)
- [Verification and limitations](docs/VERIFICATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Wiki](https://github.com/Indegosblade/HYGEIA/wiki)
- [Contributing](CONTRIBUTING.md), [security policy](SECURITY.md), and [changelog](CHANGELOG.md)

## License

[PolyForm Noncommercial 1.0.0](LICENSE). Review the license before use;
commercial licensing requires a separate agreement.

Maintained by [Kevin Estrada](https://github.com/Indegosblade).
