# Architecture

```text
stable source directory
  -> CLI copy to a new output directory
  -> classification and schema detection
  -> database, text, filesystem, and metadata processors
  -> verification plus sanitization-error aggregation
  -> private manifest and process exit status
```

| Module | Ownership |
|---|---|
| `cli.py` | Arguments, copying, stages, worker pools, final status |
| `scanner.py` | File classification and path rules |
| `patterns.py`, `rules/` | Pattern registry and packaged JSON policy |
| `platform_handlers.py` | Schema matching and database-specific handling |
| `sqlite_catalog.py` | Shared table, column, and FTS-shadow inventory |
| `sqlite_sanitizer.py` | SQLite mutation, WAL preparation, FTS cleanup, VACUUM |
| `text_sanitizer.py`, `plist_sanitizer.py` | Text and plist transformations |
| `filesystem_sanitizer.py`, `forensic_cleaner.py` | Artifact removal and filesystem metadata |
| `exif_stripper.py`, `pdf_stripper.py`, `office_stripper.py` | Format-specific metadata |
| `verifier.py` | Content checks and incomplete results |
| `compliance.py`, `manifest.py` | Coverage reports and private action records |

Database signatures cover Chrome/Chromium, Firefox, iOS, Android, and a SQLite
Windows WebCache lookalike. Genuine ESE WebCache files are not parsed as SQLite.
Unrecognized SQLite schemas receive generic scanning. Filesystem path rules are
separate and may remove complete artifacts.

## Extend policy

Packaged JSON changes are code changes: use a local checkout, synthetic fixtures,
and review. There is no CLI custom-rules-directory flag. Follow the structure of
the JSON files in `hygeia/rules/`; preserve their keys and test matches and near misses.

Add database signatures and handlers in `platform_handlers.py`, checking their
interaction with generic processing. Keep inventory in `sqlite_catalog.py` and
surface unsupported states instead of silently omitting work.

See [Contributing](../CONTRIBUTING.md) for local checks. Historical fixes remain
in [CHANGELOG.md](../CHANGELOG.md) and Git history.
