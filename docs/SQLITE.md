# SQLite coverage

In 3.15.1, `hygeia.sqlite_catalog` supplies the sanitizer and verifier's table and
column inventory. Shared policy prevents divergent handling of names, but an
inventory defect can affect both passes.

## Row carriers

- Only the literal `sqlite_` reserved prefix is excluded as internal state.
  A legal user name such as `sqliteXnotes` remains visible.
- `PRAGMA table_xinfo` includes ordinary, generated, and hidden columns. Incomplete
  metadata raises an error rather than narrowing coverage silently.
- Text values are examined regardless of declared affinity. SQLite can store text
  in a BLOB or INTEGER column.
- BLOBs are interpreted as UTF-8 and UTF-16 with invalid sequences ignored. This
  is not general decoding of compressed, encrypted, or arbitrary binary formats.
  Redaction can change the original byte encoding.
- Read/write failures are incomplete results. Generated values, constraints,
  triggers, or virtual tables can prevent a detected value from being rewritten.

## Full-text search

FTS3/4/5 shadows are identified from the parent module, configuration, and column
shape. A suffix alone does not exclude a user table. Configuration rows remain
subject to content scanning; derived index storage is handled through FTS cleanup.

Stored-content indexes are rebuilt after sanitization. Supported external-content
FTS5 indexes are rebuilt from sanitized source rows and checked for source/index
consistency. Contentless FTS has no readable original content to verify and remains
incomplete. Unsupported configurations and failed cleanup/integrity checks also
block a passing result.

## Cleanup

Processing prepares WAL state, enables secure deletion, applies rules, rebuilds
supported indexes, and runs VACUUM. The CLI carries sanitization errors into the
final incomplete result. Verification separately checks rows and freelist state.

These steps address logical database artifacts. They do not erase backups,
filesystem snapshots, storage-controller copies, or unallocated disk sectors.
Keep live applications disconnected from the working copy.
