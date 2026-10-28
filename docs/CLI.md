# CLI reference

Use `hygeia --help` for the installed parser.

| Option | Meaning |
|---|---|
| `--input PATH`, `-i` | Source directory; required for processing |
| `--output PATH`, `-o` | New output directory; required for processing |
| `--dry-run`, `-n` | Preview without creating sanitized output; verification is skipped |
| `--manifest PATH`, `-m` | Private JSON audit path; defaults to `deletion_manifest.json` beside the output directory |
| `--compliance MODE` | Additional `hipaa`, `gdpr`, `ccpa`, or `all` rules and coverage summary |
| `--only NAMES` | Comma-separated text/verifier pattern names or categories |
| `--skip-patterns NAMES` | Exclude selected patterns/categories from that scope |
| `--list-patterns` | List patterns and exit without processing; paths are not required |
| `--normalize-timestamps` | Request filesystem timestamp normalization |
| `--skip-verify` | Skip verification; `performed=false`, `passed=false` |
| `--skip-exif` | Skip the media stripping stage, including PDF and Office metadata |
| `--skip-forensic` | Skip the additional forensic-cleaner stage; earlier filesystem cleanup still runs |
| `--workers N`, `-w` | `1` sequential (default), `0` CPU-count selection, greater values use a thread pool |
| `--verbose`, `-v` | Detailed logging |

Use positive worker counts or zero; negative values are currently clamped to one.
Concurrent task logs need not reflect execution order.

## Exit status

| Code | Meaning |
|---|---|
| `0` | Normal completion, including listing, dry runs, skipped verification, or a passing scoped result |
| `1` | Explicit input/output error or an uncaught runtime failure |
| `2` | Failed/incomplete verification; argparse also uses this for invalid arguments |

Automation should inspect the manifest, not just the exit code. Full configured
verification requires `performed=true`, `passed=true`, no incomplete entries, and
`scope=null`. This describes configured checks, not universal PII absence.

## Pattern scope

```bash
hygeia --list-patterns
hygeia --input ./data --output ./clean --only identity,financial
hygeia --input ./data --output ./clean-no-crypto --skip-patterns crypto
```

Filters configure text sanitization and verification. The CLI does not pass a
filtered registry to database orchestration; database handlers and filesystem
rules remain active. `--only exif` must not be read as "only image files can change."

`--skip-exif` does not disable image verification. Missing ExifTool with supported
images present produces an incomplete result. Skipping verification cannot make
that output verified.
