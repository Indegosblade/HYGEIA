# CLI reference

Use `hygeia --help` for the installed parser.

| Option | Meaning |
|---|---|
| `--input PATH`, `-i` | Source directory; required for processing |
| `--output PATH`, `-o` | New output directory; required for processing |
| `--dry-run`, `-n` | Preview without creating sanitized output; verification is skipped |
| `--manifest PATH`, `-m` | Private JSON audit path; defaults to `deletion_manifest.json` beside the output directory |
| `--compliance MODE` | Additional `hipaa`, `gdpr`, `ccpa`, or `all` rules and coverage summary |
| `--only NAMES` | Include known text/verifier pattern names or categories |
| `--skip-patterns NAMES` | Exclude known pattern names or categories |
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
`scope` is a human-readable label such as `only=financial` or `skip=credit_card`,
not a stable parseable category-list API. Any non-null scope means a narrowed run.

## Pattern scope

```bash
hygeia --list-patterns
hygeia --input ./data --output ./clean --only identity,financial
hygeia --input ./data --output ./clean-no-crypto --skip-patterns crypto
hygeia --input ./data --output ./clean-no-card --skip-patterns credit_card
```

In 3.15.3, selectors must match names from `--list-patterns`; unknown or empty
selectors are argument errors before copying or processing. `--only` and
`--skip-patterns` are mutually exclusive. Earlier 3.15.2 accepted unknown names
and did not implement individual-name exclusions; use 3.15.3 for this contract.

Category-only selections and category exclusions retain the global keyword-gated
context detectors. An explicit individual selection narrows to that pattern;
an individual exclusion such as `--skip-patterns date_of_birth` removes that
context detector too. Category skips do not turn off all sensitive-key rules.

A mixed `--only` list containing individual names limits global context detectors
to the individually named ones, even when categories are also selected. For
example, `--only financial,date_of_birth` includes the financial category and the
global `date_of_birth` detector, but omits other global context detectors.
`--only financial,email` includes the financial category and email pattern, with
no global context detectors. This differs from category-only `--only financial`.

Filters configure text sanitization and verification. The CLI does not pass a
filtered registry to database orchestration; database handlers and filesystem
rules remain active. `exif` is not a registered pattern selector; these options
do not select processing stages or mean "only image files can change."

`--skip-exif` does not disable image verification. Missing ExifTool with supported
images present produces an incomplete result. Skipping verification cannot make
that output verified.
