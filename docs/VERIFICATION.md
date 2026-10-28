# Verification and limitations

A pass requires no findings and no incomplete checks under the configured policy.
It does not prove that all personal data is absent.

| Field | Interpretation |
|---|---|
| `performed` | Verification ran; false for dry runs and `--skip-verify` |
| `passed` | No findings or recorded incomplete checks in the configured scope |
| `scope` | Selected pattern categories when narrowed; null otherwise |
| `incomplete` | Checks that could not finish, including failed actions added by the CLI |
| Finding counts | Pattern matches, SQLite freelist findings, image metadata failures |

Checks cover supported text files, SQLite rows and freelists, and image metadata.
Missing ExifTool matters when supported images are present. Recognized databases
that cannot be opened, incomplete schema reads, unsupported FTS, and supported
text files above the default 10 MiB scan cap can yield incomplete results.

Keep actions and verification together: a fresh standalone verification cannot
reconstruct every earlier failed mutation.

## Detection boundaries

Sanitization and verification share patterns and SQLite inventory. Contextual
false-positive filters in `hygeia.verifier.is_false_positive` suppress some matches.
Test representative synthetic data and investigate unexpected suppressions; do
not skip verification as a remedy for a suspected miss.

Coverage does not include general decoding of encrypted or proprietary binary
content, packet captures, image pixels, steganography, or unallocated disk sectors.
Deleting known artifacts differs from parsing arbitrary files of that format.
Unknown files may be preserved. Identifiers outside the schema/pattern rules can
remain, including free text in unsupported languages.

## Rule profile reports

`hipaa`, `gdpr`, `ccpa`, and `all` add rules and evidence reports, not legal
certification. Inspect `identifiers_covered`, `gaps`, and `limitations` returned by
`generate_compliance_report()`; the CLI prints covered identifiers and gaps.

- Date/ZIP helpers exist, but the pipeline does not generalize arbitrary free-text
  dates or ZIP codes. Coverage is limited to implemented rules.
- GDPR special-category processing relies on column names; free-text content is
  an explicit gap.
- CCPA rules rely on known table/column names and cannot find every behavioral or
  commercial fact in arbitrary content.
- Metadata stripping leaves identifying image content, including faces, intact.

Keep manifests private and review output against the intended sharing requirements.
Historical release notes describe prior behavior; this document describes 3.15.2.
