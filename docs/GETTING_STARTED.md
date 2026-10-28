# Getting started

HYGEIA requires Python 3.10+. Follow the [published-release installation steps](../README.md#install)
in a virtual environment. Install [ExifTool](https://exiftool.org/) for image
metadata processing; HYGEIA checks `PATH` and selected common installation paths.
This guide follows current source. For a pinned package, use its tagged guide;
selector validation and individual exclusions described here require 3.15.3.

## Prepare and process

1. Close applications changing the source files and use a stable offline copy.
2. Retain the original separately: sanitization can delete files and table rows.
3. Choose a new output directory outside the input tree and a private manifest path.
4. Preview, then run:

```bash
hygeia --input ./data --output ./clean --dry-run
hygeia --input ./data --output ./clean --manifest ./audit.json
```

The live CLI copies input before processing. Direct Python sanitizers modify
their targets in place. Directory copying is not isolation from arbitrary symlink
targets or a running application; inspect untrusted datasets and use an isolated
working environment.

## Review

Inspect `verification.performed`, `passed`, `scope`, and `incomplete` in the
manifest, plus action errors. Keep the manifest private because it includes paths.

- Failed or incomplete results require investigation before publication.
- Skipped verification is unverified, even with exit code zero.
- Scoped verification covers only selected patterns.
- Passing checks remain bounded by supported formats and rules.

After failure, retain the manifest for diagnosis and use a fresh output path for
another attempt. The CLI does not resume into an existing output directory.

```bash
# List available patterns without processing files.
hygeia --list-patterns

# Add a rule profile and its coverage summary.
hygeia --input ./data --output ./clean-hipaa --compliance hipaa

# Narrow text/verifier patterns; other processing stages still run.
hygeia --input ./data --output ./clean-scoped --only identity,financial
```

See [CLI behavior](CLI.md) and the [verification contract](VERIFICATION.md).
