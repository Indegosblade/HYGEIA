# Contributing to HYGEIA

HYGEIA is a source-available forensic PII sanitization tool, licensed under
PolyForm Noncommercial 1.0.0 (see [LICENSE](LICENSE)). Contributions of any
size are welcome — bug reports, documentation fixes, new platform handlers,
and pattern additions.

## Before You Start

For anything beyond a small fix, open an issue first describing what you
want to change and why. This avoids wasted effort on changes that don't fit
the project's direction (e.g. adding a network dependency — HYGEIA is
intentionally stdlib-only aside from the optional `exiftool` binary).

## Development Setup

```bash
git clone https://github.com/Indegosblade/HYGEIA.git
cd HYGEIA
pip install -e ".[dev]"
```

This installs HYGEIA in editable mode plus the dev toolchain: pytest,
pytest-cov, ruff, mypy, bandit.

## Running the Checks Locally

These are the same checks CI runs, and all are required to pass before merge:

```bash
# Lint
ruff check .

# Tests (with coverage)
pytest tests/ -v --cov=hygeia --cov-report=term-missing

# Type check
mypy hygeia/

# Security scan
bandit -r hygeia/ -c pyproject.toml

# CLI smoke test
hygeia --help
```

CI runs the test suite across Python 3.10–3.13 on Ubuntu, Windows, and
macOS. If you're changing filesystem or path-handling code, be aware that
behavior can differ across platforms (case sensitivity, symlink semantics,
`os.utime` support) — this has caused real CI failures before.

## Code Style

- Follow the existing module layout: one concern per file
  (`sqlite_sanitizer.py`, `text_sanitizer.py`, `platform_handlers.py`, etc.).
  See the Architecture section of the [README](README.md) for what each
  module owns.
- Regex-based PII patterns belong in `hygeia/rules/pii_patterns.json`, not
  hardcoded in Python — `hygeia/patterns.py` is the single loader all
  consumers (sanitizer, verifier, text sanitizer) share.
- New platform handlers go in `hygeia/platform_handlers.py`: add a detection
  signature to `_DETECTION_SIGNATURES` and either an entry in `_NUKE_TABLES`
  (table-nuke only) or a custom handler function for column-level surgery.
- Keep functions typed; mypy runs with a fairly permissive config
  (see `[tool.mypy]` in `pyproject.toml`) but avoid introducing new
  `# type: ignore` where a real annotation is easy.
- No new runtime pip dependencies. HYGEIA's zero-dependency stdlib-only
  design (aside from the optional external `exiftool` binary) is
  intentional, not an oversight.

## Fail-Closed Is a Design Requirement, Not a Suggestion

HYGEIA's core guarantee is that it never reports a dump "clean" when it
can't actually back that up — see the Verification section of the README.
If you touch `verifier.py`, `sqlite_sanitizer.py`, or the compliance
reporting in `compliance.py`, make sure any new failure path is surfaced
(via `incomplete`, a `gap`, a non-zero exit code, or an explicit warning)
rather than silently treated as success. A change that makes a check
quietly pass when it didn't actually run is a regression, not a cleanup.

## Tests

New behavior needs a test. The test suite in `tests/` is organized roughly
by module (`test_sqlite_sanitizer.py`, `test_platform_handlers.py`,
`test_verifier.py`, etc.) — add to the matching file, or create a new one
following the same naming convention for a new module.

## Pull Requests

- `main` is protected: PRs require the `Test (Python 3.12, ubuntu-latest)`,
  `Type Check (mypy)`, and `Security Scan (bandit)` checks to pass, and the
  branch must be up to date with `main` before merge.
- Keep PRs focused — one logical change per PR is easier to review and
  easier to revert if something's wrong.
- Update `CHANGELOG.md` under an `[Unreleased]` heading for user-visible
  changes (new patterns, new handlers, behavior changes). Skip it for
  pure internal refactors.
- Squash-merge is the norm for this repository.

## Reporting Bugs

Use [GitHub Issues](https://github.com/Indegosblade/HYGEIA/issues). For
detection gaps or fail-open behavior (HYGEIA misses PII, or reports a run
clean when it shouldn't have), see [SECURITY.md](SECURITY.md) instead —
those are treated as security issues.
