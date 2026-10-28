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
python -m venv .venv
# Activate the environment before installing.
python -m pip install -e ".[dev]"
```

This installs HYGEIA in editable mode plus the dev toolchain: pytest,
pytest-cov, ruff, mypy, bandit.

## Running the Checks Locally

Run the pinned checks locally before opening or updating a PR that starts CI.
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

The Linux quality phase runs Ruff and mypy under `Type Check (mypy)`, then
Bandit under `Security Scan (bandit)`, before the Python 3.10–3.13 test matrix
starts on Ubuntu, Windows, and macOS. All 12 matrix jobs and both quality jobs
are required. Ruff/mypy and Bandit each run once per workflow; tests run in every
matrix cell. Development
tools are pinned in `pyproject.toml`; validate dependency updates locally before
publishing a branch. Superseded runs are canceled, and a failed matrix job
stops its siblings. If you're changing filesystem or path-handling code, be aware that
behavior can differ across platforms (case sensitivity, symlink semantics,
`os.utime` support) — this has caused real CI failures before.

## Code Style

- Follow the existing module layout: one concern per file
  (`sqlite_sanitizer.py`, `text_sanitizer.py`, `platform_handlers.py`, etc.).
  See the [architecture guide](docs/ARCHITECTURE.md) for what each
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

HYGEIA must not report a configured check as passed when it did not complete —
see the [verification contract](docs/VERIFICATION.md).
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

- PRs require all 14 checks: `Type Check (mypy)`, `Security Scan (bandit)`, and
  every `Test (Python VERSION, OS)` combination for Python 3.10–3.13 on
  `ubuntu-latest`, `windows-latest`, and `macos-latest`. Checks are bound to the
  GitHub Actions app. The platform matrix waits for both quality jobs.
  Keep these names stable and the branch up to date with `main`.
- Protection applies to administrators and requires a PR, linear history, and
  resolved conversations. The solo-maintainer policy requires zero approving
  reviews; it does not bypass the required checks. Force pushes and branch
  deletion are disabled on `main`.
- Keep PRs focused — one logical change per PR is easier to review and
  easier to revert if something's wrong.
- Update `CHANGELOG.md` under an `[Unreleased]` heading for user-visible
  changes (new patterns, new handlers, behavior changes). Skip it for
  pure internal refactors.
- Squash-merge is the norm for this repository.

## Publishing a Release

1. Make package and module versions agree, date the changelog entry, and review
   installation/help/API examples and license metadata.
2. Build wheel and source archives with recorded tool versions. Verify their
   contents, included license, clean installation, and a synthetic workflow.
3. Merge the reviewed PR after all 14 checks pass. Verify the merge tree matches
   the source used for the artifacts.
4. Create an annotated version tag at that exact merge commit. Do not move an
   existing tag or infer its target from a later `main`.
5. Publish wheel, source archive, and `SHA256SUMS.txt` with bounded release notes.
   Download the published assets and verify hashes, installation, and version.
6. Update release-pinned quickstarts and the wiki after publication. Later
   documentation changes do not justify moving the tag or replacing assets.

The current workflow runs for PRs and pushes to `main`; tags and release events
do not start it. Dependency-graph metadata updates are separate from this CI.

## Reporting Bugs

Use [GitHub Issues](https://github.com/Indegosblade/HYGEIA/issues). For
detection gaps or fail-open behavior (HYGEIA misses PII, or reports a run
clean when it shouldn't have), see [SECURITY.md](SECURITY.md) instead —
those are treated as security issues.
