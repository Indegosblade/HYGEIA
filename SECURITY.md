# Security Policy

HYGEIA processes forensic dumps and other data that may contain sensitive
personal information. Its entire purpose is removing that data correctly, so
a defect that causes it to miss or mishandle PII is treated as a security
issue, not just a bug.

## Supported Versions

HYGEIA does not yet maintain parallel maintenance branches. Security fixes
are made against the latest release on `main`. If you depend on a pinned
commit or older tag, re-test against current `main` before assuming a fix
applies to your pin.

## Reporting a Vulnerability

There is no dedicated security email for this project. Please report
security issues the same way as other bugs, through GitHub:

- Preferred: open a [GitHub Security Advisory](https://github.com/Indegosblade/HYGEIA/security/advisories/new)
  (private to maintainers until you and the maintainer agree to disclose).
- If advisories are unavailable to you, open a regular
  [GitHub issue](https://github.com/Indegosblade/HYGEIA/issues) and mark it
  clearly as security-sensitive. For anything that includes exploit details,
  a proof-of-concept dump, or real (not synthetic) PII, omit those specifics
  from the public issue and note that you're withholding them pending a
  private channel.

When reporting, please include:

- The HYGEIA version or commit you tested against.
- Whether the issue is a **detection gap** (PII that should be flagged/redacted
  isn't), a **fail-open** (a check reports clean when it shouldn't), or a
  **code-execution/path-traversal** class issue.
- A minimal, synthetic reproduction — do not attach real personal data to a
  report.

There is no fixed SLA for response, but detection gaps and fail-open defects
(cases where HYGEIA reports `PASSED` without actually having verified that)
are treated as the highest priority, since they undermine the tool's core
guarantee.

## Known Non-Goals

These are documented limitations, not vulnerabilities — see the Limitations
section of the [README](README.md) for the full list (encrypted databases,
non-SQLite formats like ESE, disk-level artifacts, steganography, etc.).
Reports about behavior already listed there will be closed as expected
behavior, though clarifying documentation issues are still welcome.
