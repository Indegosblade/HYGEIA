# Python API

The CLI provides the copy-and-process workflow. Module-level sanitizers modify
their supplied files in place; callers own copying, errors, and publication.

## SQLite copy

```python
from pathlib import Path
from hygeia.sqlite_sanitizer import sanitize_database_generic
from hygeia.verifier import verify_sanitization

# Already contains a disposable copy of the source database.
work = Path("clean")
action = sanitize_database_generic(work / "data.db")
if action.get("error") or action.get("errors") or action.get("success") is False:
    raise RuntimeError("Sanitization incomplete; review the action record")
result = verify_sanitization(work)
if not result.performed or not result.passed or result.incomplete or result.scope:
    raise RuntimeError("Output did not pass full configured verification")
```

`hygeia.platform_handlers.sanitize_with_platform_detection(path)` applies
schema-aware handlers followed by generic processing. Neither function processes
all unrelated filesystem, text, and media artifacts in a directory.

Keep sanitizer action errors: a standalone verifier cannot reconstruct every
earlier failed write. The CLI adds failed actions to verification's incomplete list.

## Rule profiles

```python
from hygeia.compliance import get_compliance_profile, generate_compliance_report

profile = get_compliance_profile("hipaa")
action = sanitize_database_generic(
    work / "data.db",
    extra_columns=profile.extra_sensitive_columns,
    extra_tables=profile.extra_pii_tables,
)
result = verify_sanitization(work)
report = generate_compliance_report("hipaa", [action], result.passed)
```

Inspect action errors, verification, and the report's `identifiers_covered`,
`gaps`, and `limitations`. Coverage is not a compliance certificate.

`text_sanitizer.configure()` and `verifier.configure()` change module-level
process state. Avoid concurrent scopes in one process. Direct callers can provide
`sanitize_database_generic(..., registry=...)` an explicit pattern registry.
