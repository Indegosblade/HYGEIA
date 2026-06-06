"""
HYGEIA Text Sanitizer — PII redaction for non-database file formats.

Handles JSON configs, log files, shell history, and CSV/TSV.
Reuses the same PII regex patterns as the SQLite sanitizer.
"""

import csv
import io
import json
import logging
import re
from pathlib import Path

log = logging.getLogger("hygeia.text")

PII_PATTERNS = {
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "phone_us": re.compile(r'\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "phone_intl": re.compile(r'\+(?:44|49|33|91|81|61|86|55|7|34|39|82|31|46|47|48|90)\s?\d[\d\s\-]{6,14}\d\b'),
    "ssn": re.compile(r'\b(?!000|666|9\d{2})[0-8]\d{2}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
    "ip_v4": re.compile(r'\b(?!(?:0|127|255)\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    "ip_v6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    "iban": re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'),
    "mac_addr": re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'),
}

SENSITIVE_JSON_KEYS = {
    "email", "username", "user_name", "login", "password", "passwd",
    "phone", "phone_number", "address", "street", "city", "zip",
    "first_name", "last_name", "full_name", "name", "display_name",
    "firstname", "lastname", "fullname", "nickname",
    "account", "account_name", "credential", "token", "auth",
    "secret", "api_key", "apikey", "cookie", "session",
    "access_token", "refresh_token", "id_token", "bearer",
    "oauth", "oauth_token", "client_secret",
    "ssn", "social_security", "date_of_birth", "dob",
    "card_number", "card_holder", "cardholder",
    "google.services.username", "profile.name",
}

SAFE_JSON_KEYS = {
    "version", "build", "type", "id", "key", "format",
    "schema", "encoding", "platform", "os", "arch",
}

SHELL_HISTORY_FILES = {
    ".bash_history", ".zsh_history", ".python_history",
    ".psql_history", ".mysql_history", ".node_repl_history",
    ".irb_history", ".lesshst", ".sqlite_history",
}

LOG_EXTENSIONS = {".log", ".txt", ".ips", ".crash"}


def _is_sensitive_json_key(key: str) -> bool:
    key_lower = key.lower()
    if key_lower in SAFE_JSON_KEYS:
        return False
    return key_lower in SENSITIVE_JSON_KEYS or any(
        s in key_lower for s in ("password", "token", "secret", "credential", "auth")
    )


def _redact_pii_in_string(text: str) -> tuple[str, list[str]]:
    """Apply all PII patterns to a string, return (redacted_text, types_found)."""
    found = []
    for name, pattern in PII_PATTERNS.items():
        if pattern.search(text):
            text = pattern.sub(f'[REDACTED_{name.upper()}]', text)
            found.append(name)
    return text, found


def _redact_json_recursive(obj, redacted_keys: list):
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            if _is_sensitive_json_key(key):
                if isinstance(obj[key], str) and obj[key]:
                    obj[key] = "[REDACTED]"
                    redacted_keys.append(key)
                elif isinstance(obj[key], (int, float)) and obj[key]:
                    obj[key] = 0
                    redacted_keys.append(key)
                elif isinstance(obj[key], (dict, list)):
                    _redact_json_recursive(obj[key], redacted_keys)
            elif isinstance(obj[key], str):
                redacted, _ = _redact_pii_in_string(obj[key])
                if redacted != obj[key]:
                    obj[key] = redacted
                    redacted_keys.append(key)
            else:
                _redact_json_recursive(obj[key], redacted_keys)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str):
                redacted, _ = _redact_pii_in_string(item)
                if redacted != item:
                    obj[i] = redacted
            else:
                _redact_json_recursive(item, redacted_keys)


def sanitize_json(filepath: Path) -> dict:
    result = {
        "action": "json_sanitize",
        "path": str(filepath),
        "keys_redacted": 0,
    }
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
        redacted_keys = []
        _redact_json_recursive(data, redacted_keys)
        if redacted_keys:
            filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            result["keys_redacted"] = len(redacted_keys)
            log.info(f"JSON sanitized {filepath.name}: {len(redacted_keys)} keys redacted")
    except (json.JSONDecodeError, OSError) as e:
        result["error"] = str(e)
    return result


def sanitize_log_file(filepath: Path) -> dict:
    result = {
        "action": "log_sanitize",
        "path": str(filepath),
        "lines_redacted": 0,
        "pii_types": [],
    }
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines(keepends=True)
        new_lines = []
        all_types = set()
        for line in lines:
            redacted, types = _redact_pii_in_string(line)
            if types:
                result["lines_redacted"] += 1
                all_types.update(types)
            new_lines.append(redacted)
        if result["lines_redacted"] > 0:
            filepath.write_text("".join(new_lines), encoding="utf-8")
            result["pii_types"] = sorted(all_types)
            log.info(f"Log sanitized {filepath.name}: {result['lines_redacted']} lines")
    except OSError as e:
        result["error"] = str(e)
    return result


def sanitize_csv(filepath: Path) -> dict:
    result = {
        "action": "csv_sanitize",
        "path": str(filepath),
        "cells_redacted": 0,
    }
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        dialect = csv.Sniffer().sniff(content[:4096])
        reader = csv.reader(io.StringIO(content), dialect)
        rows = list(reader)
        if not rows:
            return result

        headers = [h.lower().strip() for h in rows[0]]
        sensitive_cols = {i for i, h in enumerate(headers) if h in SENSITIVE_JSON_KEYS}

        output = io.StringIO()
        writer = csv.writer(output, dialect)
        for row_idx, row in enumerate(rows):
            new_row = list(row)
            for col_idx, cell in enumerate(row):
                if row_idx == 0:
                    continue
                if col_idx in sensitive_cols:
                    if cell.strip():
                        new_row[col_idx] = "[REDACTED]"
                        result["cells_redacted"] += 1
                elif cell:
                    redacted, types = _redact_pii_in_string(cell)
                    if types:
                        new_row[col_idx] = redacted
                        result["cells_redacted"] += 1
            writer.writerow(new_row)

        if result["cells_redacted"] > 0:
            filepath.write_text(output.getvalue(), encoding="utf-8")
            log.info(f"CSV sanitized {filepath.name}: {result['cells_redacted']} cells")
    except (csv.Error, OSError) as e:
        result["error"] = str(e)
    return result


def delete_shell_history(filepath: Path) -> dict:
    result = {
        "action": "delete_shell_history",
        "path": str(filepath),
    }
    if filepath.name.lower() in SHELL_HISTORY_FILES:
        filepath.unlink(missing_ok=True)
        log.info(f"Deleted shell history: {filepath.name}")
    return result


def find_sanitizable_text_files(dump_path: Path) -> dict[str, list[Path]]:
    """Discover text files to sanitize, grouped by type."""
    found = {"json": [], "log": [], "csv": [], "history": []}
    for f in dump_path.rglob("*"):
        if not f.is_file():
            continue
        name_lower = f.name.lower()
        suffix = f.suffix.lower()
        if name_lower in SHELL_HISTORY_FILES:
            found["history"].append(f)
        elif suffix == ".json":
            found["json"].append(f)
        elif suffix in LOG_EXTENSIONS:
            found["log"].append(f)
        elif suffix in (".csv", ".tsv"):
            found["csv"].append(f)
    return found


def sanitize_all_text_files(dump_path: Path, dry_run: bool = False) -> list[dict]:
    """Sanitize all discoverable text files in a dump."""
    actions = []
    files = find_sanitizable_text_files(dump_path)

    for hist in files["history"]:
        if dry_run:
            actions.append({"action": "delete_shell_history", "path": str(hist), "dry_run": True})
        else:
            actions.append(delete_shell_history(hist))

    for jf in files["json"]:
        if jf.stat().st_size > 50 * 1024 * 1024:
            continue
        if dry_run:
            actions.append({"action": "json_sanitize", "path": str(jf), "dry_run": True})
        else:
            actions.append(sanitize_json(jf))

    for lf in files["log"]:
        if lf.stat().st_size > 10 * 1024 * 1024:
            continue
        if dry_run:
            actions.append({"action": "log_sanitize", "path": str(lf), "dry_run": True})
        else:
            actions.append(sanitize_log_file(lf))

    for cf in files["csv"]:
        if cf.stat().st_size > 50 * 1024 * 1024:
            continue
        if dry_run:
            actions.append({"action": "csv_sanitize", "path": str(cf), "dry_run": True})
        else:
            actions.append(sanitize_csv(cf))

    log.info(f"Text sanitization: {len(files['history'])} history, "
             f"{len(files['json'])} JSON, {len(files['log'])} log, {len(files['csv'])} CSV")
    return actions
