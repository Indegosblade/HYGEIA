"""
HYGEIA Text Sanitizer — PII redaction for non-database file formats.

Handles JSON configs, log files, shell history, and CSV/TSV.
Patterns loaded from the central registry (rules/pii_patterns.json).
"""

import csv
import hashlib
import io
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .patterns import load_patterns, PatternRegistry

log = logging.getLogger("hygeia.text")

_registry: PatternRegistry | None = None


def _get_registry() -> PatternRegistry:
    global _registry
    if _registry is None:
        _registry = load_patterns()
    return _registry


def configure(only: list[str] | None = None, skip: list[str] | None = None):
    """Reconfigure the text sanitizer with specific pattern categories."""
    global _registry
    _registry = load_patterns(only=only, skip=skip)


def _sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

SAFE_JSON_KEYS = {
    "version", "build", "type", "id", "key", "format",
    "schema", "encoding", "platform", "os", "arch",
}

_SENSITIVE_KEY_SUBSTRINGS = ("password", "token", "secret", "credential", "auth")

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
    reg = _get_registry()
    return key_lower in reg.sensitive_json_keys or any(
        s in key_lower for s in _SENSITIVE_KEY_SUBSTRINGS
    )


def _redact_pii_in_string(text: str) -> tuple[str, list[str]]:
    """Apply all PII patterns to a string, return (redacted_text, types_found)."""
    reg = _get_registry()
    found = []
    for name, pattern in reg.regex_patterns.items():
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
        result["hash_before"] = _sha256(filepath)
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
        redacted_keys = []
        _redact_json_recursive(data, redacted_keys)
        if redacted_keys:
            filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            result["keys_redacted"] = len(redacted_keys)
            log.info(f"JSON sanitized {filepath.name}: {len(redacted_keys)} keys redacted")
        result["hash_after"] = _sha256(filepath)
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
        result["hash_before"] = _sha256(filepath)
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
        result["hash_after"] = _sha256(filepath)
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
        result["hash_before"] = _sha256(filepath)
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        dialect = csv.Sniffer().sniff(content[:4096])
        reader = csv.reader(io.StringIO(content), dialect)
        rows = list(reader)
        if not rows:
            result["hash_after"] = _sha256(filepath)
            return result

        headers = [h.lower().strip() for h in rows[0]]
        reg = _get_registry()
        sensitive_cols = {i for i, h in enumerate(headers) if h in reg.sensitive_json_keys}

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
        result["hash_after"] = _sha256(filepath)
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


def sanitize_all_text_files(dump_path: Path, dry_run: bool = False,
                             workers: int = 1) -> list[dict]:
    """Sanitize all discoverable text files in a dump.

    Args:
        dump_path: Root directory to sanitize.
        dry_run: If True, preview actions without executing.
        workers: Number of parallel workers.  1 = sequential (default).
                 0 = auto-detect (os.cpu_count()).  >1 = explicit pool size.
    """
    resolved_workers = workers if workers != 0 else (os.cpu_count() or 1)

    actions = []
    files = find_sanitizable_text_files(dump_path)

    # Shell history is always sequential (fast + rare)
    for hist in files["history"]:
        if dry_run:
            actions.append({"action": "delete_shell_history", "path": str(hist), "dry_run": True})
        else:
            actions.append(delete_shell_history(hist))

    # Build workload lists for the three parallelisable types
    json_files = [jf for jf in files["json"] if jf.stat().st_size <= 50 * 1024 * 1024]
    log_files = [lf for lf in files["log"] if lf.stat().st_size <= 10 * 1024 * 1024]
    csv_files = [cf for cf in files["csv"] if cf.stat().st_size <= 50 * 1024 * 1024]

    if dry_run:
        for jf in json_files:
            actions.append({"action": "json_sanitize", "path": str(jf), "dry_run": True})
        for lf in log_files:
            actions.append({"action": "log_sanitize", "path": str(lf), "dry_run": True})
        for cf in csv_files:
            actions.append({"action": "csv_sanitize", "path": str(cf), "dry_run": True})
    elif resolved_workers > 1:
        # Parallel: fan out all three types into one pool
        all_tasks: list[tuple] = (
            [(sanitize_json, f) for f in json_files] +
            [(sanitize_log_file, f) for f in log_files] +
            [(sanitize_csv, f) for f in csv_files]
        )
        total = len(all_tasks)
        results: list[dict] = [None] * total  # type: ignore[list-item]
        futures_map = {}
        with ThreadPoolExecutor(max_workers=resolved_workers) as executor:
            for idx, (fn, fp) in enumerate(all_tasks):
                futures_map[executor.submit(fn, fp)] = idx
            completed = 0
            for future in as_completed(futures_map):
                idx = futures_map[future]
                completed += 1
                result = future.result()
                results[idx] = result
                _, fp = all_tasks[idx]
                log.info(f"Sanitizing text file {completed}/{total}: {fp.name}")
        actions.extend(results)
    else:
        # Sequential
        total_json = len(json_files)
        for i, jf in enumerate(json_files):
            log.info(f"Sanitizing JSON file {i + 1}/{total_json}: {jf.name}")
            actions.append(sanitize_json(jf))

        total_log = len(log_files)
        for i, lf in enumerate(log_files):
            log.info(f"Sanitizing log file {i + 1}/{total_log}: {lf.name}")
            actions.append(sanitize_log_file(lf))

        total_csv = len(csv_files)
        for i, cf in enumerate(csv_files):
            log.info(f"Sanitizing CSV file {i + 1}/{total_csv}: {cf.name}")
            actions.append(sanitize_csv(cf))

    log.info(f"Text sanitization: {len(files['history'])} history, "
             f"{len(json_files)} JSON, {len(log_files)} log, {len(csv_files)} CSV")
    return actions
