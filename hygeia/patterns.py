"""
Shared registry for supported regex and keyword-gated PII detectors.

Loads rules/pii_patterns.json for text, SQLite, and verification consumers.
CLI filters are --only and --skip-patterns; they do not select pipeline stages.

Usage:
    from hygeia.patterns import load_patterns
    registry = load_patterns(only=["identity", "financial"])
    registry = load_patterns(skip=["crypto", "credit_card"])

Category-only selection retains global keyword-gated context detectors.
A mixed only list limits those detectors to its individual names. Individual
exclusions can remove them without changing category-exclusion behavior.
"""

import json
import re
import logging
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("hygeia.patterns")

_RULES_DIR = Path(__file__).parent / "rules"
_PATTERNS_FILE = _RULES_DIR / "pii_patterns.json"

_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}


@dataclass
class PatternRegistry:
    """Compiled pattern set ready for scanning."""

    regex_patterns: dict[str, re.Pattern] = field(default_factory=dict)
    context_patterns: dict[str, tuple[re.Pattern, set[str], int]] = field(default_factory=dict)
    sensitive_columns: set[str] = field(default_factory=set)
    sensitive_json_keys: set[str] = field(default_factory=set)
    pii_tables: set[str] = field(default_factory=set)
    active_categories: set[str] = field(default_factory=set)
    pattern_descriptions: dict[str, str] = field(default_factory=dict)


def _compile_flags(flag_list: list[str]) -> int:
    result = 0
    for f in flag_list:
        result |= _FLAG_MAP.get(f, 0)
    return result


def _load_raw() -> dict:
    with open(_PATTERNS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _resolve_categories(raw: dict, only: list[str] | None, skip: list[str] | None) -> set[str]:
    all_cats = set(raw["categories"].keys())

    if only:
        resolved = set()
        for item in only:
            if item in all_cats:
                resolved.add(item)
            else:
                for cat, cat_data in raw["categories"].items():
                    if item in cat_data["patterns"]:
                        resolved.add(cat)
        return resolved

    if skip:
        return all_cats - set(skip)

    return all_cats


def load_patterns(
    only: list[str] | None = None,
    skip: list[str] | None = None,
) -> PatternRegistry:
    """
    Compile the JSON registry using known category or individual pattern names.

    only includes selected category patterns or individual detectors; skip excludes
    selected categories and individual detectors. Global context detectors remain
    under category-only selection/exclusion unless individually excluded. A mixed
    only list limits global context detectors to its explicitly named individuals.
    Sensitive-key/table rules have separate loading policy; filtering does not
    guarantee unrelated keys or processing stages remain unchanged.

    Raises ValueError for unknown/empty names or simultaneous nonempty only/skip.
    Omitted or empty lists use the default registry policy.
    """
    raw = _load_raw()
    if only and skip:
        raise ValueError("Use either --only or --skip-patterns, not both")
    category_names = set(raw["categories"])
    pattern_names = {
        name for category in raw["categories"].values()
        for name in category["patterns"]
    } | {name for name in raw.get("context_patterns", {}) if not name.startswith("_")}
    unknown = (set(only or []) | set(skip or [])) - category_names - pattern_names
    if unknown:
        names = ", ".join(repr(name) for name in sorted(unknown))
        raise ValueError(f"Unknown pattern selector(s): {names}. Use --list-patterns for accepted names")
    excluded_patterns = set(skip or []) & pattern_names
    registry = PatternRegistry()

    # Determine which individual patterns were explicitly requested
    individual_only = set()
    if only:
        all_cats = set(raw["categories"].keys())
        individual_only = {item for item in only if item not in all_cats}

    active_cats = _resolve_categories(raw, only, skip)
    registry.active_categories = active_cats

    # Compile category patterns
    for cat_name, cat_data in raw["categories"].items():
        if cat_name not in active_cats:
            continue
        for pat_name, pat_def in cat_data["patterns"].items():
            if pat_name in excluded_patterns:
                continue
            if individual_only and pat_name not in individual_only and cat_name not in (only or []):
                continue
            flags = _compile_flags(pat_def.get("flags", []))
            try:
                compiled = re.compile(pat_def["regex"], flags)
                # If pattern has context_keywords, treat as context pattern
                if "context_keywords" in pat_def:
                    registry.context_patterns[pat_name] = (
                        compiled,
                        set(pat_def["context_keywords"]),
                        pat_def.get("context_window", 120),
                    )
                else:
                    registry.regex_patterns[pat_name] = compiled
                registry.pattern_descriptions[pat_name] = pat_def.get("description", "")
            except re.error as e:
                log.warning(f"Failed to compile pattern '{pat_name}': {e}")

    # Compile context patterns (always loaded — they're self-gating via keywords)
    for pat_name, pat_def in raw.get("context_patterns", {}).items():
        if pat_name.startswith("_"):
            continue
        if pat_name in excluded_patterns:
            continue
        if individual_only and pat_name not in individual_only:
            continue
        flags = _compile_flags(pat_def.get("flags", []))
        try:
            compiled = re.compile(pat_def["regex"], flags)
            registry.context_patterns[pat_name] = (
                compiled,
                set(pat_def["keywords"]),
                pat_def.get("window", 120),
            )
            registry.pattern_descriptions[pat_name] = pat_def.get("description", "")
        except re.error as e:
            log.warning(f"Failed to compile context pattern '{pat_name}': {e}")

    # Load sensitive columns (union of active categories)
    columns_data = raw.get("sensitive_columns", {})
    for cat_name, cols in columns_data.items():
        if cat_name.startswith("_"):
            continue
        if cat_name in active_cats or not only:
            registry.sensitive_columns.update(cols)

    # Load sensitive JSON keys
    json_keys_data = raw.get("sensitive_json_keys", {})
    for cat_name, keys in json_keys_data.items():
        if cat_name.startswith("_"):
            continue
        if cat_name in active_cats or not only:
            registry.sensitive_json_keys.update(keys)

    # Load PII tables (union of active categories)
    tables_data = raw.get("pii_tables", {})
    for cat_name, tables in tables_data.items():
        if cat_name.startswith("_"):
            continue
        if cat_name in active_cats or not only:
            registry.pii_tables.update(tables)

    log.debug(
        f"Loaded {len(registry.regex_patterns)} patterns + "
        f"{len(registry.context_patterns)} context patterns "
        f"from categories: {sorted(active_cats)}"
    )
    return registry


def list_available() -> dict[str, list[str]]:
    """Return all available categories and their pattern names."""
    raw = _load_raw()
    result = {}
    for cat_name, cat_data in raw["categories"].items():
        result[cat_name] = list(cat_data["patterns"].keys())
    result["_context"] = [
        k for k in raw.get("context_patterns", {}).keys()
        if not k.startswith("_")
    ]
    return result


# Module-level singleton — compiled once, shared by all consumers.
_default_registry: PatternRegistry | None = None


def get_default_registry() -> PatternRegistry:
    """Return the shared default registry (all patterns, compiled once)."""
    global _default_registry
    if _default_registry is None:
        _default_registry = load_patterns()
    return _default_registry
