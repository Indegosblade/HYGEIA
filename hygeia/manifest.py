"""
HYGEIA Manifest Generator -- JSON audit trail for sanitization runs.

Produces compliance-ready manifests documenting every action taken,
files removed/preserved/sanitized, and verification results.
Aligned with NIST SP 800-88, HIPAA Safe Harbor, and GDPR.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("hygeia.manifest")


def _detect_ios_version(dump_path: Path) -> str:
    """Detect iOS version from SystemVersion.plist."""
    sv_path = dump_path / "System" / "Library" / "CoreServices" / "SystemVersion.plist"
    if not sv_path.exists():
        return "unknown"
    try:
        import plistlib
        with open(sv_path, "rb") as f:
            data = plistlib.load(f)
        return data.get("ProductVersion", "unknown")
    except Exception:
        return "unknown"


def generate_manifest(
    dump_path: Path,
    scan_result,
    sanitization_actions: list[dict],
    verification_result,
    elapsed_seconds: float = 0,
    output_path: Path | None = None,
) -> dict:
    """
    Generate JSON audit manifest.

    WARNING: This manifest may contain file paths that reveal personal data existed.
    It should be treated as LOCAL ONLY and never committed to git.
    """
    from . import __version__

    manifest = {
        "tool": "HYGEIA",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ios_version": _detect_ios_version(dump_path),
        "dump_path": str(dump_path),
        "elapsed_seconds": round(elapsed_seconds, 1),
        "summary": {
            "total_files_scanned": scan_result.total_files,
            "total_size_bytes": scan_result.total_size,
            "files_deleted": sum(1 for a in sanitization_actions if a.get("action") in ("delete", "delete_directory", "delete_database")),
            "files_preserved": scan_result.preserve_count,
            "databases_sanitized": sum(1 for a in sanitization_actions if a.get("action") in ("sanitize_database", "selective_db", "generic_sanitize")),
            "plists_sanitized": sum(1 for a in sanitization_actions if a.get("action") == "plist_sanitize"),
            "exif_stripped": sum(1 for a in sanitization_actions if a.get("action") == "exif_strip"),
            "bytes_removed": scan_result.delete_size,
            "files_with_hashes": sum(
                1 for a in sanitization_actions
                if "hash_before" in a or "hash_after" in a
            ),
        },
        "jailbreak": {
            "detected": scan_result.jailbreak.detected if scan_result.jailbreak else False,
            "type": scan_result.jailbreak.jailbreak_type if scan_result.jailbreak else "",
            "preserved_paths_count": len(scan_result.jailbreak.preserve_paths) if scan_result.jailbreak else 0,
        },
        "verification": {
            "passed": verification_result.passed,
            "pii_matches": len(verification_result.pii_matches),
            "sqlite_freelist_findings": len(verification_result.sqlite_freelist_findings),
            "exif_failures": len(verification_result.exif_failures),
            "databases_inspected": verification_result.databases_inspected,
        },
        "actions": sanitization_actions,
    }

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(manifest, f, indent=2, default=str)
        log.info(f"Manifest written to {output_path}")

    return manifest
