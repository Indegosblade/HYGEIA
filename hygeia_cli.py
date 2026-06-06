#!/usr/bin/env python3
"""
HYGEIA — Forensic-Grade PII Sanitization Tool (Standalone CLI)

Platform-agnostic PII removal from filesystem dumps, databases, and
application data. iOS-aware with specialized rules, but works on any
platform: Chrome, Firefox, Android, Windows, macOS, Linux.

Usage:
    python hygeia_cli.py --input /path/to/dump --output /path/to/clean
    python hygeia_cli.py --input /path/to/dump --output /path/to/clean --optimize
    python hygeia_cli.py --input /path/to/dump --output /path/to/clean --dry-run
"""

import argparse
import json
import logging
import shutil
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from hygeia.scanner import FileScanner, FileAction, ScanResult
from hygeia.sqlite_sanitizer import (
    delete_database, sanitize_database, sanitize_knowledgec,
    sanitize_photos_sqlite, delete_wal_orphans, find_all_databases,
    sanitize_database_generic, is_sqlite_database,
)
from hygeia.plist_sanitizer import sanitize_plist
from hygeia.exif_stripper import strip_exif_directory, exiftool_available
from hygeia.text_sanitizer import sanitize_all_text_files
from hygeia.verifier import verify_sanitization
from hygeia.manifest import generate_manifest

log = logging.getLogger("hygeia")


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def copy_dump(input_path: Path, output_path: Path):
    """Copy dump to output directory for sanitization (preserves original)."""
    if output_path.exists():
        log.error(f"Output path already exists: {output_path}")
        sys.exit(1)
    log.info(f"Copying {input_path} → {output_path} ...")
    shutil.copytree(input_path, output_path, symlinks=True, dirs_exist_ok=False)
    log.info("Copy complete")


def execute_sanitization(scan_result: ScanResult, dump_path: Path, dry_run: bool = False) -> list[dict]:
    """Execute sanitization actions based on scan results."""
    actions = []

    for classification in scan_result.classifications:
        full_path = dump_path / classification.path

        if classification.action == FileAction.DELETE:
            if dry_run:
                actions.append({"action": "delete", "path": classification.path, "dry_run": True})
                continue

            if full_path.is_dir():
                shutil.rmtree(full_path, ignore_errors=True)
                actions.append({"action": "delete_directory", "path": classification.path, "reason": classification.reason})
            elif full_path.is_file():
                # Check if it's a database — needs WAL handling
                if full_path.suffix.lower() in (".db", ".sqlite", ".sqlitedb", ".storedata", ".plsql"):
                    result = delete_database(full_path)
                    actions.append(result)
                else:
                    full_path.unlink(missing_ok=True)
                    actions.append({"action": "delete", "path": classification.path, "reason": classification.reason})

        elif classification.action == FileAction.SELECTIVE_DB:
            if dry_run:
                actions.append({"action": "selective_db", "path": classification.path, "dry_run": True})
                continue

            path_lower = classification.path.lower()
            if "knowledgec.db" in path_lower:
                result = sanitize_knowledgec(full_path)
            elif "photos.sqlite" in path_lower:
                result = sanitize_photos_sqlite(full_path)
            else:
                # Generic selective — load rules and apply
                result = {"action": "selective_db", "path": classification.path, "note": "preserved (no specific rules)"}
            actions.append(result)

        elif classification.action == FileAction.PLIST_SANITIZE:
            if dry_run:
                actions.append({"action": "plist_sanitize", "path": classification.path, "dry_run": True})
                continue

            if full_path.exists():
                result = sanitize_plist(full_path)
                actions.append(result)

        elif classification.action == FileAction.EXIF_STRIP:
            if dry_run:
                actions.append({"action": "exif_strip", "path": classification.path, "dry_run": True})
                continue

            if full_path.exists() and exiftool_available():
                from hygeia.exif_stripper import strip_single_file
                strip_single_file(full_path)
                actions.append({"action": "exif_strip", "path": classification.path})

    # Clean up orphaned WAL files
    if not dry_run:
        orphans = delete_wal_orphans(dump_path)
        for o in orphans:
            actions.append({"action": "delete_orphan_wal", "path": str(o.relative_to(dump_path))})

    return actions


def delete_app_containers(dump_path: Path, scanner: FileScanner, jailbreak_info, dry_run: bool = False) -> list[dict]:
    """Delete third-party app containers, preserving jailbreak apps."""
    actions = []
    containers_path = dump_path / "private" / "var" / "mobile" / "Containers" / "Data" / "Application"
    if not containers_path.exists():
        return actions

    preserve_names = {"dopamine", "sileo", "newterm", "filza", "weightbufs"}

    for app_dir in containers_path.iterdir():
        if not app_dir.is_dir():
            continue

        # Check if this is a jailbreak app
        is_jb = False
        for item in app_dir.rglob("*"):
            if any(name in item.name.lower() for name in preserve_names):
                is_jb = True
                break

        if is_jb:
            actions.append({"action": "preserve", "path": str(app_dir.relative_to(dump_path)), "reason": "jailbreak app"})
            continue

        if dry_run:
            actions.append({"action": "delete_directory", "path": str(app_dir.relative_to(dump_path)), "dry_run": True})
        else:
            # Sanitize databases inside before deleting (WAL handling)
            for db in find_all_databases(app_dir):
                delete_database(db)
            shutil.rmtree(app_dir, ignore_errors=True)
            actions.append({"action": "delete_directory", "path": str(app_dir.relative_to(dump_path)), "reason": "third-party app"})

    return actions


def main():
    parser = argparse.ArgumentParser(
        description="HYGEIA — Forensic-Grade PII Sanitization Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python hygeia_cli.py --input ./data_dump --output ./data_clean"
    )
    parser.add_argument("--input", "-i", required=True, help="Path to filesystem dump or data directory")
    parser.add_argument("--output", "-o", required=True, help="Output path for sanitized copy")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Preview actions without executing")
    parser.add_argument("--optimize", action="store_true", help="Remove localizations and caches for smaller output")
    parser.add_argument("--skip-verify", action="store_true", help="Skip post-sanitization verification")
    parser.add_argument("--skip-exif", action="store_true", help="Skip EXIF stripping (if exiftool not available)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--manifest", "-m", help="Custom manifest output path")
    args = parser.parse_args()

    setup_logging(args.verbose)
    start_time = time.time()

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    if not input_path.exists():
        log.error(f"Input path does not exist: {input_path}")
        sys.exit(1)

    # Step 1: Copy dump
    print(f"=== HYGEIA Forensic-Grade PII Sanitization ===")
    print(f"Input:  {input_path}")
    print(f"Output: {output_path}")
    print(f"Mode:   {'DRY RUN' if args.dry_run else 'LIVE'}")
    print()

    if not args.dry_run:
        copy_dump(input_path, output_path)
        work_path = output_path
    else:
        work_path = input_path

    # Step 2: Scan and classify
    print("[1/6] Scanning filesystem...")
    scanner = FileScanner()
    scan_result = scanner.scan_dump(work_path)

    if scan_result.jailbreak and scan_result.jailbreak.detected:
        print(f"  Jailbreak detected: {scan_result.jailbreak.jailbreak_type}")
        print(f"  Preserved paths: {len(scan_result.jailbreak.preserve_paths)}")

    print(f"  Files: {scan_result.total_files}")
    print(f"  Delete: {scan_result.delete_count} ({scan_result.delete_size / 1024 / 1024:.0f} MB)")
    print(f"  Preserve: {scan_result.preserve_count}")
    print()

    # Step 3: Execute sanitization
    print("[2/6] Sanitizing databases...")
    all_actions = []

    # Detect if this is an iOS dump or generic data
    is_ios = (scan_result.jailbreak and scan_result.jailbreak.detected) or \
             any(c.reason.startswith("system:") for c in scan_result.classifications)

    if is_ios:
        # iOS-specific pipeline
        container_actions = delete_app_containers(
            work_path, scanner, scan_result.jailbreak, dry_run=args.dry_run
        )
        all_actions.extend(container_actions)

        file_actions = execute_sanitization(scan_result, work_path, dry_run=args.dry_run)
        all_actions.extend(file_actions)
    else:
        # Generic mode — scan ALL databases for PII regardless of platform
        print("  No iOS structure detected — running generic sanitization")
        databases = find_all_databases(work_path)
        print(f"  Found {len(databases)} SQLite databases")
        for db in databases:
            if args.dry_run:
                all_actions.append({"action": "generic_sanitize", "path": str(db.relative_to(work_path)), "dry_run": True})
            else:
                result = sanitize_database_generic(db)
                all_actions.append(result)
                if result.get("rows_redacted", 0) > 0:
                    print(f"    {db.name}: {result['rows_redacted']} rows redacted ({', '.join(result.get('pii_types_found', []))})")

        # Also sanitize plists if any exist (they're cross-platform)
        file_actions = execute_sanitization(scan_result, work_path, dry_run=args.dry_run)
        all_actions.extend(file_actions)

    # Step 3: Text file sanitization
    print("[3/6] Sanitizing text files...")
    text_actions = sanitize_all_text_files(work_path, dry_run=args.dry_run)
    all_actions.extend(text_actions)
    text_redacted = sum(1 for a in text_actions if a.get("keys_redacted", 0) > 0 or
                        a.get("lines_redacted", 0) > 0 or a.get("cells_redacted", 0) > 0 or
                        a.get("action") == "delete_shell_history")
    if text_redacted:
        print(f"  Text files sanitized: {text_redacted}")

    print(f"  Total actions: {len(all_actions)}")
    print()

    # Step 4: EXIF stripping
    if not args.skip_exif and not args.dry_run:
        print("[4/6] Stripping EXIF metadata...")
        if exiftool_available():
            exif_result = strip_exif_directory(work_path)
            all_actions.append(exif_result)
            print(f"  Images processed: {exif_result.get('files_stripped', 0)}")
        else:
            print("  WARNING: exiftool not installed, skipping EXIF stripping")
            print("  Install: pip install exiftool  OR  apt install libimage-exiftool-perl")
    else:
        print("[4/6] EXIF stripping: skipped")
    print()

    # Step 5: Verification
    if not args.skip_verify and not args.dry_run:
        print("[5/6] Verifying sanitization...")
        verification = verify_sanitization(work_path)
        if verification.passed:
            print("  PASSED — zero PII findings")
        else:
            print(f"  FAILED — {verification.total_findings} findings:")
            if verification.pii_matches:
                print(f"    PII regex matches: {len(verification.pii_matches)}")
            if verification.sqlite_freelist_findings:
                print(f"    SQLite freelist: {len(verification.sqlite_freelist_findings)}")
            if verification.exif_failures:
                print(f"    EXIF remaining: {len(verification.exif_failures)}")
    else:
        print("[5/6] Verification: skipped")
        from hygeia.verifier import VerificationResult
        verification = VerificationResult()
    print()

    # Step 6: Generate manifest
    print("[6/6] Generating manifest...")
    elapsed = time.time() - start_time
    manifest_path = Path(args.manifest) if args.manifest else (work_path.parent / "deletion_manifest.json")

    manifest = generate_manifest(
        dump_path=work_path,
        scan_result=scan_result,
        sanitization_actions=all_actions,
        verification_result=verification,
        elapsed_seconds=elapsed,
        output_path=manifest_path if not args.dry_run else None,
    )

    print(f"  Manifest: {manifest_path}")
    print()

    # Summary
    print("=== Summary ===")
    print(f"Files scanned:      {manifest['summary']['total_files_scanned']}")
    print(f"Files deleted:      {manifest['summary']['files_deleted']}")
    print(f"Databases sanitized:{manifest['summary']['databases_sanitized']}")
    print(f"Plists sanitized:   {manifest['summary']['plists_sanitized']}")
    print(f"Space freed:        {manifest['summary']['bytes_removed'] / 1024 / 1024:.0f} MB")
    print(f"Verification:       {'PASSED' if verification.passed else 'FAILED'}")
    print(f"Elapsed:            {elapsed:.1f}s")
    print()

    if not verification.passed and not args.dry_run:
        print("WARNING: Verification FAILED. Review manifest for residual PII.")
        sys.exit(2)

    if args.dry_run:
        print("DRY RUN complete. No files were modified.")
        # Print action preview
        action_counts = {}
        for a in all_actions:
            action_type = a.get("action", "unknown")
            action_counts[action_type] = action_counts.get(action_type, 0) + 1
        for action_type, count in sorted(action_counts.items()):
            print(f"  Would {action_type}: {count}")


if __name__ == "__main__":
    main()
