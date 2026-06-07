#!/usr/bin/env python3
"""
HYGEIA CLI — Forensic-Grade PII Sanitization

Generic-first pipeline. Platform-specific rules (iOS, Chrome, Firefox,
Android, Windows, macOS) activate automatically based on detected content.
"""

import argparse
import logging
import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .scanner import FileScanner, FileAction, ScanResult
from .sqlite_sanitizer import (
    delete_database, sanitize_knowledgec,
    sanitize_photos_sqlite, delete_wal_orphans, find_all_databases,
)
from .platform_handlers import sanitize_with_platform_detection
from .plist_sanitizer import sanitize_plist
from .exif_stripper import strip_exif_directory, find_exiftool
from .pdf_stripper import strip_pdf_directory
from .office_stripper import strip_office_directory
from .text_sanitizer import sanitize_all_text_files
from .filesystem_sanitizer import sanitize_filesystem
from .compliance import get_compliance_profile, generate_compliance_report
from .verifier import verify_sanitization
from .manifest import generate_manifest
from .forensic_cleaner import forensic_clean_all

log = logging.getLogger("hygeia")


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def copy_dump(input_path: Path, output_path: Path):
    if output_path.exists():
        log.error(f"Output path already exists: {output_path}")
        sys.exit(1)
    log.info(f"Copying {input_path} -> {output_path} ...")
    shutil.copytree(input_path, output_path, symlinks=True, dirs_exist_ok=False)
    log.info("Copy complete")


def _resolve_workers(workers: int) -> int:
    """Resolve worker count: 0 means auto-detect (cpu_count), 1 means sequential."""
    if workers == 0:
        return os.cpu_count() or 1
    return max(1, workers)


def sanitize_databases(work_path: Path, scan_result: ScanResult, compliance, dry_run: bool,
                       workers: int = 1) -> list[dict]:
    actions = []

    is_ios = (scan_result.jailbreak and scan_result.jailbreak.detected) or \
             any(c.reason.startswith("system:") for c in scan_result.classifications)

    if is_ios:
        containers_path = work_path / "private" / "var" / "mobile" / "Containers" / "Data" / "Application"
        if containers_path.exists():
            preserve_names = {"dopamine", "sileo", "newterm", "filza", "weightbufs"}
            for app_dir in containers_path.iterdir():
                if not app_dir.is_dir():
                    continue
                is_jb = any(any(name in item.name.lower() for name in preserve_names) for item in app_dir.rglob("*"))
                if is_jb:
                    actions.append({"action": "preserve", "path": str(app_dir.relative_to(work_path)), "reason": "jailbreak app"})
                    continue
                if dry_run:
                    actions.append({"action": "delete_directory", "path": str(app_dir.relative_to(work_path)), "dry_run": True})
                else:
                    for db in find_all_databases(app_dir):
                        delete_database(db)
                    shutil.rmtree(app_dir, ignore_errors=True)
                    actions.append({"action": "delete_directory", "path": str(app_dir.relative_to(work_path)), "reason": "third-party app"})

        for classification in scan_result.classifications:
            full_path = work_path / classification.path
            if classification.action == FileAction.DELETE:
                if dry_run:
                    actions.append({"action": "delete", "path": classification.path, "dry_run": True})
                elif full_path.is_dir():
                    shutil.rmtree(full_path, ignore_errors=True)
                    actions.append({"action": "delete_directory", "path": classification.path, "reason": classification.reason})
                elif full_path.is_file():
                    if full_path.suffix.lower() in (".db", ".sqlite", ".sqlitedb", ".storedata", ".plsql"):
                        actions.append(delete_database(full_path))
                    else:
                        full_path.unlink(missing_ok=True)
                        actions.append({"action": "delete", "path": classification.path, "reason": classification.reason})
            elif classification.action == FileAction.SELECTIVE_DB:
                if dry_run:
                    actions.append({"action": "selective_db", "path": classification.path, "dry_run": True})
                else:
                    path_lower = classification.path.lower()
                    if "knowledgec.db" in path_lower:
                        actions.append(sanitize_knowledgec(full_path))
                    elif "photos.sqlite" in path_lower:
                        actions.append(sanitize_photos_sqlite(full_path))
                    else:
                        actions.append({"action": "selective_db", "path": classification.path, "note": "preserved"})
            elif classification.action == FileAction.PLIST_SANITIZE:
                if dry_run:
                    actions.append({"action": "plist_sanitize", "path": classification.path, "dry_run": True})
                elif full_path.exists():
                    actions.append(sanitize_plist(full_path))

    # Platform-detected + generic database scan -- runs on ALL databases.
    # sanitize_with_platform_detection auto-detects schema, runs a surgical
    # platform handler if recognised, then falls back to the generic scanner
    # as a residual sweep.  Unrecognised databases get only the generic scan.
    databases = find_all_databases(work_path)
    extra_cols = compliance.extra_sensitive_columns if compliance else None
    extra_tbls = compliance.extra_pii_tables if compliance else None
    total_dbs = len(databases)

    if dry_run:
        for db in databases:
            actions.append({"action": "generic_sanitize", "path": str(db.relative_to(work_path)), "dry_run": True})
    elif workers > 1:
        # Parallel database sanitization
        db_results = [None] * total_dbs
        futures_map = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for idx, db in enumerate(databases):
                future = executor.submit(sanitize_with_platform_detection, db,
                                         extra_cols, extra_tbls)
                futures_map[future] = idx
            completed = 0
            for future in as_completed(futures_map):
                idx = futures_map[future]
                completed += 1
                result = future.result()
                db_results[idx] = result
                log.info(f"Sanitizing database {completed}/{total_dbs}: {databases[idx].name}")
                rows = result.get("rows_deleted", 0) + result.get("rows_redacted", 0)
                if rows > 0:
                    platform = result.get("platform", "generic")
                    print(f"    {databases[idx].name} [{platform}]: {rows} rows sanitized "
                          f"({', '.join(result.get('pii_types_found', []))})")
        actions.extend(db_results)
    else:
        # Sequential database sanitization
        for i, db in enumerate(databases):
            log.info(f"Sanitizing database {i + 1}/{total_dbs}: {db.name}")
            result = sanitize_with_platform_detection(db, extra_cols, extra_tbls)
            actions.append(result)
            rows = result.get("rows_deleted", 0) + result.get("rows_redacted", 0)
            if rows > 0:
                platform = result.get("platform", "generic")
                print(f"    {db.name} [{platform}]: {rows} rows sanitized "
                      f"({', '.join(result.get('pii_types_found', []))})")

    if not dry_run:
        orphans = delete_wal_orphans(work_path)
        for o in orphans:
            actions.append({"action": "delete_orphan_wal", "path": str(o.relative_to(work_path))})

    # Universal plist scan — runs on ALL .plist files regardless of platform/scanner classification.
    # The iOS scanner-based path above only catches paths matching plist_patterns.json sanitize_paths
    # (e.g. /mobile/Library/Preferences/). Flat or non-iOS dumps miss this entirely.
    # Track paths already handled by the scanner-based pass to avoid double-processing.
    already_sanitized = {
        str(work_path / c.path)
        for c in scan_result.classifications
        if c.action == FileAction.PLIST_SANITIZE
    }
    all_plists = [p for p in work_path.rglob("*.plist") if p.is_file() and str(p) not in already_sanitized]
    total_plists = len(all_plists)
    if total_plists > 0:
        log.info(f"Universal plist scan: {total_plists} plist files")
        if dry_run:
            for plist in all_plists:
                actions.append({"action": "plist_sanitize", "path": str(plist.relative_to(work_path)), "dry_run": True})
        elif workers > 1:
            plist_results = [None] * total_plists
            futures_map = {}
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for idx, plist in enumerate(all_plists):
                    future = executor.submit(sanitize_plist, plist)
                    futures_map[future] = idx
                completed = 0
                for future in as_completed(futures_map):
                    idx = futures_map[future]
                    completed += 1
                    plist_results[idx] = future.result()
                    log.debug(f"Plist scan {completed}/{total_plists}: {all_plists[idx].name}")
            actions.extend(r for r in plist_results if r is not None)
        else:
            for i, plist in enumerate(all_plists):
                log.debug(f"Plist scan {i + 1}/{total_plists}: {plist.name}")
                actions.append(sanitize_plist(plist))

    return actions


def main():
    parser = argparse.ArgumentParser(
        description="HYGEIA — Forensic-Grade PII Sanitization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: hygeia --input ./data --output ./clean"
    )
    parser.add_argument("--input", "-i", required=True, help="Source data directory")
    parser.add_argument("--output", "-o", required=True, help="Destination for sanitized copy")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Preview actions without executing")
    parser.add_argument("--compliance", choices=["hipaa", "gdpr", "ccpa", "all"],
                        help="Compliance mode: hipaa, gdpr, ccpa, or all")
    parser.add_argument("--normalize-timestamps", action="store_true",
                        help="Set all file timestamps to epoch (anti-forensic)")
    parser.add_argument("--skip-verify", action="store_true", help="Skip post-sanitization verification")
    parser.add_argument("--skip-exif", action="store_true", help="Skip EXIF metadata stripping")
    parser.add_argument("--skip-forensic", action="store_true", help="Skip anti-forensic hardening (LevelDB, caches, swap, timestamps)")
    parser.add_argument("--only", type=str, default=None,
                        help="Only run specific pattern categories or individual patterns (comma-separated). "
                             "Categories: identity, location, financial, credentials, crypto, healthcare, vehicle. "
                             "Example: --only exif  or  --only vin,credit_card  or  --only financial,credentials")
    parser.add_argument("--skip-patterns", type=str, default=None,
                        help="Skip specific pattern categories (comma-separated). "
                             "Example: --skip-patterns crypto,vehicle")
    parser.add_argument("--list-patterns", action="store_true",
                        help="List all available pattern categories and exit")
    parser.add_argument("--optimize", action="store_true", help="Remove localizations and caches")
    parser.add_argument("--manifest", "-m", help="Custom path for audit manifest")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument(
        "--workers", "-w", type=int, default=1,
        metavar="N",
        help=(
            "Number of parallel workers for independent sanitization tasks. "
            "1 = sequential (default). 0 = auto-detect (os.cpu_count()). "
            ">1 = explicit thread pool size."
        ),
    )
    args = parser.parse_args()

    # --list-patterns: show available categories and exit
    if args.list_patterns:
        from .patterns import list_available
        available = list_available()
        print("Available PII pattern categories:\n")
        for cat, patterns in available.items():
            if cat.startswith("_"):
                print(f"  {cat[1:]} (context-dependent):")
            else:
                print(f"  {cat}:")
            for p in patterns:
                print(f"    - {p}")
            print()
        print("Usage:")
        print("  hygeia --input ./data --output ./clean --only identity,financial")
        print("  hygeia --input ./data --output ./clean --skip-patterns crypto")
        print("  hygeia --input ./data --output ./clean --only exif  # EXIF stripping only")
        sys.exit(0)

    setup_logging(args.verbose)
    start_time = time.time()

    # Configure pattern filtering (--only / --skip-patterns)
    pattern_only = [s.strip() for s in args.only.split(",")] if args.only else None
    pattern_skip = [s.strip() for s in args.skip_patterns.split(",")] if args.skip_patterns else None

    if pattern_only or pattern_skip:
        from . import text_sanitizer, verifier
        text_sanitizer.configure(only=pattern_only, skip=pattern_skip)
        verifier.configure(only=pattern_only, skip=pattern_skip)

    # Warn early if exiftool is missing so the user sees it before the pipeline runs
    if not args.skip_exif and find_exiftool() is None:
        print(
            "WARNING: exiftool not installed. Image metadata will NOT be stripped.\n"
            "         Install from https://exiftool.org/ to enable EXIF stripping."
        )

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    if not input_path.exists():
        log.error(f"Input path does not exist: {input_path}")
        sys.exit(1)

    compliance = get_compliance_profile(args.compliance) if args.compliance else None

    # Resolve workers: 0 = auto-detect, else use as-is (clamped to >=1 inside helpers)
    workers = _resolve_workers(args.workers)

    print("=== HYGEIA Forensic-Grade PII Sanitization ===")
    print(f"Input:  {input_path}")
    print(f"Output: {output_path}")
    print(f"Mode:   {'DRY RUN' if args.dry_run else 'LIVE'}")
    if compliance:
        print(f"Compliance: {compliance.name}")
    if workers > 1:
        print(f"Workers: {workers} (parallel)")
    print()

    if not args.dry_run:
        copy_dump(input_path, output_path)
        work_path = output_path
    else:
        work_path = input_path

    # [1/7] Scan
    print("[1/7] Scanning filesystem...")
    scanner = FileScanner()
    scan_result = scanner.scan_dump(work_path)
    if scan_result.jailbreak and scan_result.jailbreak.detected:
        print(f"  iOS jailbreak detected: {scan_result.jailbreak.jailbreak_type}")
    print(f"  Files: {scan_result.total_files}")
    print(f"  Delete: {scan_result.delete_count} ({scan_result.delete_size / 1024 / 1024:.0f} MB)")
    print(f"  Preserve: {scan_result.preserve_count}")
    print()

    all_actions = []

    # [2/7] Databases
    print("[2/7] Sanitizing databases...")
    db_actions = sanitize_databases(work_path, scan_result, compliance, args.dry_run, workers=workers)
    all_actions.extend(db_actions)
    print(f"  Databases processed: {sum(1 for a in db_actions if 'sanitize' in a.get('action', ''))}")
    print()

    # [3/7] Text files
    print("[3/7] Sanitizing text files...")
    text_actions = sanitize_all_text_files(work_path, dry_run=args.dry_run, workers=workers)
    all_actions.extend(text_actions)
    text_count = sum(1 for a in text_actions if a.get("keys_redacted", 0) > 0 or
                     a.get("lines_redacted", 0) > 0 or a.get("cells_redacted", 0) > 0 or
                     a.get("action") == "delete_shell_history")
    print(f"  Text files sanitized: {text_count}")
    print()

    # [4/7] Forensic artifacts
    print("[4/7] Cleaning forensic artifacts...")
    fs_actions = sanitize_filesystem(work_path, dry_run=args.dry_run,
                                     normalize_timestamps=args.normalize_timestamps)
    all_actions.extend(fs_actions)
    fs_deleted = sum(1 for a in fs_actions if "delete" in a.get("action", ""))
    print(f"  Artifacts removed: {fs_deleted}")
    if args.normalize_timestamps:
        ts_action = next((a for a in fs_actions if a.get("action") == "normalize_timestamps"), None)
        if ts_action:
            print(f"  Timestamps normalized: {ts_action.get('files_normalized', 0)} files")
    print()

    # [5/7] EXIF + PDF + Office metadata
    if not args.skip_exif and not args.dry_run:
        print("[5/7] Stripping image EXIF metadata...")
        exif_result = strip_exif_directory(work_path)
        all_actions.append(exif_result)
        if exif_result.get("skipped"):
            print("  WARNING: exiftool not found — EXIF metadata was NOT stripped")
        else:
            print(f"  Images processed: {exif_result.get('files_stripped', 0)}")

        print("      Stripping PDF metadata...")
        pdf_result = strip_pdf_directory(work_path)
        all_actions.append(pdf_result)
        print(f"  PDFs processed: {pdf_result.get('files_processed', 0)}, "
              f"modified: {pdf_result.get('files_modified', 0)}")

        print("      Stripping Office document metadata...")
        office_result = strip_office_directory(work_path)
        all_actions.append(office_result)
        print(f"  Office docs processed: {office_result.get('files_processed', 0)}, "
              f"modified: {office_result.get('files_modified', 0)}")
    else:
        print("[5/7] EXIF/PDF/Office stripping: skipped")
    print()

    # [5b/7] Forensic hardening
    if not args.skip_forensic:
        print("[5b/7] Anti-forensic hardening...")
        forensic_actions = forensic_clean_all(work_path, dry_run=args.dry_run, workers=workers)
        all_actions.extend(forensic_actions)
        fc_deleted = sum(1 for a in forensic_actions if "delete" in a.get("action", "") and not a.get("dry_run"))
        fc_norm = next((a.get("files_normalized", 0) for a in forensic_actions if a.get("action") == "normalize_timestamps"), 0)
        print(f"  Artifacts removed: {fc_deleted}")
        if fc_norm:
            print(f"  Timestamps normalized: {fc_norm} items")
    else:
        print("[5b/7] Anti-forensic hardening: skipped")
    print()

    # [6/7] Verify
    if not args.skip_verify and not args.dry_run:
        print("[6/7] Verifying sanitization...")
        verification = verify_sanitization(work_path)
        if verification.passed:
            print("  PASSED — zero PII findings")
        else:
            print(f"  FAILED — {verification.total_findings} findings:")
            if verification.pii_matches:
                print(f"    PII matches: {len(verification.pii_matches)}")
            if verification.sqlite_freelist_findings:
                print(f"    SQLite freelist: {len(verification.sqlite_freelist_findings)}")
            if verification.exif_failures:
                print(f"    EXIF remaining: {len(verification.exif_failures)}")
    else:
        print("[6/7] Verification: skipped")
        from .verifier import VerificationResult
        verification = VerificationResult()
    print()

    # [7/7] Manifest
    print("[7/7] Generating manifest...")
    elapsed = time.time() - start_time
    manifest_path = Path(args.manifest) if args.manifest else (work_path.parent / "deletion_manifest.json")
    manifest = generate_manifest(
        dump_path=work_path, scan_result=scan_result,
        sanitization_actions=all_actions, verification_result=verification,
        elapsed_seconds=elapsed, output_path=manifest_path if not args.dry_run else None,
    )
    print(f"  Manifest: {manifest_path}")
    print()

    # Summary
    print("=== Summary ===")
    print(f"Files scanned:       {manifest['summary']['total_files_scanned']}")
    print(f"Files deleted:       {manifest['summary']['files_deleted']}")
    print(f"Databases sanitized: {manifest['summary']['databases_sanitized']}")
    print(f"Plists sanitized:    {manifest['summary']['plists_sanitized']}")
    print(f"Space freed:         {manifest['summary']['bytes_removed'] / 1024 / 1024:.0f} MB")
    print(f"Verification:        {'PASSED' if verification.passed else 'FAILED'}")
    print(f"Elapsed:             {elapsed:.1f}s")

    if args.compliance:
        comp_report = generate_compliance_report(args.compliance, all_actions, verification.passed)
        print(f"Compliance:          {comp_report['compliance_framework']}")
        if comp_report.get("identifiers_covered"):
            print(f"  Covered: {', '.join(comp_report['identifiers_covered'])}")
        if comp_report.get("gaps"):
            print(f"  Gaps:    {', '.join(comp_report['gaps'])}")
    print()

    if not verification.passed and not args.dry_run:
        print("WARNING: Verification FAILED. Review manifest for residual PII.")
        sys.exit(2)

    if args.dry_run:
        print("DRY RUN complete. No files were modified.")
        action_counts = {}
        for a in all_actions:
            t = a.get("action", "unknown")
            action_counts[t] = action_counts.get(t, 0) + 1
        for t, c in sorted(action_counts.items()):
            print(f"  Would {t}: {c}")
