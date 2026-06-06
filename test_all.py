"""Full pipeline test for HYGEIA."""
import sys
import os
import re
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

passed = 0
failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS: {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL: {name} — {e}")
        failed += 1

# ============================================================
# Test 1: All imports work
# ============================================================
print("=== Test 1: Imports ===")

def t_imports():
    from hygeia import __version__
    from hygeia.scanner import FileScanner, FileAction, ScanResult
    from hygeia.sqlite_sanitizer import (
        delete_database, sanitize_database, sanitize_knowledgec,
        sanitize_photos_sqlite, delete_wal_orphans, find_all_databases,
    )
    from hygeia.plist_sanitizer import sanitize_plist
    from hygeia.exif_stripper import strip_exif_directory, exiftool_available
    from hygeia.verifier import verify_sanitization
    from hygeia.manifest import generate_manifest
    assert __version__ == "1.0.0"

test("all imports", t_imports)

# ============================================================
# Test 2: Scanner classification
# ============================================================
print("\n=== Test 2: Scanner ===")

def t_scanner():
    from hygeia.scanner import FileScanner
    scanner = FileScanner()
    assert scanner is not None

test("scanner init", t_scanner)

# ============================================================
# Test 3: Jailbreak detection
# ============================================================
print("\n=== Test 3: Jailbreak Detection ===")

def t_jailbreak():
    from hygeia.scanner import FileScanner
    scanner = FileScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # Create Dopamine marker at private/var/jb (actual iOS path)
        jb_path = root / "private" / "var" / "jb" / "basebin"
        jb_path.mkdir(parents=True)
        (jb_path / "jailbreakd").write_text("fake")
        (jb_path / "libjailbreak.dylib").write_text("fake")

        result = scanner.detect_jailbreak(root)
        assert result.detected, "Jailbreak should be detected via /private/var/jb"

test("dopamine detection", t_jailbreak)

# ============================================================
# Test 4: CLI argument parsing
# ============================================================
print("\n=== Test 4: CLI ===")

def t_cli_help():
    old_argv = sys.argv
    sys.argv = ["hygeia_cli.py", "--help"]
    try:
        from hygeia_cli import main
        main()
    except SystemExit as e:
        assert e.code == 0
    finally:
        sys.argv = old_argv

test("CLI --help", t_cli_help)

def t_cli_no_optimize():
    import argparse
    old_argv = sys.argv
    sys.argv = ["hygeia_cli.py", "--input", "/tmp/fake", "--output", "/tmp/fake2", "--optimize"]
    try:
        from hygeia_cli import main
        main()
        assert False, "Should fail — --optimize removed"
    except SystemExit as e:
        assert e.code == 2, f"Expected exit 2 for unrecognized arg, got {e.code}"
    finally:
        sys.argv = old_argv

test("--optimize flag removed", t_cli_no_optimize)

# ============================================================
# Test 5: Exit codes match documentation
# ============================================================
print("\n=== Test 5: Exit Codes ===")

def t_exit_input_error():
    old_argv = sys.argv
    sys.argv = ["hygeia_cli.py", "--input", "/nonexistent/path/12345", "--output", "/tmp/out"]
    try:
        from hygeia_cli import main
        main()
        assert False, "Should have exited"
    except SystemExit as e:
        assert e.code == 1, f"Input error should be exit 1, got {e.code}"
    finally:
        sys.argv = old_argv

test("exit code 1 = input error", t_exit_input_error)

# ============================================================
# Test 6: Dry run mode
# ============================================================
print("\n=== Test 6: Dry Run ===")

def t_dry_run():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir) / "dump"
        root.mkdir()
        # Create some files
        (root / "System" / "Library" / "CoreServices").mkdir(parents=True)
        (root / "private" / "var" / "mobile" / "Media" / "DCIM").mkdir(parents=True)
        (root / "private" / "var" / "mobile" / "Media" / "DCIM" / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0")

        old_argv = sys.argv
        sys.argv = ["hygeia_cli.py", "--input", str(root), "--output", "/unused", "--dry-run", "--skip-verify"]
        try:
            from hygeia_cli import main
            main()
        except SystemExit as e:
            pass
        finally:
            sys.argv = old_argv

        # Original should be untouched
        assert (root / "private" / "var" / "mobile" / "Media" / "DCIM" / "photo.jpg").exists()

test("dry run preserves original", t_dry_run)

# ============================================================
# Test 7: Verifier
# ============================================================
print("\n=== Test 7: Verifier ===")

def t_verifier():
    from hygeia.verifier import verify_sanitization
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # Create a clean directory — should pass
        (root / "clean.txt").write_text("nothing personal here")
        result = verify_sanitization(root)
        assert result.passed, f"Clean dir should pass, got {result.total_findings} findings"

test("verifier on clean dir", t_verifier)

def t_verifier_pii():
    from hygeia.verifier import verify_sanitization
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # Create file with PII
        (root / "leak.txt").write_text("Contact me at user@icloud.com for details")
        result = verify_sanitization(root)
        assert not result.passed, "Dir with email should fail verification"

test("verifier catches PII", t_verifier_pii)

# ============================================================
# Test 8: SQLite sanitizer
# ============================================================
print("\n=== Test 8: SQLite Sanitizer ===")

def t_sqlite_delete():
    import sqlite3
    from hygeia.sqlite_sanitizer import delete_database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE test (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO test VALUES (1, 'secret')")
        conn.commit()
        conn.close()

        result = delete_database(db_path)
        assert not db_path.exists(), "Database should be deleted"
    finally:
        try:
            db_path.unlink(missing_ok=True)
        except PermissionError:
            pass

test("sqlite delete with WAL cleanup", t_sqlite_delete)

# ============================================================
# Test 9: Plist sanitizer
# ============================================================
print("\n=== Test 9: Plist Sanitizer ===")

def t_plist():
    import plistlib
    from hygeia.plist_sanitizer import sanitize_plist
    with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as f:
        plist_path = Path(f.name)
    try:
        data = {
            "UserName": "test_user",
            "Password": "secret123",
            "SystemVersion": "15.5",
        }
        with open(plist_path, "wb") as f:
            plistlib.dump(data, f)

        result = sanitize_plist(plist_path)
        assert result is not None
    finally:
        try:
            plist_path.unlink(missing_ok=True)
        except PermissionError:
            pass

test("plist sanitization", t_plist)

# ============================================================
# Test 10: Manifest generation
# ============================================================
print("\n=== Test 10: Manifest ===")

def t_manifest():
    from hygeia.manifest import generate_manifest
    from hygeia.scanner import ScanResult
    from hygeia.verifier import VerificationResult
    with tempfile.TemporaryDirectory() as tmpdir:
        manifest = generate_manifest(
            dump_path=Path(tmpdir),
            scan_result=ScanResult(),
            sanitization_actions=[{"action": "test"}],
            verification_result=VerificationResult(),
            elapsed_seconds=1.5,
        )
        assert manifest["tool"] == "HYGEIA"
        assert manifest["version"] == "1.0.0"

test("manifest generation", t_manifest)

# ============================================================
# Test 11: No personal data in source files
# ============================================================
print("\n=== Test 11: Personal Data Scrub ===")

def t_no_personal():
    personal_patterns = [
        r"Kevin Estrada",
        r"estradakh@gmail\.com",
        r"\bLimen\b",
        r"\bagents\b",
        r"\bVex\b",
    ]
    root = Path(__file__).parent
    violations = []

    for ext in ("*.py", "*.md", "*.toml"):
        for f in root.rglob(ext):
            if f.name == "test_all.py":
                continue
            content = f.read_text(errors="ignore")
            for pat in personal_patterns:
                if re.search(pat, content):
                    violations.append(f"{f.name}: matches {pat}")

    # Check LICENSE
    lic = (root / "LICENSE").read_text(errors="ignore")
    if "Kevin Estrada" in lic:
        violations.append("LICENSE: still contains Kevin Estrada")
    if "estradakh" in lic:
        violations.append("LICENSE: still contains email")

    # Check pyproject.toml for MIT
    toml = (root / "pyproject.toml").read_text(errors="ignore")
    if 'text = "MIT"' in toml:
        violations.append("pyproject.toml: still says MIT license")
    if "estradakh" in toml:
        violations.append("pyproject.toml: still contains email")

    assert not violations, "Personal data found:\n" + "\n".join(violations)

test("no personal data in source", t_no_personal)

# ============================================================
# Summary
# ============================================================
print(f"\n{'='*40}")
print(f"Results: {passed} passed, {failed} failed")
if failed:
    print("SOME TESTS FAILED")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
    sys.exit(0)
