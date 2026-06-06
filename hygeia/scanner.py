"""
HYGEIA File Scanner -- rule-driven file classification engine.

Classifies every file in a filesystem dump into one of six actions
based on JSON rule files. Ships with iOS rules; swap the rules
directory for any platform.
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

log = logging.getLogger("hygeia.scanner")


class FileAction(Enum):
    DELETE = "DELETE"
    PRESERVE = "PRESERVE"
    SELECTIVE_DB = "SELECTIVE_DB"
    PLIST_SANITIZE = "PLIST_SANITIZE"
    EXIF_STRIP = "EXIF_STRIP"
    UNKNOWN = "UNKNOWN"


@dataclass
class JailbreakInfo:
    detected: bool = False
    jailbreak_type: str = ""  # "dopamine", "palera1n", "roothide", "unknown"
    jb_root: Optional[Path] = None  # /var/jb/ or variant
    preboot_path: Optional[Path] = None
    preserve_paths: list = field(default_factory=list)


@dataclass
class FileClassification:
    path: str
    action: FileAction
    reason: str
    size: int = 0


@dataclass
class ScanResult:
    total_files: int = 0
    total_size: int = 0
    classifications: list = field(default_factory=list)
    jailbreak: Optional[JailbreakInfo] = None

    @property
    def delete_count(self):
        return sum(1 for c in self.classifications if c.action == FileAction.DELETE)

    @property
    def preserve_count(self):
        return sum(1 for c in self.classifications if c.action == FileAction.PRESERVE)

    @property
    def delete_size(self):
        return sum(c.size for c in self.classifications if c.action == FileAction.DELETE)


class FileScanner:
    def __init__(self, rules_dir: Optional[Path] = None):
        if rules_dir is None:
            rules_dir = Path(__file__).parent / "rules"
        self.rules_dir = rules_dir
        self.delete_patterns = self._load_rules("delete_patterns.json")
        self.preserve_patterns = self._load_rules("preserve_patterns.json")
        self.selective_db_rules = self._load_rules("selective_db_rules.json")
        self.plist_patterns = self._load_rules("plist_patterns.json")

    def _load_rules(self, filename: str) -> dict:
        path = self.rules_dir / filename
        if path.exists():
            with open(path) as f:
                return json.load(f)
        log.warning(f"Rules file not found: {path}")
        return {}

    def detect_jailbreak(self, dump_path: Path) -> JailbreakInfo:
        """Detect jailbreak presence and type dynamically."""
        info = JailbreakInfo()

        # Check standard Dopamine/Procursus path
        jb_path = dump_path / "private" / "var" / "jb"
        if jb_path.exists() or jb_path.is_symlink():
            info.detected = True
            info.jb_root = jb_path
            info.preserve_paths.append(str(jb_path))

            # Resolve symlink to find preboot location
            if jb_path.is_symlink():
                try:
                    target = jb_path.resolve()
                    if "preboot" in str(target):
                        info.preboot_path = target
                        info.preserve_paths.append(str(target))
                except OSError:
                    pass

        # Check for RootHide variant (randomized path)
        var_dir = dump_path / "private" / "var"
        if var_dir.exists():
            for d in var_dir.iterdir():
                if d.name.startswith("jb-") and d.is_dir():
                    info.detected = True
                    info.jailbreak_type = "roothide"
                    info.jb_root = d
                    info.preserve_paths.append(str(d))

        # Check preboot directory
        preboot = dump_path / "private" / "preboot"
        if preboot.exists():
            info.preserve_paths.append(str(preboot))
            # Look for dopamine markers
            for item in preboot.rglob("*"):
                name_lower = item.name.lower()
                if "dopamine" in name_lower:
                    info.jailbreak_type = "dopamine"
                    info.detected = True
                elif "palera1n" in name_lower or "jbinit" in name_lower:
                    info.jailbreak_type = "palera1n"
                    info.detected = True

        # Check cores directory (palera1n)
        cores = dump_path / "cores"
        if cores.exists() and (cores / "jbinit.log").exists():
            info.jailbreak_type = "palera1n"
            info.detected = True
            info.preserve_paths.append(str(cores))

        # Detect Dopamine app in containers
        containers_bundle = dump_path / "private" / "var" / "containers" / "Bundle" / "Application"
        if containers_bundle.exists():
            for app_dir in containers_bundle.iterdir():
                for app in app_dir.glob("*.app"):
                    if app.name.lower() in ("dopamine.app", "sileo.app", "filza.app", "newterm.app"):
                        info.preserve_paths.append(str(app_dir))

        if info.detected and not info.jailbreak_type:
            info.jailbreak_type = "unknown"

        if info.detected:
            log.info(f"Jailbreak detected: {info.jailbreak_type}, root: {info.jb_root}")

        return info

    def classify_file(self, rel_path: str, dump_path: Path, jailbreak: JailbreakInfo) -> FileClassification:
        """Classify a single file path."""
        full_path = dump_path / rel_path
        try:
            size = full_path.stat().st_size if full_path.exists() and not full_path.is_symlink() else 0
        except OSError:
            size = 0

        path_lower = rel_path.lower().replace("\\", "/")

        # Jailbreak paths — always preserve
        for jb_path in jailbreak.preserve_paths:
            try:
                jb_rel = str(Path(jb_path).relative_to(dump_path)).replace("\\", "/")
            except ValueError:
                # jb_path is an absolute device path (symlink resolved outside dump)
                # Check if the relative path contains key jailbreak markers
                jb_rel = str(Path(jb_path)).replace("\\", "/")
                if any(marker in path_lower for marker in ["preboot", "var/jb", "procursus", "dopamine"]):
                    return FileClassification(rel_path, FileAction.PRESERVE, "jailbreak infrastructure", size)
                continue
            if path_lower.startswith(jb_rel.lower()):
                return FileClassification(rel_path, FileAction.PRESERVE, "jailbreak infrastructure", size)

        # Check preserve patterns first (system files take priority)
        for pattern in self.preserve_patterns.get("paths", []):
            if path_lower.startswith(pattern.lower().lstrip("/")):
                return FileClassification(rel_path, FileAction.PRESERVE, f"system: {pattern}", size)

        # Check selective database rules
        for db_rule in self.selective_db_rules.get("databases", []):
            if path_lower.endswith(db_rule["path_suffix"].lower()):
                return FileClassification(rel_path, FileAction.SELECTIVE_DB, f"mixed db: {db_rule['name']}", size)

        # Check delete patterns
        for pattern in self.delete_patterns.get("directory_patterns", []):
            if pattern.lower().lstrip("/") in path_lower:
                return FileClassification(rel_path, FileAction.DELETE, f"personal data: {pattern}", size)

        for ext_pattern in self.delete_patterns.get("extension_patterns", []):
            ext = ext_pattern.get("ext", "")
            scope = ext_pattern.get("scope", "")
            if path_lower.endswith(ext.lower()) and scope.lower() in path_lower:
                return FileClassification(rel_path, FileAction.EXIF_STRIP if ext in (".jpg", ".jpeg", ".heic", ".png") else FileAction.DELETE, f"media in {scope}", size)

        # Check plist sanitization
        if path_lower.endswith(".plist"):
            for pattern in self.plist_patterns.get("sanitize_paths", []):
                if pattern.lower().lstrip("/") in path_lower:
                    return FileClassification(rel_path, FileAction.PLIST_SANITIZE, f"plist: {pattern}", size)

        # Default: preserve (conservative — don't delete what we don't recognize)
        return FileClassification(rel_path, FileAction.PRESERVE, "unclassified (default preserve)", size)

    def scan_dump(self, dump_path: Path) -> ScanResult:
        """Full dump scan — classify every file."""
        result = ScanResult()
        result.jailbreak = self.detect_jailbreak(dump_path)

        for f in dump_path.rglob("*"):
            if not f.is_file():
                continue
            try:
                rel = str(f.relative_to(dump_path))
                classification = self.classify_file(rel, dump_path, result.jailbreak)
                result.classifications.append(classification)
                result.total_files += 1
                result.total_size += classification.size
            except Exception as e:
                log.warning(f"Error classifying {f}: {e}")

        log.info(f"Scan complete: {result.total_files} files, "
                 f"{result.delete_count} delete, {result.preserve_count} preserve, "
                 f"delete size: {result.delete_size / 1024 / 1024:.1f} MB")
        return result
