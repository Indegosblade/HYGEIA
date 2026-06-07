"""
Tests for hygeia.forensic_cleaner -- anti-forensic hardening module.
"""

import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from hygeia.forensic_cleaner import (
    clean_leveldb_stores,
    clean_thumbnail_caches,
    clean_swap_temp_files,
    normalize_timestamps,
    forensic_clean_all,
    _is_leveldb_dir,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tmp() -> Path:
    """Return a fresh temp directory as a Path."""
    return Path(tempfile.mkdtemp())


def _mkdir(root: Path, *parts: str) -> Path:
    """Create a nested directory under root and return its Path."""
    p = root.joinpath(*parts)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _touch(path: Path, content: bytes = b"") -> Path:
    """Create a file at path (parents must exist)."""
    path.write_bytes(content)
    return path



# ---------------------------------------------------------------------------
# LevelDB tests
# ---------------------------------------------------------------------------


class TestCleanLeveldbStores:

    def test_basic_detection_and_deletion(self):
        """LevelDB dir with CURRENT + .ldb file should be deleted."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "Local Storage", "leveldb")
            _touch(store / "CURRENT", b"1")
            _touch(store / "000003.ldb", b"data")
            actions = clean_leveldb_stores(d)
            assert not store.exists(), "LevelDB store directory should be removed"
            assert len(actions) == 1
            assert actions[0]["action"] == "delete_leveldb_store"
            assert "dry_run" not in actions[0]
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_sst_extension_detected(self):
        """CURRENT + .sst file qualifies as LevelDB."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "IndexedDB", "foo.leveldb")
            _touch(store / "CURRENT", b"1")
            _touch(store / "000001.sst", b"data")
            actions = clean_leveldb_stores(d)
            assert not store.exists()
            assert len(actions) == 1
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_manifest_extension_detected(self):
        """CURRENT + MANIFEST-* file qualifies as LevelDB."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "db")
            _touch(store / "CURRENT", b"1")
            _touch(store / "MANIFEST-000001", b"data")
            clean_leveldb_stores(d)
            assert not store.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_log_extension_detected(self):
        """CURRENT + .log file qualifies as LevelDB."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "db")
            _touch(store / "CURRENT", b"1")
            _touch(store / "000001.log", b"data")
            clean_leveldb_stores(d)
            assert not store.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_current_only_not_detected(self):
        """Dir with only CURRENT file (no data files) is not a LevelDB store."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "notdb")
            _touch(store / "CURRENT", b"1")
            actions = clean_leveldb_stores(d)
            assert store.exists(), "Should NOT be deleted -- no data files"
            assert len(actions) == 0
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dry_run_preserves_directory(self):
        """dry_run=True reports the action but does not delete."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "leveldb")
            _touch(store / "CURRENT", b"1")
            _touch(store / "data.ldb", b"data")
            actions = clean_leveldb_stores(d, dry_run=True)
            assert store.exists(), "dry_run must not delete"
            assert len(actions) == 1
            assert actions[0]["dry_run"] is True
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_multiple_stores(self):
        """Multiple LevelDB stores all get deleted."""
        d = _make_tmp()
        try:
            for name in ("alpha", "beta", "gamma"):
                s = _mkdir(d, name)
                _touch(s / "CURRENT", b"1")
                _touch(s / "x.ldb", b"x")
            actions = clean_leveldb_stores(d)
            assert len(actions) == 3
            for name in ("alpha", "beta", "gamma"):
                assert not (d / name).exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestLeveldbBroadDetection:
    """Tests for broadened LevelDB detection: name-pattern + CURRENT-only heuristics."""

    def test_localstorageunderscorelevelddb_with_ldb_detected(self):
        """LocalStorage_leveldb dir with CURRENT + .ldb is detected and deleted.

        Regression for apps/chatgpt/LocalStorage_leveldb miss: directory name
        ends with _leveldb so it must be detected regardless of CURRENT presence.
        """
        d = _make_tmp()
        try:
            store = _mkdir(d, "apps", "chatgpt", "LocalStorage_leveldb")
            _touch(store / "CURRENT", b"1")
            _touch(store / "000003.ldb", b"data")
            actions = clean_leveldb_stores(d)
            assert not store.exists(), "LocalStorage_leveldb should be removed"
            assert len(actions) == 1
            assert actions[0]["action"] == "delete_leveldb_store"
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_localstorageunderscorelevelddb_log_only_detected(self):
        """LocalStorage_leveldb dir with CURRENT + .log files only is detected.

        This is the exact scenario from the real-world failure: 55 PII residuals
        in apps/chatgpt/LocalStorage_leveldb/010706.log. The dir has no .ldb
        files, only .log files. Name-pattern detection must catch it.
        """
        d = _make_tmp()
        try:
            store = _mkdir(d, "apps", "chatgpt", "LocalStorage_leveldb")
            _touch(store / "CURRENT", b"1")
            _touch(store / "010706.log", b"pii data")
            _touch(store / "010707.log", b"more pii")
            actions = clean_leveldb_stores(d)
            assert not store.exists(), "LocalStorage_leveldb should be removed"
            assert len(actions) == 1
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_foo_dot_leveldb_inside_indexeddb_detected(self):
        """foo.leveldb inside IndexedDB/ is detected and deleted."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "IndexedDB", "https_example.com_0.indexeddb.leveldb")
            _touch(store / "CURRENT", b"1")
            _touch(store / "000001.ldb", b"data")
            actions = clean_leveldb_stores(d)
            assert not store.exists(), "IndexedDB/*.leveldb should be removed"
            assert len(actions) == 1
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_leveldb_name_suffix_no_current_file_detected(self):
        """Directory ending in 'leveldb' is detected even without a CURRENT file.

        Electron apps sometimes write LevelDB stores without a CURRENT file
        during active use. Name pattern alone must trigger detection.
        """
        d = _make_tmp()
        try:
            store = _mkdir(d, "LocalStorage_leveldb")
            _touch(store / "000001.ldb", b"data")
            # No CURRENT file intentionally
            actions = clean_leveldb_stores(d)
            assert not store.exists(), "Name-pattern detection must work without CURRENT"
            assert len(actions) == 1
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_log_only_no_current_no_leveldb_name_not_detected(self):
        """Dir with only .log files and no CURRENT, no leveldb name is NOT detected.

        A plain logs/ directory must not be misidentified as LevelDB.
        """
        d = _make_tmp()
        try:
            plain_logs = _mkdir(d, "logs")
            _touch(plain_logs / "app.log", b"ordinary log")
            _touch(plain_logs / "error.log", b"error")
            actions = clean_leveldb_stores(d)
            assert plain_logs.exists(), "Plain logs/ dir must NOT be deleted"
            assert len(actions) == 0
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_is_leveldb_dir_name_suffix_match(self):
        """_is_leveldb_dir returns True for a dir whose name ends in leveldb."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "SomeApp_leveldb")
            _touch(store / "data.ldb", b"x")
            assert _is_leveldb_dir(store) is True
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_is_leveldb_dir_current_plus_log_only(self):
        """_is_leveldb_dir returns True for CURRENT + .log (no .ldb)."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "db")
            _touch(store / "CURRENT", b"1")
            _touch(store / "000001.log", b"leveldb journal")
            assert _is_leveldb_dir(store) is True
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_is_leveldb_dir_current_only_false(self):
        """_is_leveldb_dir returns False for a dir with only a CURRENT file and no name match."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "notdb")
            _touch(store / "CURRENT", b"1")
            assert _is_leveldb_dir(store) is False
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dry_run_leveldb_name_pattern(self):
        """dry_run=True on a name-pattern-matched store reports but does not delete."""
        d = _make_tmp()
        try:
            store = _mkdir(d, "SomeApp_leveldb")
            _touch(store / "CURRENT", b"1")
            _touch(store / "000001.ldb", b"data")
            actions = clean_leveldb_stores(d, dry_run=True)
            assert store.exists(), "dry_run must not delete"
            assert len(actions) == 1
            assert actions[0]["dry_run"] is True
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Thumbnail / cache tests
# ---------------------------------------------------------------------------


class TestCleanThumbnailCaches:

    def test_cache_dir_deleted(self):
        """Directory named Cache should be removed."""
        d = _make_tmp()
        try:
            cache = _mkdir(d, "Cache")
            _touch(cache / "data1", b"x")
            actions = clean_thumbnail_caches(d)
            assert not cache.exists()
            assert any(a["action"] == "delete_cache_dir" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_gpu_cache_dir_deleted(self):
        """GPUCache directory should be removed."""
        d = _make_tmp()
        try:
            gpu = _mkdir(d, "GPUCache")
            _touch(gpu / "data", b"x")
            clean_thumbnail_caches(d)
            assert not gpu.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_thumbnails_dir_deleted(self):
        """Thumbnails directory should be removed."""
        d = _make_tmp()
        try:
            t = _mkdir(d, "Thumbnails")
            _touch(t / "img.jpg", b"x")
            clean_thumbnail_caches(d)
            assert not t.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_code_cache_dir_deleted(self):
        """"Code Cache" directory should be removed."""
        d = _make_tmp()
        try:
            cc = _mkdir(d, "Code Cache")
            _touch(cc / "js", b"x")
            clean_thumbnail_caches(d)
            assert not cc.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_case_insensitive_cache_match(self):
        """Any directory with cache in its name (any case) is removed."""
        d = _make_tmp()
        try:
            mixed = _mkdir(d, "MyAppCacheData")
            _touch(mixed / "f", b"x")
            clean_thumbnail_caches(d)
            assert not mixed.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_pboard_dir_deleted(self):
        """iOS com.apple.UIKit.pboardPersistentItems dir should be removed."""
        d = _make_tmp()
        try:
            pb = _mkdir(d, "com.apple.UIKit.pboardPersistentItems")
            _touch(pb / "item", b"x")
            clean_thumbnail_caches(d)
            assert not pb.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_thumbnails_db_file_deleted(self):
        """thumbnails.db file should be deleted."""
        d = _make_tmp()
        try:
            f = _touch(d / "thumbnails.db", b"data")
            actions = clean_thumbnail_caches(d)
            assert not f.exists()
            assert any(a["action"] == "delete_cache_file" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_thumbnails_db_wal_deleted(self):
        """thumbnails.db-wal file should be deleted."""
        d = _make_tmp()
        try:
            f = _touch(d / "thumbnails.db-wal", b"data")
            clean_thumbnail_caches(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_thumbnails_journal_deleted(self):
        """thumbnails-journal file should be deleted."""
        d = _make_tmp()
        try:
            f = _touch(d / "thumbnails-journal", b"data")
            clean_thumbnail_caches(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dry_run_preserves_cache_dir(self):
        """dry_run leaves cache directories intact."""
        d = _make_tmp()
        try:
            cache = _mkdir(d, "Cache")
            _touch(cache / "x", b"x")
            actions = clean_thumbnail_caches(d, dry_run=True)
            assert cache.exists()
            assert all(a.get("dry_run") for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_non_cache_dir_preserved(self):
        """Ordinary directories should not be touched."""
        d = _make_tmp()
        try:
            safe = _mkdir(d, "Documents")
            _touch(safe / "notes.txt", b"notes")
            clean_thumbnail_caches(d)
            assert safe.exists()
            assert (safe / "notes.txt").exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)



# ---------------------------------------------------------------------------
# Swap / temp file tests
# ---------------------------------------------------------------------------


class TestCleanSwapTempFiles:

    def test_pagefile_deleted(self):
        d = _make_tmp()
        try:
            f = _touch(d / "pagefile.sys", b"data")
            actions = clean_swap_temp_files(d)
            assert not f.exists()
            assert any(a["action"] == "delete_swap_file" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_swapfile_deleted(self):
        d = _make_tmp()
        try:
            f = _touch(d / "swapfile.sys", b"data")
            clean_swap_temp_files(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_hiberfil_deleted(self):
        d = _make_tmp()
        try:
            f = _touch(d / "hiberfil.sys", b"data")
            clean_swap_temp_files(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_vim_swp_deleted(self):
        """Vim .swp files should be removed."""
        d = _make_tmp()
        try:
            f = _touch(d / ".exploit.py.swp", b"vim")
            clean_swap_temp_files(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_vim_swo_deleted(self):
        d = _make_tmp()
        try:
            f = _touch(d / "notes.swo", b"vim")
            clean_swap_temp_files(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_tmp_deleted(self):
        d = _make_tmp()
        try:
            f = _touch(d / "upload.tmp", b"x")
            clean_swap_temp_files(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_office_lockfile_deleted(self):
        """MS Office ~$ lock files should be removed."""
        d = _make_tmp()
        try:
            f = _touch(d / "~$report.docx", b"lock")
            clean_swap_temp_files(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_libreoffice_lockfile_deleted(self):
        """LibreOffice .~lock.* files should be removed."""
        d = _make_tmp()
        try:
            f = _touch(d / ".~lock.spreadsheet.ods#", b"lock")
            clean_swap_temp_files(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_case_insensitive_swap_match(self):
        """Exact names are matched case-insensitively."""
        d = _make_tmp()
        try:
            f = _touch(d / "PAGEFILE.SYS", b"data")
            clean_swap_temp_files(d)
            assert not f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dry_run_preserves_swap_files(self):
        d = _make_tmp()
        try:
            f = _touch(d / "file.tmp", b"data")
            actions = clean_swap_temp_files(d, dry_run=True)
            assert f.exists()
            assert all(a.get("dry_run") for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_regular_files_not_deleted(self):
        """Normal files should not be touched."""
        d = _make_tmp()
        try:
            f = _touch(d / "data.db", b"sqlite")
            clean_swap_temp_files(d)
            assert f.exists()
        finally:
            shutil.rmtree(d, ignore_errors=True)



# ---------------------------------------------------------------------------
# Timestamp normalization tests
# ---------------------------------------------------------------------------


class TestNormalizeTimestamps:

    def test_timestamps_set_to_default_epoch(self):
        """Default epoch 2000-01-01 should be applied to all files."""
        d = _make_tmp()
        try:
            f = _touch(d / "file.txt", b"hello")
            actions = normalize_timestamps(d)
            mtime = f.stat().st_mtime
            expected = datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp()
            assert abs(mtime - expected) < 2, f"mtime {mtime} != epoch {expected}"
            assert len(actions) == 1
            assert actions[0]["action"] == "normalize_timestamps"
            assert actions[0]["epoch"] == "2000-01-01"
            assert actions[0]["files_normalized"] >= 1
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_custom_epoch(self):
        """Custom epoch string should be applied correctly."""
        d = _make_tmp()
        try:
            _touch(d / "a.txt", b"x")
            normalize_timestamps(d, epoch="2010-06-15")
            mtime = (d / "a.txt").stat().st_mtime
            expected = datetime(2010, 6, 15, tzinfo=timezone.utc).timestamp()
            assert abs(mtime - expected) < 2
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_root_directory_normalized(self):
        """The root dump_path directory itself should also be normalized."""
        d = _make_tmp()
        try:
            _touch(d / "x", b"x")
            normalize_timestamps(d)
            mtime = d.stat().st_mtime
            expected = datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp()
            assert abs(mtime - expected) < 2
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_multiple_files_normalized(self):
        """All files and subdirs should get their timestamps normalized."""
        d = _make_tmp()
        try:
            sub = _mkdir(d, "sub")
            _touch(sub / "a.txt", b"a")
            _touch(sub / "b.txt", b"b")
            _touch(d / "root.txt", b"r")
            actions = normalize_timestamps(d)
            assert actions[0]["files_normalized"] >= 4  # sub, a.txt, b.txt, root.txt + root dir
            expected = datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp()
            for fp in [d / "root.txt", sub / "a.txt", sub / "b.txt"]:
                assert abs(fp.stat().st_mtime - expected) < 2
        finally:
            shutil.rmtree(d, ignore_errors=True)



# ---------------------------------------------------------------------------
# Integration tests (forensic_clean_all)
# ---------------------------------------------------------------------------


class TestForensicCleanAll:

    def _build_full_fixture(self, root: Path) -> dict:
        """Create a realistic dump tree with all artifact types."""
        # LevelDB store
        ldb = _mkdir(root, "Local Storage", "leveldb")
        _touch(ldb / "CURRENT", b"1")
        _touch(ldb / "000001.ldb", b"ldb")
        # Cache dir
        cache = _mkdir(root, "Cache")
        _touch(cache / "cached_data", b"x")
        # Swap/temp file
        swap = _touch(root / "temp.tmp", b"tmp")
        # Regular file (must survive)
        safe = _touch(root / "contacts.db", b"sqlite")
        return {
            "ldb": ldb,
            "cache": cache,
            "swap": swap,
            "safe": safe,
        }

    def test_live_run_removes_all_artifacts(self):
        """forensic_clean_all should remove LevelDB, cache, and swap artifacts."""
        d = _make_tmp()
        try:
            fx = self._build_full_fixture(d)
            actions = forensic_clean_all(d)
            assert not fx["ldb"].exists(), "LevelDB store should be gone"
            assert not fx["cache"].exists(), "Cache dir should be gone"
            assert not fx["swap"].exists(), "Swap file should be gone"
            assert fx["safe"].exists(), "Regular DB file should survive"
            # Should include at least one of each action type
            action_names = {a["action"] for a in actions}
            assert "delete_leveldb_store" in action_names
            assert "delete_cache_dir" in action_names
            assert "delete_swap_file" in action_names
            assert "normalize_timestamps" in action_names
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dry_run_leaves_everything_intact(self):
        """forensic_clean_all(dry_run=True) must not touch the filesystem."""
        d = _make_tmp()
        try:
            fx = self._build_full_fixture(d)
            actions = forensic_clean_all(d, dry_run=True)
            assert fx["ldb"].exists(), "LevelDB store must survive dry_run"
            assert fx["cache"].exists(), "Cache dir must survive dry_run"
            assert fx["swap"].exists(), "Swap file must survive dry_run"
            # normalize_timestamps should NOT run in dry_run mode
            assert not any(a["action"] == "normalize_timestamps" for a in actions)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_returns_combined_action_list(self):
        """Return value is a flat list of all action dicts."""
        d = _make_tmp()
        try:
            self._build_full_fixture(d)
            actions = forensic_clean_all(d)
            assert isinstance(actions, list)
            assert len(actions) > 0
            for a in actions:
                assert "action" in a
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_empty_directory_no_error(self):
        """Running on an empty directory should produce no errors."""
        d = _make_tmp()
        try:
            actions = forensic_clean_all(d)
            assert isinstance(actions, list)
            # Only timestamps normalization action for the root dir
            ts_actions = [a for a in actions if a["action"] == "normalize_timestamps"]
            assert len(ts_actions) == 1
        finally:
            shutil.rmtree(d, ignore_errors=True)

