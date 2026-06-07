"""Tests for EXIF stripper — dependency check and fallback behavior."""

import logging
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.exif_stripper import (
    exiftool_available,
    find_exiftool,
    strip_exif_directory,
    strip_single_file,
    verify_exif_stripped,
)


def _mock_no_exiftool(*args, **kwargs):
    """shutil.which replacement that always returns None."""
    return None


def _mock_path_is_file_false(self):
    """Path.is_file replacement that always returns False."""
    return False


# ---------------------------------------------------------------------------
# find_exiftool / exiftool_available
# ---------------------------------------------------------------------------

def test_find_exiftool_returns_none_when_absent():
    """When nothing is on PATH and no fallback paths exist, find_exiftool is None."""
    with patch("shutil.which", return_value=None), \
         patch("pathlib.Path.is_file", return_value=False):
        result = find_exiftool()
    assert result is None


def test_exiftool_available_false_when_absent():
    with patch("shutil.which", return_value=None), \
         patch("pathlib.Path.is_file", return_value=False):
        assert exiftool_available() is False


def test_exiftool_available_true_when_on_path():
    with patch("shutil.which", return_value="/usr/bin/exiftool"):
        assert exiftool_available() is True


# ---------------------------------------------------------------------------
# strip_exif_directory — missing exiftool
# ---------------------------------------------------------------------------

def test_strip_exif_directory_skipped_when_no_exiftool(caplog):
    """strip_exif_directory must return skipped=True and log a WARNING when exiftool missing."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.is_file", return_value=False), \
             caplog.at_level(logging.WARNING, logger="hygeia.exif"):
            result = strip_exif_directory(root)

    assert result.get("skipped") is True, "result should have skipped=True"
    assert result.get("reason") == "exiftool not installed"
    assert result.get("files_stripped", 0) == 0

    # Warning must appear in log
    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("exiftool" in m for m in warning_msgs), (
        f"Expected a WARNING mentioning exiftool, got: {warning_msgs}"
    )
    assert any("https://exiftool.org/" in m for m in warning_msgs), (
        "Warning should include the install URL"
    )


def test_strip_exif_directory_skipped_no_subprocess_call():
    """strip_exif_directory must not call subprocess when exiftool is missing."""
    import subprocess as sp
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.is_file", return_value=False), \
             patch.object(sp, "run") as mock_run:
            strip_exif_directory(root)
            mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# strip_single_file — missing exiftool
# ---------------------------------------------------------------------------

def test_strip_single_file_returns_false_when_no_exiftool():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "photo.jpg"
        f.write_bytes(b"\xff\xd8\xff" + b"\x00" * 16)  # minimal JPEG-ish header
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.is_file", return_value=False):
            result = strip_single_file(f)
    assert result is False


# ---------------------------------------------------------------------------
# verify_exif_stripped — missing exiftool
# ---------------------------------------------------------------------------

def test_verify_exif_stripped_returns_empty_when_no_exiftool(caplog):
    """verify_exif_stripped returns [] and logs WARNING when exiftool missing."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "photo.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 16)
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.is_file", return_value=False), \
             caplog.at_level(logging.WARNING, logger="hygeia.exif"):
            files = verify_exif_stripped(root)

    assert files == []
    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("exiftool" in m for m in warning_msgs)
