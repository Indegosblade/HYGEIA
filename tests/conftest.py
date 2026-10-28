"""Environment capabilities required by filesystem integration tests."""

import pytest


@pytest.fixture
def symlink_capable(tmp_path):
    target = tmp_path / "symlink-probe-target"
    target.write_text("probe", encoding="utf-8")
    link = tmp_path / "symlink-probe"
    try:
        link.symlink_to(target)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows account lacks symbolic-link privilege")
        raise
    finally:
        link.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
