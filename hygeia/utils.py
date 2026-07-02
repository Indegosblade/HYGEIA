import hashlib
import os
from pathlib import Path


def sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def quote_identifier(name: str) -> str:
    """Quote a SQLite identifier (table or column name) for safe interpolation.

    SQLite identifiers may themselves contain double-quotes — a table created
    as ``CREATE TABLE "a""b"`` has the literal name ``a"b``. Interpolating such
    a name into a ``"{name}"`` template produces malformed SQL that the
    surrounding ``except sqlite3.Error`` blocks silently swallow, so the table
    is skipped and its PII is never redacted (a false clean). Doubling embedded
    quotes is the SQLite-defined escape and makes any identifier safe to splice
    into a statement.
    """
    if "\x00" in name:
        # NUL cannot appear in a SQLite identifier and cannot be escaped.
        raise ValueError("identifier contains a NUL byte")
    return '"' + name.replace('"', '""') + '"'


def resolve_within(path: Path, root: Path) -> Path | None:
    """Resolve ``path`` and return it only if it stays inside ``root``.

    Returns the fully-resolved path when it equals ``root`` or is a descendant,
    otherwise ``None``. ``resolve()`` follows every symlink in the path, so a
    link that points outside the dump resolves outside ``root`` and is rejected.
    This is the containment check that stops a crafted symlink in a device dump
    from redirecting a HYGEIA read or write onto the operator's host.
    """
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
    except (OSError, RuntimeError):
        return None
    if resolved == root_resolved or root_resolved in resolved.parents:
        return resolved
    return None


def is_safe_regular_file(path: Path, root: Path) -> bool:
    """True only if ``path`` is a real regular file safe to rewrite in place.

    Rejects symlinks (whose target may live outside the dump) and any path that,
    after resolving parent symlinks, escapes ``root``. Every in-place rewriter
    (office, pdf, text, plist) and every timestamp pass must gate on this so a
    symlink in the dump cannot make an in-place write land on the host
    filesystem outside the sanitized output tree.
    """
    try:
        if path.is_symlink():
            return False
        if resolve_within(path, root) is None:
            return False
        return path.is_file()
    except OSError:
        return False


def safe_utime(path: Path, root: Path, times: tuple[float, float]) -> bool:
    """Set atime/mtime on ``path`` only if it is a real regular file within
    ``root``; never follows symlinks.

    ``os.utime`` defaults to ``follow_symlinks=True``, so on a preserved dump
    symlink it would rewrite the timestamps of the *target* — potentially a file
    on the operator's host outside the dump. Returns True if the timestamp was
    applied.
    """
    if not is_safe_regular_file(path, root):
        return False
    try:
        os.utime(path, times, follow_symlinks=False)
        return True
    except (OSError, NotImplementedError):
        return False
