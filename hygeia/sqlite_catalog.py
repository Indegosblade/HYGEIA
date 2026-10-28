"""SQLite row-carrier inventory shared by sanitization and verification.

Names are identifiers, never LIKE patterns. Derived FTS storage is excluded
only after its module, configuration and column shape have been established.
"""

import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from .utils import quote_identifier

_SQL_TOKEN_RE = re.compile(
    r"""--[^\n]*|/\*.*?\*/|'(?:[^']|'')*'|"(?:[^"]|"")*"|`(?:[^`]|``)*`|\[[^\]]*\]|[A-Za-z_][A-Za-z_0-9]*|\s+|.""",
    re.DOTALL,
)


def _fts_arguments(sql):
    if not sql:
        return None, []
    lexemes = [piece for piece in _SQL_TOKEN_RE.findall(sql)
               if not piece.isspace() and not piece.startswith(("--", "/*"))]
    if [piece.upper() for piece in lexemes[:3]] != ["CREATE", "VIRTUAL", "TABLE"]:
        return None, []
    start = next((i for i in range(3, len(lexemes) - 2)
                  if lexemes[i].upper() == "USING"
                  and lexemes[i + 1].lower() in {"fts3", "fts4", "fts5"}
                  and lexemes[i + 2] == "("), None)
    if start is None:
        return None, []
    arguments: list[str] = []
    argument: list[str] = []
    depth = 1
    for piece in lexemes[start + 3:]:
        if piece == "(":
            depth += 1
        elif piece == ")":
            depth -= 1
        if (piece == "," and depth == 1) or depth == 0:
            arguments.append("".join(argument))
            argument = []
            if depth == 0:
                return lexemes[start + 1].lower(), arguments
        else:
            argument.append(piece)
    raise sqlite3.DatabaseError("Unrecognized FTS declaration")


def fts_module(sql):
    return _fts_arguments(sql)[0]


def fts_option(sql, name):
    _, arguments = _fts_arguments(sql)
    pattern = re.compile(
        r"^" + re.escape(name) + r"""=(?:'((?:[^']|'')*)'|"((?:[^"]|"")*)"|([^\s,)]+))$""",
        re.IGNORECASE,
    )
    for argument in arguments:
        match = pattern.fullmatch(argument)
        if match:
            value = next(value for value in match.groups() if value is not None)
            if match.group(1) is not None:
                value = value.replace("''", "'")
            elif match.group(2) is not None:
                value = value.replace('""', '"')
            return value
    return None


def user_table_rows(conn):
    """Exclude only SQLite's literal reserved prefix, independently of LIKE."""
    return [(name, sql) for name, sql in conn.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='table'"
    ) if not name.lower().startswith("sqlite_")]


def column_info(conn, table):
    """Include ordinary, generated and hidden columns; never silently narrow."""
    rows = [tuple(row) for row in conn.execute(f"PRAGMA table_xinfo({quote_identifier(table)})")]
    if not rows or any(len(row) < 7 for row in rows):
        raise sqlite3.DatabaseError("Complete SQLite column metadata is unavailable")
    return rows


def text_variants(value):
    """The existing SQLite text-byte policy, shared by writers and verifiers."""
    if isinstance(value, str):
        yield value, None
    elif isinstance(value, (bytes, bytearray, memoryview)):
        for encoding in ("utf-8", "utf-16"):
            try:
                yield bytes(value).decode(encoding, errors="ignore"), encoding
            except (LookupError, ValueError):
                continue


@dataclass
class TableInfo:
    name: str
    sql: str | None
    columns: list[tuple[Any, ...]]
    module: str | None = None
    content: str | None = None
    fts_shadow: bool = False
    derived: bool = False


def _shadow_shapes(table):
    visible = [col[1] for col in table.columns if col[6] == 0]
    content = table.content
    if table.module == "fts5":
        columnsize = fts_option(table.sql, "columnsize")
        if columnsize not in (None, "0", "1"):
            raise sqlite3.DatabaseError("Unsupported FTS columnsize configuration")
        if fts_option(table.sql, "contentless_unindexed") not in (None, "0"):
            raise sqlite3.DatabaseError("Unsupported contentless FTS storage configuration")
        shapes = {
            "_data": [("id", "INTEGER", 1), ("block", "BLOB", 0)],
            "_idx": [("segid", "", 1), ("term", "", 2), ("pgno", "", 0)],
            "_config": [("k", "", 1), ("v", "", 0)],
        }
        if columnsize != "0":
            shapes["_docsize"] = [("id", "INTEGER", 1), ("sz", "BLOB", 0)]
        if content is None:
            shapes["_content"] = [("id", "INTEGER", 1)] + [
                (f"c{i}", "", 0) for i in range(len(visible))
            ]
        return shapes
    shapes = {
        "_segments": [("blockid", "INTEGER", 1), ("block", "BLOB", 0)],
        "_segdir": [("level", "INTEGER", 1), ("idx", "INTEGER", 2),
                    ("start_block", "INTEGER", 0), ("leaves_end_block", "INTEGER", 0),
                    ("end_block", "INTEGER", 0), ("root", "BLOB", 0)],
    }
    if content is None:
        shapes["_content"] = [("docid", "INTEGER", 1)] + [
            (f"c{i}{name}", "", 0) for i, name in enumerate(visible)
        ]
    if table.module == "fts4":
        matchinfo = fts_option(table.sql, "matchinfo")
        if matchinfo not in (None, "fts3"):
            raise sqlite3.DatabaseError("Unsupported FTS matchinfo configuration")
        if matchinfo is None:
            shapes["_docsize"] = [("docid", "INTEGER", 1), ("size", "BLOB", 0)]
        shapes["_stat"] = [("id", "INTEGER", 1), ("value", "BLOB", 0)]
    return shapes


def table_inventory(conn):
    """Inventory supported row carriers and distinguish actual derived FTS data.

    table_list alone is insufficient: xShadowName can label an ordinary unused
    ``<base>_docsize`` table as a shadow when columnsize=0. Validate configuration
    and layout too. Older SQLite without table_list uses the same explicit DDL
    and shape checks rather than a wildcard/name-only fallback.
    """
    tables = {
        name: TableInfo(name, sql, column_info(conn, name), fts_module(sql))
        for name, sql in user_table_rows(conn)
    }
    kinds = {row[1]: row[2] for row in conn.execute("PRAGMA table_list") if row[0] == "main"}
    for base in list(tables.values()):
        if base.module is None:
            continue
        base.content = fts_option(base.sql, "content")
        for suffix, expected in _shadow_shapes(base).items():
            name = base.name + suffix
            shadow = tables.get(name)
            if shadow is None:
                raise sqlite3.DatabaseError("An expected FTS storage table is missing")
            actual = [(col[1], (col[2] or "").upper(), col[5]) for col in shadow.columns]
            if actual != expected or any(col[6] != 0 for col in shadow.columns):
                raise sqlite3.DatabaseError("An FTS storage layout is unsupported")
            if kinds and kinds.get(name) != "shadow":
                raise sqlite3.DatabaseError("FTS storage ownership metadata is inconsistent")
            shadow.fts_shadow = True
            # Configuration is a readable carrier in its own right. Rebuild
            # does not promise to remove arbitrary user-added config rows.
            shadow.derived = suffix != "_config"
    return tables
