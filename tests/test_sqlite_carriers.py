"""The declared row scan must enumerate real carriers, independent of names."""

import re
import sqlite3
from contextlib import closing

import pytest

from hygeia.patterns import PatternRegistry
from hygeia.sqlite_sanitizer import sanitize_database_generic
from hygeia.verifier import scan_sqlite_content

EMAIL = "carriercheck@example.com"
NAMES = ["records", "sqliteXextension", "SQLITExExtension2", "sqlite-like",
         "gifts_archive", "Gifts_Archive2", "notes_fts_private"]


def _registry():
    return PatternRegistry(regex_patterns={"email": re.compile(r"\w+@example\.com")})


def _table(conn, name, value=EMAIL):
    conn.execute('CREATE TABLE "' + name + '"(id INTEGER PRIMARY KEY AUTOINCREMENT,payload TEXT)')
    conn.execute('INSERT INTO "' + name + '"(payload) VALUES (?)', (value,))


def test_verifier_covers_legal_sqlite_like_and_fts_like_names(tmp_path):
    database = tmp_path / "carriers.db"
    with closing(sqlite3.connect(database)) as conn, conn:
        for name in NAMES:
            _table(conn, name)
    incomplete = []
    findings = scan_sqlite_content(tmp_path, incomplete)
    assert not incomplete
    for name in NAMES:
        assert any(f":{name}.payload" in finding.path for finding in findings), name


def test_real_sanitizer_redacts_each_legal_name_without_corrupting_sequence(tmp_path):
    database = tmp_path / "carriers.db"
    with closing(sqlite3.connect(database)) as conn, conn:
        for name in NAMES:
            _table(conn, name)
    result = sanitize_database_generic(database, registry=_registry())
    assert not result.get("error"), result
    with closing(sqlite3.connect(database)) as conn:
        for name in NAMES:
            assert EMAIL not in conn.execute('SELECT payload FROM "' + name + '"').fetchone()[0]
        assert conn.execute("SELECT count(*) FROM sqlite_sequence").fetchone()[0] == len(NAMES)


@pytest.mark.parametrize("storage", ["VIRTUAL", "STORED"])
def test_generated_literal_carrier_is_found_and_not_falsely_sanitized(tmp_path, storage):
    database = tmp_path / "generated.db"
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute(
            f"CREATE TABLE records(id INTEGER,payload TEXT GENERATED ALWAYS AS "
            f"('carriercheck' || '@example.com') {storage})"
        )
        conn.execute("INSERT INTO records(id) VALUES (1)")
    incomplete = []
    findings = scan_sqlite_content(tmp_path, incomplete)
    assert findings or incomplete, "generated text must be scanned or explicitly unsupported"
    result = sanitize_database_generic(database, registry=_registry())
    assert result.get("error"), "immutable generated PII must not be certified sanitized"


def test_unused_fts5_docsize_name_is_a_real_user_carrier(tmp_path):
    database = tmp_path / "optional-shadow.db"
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("CREATE VIRTUAL TABLE search USING fts5(payload,columnsize=0)")
        conn.execute("INSERT INTO search(payload) VALUES ('ordinary searchable inventory')")
        # SQLite xShadowName may call this a shadow even though columnsize=0
        # means FTS does not create/use it. Give it the exact familiar shape.
        conn.execute("CREATE TABLE search_docsize(id INTEGER PRIMARY KEY,sz BLOB)")
        conn.execute("INSERT INTO search_docsize VALUES (1,?)", (EMAIL.encode(),))
    result = sanitize_database_generic(database, registry=_registry())
    assert not result.get("error"), result
    with closing(sqlite3.connect(database)) as conn:
        remaining = conn.execute("SELECT sz FROM search_docsize").fetchone()[0]
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert EMAIL.encode() not in remaining


def test_generated_projection_of_cleaned_source_is_not_mistaken_for_writable_storage(tmp_path):
    database = tmp_path / "projection.db"
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("CREATE TABLE records(payload TEXT, mirror TEXT AS (payload) VIRTUAL)")
        conn.execute("INSERT INTO records(payload) VALUES (?)", (EMAIL,))
    result = sanitize_database_generic(database, registry=_registry())
    assert not result.get("error"), result
    with closing(sqlite3.connect(database)) as conn:
        payload, mirror = conn.execute("SELECT payload,mirror FROM records").fetchone()
    assert EMAIL not in payload and payload == mirror


def test_verifier_uses_both_existing_text_byte_decoders(tmp_path):
    database = tmp_path / "text-bytes.db"
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("CREATE TABLE records(payload BLOB)")
        conn.execute("INSERT INTO records VALUES (?)", (EMAIL.encode("utf-16"),))
    assert scan_sqlite_content(tmp_path), "UTF-16 already supported by the writer must be verified"


def test_package_version_identity_is_consistent():
    import importlib.metadata
    import pathlib
    import hygeia

    project = (pathlib.Path(__file__).parent.parent / "pyproject.toml").read_text()
    assert f'version = "{hygeia.__version__}"' in project
    assert importlib.metadata.version("hygeia") == hygeia.__version__


def test_older_sqlite_metadata_fallback_uses_config_and_shapes_not_name_patterns():
    from hygeia.sqlite_catalog import table_inventory

    class WithoutTableList(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "PRAGMA table_list":
                return super().execute("SELECT 1 WHERE 0")
            return super().execute(sql, *args)

    with closing(sqlite3.connect(":memory:", factory=WithoutTableList)) as conn:
        _table(conn, "sqliteXextension")
        conn.execute("CREATE VIRTUAL TABLE search USING fts5(payload,columnsize=0)")
        conn.execute("CREATE TABLE search_docsize(id INTEGER PRIMARY KEY,sz BLOB)")
        inventory = table_inventory(conn)
        assert "sqliteXextension" in inventory and "sqlite_sequence" not in inventory
        assert inventory["search_data"].derived
        assert not inventory["search_docsize"].derived
        assert not inventory["search_config"].derived
        assert any(col[6] == 1 for col in inventory["search"].columns)


def test_actual_fts_configuration_rows_are_not_blindly_omitted(tmp_path):
    database = tmp_path / "fts-config.db"
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("CREATE VIRTUAL TABLE search USING fts5(payload)")
        conn.execute("INSERT INTO search_config(k,v) VALUES ('user_note',?)", (EMAIL,))
    incomplete = []
    findings = scan_sqlite_content(tmp_path, incomplete)
    assert findings or incomplete
    result = sanitize_database_generic(database, registry=_registry())
    with closing(sqlite3.connect(database)) as conn:
        value = conn.execute("SELECT v FROM search_config WHERE k='user_note'").fetchone()[0]
    assert result.get("error") or EMAIL not in value
