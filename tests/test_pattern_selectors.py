"""Selector errors must stop processing; accepted exclusions must take effect."""

import pytest

from hygeia import cli
from hygeia import verifier
from hygeia.patterns import list_available, load_patterns


def test_known_category_preserves_context_detectors():
    selected = load_patterns(only=["financial"])
    skipped = load_patterns(skip=["crypto"])
    assert selected.active_categories == {"financial"}
    assert "credit_card" in selected.regex_patterns
    assert selected.context_patterns.keys() >= set(list_available()["_context"])
    assert "crypto" not in skipped.active_categories
    assert skipped.context_patterns.keys() >= set(list_available()["_context"])


def test_known_individual_include_and_exclusions():
    default = load_patterns()
    selected = load_patterns(only=["credit_card"])
    skipped = load_patterns(skip=["credit_card", "date_of_birth"])
    assert set(selected.regex_patterns) == {"credit_card"}
    assert "credit_card" in default.regex_patterns
    assert "date_of_birth" in default.context_patterns
    assert "credit_card" not in skipped.regex_patterns
    assert "date_of_birth" not in skipped.context_patterns
    assert set(skipped.regex_patterns) == set(default.regex_patterns) - {"credit_card"}
    assert set(skipped.context_patterns) == set(default.context_patterns) - {"date_of_birth"}


def test_category_and_individual_exclusions_can_be_combined():
    skipped = load_patterns(skip=["crypto", "credit_card"])
    assert "crypto" not in skipped.active_categories
    assert "bitcoin_address" not in skipped.regex_patterns
    assert "credit_card" not in skipped.regex_patterns
    assert "email" in skipped.regex_patterns


@pytest.mark.parametrize(("filters", "label"), [({"only": ["credit_card"]}, "only=credit_card"),
                                               ({"skip": ["credit_card", "date_of_birth"]},
                                                "skip=credit_card, date_of_birth")])
def test_scope_label_exposes_individual_selectors(filters, label, tmp_path):
    verifier.configure(**filters)
    try:
        result = verifier.verify_sanitization(tmp_path)
        assert result.scope == label
        assert result.passed
    finally:
        verifier.configure()


@pytest.mark.parametrize("filters", [{"only": ["exif"]}, {"skip": ["unknown"]},
                                    {"only": [""]}, {"only": ["financial"], "skip": ["crypto"]}])
def test_registry_rejects_invalid_filters(filters):
    with pytest.raises(ValueError):
        load_patterns(**filters)


@pytest.mark.parametrize("arguments", [["--only", "exif"], ["--skip-patterns", "unknown"],
                                       ["--only", ""], ["--skip-patterns", "crypto,"],
                                       ["--only", "financial", "--skip-patterns", "crypto"]])
def test_invalid_cli_filters_have_no_filesystem_side_effects(arguments, monkeypatch, tmp_path, capsys):
    source = tmp_path / "data"
    source.mkdir()
    fixture = source / "notes.txt"
    fixture.write_text("contact: fixture.person@example.com\n")
    original = fixture.read_bytes()
    output = tmp_path / "clean"
    manifest = tmp_path / "audit.json"
    monkeypatch.setattr("sys.argv", ["hygeia", "--input", str(source), "--output", str(output),
                                    "--manifest", str(manifest), *arguments])

    def unexpected_processing(*args, **kwargs):
        pytest.fail("Invalid selectors must stop before copying or scanning")

    monkeypatch.setattr(cli, "copy_dump", unexpected_processing)
    monkeypatch.setattr(cli, "FileScanner", unexpected_processing)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err
    assert not output.exists()
    assert not manifest.exists()
    assert fixture.read_bytes() == original
