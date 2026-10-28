"""Informational commands do not require a processing destination."""

import pytest

from hygeia import cli


def test_list_patterns_without_paths(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["hygeia", "--list-patterns"])

    def unexpected_processing(*args, **kwargs):
        pytest.fail("Listing patterns must not start file processing")

    monkeypatch.setattr(cli, "copy_dump", unexpected_processing)
    monkeypatch.setattr(cli, "FileScanner", unexpected_processing)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    output = capsys.readouterr()
    assert "Available PII pattern categories:" in output.out
    assert "identity:" in output.out
    assert "credit_card" in output.out
    assert not output.err


@pytest.mark.parametrize(
    ("arguments", "missing"),
    [([], ("--input", "--output")),
     (["--input", "data"], ("--output",)),
     (["--output", "clean"], ("--input",)),
     (["--dry-run"], ("--input", "--output"))],
)
def test_processing_requires_paths(arguments, missing, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["hygeia", *arguments])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "required" in error
    for option in missing:
        assert option in error
