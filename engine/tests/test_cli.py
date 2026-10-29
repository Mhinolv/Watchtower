import json
import sqlite3

from watchtower_engine import cli
from watchtower_engine.cli import main
from watchtower_engine.models import SCHEMA_VERSION

from contract import FIXTURES, build_partial_state, check_fixture


def test_version_prints_json(capsys):
    assert main(["version"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["engine"]
    assert out["schema_version"] == SCHEMA_VERSION


def test_version_has_fixture_fields(capsys):
    # Same keys as the fixture. The version string itself changes with each release.
    assert main(["version"]) == 0
    out = json.loads(capsys.readouterr().out)
    fixture = json.loads((FIXTURES / "version.json").read_text())
    assert out.keys() == fixture.keys()


def test_state_on_empty_data_dir(tmp_path, capsys):
    assert main(["--data-dir", str(tmp_path / "data"), "state"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    check_fixture("state-empty.json", captured.out)


def test_state_after_partial_refresh_matches_fixture(tmp_path, capsys):
    build_partial_state(tmp_path / "data").close()
    assert main(["--data-dir", str(tmp_path / "data"), "state"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    check_fixture("state-partial.json", captured.out)


def test_state_reads_env_data_dir(tmp_path, monkeypatch, capsys):
    build_partial_state(tmp_path / "data").close()
    monkeypatch.setenv("WATCHTOWER_DATA_DIR", str(tmp_path / "data"))
    assert main(["state"]) == 0
    assert json.loads(capsys.readouterr().out)["refresh"]["status"] == "partial"


def test_store_error_goes_to_stderr_not_stdout(tmp_path, capsys):
    data = tmp_path / "data"
    build_partial_state(data).close()
    db = sqlite3.connect(data / "watchtower.sqlite3")
    db.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    db.commit()
    db.close()
    assert main(["--data-dir", str(data), "state"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    check_fixture("error.json", captured.err)


def test_unexpected_error_goes_to_stderr_not_stdout(tmp_path, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(cli, "Store", boom)
    assert main(["--data-dir", str(tmp_path), "state"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    err = json.loads(captured.err)
    assert err == {
        "schema_version": SCHEMA_VERSION,
        "error": "The Watchtower engine failed.",
        "detail": "RuntimeError('disk on fire')",
    }


def test_no_command_prints_help_to_stderr(capsys):
    assert main([]) == 2
    assert capsys.readouterr().out == ""
