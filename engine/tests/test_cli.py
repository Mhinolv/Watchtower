import json

from watchtower_engine.cli import main


def test_version_prints_json(capsys):
    assert main(["version"]) == 0
    assert json.loads(capsys.readouterr().out)["engine"]
