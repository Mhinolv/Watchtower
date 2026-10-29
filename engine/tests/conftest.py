import pytest


@pytest.fixture(autouse=True)
def _no_real_home(tmp_path, monkeypatch):
    """Tests never touch the real home folder or the real data folder."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("WATCHTOWER_DATA_DIR", raising=False)
