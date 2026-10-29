import socket

import pytest


@pytest.fixture(autouse=True)
def _no_real_home(tmp_path, monkeypatch):
    """Tests never touch the real home folder or the real data folder."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("WATCHTOWER_DATA_DIR", raising=False)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Tests never use the network. A test that tries fails at once."""

    def refuse(*args, **kwargs):
        raise OSError("network is disabled in tests")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
