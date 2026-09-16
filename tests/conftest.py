import pytest

from envrcctl import cli


@pytest.fixture(autouse=True)
def _isolated_user_state(tmp_path, monkeypatch):
    home = tmp_path / "test-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / "state"))


@pytest.fixture(autouse=True)
def _direnv_available(monkeypatch):
    original = cli.shutil.which

    def fake_which(cmd, *args, **kwargs):
        if cmd == "direnv":
            return "/usr/bin/direnv"
        return original(cmd, *args, **kwargs)

    monkeypatch.setattr(cli.shutil, "which", fake_which)
