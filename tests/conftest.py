import pytest

from envrcctl import cli


@pytest.fixture(autouse=True)
def _direnv_available(monkeypatch):
    original = cli.shutil.which

    def fake_which(cmd, *args, **kwargs):
        if cmd == "direnv":
            return "/usr/bin/direnv"
        return original(cmd, *args, **kwargs)

    monkeypatch.setattr(cli.shutil, "which", fake_which)
