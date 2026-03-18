from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.envrc import ENVRC_FILENAME
from tests.helpers.cli_support import read_envrc


def test_cli_migrate_moves_unmanaged_exports(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    content = "\n".join(
        [
            "export OUTSIDE=1",
            "export ENVRCCTL_SECRET_API_KEY=kc:svc:acct",
        ]
    )
    (tmp_path / ENVRC_FILENAME).write_text(content, encoding="utf-8")

    result = runner.invoke(cli.app, ["migrate", "--yes"])
    assert result.exit_code == 0

    envrc_text = read_envrc(tmp_path / ENVRC_FILENAME)
    assert "export OUTSIDE=1" in envrc_text
    assert "ENVRCCTL_SECRET_API_KEY" in envrc_text


def test_cli_migrate_adds_inject_line_when_requested(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    content = "\n".join(
        [
            "export OUTSIDE=1",
            "export ENVRCCTL_SECRET_API_KEY=kc:svc:acct",
        ]
    )
    (tmp_path / ENVRC_FILENAME).write_text(content, encoding="utf-8")

    result = runner.invoke(cli.app, ["migrate", "--yes", "--inject"])
    assert result.exit_code == 0

    envrc_text = read_envrc(tmp_path / ENVRC_FILENAME)
    assert 'eval "$(envrcctl inject)"' in envrc_text
