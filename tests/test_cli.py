from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.envrc import ENVRC_FILENAME
from tests.helpers.cli_support import read_envrc


def test_cli_init_set_get_list_unset(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["init", "--inject"])
    assert result.exit_code == 0

    result = runner.invoke(cli.app, ["set", "FOO", "bar"])
    assert result.exit_code == 0

    result = runner.invoke(cli.app, ["get", "FOO"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "bar"

    result = runner.invoke(cli.app, ["list"])
    assert result.exit_code == 0
    assert "FOO=bar" in result.stdout

    result = runner.invoke(cli.app, ["unset", "FOO"])
    assert result.exit_code == 0

    result = runner.invoke(cli.app, ["list"])
    assert result.exit_code == 0
    assert "FOO=bar" not in result.stdout

    envrc_text = read_envrc(tmp_path / ENVRC_FILENAME)
    assert 'eval "$(envrcctl inject)"' in envrc_text


def test_cli_set_adds_inject_line_when_requested(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["set", "FOO", "bar", "--inject"])
    assert result.exit_code == 0

    envrc_text = read_envrc(tmp_path / ENVRC_FILENAME)
    assert 'eval "$(envrcctl inject)"' in envrc_text


def test_cli_inherit_on_off(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["inherit", "on"])
    assert result.exit_code == 0
    assert "source_up" in read_envrc(tmp_path / ENVRC_FILENAME)

    result = runner.invoke(cli.app, ["inherit", "off"])
    assert result.exit_code == 0
    assert "source_up" not in read_envrc(tmp_path / ENVRC_FILENAME)


def test_find_nearest_envrc_dir_returns_none(tmp_path: Path) -> None:
    assert cli._find_nearest_envrc_dir(tmp_path) is None


def test_init_warns_when_world_writable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    envrc_path = tmp_path / ENVRC_FILENAME
    envrc_path.write_text("# placeholder\n", encoding="utf-8")
    envrc_path.chmod(0o666)

    result = runner.invoke(cli.app, ["init", "--yes"])
    assert result.exit_code == 1
    assert "world-writable" in result.stderr
