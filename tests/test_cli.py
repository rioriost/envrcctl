from __future__ import annotations

import os
import sys
from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.envrc import ENVRC_FILENAME
from envrcctl.errors import EnvrcctlError
from envrcctl.managed_block import ManagedBlock, render_managed_block
from tests.helpers.cli_support import DummyBackend, read_envrc


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


def test_cli_eval_includes_parent(tmp_path: Path, monkeypatch) -> None:
    parent_dir = tmp_path / "parent"
    child_dir = parent_dir / "child"
    child_dir.mkdir(parents=True)
    monkeypatch.chdir(child_dir)

    parent_block = ManagedBlock(exports={"PARENT": "one"}, include_inject=False)
    (parent_dir / ENVRC_FILENAME).write_text(
        render_managed_block(parent_block), encoding="utf-8"
    )

    child_block = ManagedBlock(
        inherit=True,
        exports={"CHILD": "two"},
        secret_refs={"TOKEN": "kc:svc:acct"},
        include_inject=False,
    )
    (child_dir / ENVRC_FILENAME).write_text(
        render_managed_block(child_block), encoding="utf-8"
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["eval"])
    assert result.exit_code == 0
    assert "PARENT = one" in result.stdout
    assert "CHILD = two" in result.stdout
    assert "TOKEN = ******" in result.stdout


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


def test_eval_stops_when_no_parent_envrc(tmp_path: Path, monkeypatch) -> None:
    child_dir = tmp_path / "child"
    child_dir.mkdir()
    monkeypatch.chdir(child_dir)

    block = ManagedBlock(
        inherit=True,
        exports={"CHILD": "two"},
        include_inject=False,
    )
    (child_dir / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["eval"])
    assert result.exit_code == 0
    assert "CHILD = two" in result.stdout


def test_eval_stops_when_parent_has_no_managed_block(
    tmp_path: Path, monkeypatch
) -> None:
    parent_dir = tmp_path / "parent"
    child_dir = parent_dir / "child"
    child_dir.mkdir(parents=True)

    (parent_dir / ENVRC_FILENAME).write_text("export PARENT=1\n", encoding="utf-8")

    block = ManagedBlock(
        inherit=True,
        exports={"CHILD": "two"},
        include_inject=False,
    )
    (child_dir / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )

    monkeypatch.chdir(child_dir)
    runner = CliRunner()
    result = runner.invoke(cli.app, ["eval"])
    assert result.exit_code == 0
    assert "CHILD = two" in result.stdout
    assert "PARENT =" not in result.stdout


def test_cli_eval_includes_parent(tmp_path: Path, monkeypatch) -> None:
    parent_dir = tmp_path / "parent"
    child_dir = parent_dir / "child"
    child_dir.mkdir(parents=True)
    monkeypatch.chdir(child_dir)

    parent_block = ManagedBlock(exports={"PARENT": "one"}, include_inject=False)
    (parent_dir / ENVRC_FILENAME).write_text(
        render_managed_block(parent_block), encoding="utf-8"
    )

    child_block = ManagedBlock(
        inherit=True,
        exports={"CHILD": "two"},
        secret_refs={"TOKEN": "kc:svc:acct"},
        include_inject=False,
    )
    (child_dir / ENVRC_FILENAME).write_text(
        render_managed_block(child_block), encoding="utf-8"
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["eval"])
    assert result.exit_code == 0
    assert "PARENT = one" in result.stdout
    assert "CHILD = two" in result.stdout
    assert "TOKEN = ******" in result.stdout


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


def test_eval_stops_when_no_parent_envrc(tmp_path: Path, monkeypatch) -> None:
    child_dir = tmp_path / "child"
    child_dir.mkdir()
    monkeypatch.chdir(child_dir)

    block = ManagedBlock(
        inherit=True,
        exports={"CHILD": "two"},
        include_inject=False,
    )
    (child_dir / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["eval"])
    assert result.exit_code == 0
    assert "CHILD = two" in result.stdout


def test_eval_stops_when_parent_has_no_managed_block(
    tmp_path: Path, monkeypatch
) -> None:
    parent_dir = tmp_path / "parent"
    child_dir = parent_dir / "child"
    child_dir.mkdir(parents=True)

    (parent_dir / ENVRC_FILENAME).write_text("export PARENT=1\n", encoding="utf-8")

    block = ManagedBlock(
        inherit=True,
        exports={"CHILD": "two"},
        include_inject=False,
    )
    (child_dir / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )

    monkeypatch.chdir(child_dir)
    runner = CliRunner()
    result = runner.invoke(cli.app, ["eval"])
    assert result.exit_code == 0
    assert "CHILD = two" in result.stdout
    assert "PARENT =" not in result.stdout
