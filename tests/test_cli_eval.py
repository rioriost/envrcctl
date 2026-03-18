from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.envrc import ENVRC_FILENAME
from envrcctl.managed_block import ManagedBlock, render_managed_block


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
