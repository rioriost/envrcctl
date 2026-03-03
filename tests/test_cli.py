from __future__ import annotations

from pathlib import Path
from typing import Dict

from typer.testing import CliRunner

from envrctl import cli
from envrctl.envrc import ENVRC_FILENAME
from envrctl.managed_block import ManagedBlock, render_managed_block


class DummyBackend:
    def __init__(self) -> None:
        self._store: Dict[tuple[str, str], str] = {}

    def get(self, ref) -> str:
        return self._store[(ref.service, ref.account)]

    def set(self, ref, value: str) -> None:
        self._store[(ref.service, ref.account)] = value

    def delete(self, ref) -> None:
        self._store.pop((ref.service, ref.account), None)

    def list(self, prefix: str | None = None):
        return []


def _read_envrc(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_cli_init_set_get_list_unset(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["init"])
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

    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert 'eval "$(envrcctl inject)"' in envrc_text


def test_cli_inherit_on_off(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["inherit", "on"])
    assert result.exit_code == 0
    assert "source_up" in _read_envrc(tmp_path / ENVRC_FILENAME)

    result = runner.invoke(cli.app, ["inherit", "off"])
    assert result.exit_code == 0
    assert "source_up" not in _read_envrc(tmp_path / ENVRC_FILENAME)


def test_cli_secret_set_inject_unset(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])

    result = runner.invoke(
        cli.app,
        ["secret", "set", "OPENAI_API_KEY", "--account", "openai:prod", "--stdin"],
        input="secretvalue",
    )
    assert result.exit_code == 0
    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_OPENAI_API_KEY" in envrc_text

    result = runner.invoke(cli.app, ["inject"])
    assert result.exit_code == 0
    assert "export OPENAI_API_KEY=secretvalue" in result.stdout

    result = runner.invoke(cli.app, ["secret", "unset", "OPENAI_API_KEY"])
    assert result.exit_code == 0
    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_OPENAI_API_KEY" not in envrc_text


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


def test_cli_doctor_warns_for_unmanaged_and_missing_inject(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=False)
    content = "\n".join(
        [
            "export UNMANAGED=1",
            render_managed_block(block).rstrip(),
            "# trailing",
        ]
    )
    (tmp_path / ENVRC_FILENAME).write_text(content, encoding="utf-8")

    monkeypatch.setattr(cli, "is_world_writable", lambda _: True)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "world-writable" in result.stderr
    assert "inject line missing" in result.stderr
    assert "unmanaged exports outside block" in result.stderr


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

    result = runner.invoke(cli.app, ["migrate"])
    assert result.exit_code == 0

    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert "export OUTSIDE=1" in envrc_text
    assert "ENVRCCTL_SECRET_API_KEY" in envrc_text
