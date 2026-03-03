from __future__ import annotations

import sys
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

    result = runner.invoke(cli.app, ["inject", "--force"])
    assert result.exit_code == 0
    assert "export OPENAI_API_KEY=secretvalue" in result.stdout

    result = runner.invoke(cli.app, ["secret", "unset", "OPENAI_API_KEY"])
    assert result.exit_code == 0
    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_OPENAI_API_KEY" not in envrc_text


def test_cli_exec_injects_secrets_into_child(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    script = "import os, sys; sys.exit(0 if os.getenv('TOKEN') == 'secretvalue' else 1)"
    result = runner.invoke(cli.app, ["exec", "--", sys.executable, "-c", script])
    assert result.exit_code == 0


def test_cli_exec_skips_admin_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        [
            "secret",
            "set",
            "ADMIN_TOKEN",
            "--account",
            "acct",
            "--kind",
            "admin",
            "--stdin",
        ],
        input="secretvalue",
    )

    script = "import os, sys; sys.exit(0 if os.getenv('ADMIN_TOKEN') is None else 1)"
    result = runner.invoke(cli.app, ["exec", "--", sys.executable, "-c", script])
    assert result.exit_code == 0


def test_cli_exec_rejects_admin_when_selected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        [
            "secret",
            "set",
            "ADMIN_TOKEN",
            "--account",
            "acct",
            "--kind",
            "admin",
            "--stdin",
        ],
        input="secretvalue",
    )

    result = runner.invoke(
        cli.app,
        ["exec", "-k", "ADMIN_TOKEN", "--", sys.executable, "-c", "print('x')"],
    )
    assert result.exit_code == 1
    assert "admin" in result.stderr


def test_cli_inject_requires_tty(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["inject"])
    assert result.exit_code == 1
    assert "inject is blocked" in result.stderr


def test_cli_inject_skips_admin_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "RUNTIME_TOKEN", "--account", "runtime", "--stdin"],
        input="runtimevalue",
    )
    runner.invoke(
        cli.app,
        [
            "secret",
            "set",
            "ADMIN_TOKEN",
            "--account",
            "admin",
            "--kind",
            "admin",
            "--stdin",
        ],
        input="adminvalue",
    )

    result = runner.invoke(cli.app, ["inject", "--force"])
    assert result.exit_code == 0
    assert "RUNTIME_TOKEN=runtimevalue" in result.stdout
    assert "ADMIN_TOKEN" not in result.stdout


def test_cli_secret_get_copies_masked(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()
    copied: Dict[str, str] = {}

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)
    monkeypatch.setattr(
        cli, "_copy_to_clipboard", lambda value: copied.setdefault("value", value)
    )

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="supersecretvalue",
    )

    result = runner.invoke(cli.app, ["secret", "get", "TOKEN"])
    assert result.exit_code == 0
    assert copied["value"] == "supersecretvalue"
    assert "TOKEN=" in result.stdout
    assert "supersecretvalue" not in result.stdout


def test_cli_secret_get_plain_interactive(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="supersecretvalue",
    )

    result = runner.invoke(cli.app, ["secret", "get", "TOKEN", "--plain"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "supersecretvalue"


def test_cli_secret_get_force_plain_non_interactive(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="supersecretvalue",
    )

    result = runner.invoke(cli.app, ["secret", "get", "TOKEN", "--force-plain"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "supersecretvalue"


def test_cli_outputs_do_not_leak_secret_except_inject(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])

    secret = "supersecret"
    result = runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input=secret,
    )
    assert result.exit_code == 0
    assert secret not in result.stdout
    assert secret not in result.stderr

    for args in [
        ["secret", "list"],
        ["eval"],
        ["doctor"],
    ]:
        result = runner.invoke(cli.app, args)
        assert result.exit_code == 0
        assert secret not in result.stdout
        assert secret not in result.stderr

    result = runner.invoke(cli.app, ["inject", "--force"])
    assert result.exit_code == 0
    assert f"export TOKEN={secret}" in result.stdout


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


def test_cli_doctor_warns_for_plaintext_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(exports={"API_TOKEN": "plaintext"}, include_inject=True)
    (tmp_path / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "possible plaintext secrets" in result.stderr


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

    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert "export OUTSIDE=1" in envrc_text
    assert "ENVRCCTL_SECRET_API_KEY" in envrc_text


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


def test_secret_set_uses_getpass(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: "secretvalue")

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "set", "TOKEN", "--account", "acct"])
    assert result.exit_code == 0

    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_TOKEN" in envrc_text


def test_secret_unset_missing_ref(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "unset", "MISSING"])
    assert result.exit_code == 1
    assert "has no secret reference" in result.stderr


def test_secret_list_outputs_refs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(
        secret_refs={"TOKEN": "kc:svc:acct"},
        include_inject=False,
    )
    (tmp_path / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )

    result = runner.invoke(cli.app, ["secret", "list"])
    assert result.exit_code == 0
    assert "TOKEN=kc:svc:acct" in result.stdout


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


def test_doctor_warns_when_no_managed_block(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    (tmp_path / ENVRC_FILENAME).write_text("export FOO=bar\n", encoding="utf-8")

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "Managed block not found" in result.stderr


def test_doctor_warns_for_unmanaged_secret_refs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=True)
    content = "\n".join(
        [
            "export ENVRCCTL_SECRET_API_KEY=kc:svc:acct",
            render_managed_block(block).rstrip(),
        ]
    )
    (tmp_path / ENVRC_FILENAME).write_text(content, encoding="utf-8")

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "unmanaged secret refs outside block" in result.stderr


def test_doctor_ok_when_no_warnings(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=True)
    (tmp_path / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "OK"
