from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.envrc import ENVRC_FILENAME
from envrcctl.managed_block import ManagedBlock, render_managed_block
from tests.helpers.cli_support import DummyBackend


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

    monkeypatch.setattr(cli.sys, "platform", "linux")

    result = runner.invoke(cli.app, ["inject", "--force"])
    assert result.exit_code == 0
    assert f"export TOKEN={secret}" in result.stdout
