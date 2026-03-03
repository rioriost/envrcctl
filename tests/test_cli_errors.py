from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.envrc import ENVRC_FILENAME


def test_init_fails_when_direnv_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    def fake_which(cmd, *args, **kwargs):
        if cmd == "direnv":
            return None
        return "/usr/bin/other"

    monkeypatch.setattr(cli.shutil, "which", fake_which)

    result = runner.invoke(cli.app, ["init"])
    assert result.exit_code == 1
    assert "direnv not found" in result.stderr


def test_set_rejects_invalid_env_var(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["set", "not-valid", "value"])
    assert result.exit_code == 1
    assert "Invalid environment variable name" in result.stderr


def test_inherit_rejects_invalid_state(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["inherit", "maybe"])
    assert result.exit_code == 1
    assert "inherit expects" in result.stderr


def test_get_missing_var_errors(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["get", "MISSING"])
    assert result.exit_code == 1
    assert "is not set in the managed block" in result.stderr


def test_secret_set_rejects_empty_value(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="",
    )
    assert result.exit_code == 1
    assert "Secret value is empty" in result.stderr


def test_secret_get_blocked_in_non_interactive(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    class DummyBackend:
        def __init__(self) -> None:
            self._store: dict[tuple[str, str], str] = {}

        def get(self, ref) -> str:
            return self._store[(ref.service, ref.account)]

        def set(self, ref, value: str) -> None:
            self._store[(ref.service, ref.account)] = value

        def delete(self, ref) -> None:
            self._store.pop((ref.service, ref.account), None)

        def list(self, prefix: str | None = None):
            return []

    dummy = DummyBackend()
    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["secret", "get", "TOKEN"])
    assert result.exit_code == 1
    assert "secret get is blocked in non-interactive environments" in result.stderr


def test_inject_blocked_in_non_interactive(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["inject"])
    assert result.exit_code == 1
    assert "inject is blocked in non-interactive environments" in result.stderr


def test_eval_requires_managed_block(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["eval"])
    assert result.exit_code == 1
    assert "Managed block not found" in result.stderr


def test_doctor_requires_envrc(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 1
    assert ".envrc not found" in result.stderr


def test_migrate_requires_envrc(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["migrate"])
    assert result.exit_code == 1
    assert ".envrc not found" in result.stderr
