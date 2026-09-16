from __future__ import annotations

from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.envrc import ENVRC_FILENAME
from envrcctl.errors import EnvrcctlError


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


def test_secret_get_on_macos_requires_interactive_even_with_force_plain(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    class DummyBackend:
        def __init__(self) -> None:
            self._store: dict[tuple[str, str], str] = {}

        def get(self, ref) -> str:
            return self._store[(ref.service, ref.account)]

        def get_with_auth(self, ref, reason: str | None = None) -> str:
            return self.get(ref)

        def set(self, ref, value: str) -> None:
            self._store[(ref.service, ref.account)] = value

        def delete(self, ref) -> None:
            self._store.pop((ref.service, ref.account), None)

        def list(self, prefix: str | None = None):
            return []

    dummy = DummyBackend()
    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli.sys, "platform", "darwin")

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["secret", "get", "TOKEN", "--force-plain"])
    assert result.exit_code == 1
    assert (
        "secret get on macOS requires an interactive shell and device owner authentication."
        in result.stderr
    )


def test_inject_on_macos_requires_interactive_even_with_force(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    monkeypatch.setattr(cli.sys, "platform", "darwin")

    result = runner.invoke(cli.app, ["inject", "--force"])
    assert result.exit_code == 1
    assert (
        "inject on macOS requires an interactive shell and device owner authentication."
        in result.stderr
    )


def test_get_secret_values_without_bulk_support_falls_back_to_single_fetch(
    monkeypatch,
) -> None:
    class SingleOnlyBackend:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, str | None]] = []

        def get(self, ref) -> str:
            return f"value-{ref.account}"

        def get_with_auth(self, ref, reason: str | None = None) -> str:
            self.calls.append((ref.service, ref.account, reason))
            return f"value-{ref.account}"

        def set(self, ref, value: str) -> None:
            raise AssertionError("not used")

        def delete(self, ref) -> None:
            raise AssertionError("not used")

        def list(self, prefix: str | None = None):
            return []

    backend = SingleOnlyBackend()
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: backend)

    refs = [
        cli.parse_ref("kc:svc:acct1:runtime"),
        cli.parse_ref("kc:svc:acct2:runtime"),
    ]

    with pytest.raises(EnvrcctlError, match="does not support authenticated access"):
        cli._get_secret_values(refs, "Authenticate for envrcctl")
    assert backend.calls == []


def test_get_secret_values_uses_first_backend_on_non_macos(monkeypatch) -> None:
    class Backend:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, str | None]] = []

        def get(self, ref) -> str:
            self.calls.append((ref.service, ref.account, None))
            return f"value-{ref.account}"

        def get_with_auth(self, ref, reason: str | None = None) -> str:
            raise AssertionError("not used")

        def set(self, ref, value: str) -> None:
            raise AssertionError("not used")

        def delete(self, ref) -> None:
            raise AssertionError("not used")

        def list(self, prefix: str | None = None):
            return []

    backend = Backend()
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: backend)

    refs = [
        cli.parse_ref("kc:svc:acct1:runtime"),
        cli.parse_ref("kc:svc:acct2:runtime"),
    ]

    values = cli._get_secret_values(refs, None)

    assert values == {
        ("kc", "svc", "acct1"): "value-acct1",
        ("kc", "svc", "acct2"): "value-acct2",
    }
    assert backend.calls == [
        ("svc", "acct1", None),
        ("svc", "acct2", None),
    ]


def test_exec_propagates_non_envrcctl_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    runner.invoke(cli.app, ["init"])

    result = runner.invoke(cli.app, ["exec", "--", "printenv"])
    assert result.exit_code == 1
    assert isinstance(result.exception, RuntimeError)
    assert str(result.exception) == "boom"


def test_secret_get_propagates_non_envrcctl_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    class DummyBackend:
        def __init__(self) -> None:
            self._store: dict[tuple[str, str], str] = {}

        def get(self, ref) -> str:
            raise RuntimeError("boom")

        def get_with_auth(self, ref, reason: str | None = None) -> str:
            raise RuntimeError("boom")

        def set(self, ref, value: str) -> None:
            self._store[(ref.service, ref.account)] = value

        def delete(self, ref) -> None:
            self._store.pop((ref.service, ref.account), None)

        def list(self, prefix: str | None = None):
            return []

    dummy = DummyBackend()
    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)
    monkeypatch.setattr(cli, "_copy_to_clipboard", lambda value: None)
    monkeypatch.setattr(cli.sys, "platform", "linux")

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["secret", "get", "TOKEN"])
    assert result.exit_code == 1
    assert isinstance(result.exception, RuntimeError)
    assert str(result.exception) == "boom"


def test_run_wraps_envrcctl_error_into_exit() -> None:
    with pytest.raises(typer.Exit) as exc:
        cli._run(lambda: (_ for _ in ()).throw(EnvrcctlError("wrapped error")))

    assert exc.value.exit_code == 1


def test_mask_secret_masks_short_values() -> None:
    assert cli._mask_secret("short") == "*****"


def test_clipboard_command_prefers_pbcopy_on_macos(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "darwin")

    def fake_which(cmd: str) -> str | None:
        if cmd == "pbcopy":
            return "/usr/bin/pbcopy"
        return None

    monkeypatch.setattr(cli.shutil, "which", fake_which)

    assert cli._clipboard_command() == ["pbcopy"]


def test_clipboard_command_uses_xclip_when_available(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "linux")

    def fake_which(cmd: str) -> str | None:
        if cmd == "xclip":
            return "/usr/bin/xclip"
        return None

    monkeypatch.setattr(cli.shutil, "which", fake_which)

    assert cli._clipboard_command() == ["xclip", "-selection", "clipboard"]


def test_clipboard_command_uses_xsel_when_xclip_missing(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "linux")

    def fake_which(cmd: str) -> str | None:
        if cmd == "xsel":
            return "/usr/bin/xsel"
        return None

    monkeypatch.setattr(cli.shutil, "which", fake_which)

    assert cli._clipboard_command() == ["xsel", "--clipboard", "--input"]


def test_clipboard_command_returns_none_when_no_tool(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli.shutil, "which", lambda cmd: None)

    assert cli._clipboard_command() is None


def test_copy_to_clipboard_calls_run_command(monkeypatch) -> None:
    calls: list[tuple[list[str], str | None, set[str], str]] = []

    monkeypatch.setattr(cli, "_clipboard_command", lambda: ["pbcopy"])

    def fake_run_command(args, input_text=None, allowed_commands=None, error_message="") -> None:
        calls.append((args, input_text, allowed_commands, error_message))

    monkeypatch.setattr(cli, "run_command", fake_run_command)

    cli._copy_to_clipboard("secret")

    assert calls == [
        (
            ["pbcopy"],
            "secret",
            {"pbcopy"},
            "Clipboard command failed.",
        )
    ]


def test_copy_to_clipboard_requires_tool(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_clipboard_command", lambda: None)

    with pytest.raises(EnvrcctlError) as exc:
        cli._copy_to_clipboard("secret")

    assert "Clipboard tool not available" in str(exc.value)


def test_confirm_or_abort_raises_when_confirmation_rejected(monkeypatch) -> None:
    monkeypatch.setattr(cli.typer, "confirm", lambda message, default=False: False)

    with pytest.raises(EnvrcctlError) as exc:
        cli._confirm_or_abort("Proceed?", assume_yes=False)

    assert "Operation cancelled." in str(exc.value)


def test_ensure_not_world_writable_allows_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / ENVRC_FILENAME

    cli._ensure_not_world_writable(missing)


def test_write_envrc_raises_when_write_warns(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    def fake_write_envrc(path, doc, block):
        return True

    monkeypatch.setattr(cli, "write_envrc", fake_write_envrc)

    doc = cli.load_envrc(tmp_path / ENVRC_FILENAME)
    block = cli.ensure_managed_block(doc)

    with pytest.raises(EnvrcctlError) as exc:
        cli._write_envrc(doc, block)

    assert "world-writable after write" in str(exc.value)


def test_exec_blocked_in_non_interactive_on_linux(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    monkeypatch.setattr(cli.sys, "platform", "linux")

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["exec", "--", "printenv"])

    assert result.exit_code == 1
    assert "exec is blocked in non-interactive environments." in result.stderr
