from __future__ import annotations

import sys
from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.audit import AuditErrorInfo, AuditRef
from envrcctl.errors import EnvrcctlError
from tests.helpers.cli_support import DummyBackend


def test_cli_exec_injects_secrets_into_child(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    script = "import os, sys; sys.exit(0 if os.getenv('TOKEN') == 'secretvalue' else 1)"
    result = runner.invoke(cli.app, ["exec", "--", sys.executable, "-c", script])
    assert result.exit_code == 0


def test_cli_exec_records_success_audit_event(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()
    audit_calls: list[dict] = []

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)
    monkeypatch.setattr(
        cli, "append_event", lambda **kwargs: audit_calls.append(kwargs)
    )
    monkeypatch.setattr(cli.sys, "platform", "linux")

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    script = "import os, sys; sys.exit(0 if os.getenv('TOKEN') == 'secretvalue' else 1)"
    result = runner.invoke(cli.app, ["exec", "--", sys.executable, "-c", script])

    assert result.exit_code == 0
    assert audit_calls == [
        {
            "action": "exec",
            "status": "success",
            "vars": ["TOKEN"],
            "refs": [
                AuditRef(
                    scheme="kc",
                    service="st.rio.envrcctl",
                    account="acct",
                    kind="runtime",
                )
            ],
            "cwd": tmp_path,
            "platform": "linux",
            "command": [sys.executable, "-c", script],
            "error": None,
        }
    ]


def test_cli_exec_records_failure_audit_event(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()
    audit_calls: list[dict] = []

    def fake_get(ref) -> str:
        raise EnvrcctlError("boom")

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(dummy, "get", fake_get)
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)
    monkeypatch.setattr(
        cli, "append_event", lambda **kwargs: audit_calls.append(kwargs)
    )
    monkeypatch.setattr(cli.sys, "platform", "linux")

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["exec", "--", "printenv"])

    assert result.exit_code == 1
    assert "boom" in result.stderr
    assert audit_calls == [
        {
            "action": "exec",
            "status": "failure",
            "vars": ["TOKEN"],
            "refs": [
                AuditRef(
                    scheme="kc",
                    service="st.rio.envrcctl",
                    account="acct",
                    kind="runtime",
                )
            ],
            "cwd": tmp_path,
            "platform": "linux",
            "command": ["printenv"],
            "error": AuditErrorInfo(code="exec_failed", message="boom"),
        }
    ]


def test_cli_exec_on_macos_requires_auth(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()
    auth_calls: list[tuple[list[tuple[str, str]], str | None]] = []

    def fake_get_many_with_auth(refs, reason: str | None = None):
        auth_calls.append(([(ref.service, ref.account) for ref in refs], reason))
        return {(ref.service, ref.account): dummy.get(ref) for ref in refs}

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(dummy, "get_many_with_auth", fake_get_many_with_auth)
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    script = "import os, sys; sys.exit(0 if os.getenv('TOKEN') == 'secretvalue' else 1)"
    result = runner.invoke(cli.app, ["exec", "--", sys.executable, "-c", script])

    assert result.exit_code == 0
    assert auth_calls == [
        (
            [("st.rio.envrcctl", "acct")],
            "Execute command with envrcctl",
        )
    ]


def test_cli_exec_on_macos_requires_interactive_shell(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_is_interactive", lambda: False)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["exec", "--", sys.executable, "-c", "print('x')"])

    assert result.exit_code == 1
    assert (
        "exec on macOS requires an interactive shell and device owner authentication."
        in result.stderr
    )


def test_cli_exec_on_macos_fails_closed_when_auth_is_cancelled(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    def fake_get_many_with_auth(refs, reason: str | None = None):
        raise EnvrcctlError("Authentication cancelled.")

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(dummy, "get_many_with_auth", fake_get_many_with_auth)
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["exec", "--", sys.executable, "-c", "print('x')"])

    assert result.exit_code == 1
    assert "Authentication cancelled." in result.stderr


def test_cli_exec_skips_admin_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

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
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

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


def test_cli_exec_requires_command(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["exec"])
    assert result.exit_code == 1
    assert "No command provided" in result.stderr


def test_cli_exec_missing_selected_secret(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(
        cli.app,
        ["exec", "-k", "MISSING", "--", sys.executable, "-c", "print('x')"],
    )
    assert result.exit_code == 1
    assert "Secrets not found" in result.stderr


def test_cli_exec_includes_exports_and_selected_secrets(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    runner.invoke(cli.app, ["set", "FOO", "bar"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input="secretvalue",
    )
    runner.invoke(
        cli.app,
        ["secret", "set", "OTHER", "--account", "other", "--stdin"],
        input="othervalue",
    )

    script = (
        "import os, sys; "
        "sys.exit(0 if (os.getenv('FOO')=='bar' and "
        "os.getenv('TOKEN')=='secretvalue' and "
        "os.getenv('OTHER') is None) else 1)"
    )
    result = runner.invoke(
        cli.app, ["exec", "-k", "TOKEN", "--", sys.executable, "-c", script]
    )
    assert result.exit_code == 0


def test_cli_exec_propagates_exit_code(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(
        cli.app, ["exec", "--", sys.executable, "-c", "import sys; sys.exit(2)"]
    )
    assert result.exit_code == 2
