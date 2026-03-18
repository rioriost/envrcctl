from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.audit import AuditErrorInfo, AuditRef
from envrcctl.errors import EnvrcctlError
from tests.helpers.cli_support import DummyBackend


def test_cli_inject_records_success_audit_event(tmp_path: Path, monkeypatch) -> None:
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

    result = runner.invoke(cli.app, ["inject"])

    assert result.exit_code == 0
    assert "export TOKEN=secretvalue" in result.stdout
    assert audit_calls == [
        {
            "action": "inject",
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
            "command": None,
            "error": None,
        }
    ]


def test_cli_inject_records_failure_audit_event(tmp_path: Path, monkeypatch) -> None:
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

    result = runner.invoke(cli.app, ["inject"])

    assert result.exit_code == 1
    assert "boom" in result.stderr
    assert audit_calls == [
        {
            "action": "inject",
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
            "command": None,
            "error": AuditErrorInfo(code="inject_failed", message="boom"),
        }
    ]


def test_cli_inject_on_macos_requires_auth(tmp_path: Path, monkeypatch) -> None:
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

    result = runner.invoke(cli.app, ["inject"])
    assert result.exit_code == 0
    assert "export TOKEN=secretvalue" in result.stdout
    assert auth_calls == [
        ([("st.rio.envrcctl", "acct")], "Inject secrets with envrcctl")
    ]


def test_cli_inject_on_macos_force_does_not_bypass_auth_failure(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    def fake_get_many_with_auth(refs, reason: str | None = None):
        raise EnvrcctlError("Authentication unavailable.")

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

    result = runner.invoke(cli.app, ["inject", "--force"])
    assert result.exit_code == 1
    assert "Authentication unavailable." in result.stderr


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

    monkeypatch.setattr(cli.sys, "platform", "linux")

    result = runner.invoke(cli.app, ["inject", "--force"])
    assert result.exit_code == 0
    assert "RUNTIME_TOKEN=runtimevalue" in result.stdout
    assert "ADMIN_TOKEN" not in result.stdout
