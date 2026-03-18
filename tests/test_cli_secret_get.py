from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.audit import AuditErrorInfo, AuditRef
from envrcctl.errors import EnvrcctlError
from tests.helpers.cli_support import DummyBackend


def test_cli_secret_get_records_success_audit_event(
    tmp_path: Path, monkeypatch
) -> None:
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

    result = runner.invoke(cli.app, ["secret", "get", "TOKEN", "--plain"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "secretvalue"
    assert audit_calls == [
        {
            "action": "secret_get",
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


def test_cli_secret_get_records_failure_audit_event(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()
    audit_calls: list[dict] = []

    def fake_get(ref) -> str:
        raise EnvrcctlError("boom")

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(dummy, "get", fake_get)
    monkeypatch.setattr(cli, "_is_interactive", lambda: False)
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

    result = runner.invoke(cli.app, ["secret", "get", "TOKEN", "--force-plain"])

    assert result.exit_code == 1
    assert "boom" in result.stderr
    assert audit_calls == [
        {
            "action": "secret_get",
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
            "error": AuditErrorInfo(code="secret_get_failed", message="boom"),
        }
    ]


def test_cli_secret_get_on_macos_requires_auth_for_plain_output(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()
    auth_calls: list[tuple[str, str, str | None]] = []

    def fake_get_with_auth(ref, reason: str | None = None) -> str:
        auth_calls.append((ref.service, ref.account, reason))
        return dummy.get(ref)

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(dummy, "get_with_auth", fake_get_with_auth)
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "OPENAI_API_KEY", "--account", "openai:prod", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["secret", "get", "OPENAI_API_KEY", "--plain"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "secretvalue"
    assert auth_calls == [
        (
            "st.rio.envrcctl",
            "openai:prod",
            "Access secret OPENAI_API_KEY with envrcctl",
        )
    ]


def test_cli_secret_get_on_macos_requires_auth_for_clipboard_default(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()
    auth_calls: list[tuple[str, str, str | None]] = []
    clipboard: list[str] = []

    def fake_get_with_auth(ref, reason: str | None = None) -> str:
        auth_calls.append((ref.service, ref.account, reason))
        return dummy.get(ref)

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(dummy, "get_with_auth", fake_get_with_auth)
    monkeypatch.setattr(
        cli, "_copy_to_clipboard", lambda value: clipboard.append(value)
    )
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "OPENAI_API_KEY", "--account", "openai:prod", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["secret", "get", "OPENAI_API_KEY"])
    assert result.exit_code == 0
    assert "Copied to clipboard" in result.stdout
    assert clipboard == ["secretvalue"]
    assert auth_calls == [
        (
            "st.rio.envrcctl",
            "openai:prod",
            "Access secret OPENAI_API_KEY with envrcctl",
        )
    ]


def test_cli_secret_get_on_macos_fails_closed_when_auth_is_cancelled(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()
    clipboard: list[str] = []

    def fake_get_with_auth(ref, reason: str | None = None) -> str:
        raise EnvrcctlError("Authentication cancelled.")

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(dummy, "get_with_auth", fake_get_with_auth)
    monkeypatch.setattr(
        cli, "_copy_to_clipboard", lambda value: clipboard.append(value)
    )
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "OPENAI_API_KEY", "--account", "openai:prod", "--stdin"],
        input="secretvalue",
    )

    result = runner.invoke(cli.app, ["secret", "get", "OPENAI_API_KEY"])
    assert result.exit_code == 1
    assert "Authentication cancelled." in result.stderr
    assert clipboard == []


def test_cli_secret_get_missing_ref(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "get", "MISSING"])
    assert result.exit_code == 1
    assert "no secret reference" in result.stderr


def test_cli_secret_get_copies_masked(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()
    copied: dict[str, str] = {}

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

    monkeypatch.setattr(cli.sys, "platform", "linux")

    result = runner.invoke(cli.app, ["secret", "get", "TOKEN", "--force-plain"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "supersecretvalue"
