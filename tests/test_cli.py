from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.audit import AuditErrorInfo, AuditRef
from envrcctl.envrc import ENVRC_FILENAME
from envrcctl.errors import EnvrcctlError
from envrcctl.managed_block import ManagedBlock, render_managed_block


class DummyBackend:
    def __init__(self) -> None:
        self._store: Dict[tuple[str, str], str] = {}

    def get(self, ref) -> str:
        return self._store[(ref.service, ref.account)]

    def get_with_auth(self, ref, reason: str | None = None) -> str:
        return self.get(ref)

    def get_many_with_auth(self, refs, reason: str | None = None):
        return {
            (ref.service, ref.account): self._store[(ref.service, ref.account)]
            for ref in refs
        }

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

    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert 'eval "$(envrcctl inject)"' in envrc_text


def test_cli_set_adds_inject_line_when_requested(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["set", "FOO", "bar", "--inject"])
    assert result.exit_code == 0

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
        [
            "secret",
            "set",
            "OPENAI_API_KEY",
            "--account",
            "openai:prod",
            "--stdin",
            "--inject",
        ],
        input="secretvalue",
    )
    assert result.exit_code == 0
    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_OPENAI_API_KEY" in envrc_text
    assert 'eval "$(envrcctl inject)"' in envrc_text

    monkeypatch.setattr(cli.sys, "platform", "linux")

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


def test_cli_secret_unset_preserves_shared_keychain_item(
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
    runner.invoke(
        cli.app,
        ["secret", "set", "TEST_TOKEN", "--account", "acct", "--stdin"],
        input="sharedsecret",
    )

    envrc_path = tmp_path / ENVRC_FILENAME
    envrc_text = _read_envrc(envrc_path)
    envrc_text = envrc_text.replace(
        "export ENVRCCTL_SECRET_TEST_TOKEN=kc:st.rio.envrcctl:acct:runtime",
        "\n".join(
            [
                "export ENVRCCTL_SECRET_TEST_TOKEN=kc:st.rio.envrcctl:acct:runtime",
                "export ENVRCCTL_SECRET_UV_PUBLISH_TOKEN=kc:st.rio.envrcctl:acct:runtime",
            ]
        ),
    )
    envrc_path.write_text(envrc_text, encoding="utf-8")

    result = runner.invoke(cli.app, ["secret", "unset", "TEST_TOKEN"])
    assert result.exit_code == 0

    result = runner.invoke(
        cli.app,
        ["secret", "get", "UV_PUBLISH_TOKEN", "--plain"],
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "sharedsecret"


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


def test_cli_secret_get_missing_ref(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "get", "MISSING"])
    assert result.exit_code == 1
    assert "no secret reference" in result.stderr


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


def test_cli_doctor_warns_on_symlink(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    target = tmp_path / "real.envrc"
    target.write_text(
        render_managed_block(ManagedBlock(include_inject=True)), encoding="utf-8"
    )
    envrc_path = tmp_path / ENVRC_FILENAME
    envrc_path.symlink_to(target)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "symlink" in result.stderr


def test_cli_doctor_warns_on_group_writable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    envrc_path = tmp_path / ENVRC_FILENAME
    os.chmod(envrc_path, 0o660)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "group-writable" in result.stderr


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

    monkeypatch.setattr(cli.sys, "platform", "linux")

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

    monkeypatch.setattr(cli.sys, "platform", "linux")

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

    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
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


def test_secret_set_uses_getpass(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    values = iter(["secretvalue", "secretvalue"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(values))

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "set", "TOKEN", "--account", "acct"])
    assert result.exit_code == 0

    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_TOKEN" in envrc_text


def test_secret_set_rejects_mismatched_confirmation(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    values = iter(["secretvalue", "different"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(values))

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "set", "TOKEN", "--account", "acct"])
    assert result.exit_code == 1
    assert "does not match confirmation" in result.stderr


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


def test_cli_secret_get_missing_ref(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "get", "MISSING"])
    assert result.exit_code == 1
    assert "no secret reference" in result.stderr


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


def test_cli_doctor_warns_on_symlink(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    target = tmp_path / "real.envrc"
    target.write_text(
        render_managed_block(ManagedBlock(include_inject=True)), encoding="utf-8"
    )
    envrc_path = tmp_path / ENVRC_FILENAME
    envrc_path.symlink_to(target)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "symlink" in result.stderr


def test_cli_doctor_warns_on_group_writable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    envrc_path = tmp_path / ENVRC_FILENAME
    os.chmod(envrc_path, 0o660)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "group-writable" in result.stderr


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

    monkeypatch.setattr(cli.sys, "platform", "linux")

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

    monkeypatch.setattr(cli.sys, "platform", "linux")

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

    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
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


def test_secret_set_uses_getpass(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    values = iter(["secretvalue", "secretvalue"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(values))

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "set", "TOKEN", "--account", "acct"])
    assert result.exit_code == 0

    envrc_text = _read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_TOKEN" in envrc_text


def test_secret_set_rejects_mismatched_confirmation(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    values = iter(["secretvalue", "different"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(values))

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "set", "TOKEN", "--account", "acct"])
    assert result.exit_code == 1
    assert "does not match confirmation" in result.stderr


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
    monkeypatch.setattr(
        cli,
        "verify_chain",
        lambda: type(
            "AuditVerifyResultStub",
            (),
            {
                "ok": True,
                "event_count": 0,
                "latest_hash": None,
                "failure_line": None,
                "failure_event_id": None,
                "failure_reason": None,
            },
        )(),
    )
    monkeypatch.setattr(cli, "ensure_audit_store_secure", lambda: None)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "OK"


def test_doctor_warns_when_audit_chain_verification_fails(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=True)
    (tmp_path / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )
    monkeypatch.setattr(
        cli,
        "verify_chain",
        lambda: type(
            "AuditVerifyResultStub",
            (),
            {
                "ok": False,
                "event_count": 1,
                "latest_hash": "hash-1",
                "failure_line": 2,
                "failure_event_id": "evt-2",
                "failure_reason": "Audit event hash mismatch.",
            },
        )(),
    )

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "audit chain verification failed" in result.stderr
    assert "line=2" in result.stderr
    assert "event_id=evt-2" in result.stderr
    assert "reason=Audit event hash mismatch." in result.stderr


def test_doctor_warns_when_audit_store_is_not_secure(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=True)
    (tmp_path / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )
    monkeypatch.setattr(
        cli,
        "verify_chain",
        lambda: type(
            "AuditVerifyResultStub",
            (),
            {
                "ok": True,
                "event_count": 0,
                "latest_hash": None,
                "failure_line": None,
                "failure_event_id": None,
                "failure_reason": None,
            },
        )(),
    )

    def fake_ensure_audit_store_secure() -> None:
        raise EnvrcctlError("permissions are insecure")

    monkeypatch.setattr(
        cli, "ensure_audit_store_secure", fake_ensure_audit_store_secure
    )

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "audit store is not secure" in result.stderr
    assert "permissions are insecure" in result.stderr
