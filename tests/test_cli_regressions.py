from __future__ import annotations

import errno
import os
import pty
import select
import signal
import subprocess
import sys
import time

import pytest
from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.audit import audit_file, iter_events, verify_chain
from envrcctl.errors import EnvrcctlError
from envrcctl.managed_block import ManagedBlock, render_managed_block
from envrcctl.secrets import parse_ref
from tests.helpers.cli_support import DummyBackend


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    backend = DummyBackend()
    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", backend))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: backend)
    return tmp_path, backend, CliRunner()


def write_block(path, refs=None, exports=None):
    content = render_managed_block(ManagedBlock(secret_refs=refs or {}, exports=exports or {}))
    (path / ".envrc").write_text(content, encoding="utf-8")
    return content


@pytest.mark.parametrize("value", ["it's valid", "one\ntwo\n", "a\r\nb\r", "'\"\\$", "日本語"])
def test_cli_value_survives_another_update(project, value):
    path, _, runner = project
    assert runner.invoke(cli.app, ["set", "VALUE", value]).exit_code == 0
    assert runner.invoke(cli.app, ["set", "OTHER", "ok"]).exit_code == 0
    result = runner.invoke(cli.app, ["get", "VALUE"])
    assert result.exit_code == 0
    assert result.stdout_bytes == (value + "\n").encode("utf-8")
    result = subprocess.run(
        ["/bin/bash", "-c", '. "$1"; printf %s "$VALUE"', "_", str(path / ".envrc")],
        capture_output=True,
        check=True,
    )
    assert result.stdout.decode("utf-8") == value


@pytest.mark.parametrize("operation", ["set", "unset"])
def test_rejected_file_does_not_change_backend(project, operation):
    path, backend, runner = project
    ref = parse_ref("kc:svc:acct")
    backend.set(ref, "original")
    original = write_block(path, {"TOKEN": "kc:svc:acct"})
    (path / ".envrc").chmod(0o666)
    args = (
        ["secret", "set", "TOKEN", "--service", "svc", "--account", "acct", "--stdin"]
        if operation == "set"
        else ["secret", "unset", "TOKEN", "--delete", "--yes"]
    )
    result = runner.invoke(cli.app, args, input="replacement")
    assert result.exit_code == 1
    assert backend.get(ref) == "original"
    assert (path / ".envrc").read_text() == original


@pytest.mark.parametrize("existing", [True, False])
def test_backend_set_failure_restores_original_document(project, monkeypatch, existing):
    path, backend, runner = project
    original = write_block(path, exports={"KEEP": "value"}) if existing else None

    def fail_set(ref, value):
        raise EnvrcctlError("Simulated backend failure.")

    monkeypatch.setattr(backend, "set", fail_set)
    result = runner.invoke(
        cli.app, ["secret", "set", "TOKEN", "--account", "acct", "--stdin"], input="dummy"
    )
    assert result.exit_code == 1
    if existing:
        assert (path / ".envrc").read_text() == original
    else:
        assert not (path / ".envrc").exists()


def test_backend_delete_failure_restores_reference(project, monkeypatch):
    path, backend, runner = project
    original = write_block(path, {"TOKEN": "kc:svc:acct"})

    def fail_delete(ref):
        raise EnvrcctlError("Simulated deletion failure.")

    monkeypatch.setattr(backend, "delete", fail_delete)
    result = runner.invoke(cli.app, ["secret", "unset", "TOKEN", "--delete", "--yes"])
    assert result.exit_code == 1
    assert (path / ".envrc").read_text() == original


def test_default_unset_keeps_shared_store_item(project):
    path, backend, runner = project
    ref = parse_ref("kc:svc:acct")
    backend.set(ref, "dummy")
    write_block(path, {"TOKEN": "kc:svc:acct"})
    assert runner.invoke(cli.app, ["secret", "unset", "TOKEN"]).exit_code == 0
    assert backend.get(ref) == "dummy"


@pytest.mark.parametrize("alias", ["kc:svc:acct:runtime", "kc:svc:acct:admin"])
def test_delete_rejects_canonical_aliases(project, alias):
    path, backend, runner = project
    ref = parse_ref("kc:svc:acct")
    backend.set(ref, "dummy")
    original = write_block(path, {"TOKEN": "kc:svc:acct", "ALIAS": alias})
    result = runner.invoke(cli.app, ["secret", "unset", "TOKEN", "--delete", "--yes"])
    assert result.exit_code == 1
    assert "still referenced" in result.stderr
    assert backend.get(ref) == "dummy"
    assert (path / ".envrc").read_text() == original


def test_secret_stdin_preserves_newlines(project):
    _, backend, runner = project
    result = runner.invoke(
        cli.app,
        ["secret", "set", "TOKEN", "--account", "acct", "--stdin"],
        input=" dummy \n\n",
    )
    assert result.exit_code == 0
    assert backend.get(parse_ref("kc:st.rio.envrcctl:acct")) == " dummy \n\n"


@pytest.mark.parametrize(
    "content",
    [
        'export TARGET="$HOME/bin"\n',
        "if false; then\n  export CONDITIONAL=yes\nfi\n",
        render_managed_block(ManagedBlock(exports={"VALUE": "old"})) + "export VALUE=new\n",
    ],
)
def test_migration_refuses_semantic_changes(project, content):
    path, _, runner = project
    (path / ".envrc").write_text(content, encoding="utf-8")
    result = runner.invoke(cli.app, ["migrate", "--yes"])
    assert result.exit_code == 1
    assert (path / ".envrc").read_text() == content


def test_exec_audit_failure_prevents_child(project, monkeypatch):
    _, _, runner = project
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    def fail_audit(**kwargs):
        raise EnvrcctlError("Simulated audit failure.")

    def forbidden_child(*args, **kwargs):
        pytest.fail("Child must not start without durable audit.")

    monkeypatch.setattr(cli, "append_event", fail_audit)
    monkeypatch.setattr(cli.subprocess, "run", forbidden_child)
    result = runner.invoke(cli.app, ["exec", "--", "dummy-command"])
    assert result.exit_code == 1
    assert "Simulated audit failure" in result.stderr


@pytest.mark.parametrize(
    "failure", [FileNotFoundError(errno.ENOENT, "missing"), KeyboardInterrupt()]
)
def test_exec_launch_failure_has_correlated_events(project, monkeypatch, failure):
    _, _, runner = project
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    def fail_child(*args, **kwargs):
        raise failure

    monkeypatch.setattr(cli.subprocess, "run", fail_child)
    result = runner.invoke(cli.app, ["exec", "--", "dummy-command", "--token", "DUMMY_TOKEN"])
    assert result.exit_code in (1, 130)
    events = list(iter_events())
    assert [event.status for event in events] == [
        "started",
        "cancelled" if isinstance(failure, KeyboardInterrupt) else "failure",
    ]
    assert events[0].operation_id == events[1].operation_id
    assert events[0].operation_id
    assert events[0].event_id != events[1].event_id
    assert "DUMMY_TOKEN" not in audit_file().read_text()
    assert verify_chain().ok


def test_exec_start_is_visible_while_child_runs(project, monkeypatch):
    _, _, runner = project
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    def child(*args, **kwargs):
        events = list(iter_events())
        assert len(events) == 1
        assert events[0].status == "started"
        assert verify_chain().ok
        return subprocess.CompletedProcess(args[0], -signal.SIGTERM)

    monkeypatch.setattr(cli.subprocess, "run", child)
    result = runner.invoke(cli.app, ["exec", "--", "dummy-command"])
    assert result.exit_code == 128 + signal.SIGTERM
    assert [event.status for event in iter_events()] == ["started", "failure"]


def test_inject_audit_failure_does_not_retry_or_emit_secrets(project, monkeypatch):
    path, backend, runner = project
    ref = parse_ref("kc:svc:acct")
    backend.set(ref, "DUMMY_VALUE")
    write_block(path, {"TOKEN": "kc:svc:acct"})
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)
    calls = []

    def fail_audit(**kwargs):
        calls.append(kwargs)
        raise EnvrcctlError("Audit unavailable.")

    monkeypatch.setattr(cli, "append_event", fail_audit)
    result = runner.invoke(cli.app, ["inject"])
    assert result.exit_code == 1
    assert "DUMMY_VALUE" not in result.output
    assert len(calls) == 1


@pytest.mark.parametrize("failure", [False, True])
def test_generated_capture_with_actual_controlling_terminal(project, failure):
    path, _, _ = project
    bindir = path / "bin"
    bindir.mkdir()
    stub = bindir / "envrcctl"
    stub.write_text(
        f"#!{sys.executable}\n"
        "from envrcctl import cli\n"
        "from envrcctl.errors import EnvrcctlError\n"
        "class Backend:\n"
        "    def get(self, ref):\n"
        + (
            "        raise EnvrcctlError('Synthetic failure')\n"
            if failure
            else "        return 'DUMMY_VALUE'\n"
        )
        + "    def get_many_with_auth(self, refs, reason):\n"
        "        return {(r.service, r.account): self.get(r) for r in refs}\n"
        "    def get_with_auth(self, ref, reason=None):\n"
        "        return self.get(ref)\n"
        "    def set(self, ref, value):\n"
        "        raise AssertionError('unused')\n"
        "    def delete(self, ref):\n"
        "        raise AssertionError('unused')\n"
        "    def list(self, prefix=None):\n"
        "        return []\n"
        "cli.backend_for_ref = lambda ref: Backend()\n"
        "cli.app()\n",
        encoding="utf-8",
    )
    stub.chmod(0o700)
    (path / ".envrc").write_text(
        render_managed_block(
            ManagedBlock(secret_refs={"TOKEN": "kc:svc:acct"}, include_inject=True)
        ),
        encoding="utf-8",
    )
    script = 'export PATH="$1:$PATH"; unset TOKEN; . ./.envrc; result=$?; ' + (
        'test "$result" -ne 0 && test -z "${TOKEN-}"'
        if failure
        else 'test "$result" -eq 0 && test "$TOKEN" = DUMMY_VALUE'
    )
    pid, master = pty.fork()
    if pid == 0:
        os.execv("/bin/bash", ["bash", "-c", script, "_", str(bindir)])
    output = bytearray()
    deadline = time.monotonic() + 15
    status = None
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                try:
                    data = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    break
                if not data:
                    break
                output.extend(data)
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                pid = 0
                break
        while pid and time.monotonic() < deadline:
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                pid = 0
            else:
                time.sleep(0.01)
        assert not pid, f"PTY child timed out: {output!r}"
        assert status is not None and os.waitstatus_to_exitcode(status) == 0, output
    finally:
        os.close(master)
        if pid:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def test_batch_results_keep_backend_identity(monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "linux")
    keychain, service = DummyBackend(), DummyBackend()
    kc_ref, ss_ref = parse_ref("kc:svc:acct"), parse_ref("ss:svc:acct")
    keychain.set(kc_ref, "keychain-dummy")
    service.set(ss_ref, "service-dummy")
    monkeypatch.setattr(
        cli, "backend_for_ref", lambda ref: keychain if ref.scheme == "kc" else service
    )
    assert cli._get_secret_values([kc_ref, ss_ref], None) == {
        ("kc", "svc", "acct"): "keychain-dummy",
        ("ss", "svc", "acct"): "service-dummy",
    }


def test_incomplete_batch_is_rejected_without_export(project, monkeypatch):
    path, backend, runner = project
    write_block(path, {"ONE": "kc:svc:one", "TWO": "kc:svc:two"})
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)
    monkeypatch.setattr(
        backend, "get_many_with_auth", lambda refs, reason: {("svc", "one"): "DUMMY_PARTIAL"}
    )
    result = runner.invoke(cli.app, ["inject"])
    assert result.exit_code == 1
    assert "DUMMY_PARTIAL" not in result.output
    assert "incomplete" in result.stderr


def test_shell_capture_without_terminal_stays_blocked(project, monkeypatch):
    _, _, runner = project
    monkeypatch.setattr(cli, "_is_interactive", lambda: False)
    monkeypatch.setattr(cli, "_has_controlling_terminal", lambda: False)
    result = runner.invoke(cli.app, ["inject", "--shell"])
    assert result.exit_code == 1
    assert "blocked" in result.stderr


def test_terminal_inspection_resource_failure_is_explicit(monkeypatch):
    def fail_open(*args, **kwargs):
        raise OSError(errno.EMFILE, "too many open files")

    monkeypatch.setattr(cli.os, "open", fail_open)
    with pytest.raises(EnvrcctlError, match="Could not inspect"):
        cli._has_controlling_terminal()
