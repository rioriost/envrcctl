from __future__ import annotations

import subprocess
from subprocess import CalledProcessError

import pytest

from envrctl.errors import EnvrcctlError
from envrctl.secrets import SecretRef
from envrctl.secretservice import SecretServiceBackend


class DummyResult:
    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.stderr = ""


def test_secretservice_error_prefers_stderr(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, args[0], output="out", stderr="err")

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = SecretServiceBackend()
    ref = SecretRef(scheme="ss", service="svc", account="acct", kind="runtime")

    with pytest.raises(EnvrcctlError) as exc:
        backend.get(ref)

    assert "err" in str(exc.value)


def test_secretservice_error_falls_back_to_stdout(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, args[0], output="oops", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = SecretServiceBackend()
    ref = SecretRef(scheme="ss", service="svc", account="acct", kind="runtime")

    with pytest.raises(EnvrcctlError) as exc:
        backend.get(ref)

    assert "oops" in str(exc.value)


def test_secretservice_error_redacts_input(monkeypatch) -> None:
    secret = "supersecret"

    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, args[0], output="", stderr=f"boom {secret}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = SecretServiceBackend()
    ref = SecretRef(scheme="ss", service="svc", account="acct", kind="runtime")

    with pytest.raises(EnvrcctlError) as exc:
        backend.set(ref, secret)

    message = str(exc.value)
    assert secret not in message
    assert "[REDACTED]" in message


def test_secretservice_commands(monkeypatch) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return DummyResult(stdout="value")

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = SecretServiceBackend()
    ref = SecretRef(scheme="ss", service="svc", account="acct", kind="runtime")

    assert backend.get(ref) == "value"
    backend.set(ref, "secret")
    backend.delete(ref)

    assert calls[0][:2] == ["secret-tool", "lookup"]
    assert calls[1][0:2] == ["secret-tool", "store"]
    assert calls[2][0:2] == ["secret-tool", "clear"]


def test_secretservice_list_returns_empty() -> None:
    backend = SecretServiceBackend()
    assert backend.list() == []
