from __future__ import annotations

import subprocess
from subprocess import CalledProcessError

import pytest

from envrctl.errors import EnvrcctlError
from envrctl.keychain import KeychainBackend
from envrctl.secrets import SecretRef


class DummyResult:
    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.stderr = ""


def test_keychain_get_calls_security(monkeypatch) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return DummyResult(stdout="secret\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = KeychainBackend()
    ref = SecretRef(scheme="kc", service="svc", account="acct")

    value = backend.get(ref)
    assert value == "secret"
    assert calls[0][0][:3] == ["security", "find-generic-password", "-s"]
    assert "-a" in calls[0][0]
    assert "-w" in calls[0][0]


def test_keychain_set_uses_stdin(monkeypatch) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return DummyResult()

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = KeychainBackend()
    ref = SecretRef(scheme="kc", service="svc", account="acct")

    backend.set(ref, "value")
    args, kwargs = calls[0]
    assert args[:3] == ["security", "add-generic-password", "-s"]
    assert "-U" in args
    assert args[-1] == "-w"
    assert kwargs["input"] == "value\n"


def test_keychain_delete_calls_security(monkeypatch) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return DummyResult()

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = KeychainBackend()
    ref = SecretRef(scheme="kc", service="svc", account="acct")

    backend.delete(ref)
    args, _ = calls[0]
    assert args[:2] == ["security", "delete-generic-password"]
    assert "-s" in args
    assert "-a" in args


def test_keychain_error_prefers_stderr(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, args[0], output="out", stderr="err")

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = KeychainBackend()
    ref = SecretRef(scheme="kc", service="svc", account="acct")

    with pytest.raises(EnvrcctlError) as exc:
        backend.get(ref)

    assert "err" in str(exc.value)


def test_keychain_error_falls_back_to_stdout(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, args[0], output="oops", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = KeychainBackend()
    ref = SecretRef(scheme="kc", service="svc", account="acct")

    with pytest.raises(EnvrcctlError) as exc:
        backend.get(ref)

    assert "oops" in str(exc.value)


def test_keychain_error_redacts_secret(monkeypatch) -> None:
    secret = "supersecret"

    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, args[0], output="", stderr=f"bad {secret} msg")

    monkeypatch.setattr(subprocess, "run", fake_run)

    backend = KeychainBackend()
    ref = SecretRef(scheme="kc", service="svc", account="acct")

    with pytest.raises(EnvrcctlError) as exc:
        backend.set(ref, secret)

    assert secret not in str(exc.value)
    assert "[REDACTED]" in str(exc.value)
