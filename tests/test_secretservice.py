from __future__ import annotations

import subprocess
import traceback

import pytest

from envrcctl.errors import EnvrcctlError
from envrcctl.secrets import SecretRef
from envrcctl.secretservice import SecretServiceBackend


@pytest.mark.parametrize("value", ["", " ", "\t token \t", "token\n\n", "\r\n\r", "日本語🔒\r\n"])
def test_secretservice_exact_store_and_lookup(monkeypatch, value) -> None:
    calls = []
    stored = None

    def run(args, **kwargs):
        nonlocal stored
        calls.append((args, kwargs))
        assert not kwargs.get("text", False)
        if args[1] == "store":
            stored = kwargs["input"]
            return subprocess.CompletedProcess(args, 0, b"", b"")
        assert args[1] == "lookup"
        return subprocess.CompletedProcess(args, 0, stored, b"")

    monkeypatch.setattr(subprocess, "run", run)
    backend = SecretServiceBackend()
    ref = SecretRef("ss", "svc", "acct", "runtime")
    backend.set(ref, value)
    assert stored == value.encode("utf-8")
    assert backend.get(ref) == value
    assert calls[0][0] == [
        "secret-tool",
        "store",
        "--label",
        "envrcctl:svc:acct",
        "service",
        "svc",
        "account",
        "acct",
    ]
    assert calls[1][0] == ["secret-tool", "lookup", "service", "svc", "account", "acct"]
    assert all(value not in args for args, _ in calls) if value else True


@pytest.mark.parametrize("operation", ["get", "set", "delete"])
@pytest.mark.parametrize("error", ["exit", 2, 13, 8])
def test_secretservice_failures_are_sanitized(monkeypatch, operation, error) -> None:
    secret = "dummy-sensitive-value"
    calls = []

    def fail(args, **kwargs):
        calls.append(args)
        if error == "exit":
            raise subprocess.CalledProcessError(1, [*args, secret], secret, secret)
        raise OSError(error, secret, secret)

    monkeypatch.setattr(subprocess, "run", fail)
    backend = SecretServiceBackend()
    ref = SecretRef("ss", "svc", "acct", "runtime")
    with pytest.raises(EnvrcctlError, match="SecretService command failed") as exc:
        getattr(backend, operation)(ref, secret) if operation == "set" else getattr(
            backend, operation
        )(ref)
    assert len(calls) == 1
    assert secret not in "".join(traceback.format_exception(exc.value))
    assert exc.value.__context__ is None
    assert exc.value.__cause__ is None


@pytest.mark.parametrize("operation", ["get", "set", "delete"])
def test_secretservice_rejects_foreign_refs(monkeypatch, operation) -> None:
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: calls.append(a))
    backend = SecretServiceBackend()
    ref = SecretRef("kc", "svc", "acct", "runtime")
    with pytest.raises(EnvrcctlError, match="ss secret reference"):
        getattr(backend, operation)(ref, "dummy") if operation == "set" else getattr(
            backend, operation
        )(ref)
    assert calls == []


def test_secretservice_clear_and_list(monkeypatch) -> None:
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    backend = SecretServiceBackend()
    backend.delete(SecretRef("ss", "svc", "acct", "runtime"))
    assert calls == [["secret-tool", "clear", "service", "svc", "account", "acct"]]
    assert backend.list() == []
