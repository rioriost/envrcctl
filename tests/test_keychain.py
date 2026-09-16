from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import traceback
from pathlib import Path

import pytest

from envrcctl.errors import EnvrcctlError
from envrcctl.keychain import KeychainBackend
from envrcctl.secrets import SecretRef

VALUES = ["", " ", "\t token \t", "token\n\n", "\r\n\r", "日本語🔒\r\n", "a\x00b"]


@pytest.fixture
def backend(monkeypatch, tmp_path):
    helper = tmp_path / "helper"
    helper.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    helper.chmod(0o755)
    monkeypatch.setenv(KeychainBackend.HELPER_ENV_VAR, str(helper))
    return KeychainBackend()


def result(args, payload):
    if not isinstance(payload, bytes):
        payload = json.dumps(payload).encode("utf-8")
    return subprocess.CompletedProcess(args, 0, payload, b"")


@pytest.mark.parametrize("value", VALUES)
def test_keychain_set_stdin_only_exact_utf8(monkeypatch, backend, value):
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return result(args, b"")

    monkeypatch.setattr(subprocess, "run", run)
    backend.set(SecretRef("kc", "svc", "acct", "runtime"), value)
    args, kwargs = calls.pop()
    assert args == [
        str(backend._helper_path()),
        "--set",
        "--service",
        "svc",
        "--account",
        "acct",
        "--reason",
        backend._build_auth_reason("store", SecretRef("kc", "svc", "acct", "runtime")),
    ]
    assert kwargs["input"] == value.encode("utf-8")
    assert not kwargs.get("text", False)
    assert calls == []


@pytest.mark.parametrize("value", VALUES)
@pytest.mark.parametrize("operation", ["get", "get_with_auth", "get_many_with_auth"])
def test_keychain_reads_use_exact_json_protocol(monkeypatch, backend, value, operation):
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return result(args, {"items": [{"service": "svc", "account": "acct", "value": value}]})

    monkeypatch.setattr(subprocess, "run", run)
    ref = SecretRef("kc", "svc", "acct", "runtime")
    if operation == "get_many_with_auth":
        assert backend.get_many_with_auth([ref], "Read") == {("svc", "acct"): value}
    elif operation == "get_with_auth":
        assert backend.get_with_auth(ref, "Read") == value
    else:
        assert backend.get(ref) == value
    args, kwargs = calls.pop()
    assert args[:4] == [str(backend._helper_path()), "--input-json", "-", "--reason"]
    assert json.loads(kwargs["input"]) == {"items": [{"service": "svc", "account": "acct"}]}
    assert calls == []


def test_keychain_batch_deduplicates_with_single_helper_call(monkeypatch, backend):
    calls = []
    refs = [
        SecretRef("kc", "svc", account, kind)
        for account, kind in [("acct", "runtime"), ("acct", "admin"), ("other", "runtime")]
    ]

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return result(
            args,
            {
                "items": [
                    {"service": "svc", "account": "acct", "value": "one"},
                    {"service": "svc", "account": "other", "value": "two"},
                ]
            },
        )

    monkeypatch.setattr(subprocess, "run", run)
    assert backend.get_many_with_auth(refs) == {("svc", "acct"): "one", ("svc", "other"): "two"}
    assert len(calls) == 1
    assert json.loads(calls[0][1]["input"]) == {
        "items": [
            {"service": "svc", "account": "acct"},
            {"service": "svc", "account": "other"},
        ]
    }


@pytest.mark.parametrize(
    "payload",
    [
        b"dummy-sensitive-value",
        None,
        [],
        1,
        "dummy-sensitive-value",
        {},
        {"items": {}},
        {"items": ["dummy-sensitive-value"]},
        {"items": [{"service": "svc", "account": 1, "value": "dummy-sensitive-value"}]},
        {"items": [{"service": "svc", "account": "acct"}]},
        {"items": [{"service": "svc", "account": "acct", "value": None}]},
        {"items": []},
        {"items": [{"service": "svc", "account": "other", "value": "dummy-sensitive-value"}]},
        {
            "items": [
                {"service": "svc", "account": "acct", "value": "dummy-sensitive-value"},
                {"service": "svc", "account": "acct", "value": "dummy-sensitive-value"},
            ]
        },
        {
            "items": [
                {"service": "svc", "account": "acct", "value": "dummy-sensitive-value"},
                {"service": "svc", "account": "other", "value": "dummy-sensitive-value"},
            ]
        },
    ],
)
def test_keychain_rejects_invalid_responses_without_secret_exception_chains(
    monkeypatch, backend, payload
):
    monkeypatch.setattr(subprocess, "run", lambda args, **kwargs: result(args, payload))
    with pytest.raises(EnvrcctlError) as exc:
        backend.get_many_with_auth([SecretRef("kc", "svc", "acct", "runtime")])
    assert "dummy-sensitive-value" not in "".join(traceback.format_exception(exc.value))
    assert exc.value.__context__ is None
    assert exc.value.__cause__ is None


@pytest.mark.parametrize(
    "operation", ["get", "get_with_auth", "get_many_with_auth", "set", "delete"]
)
@pytest.mark.parametrize("error", ["exit", 2, 13, 8])
def test_keychain_failures_are_sanitized_without_fallback(monkeypatch, backend, operation, error):
    secret = "dummy-sensitive-value"
    calls = []

    def fail(args, **kwargs):
        calls.append(args)
        if error == "exit":
            raise subprocess.CalledProcessError(1, [*args, secret], secret, secret)
        raise OSError(error, secret, secret)

    monkeypatch.setattr(subprocess, "run", fail)
    ref = SecretRef("kc", "svc", "acct", "runtime")
    with pytest.raises(EnvrcctlError) as exc:
        if operation == "get_many_with_auth":
            backend.get_many_with_auth([ref])
        elif operation == "set":
            backend.set(ref, secret)
        else:
            getattr(backend, operation)(ref)
    assert len(calls) == 1
    assert secret not in "".join(traceback.format_exception(exc.value))
    assert exc.value.__context__ is None
    assert exc.value.__cause__ is None


@pytest.mark.parametrize(
    "operation", ["get", "get_with_auth", "get_many_with_auth", "set", "delete"]
)
def test_keychain_rejects_foreign_schemes_before_any_command(monkeypatch, backend, operation):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: calls.append(a))
    foreign = SecretRef("ss", "svc", "acct", "runtime")
    with pytest.raises(EnvrcctlError, match="kc secret reference"):
        if operation == "get_many_with_auth":
            backend.get_many_with_auth([SecretRef("kc", "svc", "acct", "runtime"), foreign])
        elif operation == "set":
            backend.set(foreign, "dummy")
        else:
            getattr(backend, operation)(foreign)
    assert calls == []


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("account", ["acct", "other"])
def test_keychain_batch_rejects_mixed_stores_in_either_order(
    monkeypatch, backend, reverse, account
):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: calls.append(a))
    refs = [SecretRef("kc", "svc", "acct", "runtime"), SecretRef("ss", "svc", account, "runtime")]
    with pytest.raises(EnvrcctlError, match="kc secret reference"):
        backend.get_many_with_auth(refs[::-1] if reverse else refs)
    assert calls == []


def test_keychain_delete_and_empty_operations(monkeypatch, backend):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return result(args, b"")

    monkeypatch.setattr(subprocess, "run", run)
    assert backend.get_many_with_auth([]) == {}
    assert backend.list() == []
    assert calls == []
    backend.delete(SecretRef("kc", "svc", "acct", "runtime"))
    assert calls == [["security", "delete-generic-password", "-s", "svc", "-a", "acct"]]


_SWIFT_HARNESS = r"""
import Foundation
import LocalAuthentication
import Security

@main
struct SyntheticMain {
    static func main() {
        let mode = ProcessInfo.processInfo.environment["SYNTHETIC_MODE"] ?? "read"
        let context = LAContext()
        var authCalls = 0
        var readCalls = 0
        var updateCalls = 0
        var addCalls = 0
        var stored: Data?
        var acl = "existing-acl"
        defer {
            let state: [String: Any] = [
                "auth": authCalls, "reads": readCalls, "updates": updateCalls, "adds": addCalls,
                "acl": acl, "value": stored?.base64EncodedString() ?? "",
            ]
            let data = try! JSONSerialization.data(withJSONObject: state, options: [.sortedKeys])
            FileHandle.standardError.write(data)
        }
        do {
            try runHelper(
                CommandLine.arguments,
                authorize: { _ in
                    authCalls += 1
                    if mode == "cancel" { throw HelperError.authenticationFailed("Cancelled.") }
                    return context
                },
                read: { service, account, receivedContext in
                    precondition(receivedContext === context)
                    readCalls += 1
                    if account == "missing" { throw HelperError.keychainFailure("Missing.") }
                    return " \t日本語🔒\r\n\r\n"
                },
                store: { service, account, data, receivedContext in
                    precondition(receivedContext === context)
                    try storeSecret(
                        service: service, account: account, data: data, context: receivedContext,
                        keychain: { "synthetic-default-keychain" },
                        update: { rawQuery, rawChanges in
                            let query = rawQuery as NSDictionary
                            let changes = rawChanges as NSDictionary
                            precondition(query[kSecAttrService] as? String == service)
                            precondition(query[kSecAttrAccount] as? String == account)
                            precondition(
                                query[kSecClass] as? String == kSecClassGenericPassword as String)
                            precondition(
                                query[kSecMatchSearchList] as? [String]
                                == ["synthetic-default-keychain"])
                            precondition(
                                query[kSecUseAuthenticationContext] as? LAContext === context)
                            precondition(
                                changes.count == 1 && changes[kSecValueData] as? Data == data)
                            updateCalls += 1
                            if mode == "write-fail" { return errSecAuthFailed }
                            if updateCalls == 1 && ["create", "race", "add-fail"].contains(mode) {
                                return errSecItemNotFound
                            }
                            stored = data
                            return errSecSuccess
                        },
                        add: { rawAttributes, output in
                            let attrs = rawAttributes as NSDictionary
                            precondition(output == nil)
                            precondition(attrs[kSecAttrService] as? String == service)
                            precondition(attrs[kSecAttrAccount] as? String == account)
                            precondition(
                                attrs[kSecUseKeychain] as? String == "synthetic-default-keychain")
                            precondition(
                                attrs[kSecAttrAccess] == nil && attrs[kSecAttrAccessControl] == nil)
                            precondition(attrs[kSecValueData] as? Data == data)
                            addCalls += 1
                            if mode == "race" { return errSecDuplicateItem }
                            if mode == "add-fail" { return errSecAuthFailed }
                            acl = "system-default-acl"
                            stored = data
                            return errSecSuccess
                        }
                    )
                }
            )
        } catch {
            // Exit status is communicated without bypassing the deferred synthetic state.
            FileHandle.standardError.write(Data("FAILED\n".utf8))
        }
    }
}
"""


@pytest.fixture(scope="module")
def synthetic_helper(tmp_path_factory):
    if sys.platform != "darwin" or shutil.which("swiftc") is None:
        pytest.skip("Synthetic native protocol tests require the macOS Swift SDK.")
    directory = tmp_path_factory.mktemp("synthetic-helper")
    source = directory / "SyntheticMain.swift"
    source.write_text(_SWIFT_HARNESS, encoding="utf-8")
    helper = directory / "synthetic-helper"
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, TMPDIR=str(directory), CLANG_MODULE_CACHE_PATH=str(directory / "cache"))
    completed = subprocess.run(
        [
            "xcrun",
            "--sdk",
            "macosx",
            "swiftc",
            "-parse-as-library",
            "-D",
            "ENVRCCTL_HELPER_TESTING",
            "-module-cache-path",
            str(directory / "cache"),
            "-framework",
            "LocalAuthentication",
            "-framework",
            "Security",
            str(root / "scripts/macos/envrcctl-macos-auth.swift"),
            str(source),
            "-o",
            str(helper),
        ],
        capture_output=True,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8")
    return helper


def run_synthetic(helper, args, value=b"", mode="read"):
    completed = subprocess.run(
        [str(helper), *args],
        input=value,
        capture_output=True,
        env=dict(os.environ, SYNTHETIC_MODE=mode),
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    failed = completed.stderr.startswith(b"FAILED\n")
    state = json.loads(completed.stderr.removeprefix(b"FAILED\n"))
    return completed.stdout, state, failed


@pytest.mark.parametrize("value", VALUES)
@pytest.mark.parametrize(
    ("mode", "updates", "adds", "acl"),
    [
        ("create", 1, 1, "system-default-acl"),
        ("update", 1, 0, "existing-acl"),
        ("race", 2, 1, "existing-acl"),
    ],
)
def test_native_stdin_create_update_and_acl_preservation(
    synthetic_helper, value, mode, updates, adds, acl
):
    import base64

    output, state, failed = run_synthetic(
        synthetic_helper,
        ["--set", "--service", "svc", "--account", "acct", "--reason", "Store"],
        value.encode("utf-8"),
        mode,
    )
    assert not failed
    assert output == b""
    assert state == {
        "auth": 1,
        "reads": 0,
        "updates": updates,
        "adds": adds,
        "acl": acl,
        "value": base64.b64encode(value.encode("utf-8")).decode("ascii"),
    }


@pytest.mark.parametrize("mode", ["write-fail", "add-fail", "cancel"])
def test_native_write_failure_never_outputs_or_recreates(synthetic_helper, mode):
    output, state, failed = run_synthetic(
        synthetic_helper,
        ["--set", "--service", "svc", "--account", "acct", "--reason", "Store"],
        b"dummy-sensitive-value",
        mode,
    )
    assert failed
    assert output == b""
    assert state["value"] == ""
    assert state["acl"] == "existing-acl"
    assert state["adds"] == (1 if mode == "add-fail" else 0)


def test_native_single_and_batch_exact_values_and_shared_authentication(synthetic_helper):
    output, state, failed = run_synthetic(
        synthetic_helper, ["--service", "svc", "--account", "acct", "--reason", "Read"]
    )
    assert not failed
    assert output == " \t日本語🔒\r\n\r\n".encode()
    assert state["auth"] == state["reads"] == 1
    request = {
        "items": [{"service": "svc", "account": "acct"}, {"service": "svc", "account": "other"}]
    }
    output, state, failed = run_synthetic(
        synthetic_helper, ["--input-json", "-", "--reason", "Read"], json.dumps(request).encode()
    )
    assert not failed
    assert json.loads(output) == {
        "items": [dict(item, value=" \t日本語🔒\r\n\r\n") for item in request["items"]]
    }
    assert state["auth"] == 1
    assert state["reads"] == 2


def test_native_batch_failure_has_no_partial_output(synthetic_helper):
    request = {
        "items": [{"service": "svc", "account": "acct"}, {"service": "svc", "account": "missing"}]
    }
    output, state, failed = run_synthetic(
        synthetic_helper, ["--input-json", "-", "--reason", "Read"], json.dumps(request).encode()
    )
    assert failed
    assert output == b""
    assert state["auth"] == 1
    assert state["reads"] == 2


def test_native_authorization_only_does_not_access_secrets(synthetic_helper):
    output, state, failed = run_synthetic(
        synthetic_helper, ["--authorize-only", "--reason", "Authorize"]
    )
    assert not failed
    assert output == b""
    assert state["auth"] == 1
    assert state["reads"] == state["updates"] == state["adds"] == 0


def test_native_cancelled_batch_never_reads_or_outputs_secrets(synthetic_helper):
    request = {"items": [{"service": "svc", "account": "acct"}]}
    output, state, failed = run_synthetic(
        synthetic_helper,
        ["--input-json", "-", "--reason", "Read"],
        json.dumps(request).encode(),
        "cancel",
    )
    assert failed
    assert output == b""
    assert state["auth"] == 1
    assert state["reads"] == 0


@pytest.mark.parametrize(
    ("args", "value"),
    [
        (["--set", "--input-json", "-", "--reason", "Store"], b"{}"),
        (["--set", "--authorize-only", "--reason", "Store"], b"dummy"),
        (["--set", "--service", "svc", "--account", "acct", "--reason", "Store"], b"\xff"),
        (["--input-json", "-", "--reason", "Read"], b'{"items": []}'),
        (
            ["--input-json", "-", "--reason", "Read"],
            b'{"items": [{"service": "", "account": "a"}]}',
        ),
        (["--input-json", "-", "--reason", "Read"], b"dummy-sensitive-value"),
    ],
)
def test_native_invalid_requests_fail_before_authentication(synthetic_helper, args, value):
    output, state, failed = run_synthetic(synthetic_helper, args, value)
    assert failed
    assert output == b""
    assert state["auth"] == state["reads"] == state["updates"] == state["adds"] == 0
