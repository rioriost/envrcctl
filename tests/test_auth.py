from __future__ import annotations

import subprocess
from pathlib import Path
from subprocess import CalledProcessError

import pytest

from envrcctl import auth
from envrcctl.errors import EnvrcctlError


class DummyCompletedProcess:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.stdout = stdout
        self.stderr = stderr


def test_default_helper_path_points_next_to_module() -> None:
    path = auth._default_helper_path()

    assert path.name == "envrcctl-macos-auth"
    assert path.parent == Path(auth.__file__).resolve().parent


def test_helper_path_uses_env_var(monkeypatch, tmp_path: Path) -> None:
    helper_path = tmp_path / "custom-helper"
    monkeypatch.setenv("ENVRCCTL_MACOS_AUTH_HELPER", str(helper_path))

    path = auth._helper_path()

    assert path == helper_path


def test_helper_path_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.delenv("ENVRCCTL_MACOS_AUTH_HELPER", raising=False)
    monkeypatch.setattr(auth.shutil, "which", lambda _: None)

    path = auth._helper_path()

    assert path == auth._default_helper_path()


def test_ensure_helper_ready_requires_existing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing-helper"

    with pytest.raises(EnvrcctlError) as exc:
        auth._ensure_helper_ready(missing)

    assert "not found" in str(exc.value).lower()


def test_ensure_helper_ready_requires_regular_file(tmp_path: Path) -> None:
    helper_dir = tmp_path / "helper-dir"
    helper_dir.mkdir()

    with pytest.raises(EnvrcctlError) as exc:
        auth._ensure_helper_ready(helper_dir)

    assert "invalid" in str(exc.value).lower()


def test_ensure_helper_ready_requires_executable_file(tmp_path: Path) -> None:
    helper_path = tmp_path / "helper"
    helper_path.write_text("#!/bin/sh\n", encoding="utf-8")
    helper_path.chmod(0o644)

    with pytest.raises(EnvrcctlError) as exc:
        auth._ensure_helper_ready(helper_path)

    assert "not executable" in str(exc.value).lower()


def test_ensure_device_owner_auth_is_noop_off_macos(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return DummyCompletedProcess()

    monkeypatch.setattr(auth.sys, "platform", "linux")
    monkeypatch.setattr(subprocess, "run", fake_run)

    auth.ensure_device_owner_auth("Authenticate for envrcctl")

    assert calls == []


def test_ensure_device_owner_auth_rejects_empty_reason_on_macos(monkeypatch) -> None:
    monkeypatch.setattr(auth.sys, "platform", "darwin")

    with pytest.raises(EnvrcctlError) as exc:
        auth.ensure_device_owner_auth("   ")

    assert "reason cannot be empty" in str(exc.value).lower()


def test_ensure_device_owner_auth_runs_helper(monkeypatch, tmp_path: Path) -> None:
    calls = []
    helper_path = tmp_path / "envrcctl-macos-auth"
    helper_path.write_text("#!/bin/sh\n", encoding="utf-8")
    helper_path.chmod(0o755)

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return DummyCompletedProcess()

    monkeypatch.setattr(auth.sys, "platform", "darwin")
    monkeypatch.setenv("ENVRCCTL_MACOS_AUTH_HELPER", str(helper_path))
    monkeypatch.setattr(subprocess, "run", fake_run)

    auth.ensure_device_owner_auth("Authenticate for envrcctl")

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == [
        str(helper_path),
        "--authorize-only",
        "--reason",
        "Authenticate for envrcctl",
    ]
    assert not kwargs.get("text", False)
    assert kwargs["capture_output"] is True
    assert kwargs["check"] is True


def test_ensure_device_owner_auth_discards_stderr(monkeypatch, tmp_path: Path) -> None:
    helper_path = tmp_path / "envrcctl-macos-auth"
    helper_path.write_text("#!/bin/sh\n", encoding="utf-8")
    helper_path.chmod(0o755)

    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, args[0], output="out", stderr="auth failed")

    monkeypatch.setattr(auth.sys, "platform", "darwin")
    monkeypatch.setenv("ENVRCCTL_MACOS_AUTH_HELPER", str(helper_path))
    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EnvrcctlError) as exc:
        auth.ensure_device_owner_auth("Authenticate for envrcctl")

    assert str(exc.value) == "Device owner authentication failed."


def test_ensure_device_owner_auth_discards_stdout(monkeypatch, tmp_path: Path) -> None:
    helper_path = tmp_path / "envrcctl-macos-auth"
    helper_path.write_text("#!/bin/sh\n", encoding="utf-8")
    helper_path.chmod(0o755)

    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, args[0], output="auth cancelled", stderr="")

    monkeypatch.setattr(auth.sys, "platform", "darwin")
    monkeypatch.setenv("ENVRCCTL_MACOS_AUTH_HELPER", str(helper_path))
    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EnvrcctlError) as exc:
        auth.ensure_device_owner_auth("Authenticate for envrcctl")

    assert str(exc.value) == "Device owner authentication failed."


def test_ensure_device_owner_auth_uses_default_error_when_no_output(
    monkeypatch, tmp_path: Path
) -> None:
    helper_path = tmp_path / "envrcctl-macos-auth"
    helper_path.write_text("#!/bin/sh\n", encoding="utf-8")
    helper_path.chmod(0o755)

    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, args[0], output="", stderr="")

    monkeypatch.setattr(auth.sys, "platform", "darwin")
    monkeypatch.setenv("ENVRCCTL_MACOS_AUTH_HELPER", str(helper_path))
    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EnvrcctlError) as exc:
        auth.ensure_device_owner_auth("Authenticate for envrcctl")

    assert str(exc.value) == "Device owner authentication failed."


@pytest.mark.parametrize("selection", ["./helper", "helper", "subdir/helper", "path", "default"])
def test_shared_helper_lookup_executes_only_checked_absolute_path(
    monkeypatch, tmp_path: Path, selection: str
) -> None:
    from envrcctl.keychain import KeychainBackend
    from envrcctl.secrets import SecretRef

    monkeypatch.chdir(tmp_path)
    relative = "subdir/helper" if selection == "subdir/helper" else "helper"
    candidate = tmp_path / relative
    candidate.parent.mkdir(exist_ok=True)
    candidate.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    candidate.chmod(0o755)
    monkeypatch.setattr(auth.sys, "platform", "darwin")
    shadow = tmp_path / "shadow" / "helper"
    shadow.parent.mkdir()
    shadow.write_text("#!/bin/sh\nexit 98\n", encoding="utf-8")
    shadow.chmod(0o755)
    monkeypatch.setattr(auth.shutil, "which", lambda _: "shadow/helper")
    if selection in {"path", "default"}:
        monkeypatch.delenv("ENVRCCTL_MACOS_AUTH_HELPER", raising=False)
        monkeypatch.setattr(auth.shutil, "which", lambda _: "helper")
        if selection == "default":
            monkeypatch.setattr(auth.shutil, "which", lambda _: None)
            monkeypatch.setattr(auth, "_default_helper_path", lambda: Path("helper"))
    else:
        monkeypatch.setenv("ENVRCCTL_MACOS_AUTH_HELPER", selection)
    checked = []
    executed = []
    real_check = auth._ensure_helper_ready

    def check(path):
        checked.append(path)
        real_check(path)

    def run(args, **kwargs):
        executed.append(Path(args[0]))
        return DummyCompletedProcess()

    monkeypatch.setattr(auth, "_ensure_helper_ready", check)
    monkeypatch.setattr(subprocess, "run", run)
    auth.ensure_device_owner_auth("Authorize")
    KeychainBackend().set(SecretRef("kc", "svc", "acct", "runtime"), "dummy")
    assert checked == executed == [candidate, candidate]
    assert all(path.is_absolute() for path in executed)


@pytest.mark.parametrize("error_number", [2, 13, 8])
def test_auth_process_boundary_is_sanitized(monkeypatch, tmp_path, error_number) -> None:
    import traceback

    helper = tmp_path / "helper"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o755)
    monkeypatch.setenv("ENVRCCTL_MACOS_AUTH_HELPER", str(helper))
    monkeypatch.setattr(auth.sys, "platform", "darwin")
    calls = []

    def fail(args, **kwargs):
        calls.append(args)
        raise OSError(error_number, "dummy-sensitive-diagnostic", "dummy-sensitive-path")

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(EnvrcctlError) as exc:
        auth.ensure_device_owner_auth("Authorize")
    assert len(calls) == 1
    assert "dummy-sensitive" not in "".join(traceback.format_exception(exc.value))
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


def test_helper_path_resolution_errors_are_sanitized(monkeypatch) -> None:
    def fail():
        raise OSError("dummy-sensitive-path")

    monkeypatch.setattr(auth, "_selected_helper_path", fail)
    with pytest.raises(EnvrcctlError, match="could not be resolved") as exc:
        auth.ready_helper_path()
    assert exc.value.__context__ is None
    assert "dummy-sensitive-path" not in str(exc.value)
