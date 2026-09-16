from __future__ import annotations

import subprocess
import sys
import traceback

import pytest

from envrcctl.command_runner import _validate_command_args, run_command
from envrcctl.errors import EnvrcctlError


def test_validate_command_args_rejects_empty() -> None:
    with pytest.raises(EnvrcctlError):
        _validate_command_args([], None)


def test_validate_command_args_rejects_non_string() -> None:
    with pytest.raises(EnvrcctlError):
        _validate_command_args(["ok", 123], None)


def test_validate_command_args_rejects_empty_string() -> None:
    with pytest.raises(EnvrcctlError):
        _validate_command_args([""], None)


def test_validate_command_args_rejects_null_byte() -> None:
    with pytest.raises(EnvrcctlError):
        _validate_command_args(["bad\x00arg"], None)


def test_validate_command_args_rejects_disallowed_command() -> None:
    with pytest.raises(EnvrcctlError):
        _validate_command_args(["rm", "-rf", "/"], {"echo"})


def test_run_command_discards_sensitive_diagnostics_and_exception_chain(monkeypatch) -> None:
    secret = "supersecret"

    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            1, [*args[0], secret], output=f"partial {secret}", stderr=f"boom {secret}"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EnvrcctlError) as exc:
        run_command(["echo"], input_text=secret, allowed_commands={"echo"})

    message = str(exc.value)
    assert secret not in message
    assert message == "Command failed."
    assert secret not in "".join(traceback.format_exception(exc.value))
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


@pytest.mark.parametrize("value", ["", " ", "\t token \t", "token\n\n", "\r\n\r", "日本語🔒\r\n"])
def test_run_command_round_trips_exact_utf8_in_real_harmless_child(value) -> None:
    result = run_command(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
        input_text=value,
        allowed_commands={sys.executable},
    )
    assert result == value


@pytest.mark.parametrize(
    ("error_number", "message"),
    [
        (2, "Executable not found"),
        (13, "permission denied"),
        (8, "format is invalid"),
        (5, "Unable to start command"),
    ],
)
def test_run_command_sanitizes_os_errors(monkeypatch, error_number, message) -> None:
    secret = "dummy-secret"

    def fail(*args, **kwargs):
        raise OSError(error_number, secret, secret)

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(EnvrcctlError, match=message) as exc:
        run_command(["helper"], input_text=secret, error_message="Helper failed.")
    assert secret not in "".join(traceback.format_exception(exc.value))
    assert exc.value.__context__ is None


def test_run_command_invalid_utf8_does_not_leak_partial_output(monkeypatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, b"dummy-secret\xff", b""),
    )
    with pytest.raises(EnvrcctlError, match="Invalid UTF-8") as exc:
        run_command(["helper"])
    assert "dummy-secret" not in "".join(traceback.format_exception(exc.value))
    assert exc.value.__context__ is None


def test_run_command_invalid_input_encoding_never_starts_child(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: calls.append(a))
    with pytest.raises(EnvrcctlError, match="Invalid UTF-8") as exc:
        run_command(["helper"], input_text="dummy-secret\ud800")
    assert calls == []
    assert exc.value.__context__ is None


def test_run_command_interruption_is_a_domain_error(monkeypatch) -> None:
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess, "run", interrupt)
    with pytest.raises(EnvrcctlError, match="interrupted") as exc:
        run_command(["helper"])
    assert exc.value.__context__ is None
