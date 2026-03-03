from __future__ import annotations

import subprocess

import pytest

from envrctl.command_runner import _validate_command_args, run_command
from envrctl.errors import EnvrcctlError


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


def test_run_command_redacts_input_text(monkeypatch) -> None:
    secret = "supersecret"

    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            1, args[0], output="", stderr=f"boom {secret}"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EnvrcctlError) as exc:
        run_command(["echo"], input_text=secret, allowed_commands={"echo"})

    message = str(exc.value)
    assert secret not in message
    assert "[REDACTED]" in message
