from __future__ import annotations

import subprocess
from typing import Iterable, Sequence

from .errors import EnvrcctlError


def _validate_command_args(
    args: Sequence[str],
    allowed_commands: Iterable[str] | None,
) -> list[str]:
    if not args:
        raise EnvrcctlError("Command arguments cannot be empty.")
    validated: list[str] = []
    for arg in args:
        if not isinstance(arg, str):
            raise EnvrcctlError("Command arguments must be strings.")
        if arg == "":
            raise EnvrcctlError("Command arguments cannot be empty strings.")
        if "\x00" in arg:
            raise EnvrcctlError("Command arguments cannot contain null bytes.")
        validated.append(arg)
    if allowed_commands is not None and validated[0] not in allowed_commands:
        raise EnvrcctlError(f"Command not allowed: {validated[0]}")
    return validated


def run_command(
    args: Sequence[str],
    input_text: str | None = None,
    error_message: str = "Command failed.",
    allowed_commands: Iterable[str] | None = None,
) -> str:
    validated_args = _validate_command_args(args, allowed_commands)
    try:
        result = subprocess.run(
            validated_args,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or error_message
        raise EnvrcctlError(message) from exc
    return result.stdout
