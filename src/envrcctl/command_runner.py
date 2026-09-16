from __future__ import annotations

import errno
import subprocess
from collections.abc import Iterable, Sequence

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
        raise EnvrcctlError("Command not allowed.")
    return validated


def run_command(
    args: Sequence[str],
    input_text: str | None = None,
    error_message: str = "Command failed.",
    allowed_commands: Iterable[str] | None = None,
) -> str:
    """Transport exact UTF-8 without retaining subprocess diagnostics or exception chains."""
    validated_args = _validate_command_args(args, allowed_commands)
    failure = error_message
    try:
        result = subprocess.run(
            validated_args,
            input=None if input_text is None else input_text.encode("utf-8"),
            capture_output=True,
            check=True,
        )
        return result.stdout.decode("utf-8")
    except subprocess.CalledProcessError:
        pass
    except OSError as exc:
        details = {
            errno.ENOENT: "Executable not found.",
            errno.EACCES: "Executable permission denied.",
            errno.ENOEXEC: "Executable format is invalid.",
        }
        failure = f"{error_message} {details.get(exc.errno, 'Unable to start command.')}"
    except UnicodeError:
        failure = f"{error_message} Invalid UTF-8 data."
    except KeyboardInterrupt:
        failure = f"{error_message} Command interrupted."

    # Raising outside the handlers also discards __context__, not just its display.
    raise EnvrcctlError(failure)
