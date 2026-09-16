from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .command_runner import run_command
from .errors import EnvrcctlError

_HELPER_ENV_VAR = "ENVRCCTL_MACOS_AUTH_HELPER"
_DEFAULT_HELPER_BASENAME = "envrcctl-macos-auth"


def _default_helper_path() -> Path:
    return Path(__file__).resolve().parent / _DEFAULT_HELPER_BASENAME


def _helper_path() -> Path:
    try:
        return _selected_helper_path().expanduser().resolve()
    except OSError, RuntimeError, ValueError:
        pass
    raise EnvrcctlError("macOS authentication helper path could not be resolved.")


def _selected_helper_path() -> Path:
    configured = os.getenv(_HELPER_ENV_VAR)
    if configured:
        return Path(configured)

    helper_on_path = shutil.which(_DEFAULT_HELPER_BASENAME)
    if helper_on_path:
        return Path(helper_on_path)

    return _default_helper_path()


def _ensure_helper_ready(path: Path) -> None:
    if not path.exists():
        raise EnvrcctlError(
            "macOS authentication helper not found. "
            "Build or install envrcctl-macos-auth to use device owner authentication."
        )
    if not path.is_file():
        raise EnvrcctlError(
            "macOS authentication helper path is invalid. Expected an executable file."
        )
    if not os.access(path, os.X_OK):
        raise EnvrcctlError(
            "macOS authentication helper is not executable. Fix permissions and retry."
        )


def ready_helper_path() -> Path:
    """Return the same absolute helper path that was checked for execution."""
    path = _helper_path()
    failure = False
    try:
        _ensure_helper_ready(path)
    except OSError:
        failure = True
    if failure:
        raise EnvrcctlError("macOS authentication helper could not be inspected.")
    return path


def ensure_device_owner_auth(reason: str) -> None:
    """Require macOS device owner authentication for sensitive secret access."""

    if sys.platform != "darwin":
        return

    if not reason.strip():
        raise EnvrcctlError("Authentication reason cannot be empty.")

    helper_path = ready_helper_path()
    run_command(
        [str(helper_path), "--authorize-only", "--reason", reason],
        allowed_commands={str(helper_path)},
        error_message="Device owner authentication failed.",
    )
