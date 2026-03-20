from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .errors import EnvrcctlError

_HELPER_ENV_VAR = "ENVRCCTL_MACOS_AUTH_HELPER"
_DEFAULT_HELPER_BASENAME = "envrcctl-macos-auth"


def _default_helper_path() -> Path:
    return Path(__file__).resolve().parent / _DEFAULT_HELPER_BASENAME


def _helper_path() -> Path:
    configured = os.getenv(_HELPER_ENV_VAR)
    if configured:
        return Path(configured).expanduser()

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


def ensure_device_owner_auth(reason: str) -> None:
    """Require macOS device owner authentication for sensitive secret access."""

    if sys.platform != "darwin":
        return

    if not reason.strip():
        raise EnvrcctlError("Authentication reason cannot be empty.")

    helper_path = _helper_path()
    _ensure_helper_ready(helper_path)

    try:
        subprocess.run(
            [str(helper_path), "--authorize-only", "--reason", reason],
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip()
        if not message:
            message = "Device owner authentication failed."
        raise EnvrcctlError(message) from exc
