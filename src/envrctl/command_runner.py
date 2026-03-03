from __future__ import annotations

import subprocess
from typing import Sequence

from .errors import EnvrcctlError


def run_command(
    args: Sequence[str],
    input_text: str | None = None,
    error_message: str = "Command failed.",
) -> str:
    try:
        result = subprocess.run(
            list(args),
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or error_message
        raise EnvrcctlError(message) from exc
    return result.stdout
