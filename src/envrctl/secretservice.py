from __future__ import annotations

import subprocess
from typing import List

from .errors import EnvrcctlError
from .secrets import SecretBackend, SecretRef


class SecretServiceBackend(SecretBackend):
    """Linux SecretService backend using secret-tool."""

    def get(self, ref: SecretRef) -> str:
        result = _run_secret_tool(
            [
                "secret-tool",
                "lookup",
                "service",
                ref.service,
                "account",
                ref.account,
            ]
        )
        return result.strip()

    def set(self, ref: SecretRef, value: str) -> None:
        label = f"envrcctl:{ref.service}:{ref.account}"
        _run_secret_tool(
            [
                "secret-tool",
                "store",
                "--label",
                label,
                "service",
                ref.service,
                "account",
                ref.account,
            ],
            input_text=value + "\n",
        )

    def delete(self, ref: SecretRef) -> None:
        _run_secret_tool(
            [
                "secret-tool",
                "clear",
                "service",
                ref.service,
                "account",
                ref.account,
            ]
        )

    def list(self, prefix: str | None = None) -> List[SecretRef]:
        # SecretService listing is not required for MVP usage.
        return []


def _run_secret_tool(args: List[str], input_text: str | None = None) -> str:
    try:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        message = (
            exc.stderr.strip() or exc.stdout.strip() or "SecretService command failed."
        )
        raise EnvrcctlError(message) from exc
    return result.stdout
