from __future__ import annotations

from typing import List

from .command_runner import run_command
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
    return run_command(
        args,
        input_text=input_text,
        error_message="SecretService command failed.",
    )
