from __future__ import annotations

from .command_runner import run_command
from .errors import EnvrcctlError
from .secrets import SecretRef


class SecretServiceBackend:
    """Linux SecretService backend using secret-tool."""

    def _validate_ref(self, ref: SecretRef) -> None:
        if ref.scheme != "ss":
            raise EnvrcctlError("SecretService backend requires an ss secret reference.")

    def get(self, ref: SecretRef) -> str:
        self._validate_ref(ref)
        return _run_secret_tool(
            [
                "secret-tool",
                "lookup",
                "service",
                ref.service,
                "account",
                ref.account,
            ]
        )

    def set(self, ref: SecretRef, value: str) -> None:
        self._validate_ref(ref)
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
            input_text=value,
        )

    def delete(self, ref: SecretRef) -> None:
        self._validate_ref(ref)
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

    def list(self, prefix: str | None = None) -> list[SecretRef]:
        # SecretService listing is not required for MVP usage.
        return []


def _run_secret_tool(args: list[str], input_text: str | None = None) -> str:
    return run_command(
        args,
        input_text=input_text,
        allowed_commands={"secret-tool"},
        error_message="SecretService command failed.",
    )
