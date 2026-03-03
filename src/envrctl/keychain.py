from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .command_runner import run_command
from .secrets import SecretBackend, SecretRef


class KeychainBackend(SecretBackend):
    """macOS Keychain backend using /usr/bin/security."""

    def get(self, ref: SecretRef) -> str:
        result = run_command(
            [
                "security",
                "find-generic-password",
                "-s",
                ref.service,
                "-a",
                ref.account,
                "-w",
            ],
            allowed_commands={"security"},
            error_message="Keychain command failed.",
        )
        return result.strip()

    def set(self, ref: SecretRef, value: str) -> None:
        # Use -w as the final option to prompt for password to avoid CLI args.
        # Provide value via stdin.
        run_command(
            [
                "security",
                "add-generic-password",
                "-s",
                ref.service,
                "-a",
                ref.account,
                "-U",
                "-w",
            ],
            input_text=value + "\n",
            allowed_commands={"security"},
            error_message="Keychain command failed.",
        )

    def delete(self, ref: SecretRef) -> None:
        run_command(
            [
                "security",
                "delete-generic-password",
                "-s",
                ref.service,
                "-a",
                ref.account,
            ],
            allowed_commands={"security"},
            error_message="Keychain command failed.",
        )

    def list(self, prefix: str | None = None) -> List[SecretRef]:
        # Keychain listing is not required for Phase 1 use-cases.
        return []
