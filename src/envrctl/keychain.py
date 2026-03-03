from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import List

from .errors import EnvrcctlError
from .secrets import SecretBackend, SecretRef


class KeychainBackend(SecretBackend):
    """macOS Keychain backend using /usr/bin/security."""

    def get(self, ref: SecretRef) -> str:
        result = _run_security(
            [
                "security",
                "find-generic-password",
                "-s",
                ref.service,
                "-a",
                ref.account,
                "-w",
            ]
        )
        return result.strip()

    def set(self, ref: SecretRef, value: str) -> None:
        # Use -w as the final option to prompt for password to avoid CLI args.
        # Provide value via stdin.
        _run_security(
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
        )

    def delete(self, ref: SecretRef) -> None:
        _run_security(
            [
                "security",
                "delete-generic-password",
                "-s",
                ref.service,
                "-a",
                ref.account,
            ]
        )

    def list(self, prefix: str | None = None) -> List[SecretRef]:
        # Keychain listing is not required for Phase 1 use-cases.
        return []


def _run_security(args: List[str], input_text: str | None = None) -> str:
    try:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or "Keychain command failed."
        raise EnvrcctlError(message) from exc
    return result.stdout
