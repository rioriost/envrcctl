from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import List

from .command_runner import run_command
from .errors import EnvrcctlError
from .secrets import SecretBackend, SecretRef


class KeychainBackend(SecretBackend):
    """macOS Keychain backend using /usr/bin/security and a native auth helper."""

    HELPER_ENV_VAR = "ENVRCCTL_MACOS_AUTH_HELPER"
    DEFAULT_HELPER_BASENAME = "envrcctl-macos-auth"

    def _helper_path(self) -> Path:
        configured = os.getenv(self.HELPER_ENV_VAR)
        if configured:
            return Path(configured).expanduser()

        on_path = shutil.which(self.DEFAULT_HELPER_BASENAME)
        if on_path:
            return Path(on_path)

        return Path(__file__).resolve().parent / self.DEFAULT_HELPER_BASENAME

    def _ensure_helper_ready(self, helper_path: Path) -> None:
        if not helper_path.exists():
            raise EnvrcctlError(
                "macOS authentication helper not found. "
                "Build or install envrcctl-macos-auth to use authenticated secret access."
            )
        if not helper_path.is_file():
            raise EnvrcctlError(
                "macOS authentication helper path is invalid. Expected an executable file."
            )
        if not os.access(helper_path, os.X_OK):
            raise EnvrcctlError(
                "macOS authentication helper is not executable. Fix permissions and retry."
            )

    def _build_auth_reason(self, action: str, ref: SecretRef) -> str:
        return (
            f"envrcctl needs device owner authentication to {action} the secret for {ref.account}."
        )

    def _run_auth_helper(self, args: list[str], input_text: str | None = None) -> str:
        helper_path = self._helper_path()
        self._ensure_helper_ready(helper_path)
        result = run_command(
            [str(helper_path), *args],
            input_text=input_text,
            allowed_commands={str(helper_path)},
            error_message="Authenticated Keychain command failed.",
        )
        return result.rstrip("\n")

    def get_with_auth(self, ref: SecretRef, reason: str | None = None) -> str:
        return self._run_auth_helper(
            [
                "--service",
                ref.service,
                "--account",
                ref.account,
                "--reason",
                reason or self._build_auth_reason("access", ref),
            ]
        )

    def get_many_with_auth(
        self,
        refs: list[SecretRef],
        reason: str | None = None,
    ) -> dict[tuple[str, str], str]:
        if not refs:
            return {}

        unique_refs: list[SecretRef] = []
        seen_refs: set[tuple[str, str]] = set()
        for ref in refs:
            key = (ref.service, ref.account)
            if key in seen_refs:
                continue
            seen_refs.add(key)
            unique_refs.append(ref)

        items = [{"service": ref.service, "account": ref.account} for ref in unique_refs]
        payload = json.dumps({"items": items})

        output = self._run_auth_helper(
            [
                "--input-json",
                "-",
                "--reason",
                reason
                or (
                    "envrcctl needs device owner authentication to access secrets for "
                    + ", ".join(ref.account for ref in unique_refs)
                    + "."
                ),
            ],
            input_text=payload,
        )

        try:
            decoded = json.loads(output)
        except json.JSONDecodeError as exc:
            raise EnvrcctlError("Authenticated Keychain helper returned invalid JSON.") from exc

        raw_items = decoded.get("items")
        if not isinstance(raw_items, list):
            raise EnvrcctlError("Authenticated Keychain helper returned an invalid response.")

        values: dict[tuple[str, str], str] = {}
        for item in raw_items:
            if not isinstance(item, dict):
                raise EnvrcctlError("Authenticated Keychain helper returned an invalid item.")
            service = item.get("service")
            account = item.get("account")
            value = item.get("value")
            if not isinstance(service, str) or not isinstance(account, str):
                raise EnvrcctlError(
                    "Authenticated Keychain helper returned an invalid item payload."
                )
            if not isinstance(value, str):
                raise EnvrcctlError("Authenticated Keychain helper response is missing a value.")
            key = (service, account)
            if key in values:
                raise EnvrcctlError(
                    "Authenticated Keychain helper returned duplicate secret entries."
                )
            values[key] = value

        expected = {(ref.service, ref.account) for ref in unique_refs}
        missing = expected - set(values.keys())
        if missing:
            missing_list = ", ".join(f"{service}/{account}" for service, account in sorted(missing))
            raise EnvrcctlError(
                f"Authenticated Keychain helper response is missing secrets: {missing_list}"
            )

        return values

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
        # Pass password directly to avoid interactive prompt.
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
                value,
            ],
            input_text=value,
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
        # Keychain listing is not required for current use-cases.
        return []
