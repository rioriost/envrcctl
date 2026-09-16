from __future__ import annotations

import json
from pathlib import Path

from . import auth
from .command_runner import run_command
from .errors import EnvrcctlError
from .secrets import SecretRef


class KeychainBackend:
    """macOS Keychain backend using /usr/bin/security and a native auth helper."""

    HELPER_ENV_VAR = auth._HELPER_ENV_VAR
    DEFAULT_HELPER_BASENAME = auth._DEFAULT_HELPER_BASENAME

    def _helper_path(self) -> Path:
        return auth._helper_path()

    def _validate_ref(self, ref: SecretRef) -> None:
        if ref.scheme != "kc":
            raise EnvrcctlError("Keychain backend requires a kc secret reference.")

    def _build_auth_reason(self, action: str, ref: SecretRef) -> str:
        return (
            f"envrcctl needs device owner authentication to {action} the secret for {ref.account}."
        )

    def _run_auth_helper(self, args: list[str], input_text: str | None = None) -> str:
        helper_path = auth.ready_helper_path()
        return run_command(
            [str(helper_path), *args],
            input_text=input_text,
            allowed_commands={str(helper_path)},
            error_message="Authenticated Keychain command failed.",
        )

    def get_with_auth(self, ref: SecretRef, reason: str | None = None) -> str:
        self._validate_ref(ref)
        values = self.get_many_with_auth([ref], reason or self._build_auth_reason("access", ref))
        return values[(ref.service, ref.account)]

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
            self._validate_ref(ref)
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

        decoded = None
        try:
            decoded = json.loads(output)
        except ValueError, RecursionError:
            pass
        if decoded is None:
            raise EnvrcctlError("Authenticated Keychain helper returned invalid JSON.")
        if not isinstance(decoded, dict):
            raise EnvrcctlError("Authenticated Keychain helper returned an invalid response.")

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
        if set(values) != expected:
            raise EnvrcctlError("Authenticated Keychain helper returned unexpected secret entries.")

        return values

    def get(self, ref: SecretRef) -> str:
        return self.get_with_auth(ref)

    def set(self, ref: SecretRef, value: str) -> None:
        self._validate_ref(ref)
        self._run_auth_helper(
            [
                "--set",
                "--service",
                ref.service,
                "--account",
                ref.account,
                "--reason",
                self._build_auth_reason("store", ref),
            ],
            input_text=value,
        )

    def delete(self, ref: SecretRef) -> None:
        self._validate_ref(ref)
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

    def list(self, prefix: str | None = None) -> list[SecretRef]:
        # Keychain listing is not required for current use-cases.
        return []
