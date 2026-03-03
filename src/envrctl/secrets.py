from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Iterable, Protocol

from .errors import EnvrcctlError

REF_PREFIX = "kc"
DEFAULT_SERVICE = "com.rio.envrcctl"


@dataclass(frozen=True)
class SecretRef:
    service: str
    account: str


class SecretBackend(Protocol):
    def get(self, ref: SecretRef) -> str: ...

    def set(self, ref: SecretRef, value: str) -> None: ...

    def delete(self, ref: SecretRef) -> None: ...

    def list(self, prefix: str | None = None) -> Iterable[SecretRef]: ...


def parse_ref(ref: str) -> SecretRef:
    parts = ref.split(":", 2)
    if len(parts) != 3 or parts[0] != REF_PREFIX:
        raise EnvrcctlError(f"Invalid secret ref: {ref}")
    _, service, account = parts
    if not service or not account:
        raise EnvrcctlError(f"Invalid secret ref: {ref}")
    return SecretRef(service=service, account=account)


def format_ref(service: str, account: str) -> str:
    if not service or not account:
        raise EnvrcctlError("Service and account are required for secret refs.")
    return f"{REF_PREFIX}:{service}:{account}"


def get_default_backend() -> SecretBackend:
    if sys.platform == "darwin":
        from .keychain import KeychainBackend

        return KeychainBackend()
    raise EnvrcctlError("No supported secret backend for this platform.")
