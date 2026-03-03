from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass
from typing import Iterable, Protocol

from .errors import EnvrcctlError

DEFAULT_SERVICE = "st.rio.envrcctl"
SUPPORTED_SCHEMES = ("kc", "ss")
SUPPORTED_KINDS = ("runtime", "admin")
SERVICE_RE = re.compile(r"^[A-Za-z0-9._-]+$")
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


def _validate_ref_part(label: str, value: str, pattern: re.Pattern[str]) -> None:
    if not value or not pattern.match(value):
        raise EnvrcctlError(f"Invalid secret ref {label}: {value}")


def _normalize_kind(kind: str) -> str:
    normalized = kind.strip().lower()
    if normalized not in SUPPORTED_KINDS:
        supported = ", ".join(SUPPORTED_KINDS)
        raise EnvrcctlError(
            f"Invalid secret kind: {kind}. Supported kinds: {supported}."
        )
    return normalized


@dataclass(frozen=True)
class SecretRef:
    scheme: str
    service: str
    account: str
    kind: str


class SecretBackend(Protocol):
    def get(self, ref: SecretRef) -> str: ...

    def set(self, ref: SecretRef, value: str) -> None: ...

    def delete(self, ref: SecretRef) -> None: ...

    def list(self, prefix: str | None = None) -> Iterable[SecretRef]: ...


def parse_ref(ref: str) -> SecretRef:
    parts = ref.split(":", 2)
    if len(parts) != 3:
        raise EnvrcctlError(f"Invalid secret ref: {ref}")
    scheme, service, rest = parts
    if scheme not in SUPPORTED_SCHEMES:
        raise EnvrcctlError(f"Unsupported secret backend scheme: {scheme}")
    _validate_ref_part("service", service, SERVICE_RE)

    if rest.endswith(":runtime") or rest.endswith(":admin"):
        account, kind = rest.rsplit(":", 1)
        if not account:
            raise EnvrcctlError(f"Invalid secret ref account: {rest}")
    else:
        account = rest
        kind = "runtime"

    _validate_ref_part("account", account, ACCOUNT_RE)
    kind = _normalize_kind(kind)
    return SecretRef(scheme=scheme, service=service, account=account, kind=kind)


def format_ref(
    service: str,
    account: str,
    scheme: str = "kc",
    kind: str = "runtime",
) -> str:
    if scheme not in SUPPORTED_SCHEMES:
        raise EnvrcctlError(f"Unsupported secret backend scheme: {scheme}")
    _validate_ref_part("service", service, SERVICE_RE)
    _validate_ref_part("account", account, ACCOUNT_RE)
    kind = _normalize_kind(kind)
    return f"{scheme}:{service}:{account}:{kind}"


def resolve_backend(scheme: str | None = None) -> tuple[str, SecretBackend]:
    requested = (scheme or os.getenv("ENVRCCTL_BACKEND") or "").strip().lower()
    if requested:
        if requested not in SUPPORTED_SCHEMES:
            supported = ", ".join(SUPPORTED_SCHEMES)
            raise EnvrcctlError(
                f"Unsupported secret backend scheme: {requested}. "
                f"Supported schemes: {supported}."
            )
        return requested, _backend_for_scheme(requested)

    if sys.platform == "darwin":
        return "kc", _backend_for_scheme("kc")
    if _have_cmd("secret-tool"):
        return "ss", _backend_for_scheme("ss")
    raise EnvrcctlError("No supported secret backend for this platform.")


def backend_for_ref(ref: SecretRef) -> SecretBackend:
    return _backend_for_scheme(ref.scheme)


def _backend_for_scheme(scheme: str) -> SecretBackend:
    if scheme == "kc":
        if sys.platform != "darwin":
            raise EnvrcctlError("Keychain backend requires macOS.")
        from .keychain import KeychainBackend

        return KeychainBackend()
    if scheme == "ss":
        if not _have_cmd("secret-tool"):
            raise EnvrcctlError("SecretService backend requires secret-tool.")
        from .secretservice import SecretServiceBackend

        return SecretServiceBackend()
    raise EnvrcctlError(f"Unsupported secret backend scheme: {scheme}")


def _have_cmd(command: str) -> bool:
    return shutil.which(command) is not None
