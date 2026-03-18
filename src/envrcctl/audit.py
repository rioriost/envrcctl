from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from .errors import EnvrcctlError

_SCHEMA_VERSION = 1
_AUDIT_DIRNAME = "audit"
_AUDIT_FILENAME = "audit.jsonl"
_LATEST_HASH_FILENAME = "latest_hash"
_META_FILENAME = "meta.json"


@dataclass(frozen=True)
class AuditRef:
    scheme: str
    service: str
    account: str
    kind: str


@dataclass(frozen=True)
class AuditErrorInfo:
    code: str
    message: str


@dataclass(frozen=True)
class AuditEvent:
    schema_version: int
    event_id: str
    timestamp: str
    action: str
    status: str
    vars: list[str]
    refs: list[AuditRef]
    cwd: str
    platform: str
    command: list[str] | None
    error: AuditErrorInfo | None
    prev_hash: str | None
    hash: str


@dataclass(frozen=True)
class AuditVerifyResult:
    ok: bool
    event_count: int
    latest_hash: str | None
    failure_reason: str | None = None
    failure_line: int | None = None
    failure_event_id: str | None = None


def state_root(platform: str | None = None, home: Path | None = None) -> Path:
    resolved_platform = platform or os.sys.platform
    resolved_home = (home or Path.home()).expanduser()

    if resolved_platform == "darwin":
        return resolved_home / "Library" / "Application Support" / "envrcctl"

    xdg_state_home = os.getenv("XDG_STATE_HOME")
    if xdg_state_home:
        return Path(xdg_state_home).expanduser() / "envrcctl"

    return resolved_home / ".local" / "state" / "envrcctl"


def audit_dir(platform: str | None = None, home: Path | None = None) -> Path:
    return state_root(platform=platform, home=home) / _AUDIT_DIRNAME


def audit_file(platform: str | None = None, home: Path | None = None) -> Path:
    return audit_dir(platform=platform, home=home) / _AUDIT_FILENAME


def latest_hash_file(platform: str | None = None, home: Path | None = None) -> Path:
    return audit_dir(platform=platform, home=home) / _LATEST_HASH_FILENAME


def meta_file(platform: str | None = None, home: Path | None = None) -> Path:
    return audit_dir(platform=platform, home=home) / _META_FILENAME


def ensure_audit_store_secure(
    platform: str | None = None, home: Path | None = None
) -> Path:
    directory = audit_dir(platform=platform, home=home)
    directory.mkdir(parents=True, exist_ok=True)
    _chmod_exact(directory, 0o700)
    _ensure_mode_exact(directory, 0o700, label="Audit directory")
    return directory


def ensure_audit_files_secure(
    platform: str | None = None, home: Path | None = None
) -> None:
    ensure_audit_store_secure(platform=platform, home=home)

    for path in (
        audit_file(platform=platform, home=home),
        latest_hash_file(platform=platform, home=home),
        meta_file(platform=platform, home=home),
    ):
        if path.exists():
            _chmod_exact(path, 0o600)
            _ensure_mode_exact(path, 0o600, label=f"Audit file {path.name}")


def append_event(
    *,
    action: str,
    status: str,
    vars: Iterable[str],
    refs: Iterable[AuditRef],
    cwd: str | Path,
    platform: str | None = None,
    command: list[str] | None = None,
    error: AuditErrorInfo | None = None,
    timestamp: str | None = None,
    event_id: str | None = None,
    home: Path | None = None,
) -> AuditEvent:
    resolved_platform = platform or os.sys.platform
    ensure_audit_store_secure(platform=resolved_platform, home=home)

    previous_hash = read_latest_hash(platform=resolved_platform, home=home)

    event_data = {
        "schema_version": _SCHEMA_VERSION,
        "event_id": event_id or str(uuid.uuid4()),
        "timestamp": timestamp or _utc_now_rfc3339(),
        "action": action,
        "status": status,
        "vars": list(vars),
        "refs": [asdict(ref) for ref in refs],
        "cwd": str(cwd),
        "platform": resolved_platform,
        "command": command,
        "error": asdict(error) if error is not None else None,
        "prev_hash": previous_hash,
    }
    event_hash = hash_event_payload(event_data)

    event = AuditEvent(
        schema_version=event_data["schema_version"],
        event_id=event_data["event_id"],
        timestamp=event_data["timestamp"],
        action=event_data["action"],
        status=event_data["status"],
        vars=event_data["vars"],
        refs=[AuditRef(**item) for item in event_data["refs"]],
        cwd=event_data["cwd"],
        platform=event_data["platform"],
        command=event_data["command"],
        error=AuditErrorInfo(**event_data["error"])
        if event_data["error"] is not None
        else None,
        prev_hash=event_data["prev_hash"],
        hash=event_hash,
    )

    line = canonical_json(_event_to_serializable(event)) + "\n"
    path = audit_file(platform=resolved_platform, home=home)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
    _chmod_exact(path, 0o600)

    latest_path = latest_hash_file(platform=resolved_platform, home=home)
    latest_path.write_text(event.hash + "\n", encoding="utf-8")
    _chmod_exact(latest_path, 0o600)

    write_meta(platform=resolved_platform, home=home)

    ensure_audit_files_secure(platform=resolved_platform, home=home)
    return event


def iter_events(
    platform: str | None = None, home: Path | None = None
) -> Iterator[AuditEvent]:
    path = audit_file(platform=platform, home=home)
    if not path.exists():
        return iter(())

    def _generator() -> Iterator[AuditEvent]:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise EnvrcctlError(
                        f"Invalid audit log JSON at line {line_number}."
                    ) from exc
                yield parse_event(payload)

    return _generator()


def verify_chain(
    platform: str | None = None, home: Path | None = None
) -> AuditVerifyResult:
    try:
        directory = audit_dir(platform=platform, home=home)
        if directory.exists():
            _ensure_mode_exact(directory, 0o700, label="Audit directory")
        else:
            ensure_audit_store_secure(platform=platform, home=home)
        ensure_audit_files_secure(platform=platform, home=home)
    except EnvrcctlError as exc:
        return AuditVerifyResult(
            ok=False,
            event_count=0,
            latest_hash=None,
            failure_reason=str(exc),
        )

    path = audit_file(platform=platform, home=home)
    if not path.exists():
        return AuditVerifyResult(ok=True, event_count=0, latest_hash=None)

    previous_hash: str | None = None
    latest_hash: str | None = None
    event_count = 0

    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                return AuditVerifyResult(
                    ok=False,
                    event_count=event_count,
                    latest_hash=latest_hash,
                    failure_reason="Invalid JSON in audit log.",
                    failure_line=line_number,
                )

            try:
                event = parse_event(payload)
            except EnvrcctlError as exc:
                return AuditVerifyResult(
                    ok=False,
                    event_count=event_count,
                    latest_hash=latest_hash,
                    failure_reason=str(exc),
                    failure_line=line_number,
                    failure_event_id=payload.get("event_id"),
                )

            expected_prev_hash = previous_hash
            if event.prev_hash != expected_prev_hash:
                return AuditVerifyResult(
                    ok=False,
                    event_count=event_count,
                    latest_hash=latest_hash,
                    failure_reason="Audit chain previous hash mismatch.",
                    failure_line=line_number,
                    failure_event_id=event.event_id,
                )

            computed_hash = hash_event(event)
            if event.hash != computed_hash:
                return AuditVerifyResult(
                    ok=False,
                    event_count=event_count,
                    latest_hash=latest_hash,
                    failure_reason="Audit event hash mismatch.",
                    failure_line=line_number,
                    failure_event_id=event.event_id,
                )

            previous_hash = event.hash
            latest_hash = event.hash
            event_count += 1

    sidecar_latest_hash = read_latest_hash(platform=platform, home=home)
    if sidecar_latest_hash != latest_hash:
        return AuditVerifyResult(
            ok=False,
            event_count=event_count,
            latest_hash=latest_hash,
            failure_reason="Latest hash sidecar does not match audit log tail.",
        )

    return AuditVerifyResult(ok=True, event_count=event_count, latest_hash=latest_hash)


def parse_event(payload: dict[str, Any]) -> AuditEvent:
    required = {
        "schema_version",
        "event_id",
        "timestamp",
        "action",
        "status",
        "vars",
        "refs",
        "cwd",
        "platform",
        "command",
        "error",
        "prev_hash",
        "hash",
    }
    missing = required - set(payload.keys())
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise EnvrcctlError(f"Audit event is missing required fields: {missing_list}")

    refs_payload = payload["refs"]
    if not isinstance(refs_payload, list):
        raise EnvrcctlError("Audit event refs must be a list.")

    refs: list[AuditRef] = []
    for item in refs_payload:
        if not isinstance(item, dict):
            raise EnvrcctlError("Audit event ref entry must be an object.")
        refs.append(
            AuditRef(
                scheme=_expect_str(item, "scheme"),
                service=_expect_str(item, "service"),
                account=_expect_str(item, "account"),
                kind=_expect_str(item, "kind"),
            )
        )

    error_payload = payload["error"]
    error_info: AuditErrorInfo | None = None
    if error_payload is not None:
        if not isinstance(error_payload, dict):
            raise EnvrcctlError("Audit event error must be an object or null.")
        error_info = AuditErrorInfo(
            code=_expect_str(error_payload, "code"),
            message=_expect_str(error_payload, "message"),
        )

    vars_payload = payload["vars"]
    if not isinstance(vars_payload, list) or any(
        not isinstance(item, str) for item in vars_payload
    ):
        raise EnvrcctlError("Audit event vars must be a list of strings.")

    command_payload = payload["command"]
    if command_payload is not None:
        if not isinstance(command_payload, list) or any(
            not isinstance(item, str) for item in command_payload
        ):
            raise EnvrcctlError(
                "Audit event command must be a list of strings or null."
            )

    prev_hash = payload["prev_hash"]
    if prev_hash is not None and not isinstance(prev_hash, str):
        raise EnvrcctlError("Audit event prev_hash must be a string or null.")

    return AuditEvent(
        schema_version=_expect_int(payload, "schema_version"),
        event_id=_expect_str(payload, "event_id"),
        timestamp=_expect_str(payload, "timestamp"),
        action=_expect_str(payload, "action"),
        status=_expect_str(payload, "status"),
        vars=list(vars_payload),
        refs=refs,
        cwd=_expect_str(payload, "cwd"),
        platform=_expect_str(payload, "platform"),
        command=list(command_payload) if command_payload is not None else None,
        error=error_info,
        prev_hash=prev_hash,
        hash=_expect_str(payload, "hash"),
    )


def hash_event(event: AuditEvent) -> str:
    payload = _event_to_serializable(event)
    payload.pop("hash", None)
    return hash_event_payload(payload)


def hash_event_payload(payload: dict[str, Any]) -> str:
    serialized = canonical_json(payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def read_latest_hash(
    platform: str | None = None, home: Path | None = None
) -> str | None:
    path = latest_hash_file(platform=platform, home=home)
    if not path.exists():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


def write_meta(platform: str | None = None, home: Path | None = None) -> None:
    path = meta_file(platform=platform, home=home)
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "updated_at": _utc_now_rfc3339(),
    }
    path.write_text(canonical_json(payload) + "\n", encoding="utf-8")
    _chmod_exact(path, 0o600)


def _utc_now_rfc3339() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _event_to_serializable(event: AuditEvent) -> dict[str, Any]:
    return {
        "schema_version": event.schema_version,
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "action": event.action,
        "status": event.status,
        "vars": list(event.vars),
        "refs": [asdict(ref) for ref in event.refs],
        "cwd": event.cwd,
        "platform": event.platform,
        "command": list(event.command) if event.command is not None else None,
        "error": asdict(event.error) if event.error is not None else None,
        "prev_hash": event.prev_hash,
        "hash": event.hash,
    }


def _expect_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise EnvrcctlError(f"Audit event field {key} must be a string.")
    return value


def _expect_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise EnvrcctlError(f"Audit event field {key} must be an integer.")
    return value


def _ensure_mode_exact(path: Path, expected_mode: int, label: str) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != expected_mode:
        raise EnvrcctlError(
            f"{label} permissions are insecure: expected {oct(expected_mode)}, got {oct(mode)}."
        )


def _chmod_exact(path: Path, mode: int) -> None:
    os.chmod(path, mode)
