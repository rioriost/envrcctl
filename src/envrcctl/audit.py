from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import EnvrcctlError

_SCHEMA_VERSION = 2
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
    operation_id: str | None = None


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


def ensure_audit_store_secure(platform: str | None = None, home: Path | None = None) -> Path:
    directory = audit_dir(platform=platform, home=home)
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _ensure_secure_stat(directory.lstat(), 0o700, "Audit directory", directory=True)
    except OSError as exc:
        raise _storage_error(exc) from exc
    return directory


def ensure_audit_files_secure(platform: str | None = None, home: Path | None = None) -> None:
    """Validate existing permissions without creating or repairing the store."""
    with _locked_store(platform=platform, home=home):
        pass


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
    operation_id: str | None = None,
) -> AuditEvent:
    resolved_platform = platform or os.sys.platform
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
        "command": _command_metadata(command),
        "error": asdict(_safe_error(error)) if error is not None else None,
        "prev_hash": None,
        "operation_id": operation_id,
        "hash": "",
    }
    parse_event(event_data)
    with _locked_store(platform=resolved_platform, home=home, create=True, exclusive=True) as fd:
        if fd is None:
            raise EnvrcctlError(
                "Audit store is unavailable for writing. Run audit verify before retrying."
            )
        result = _verify_locked(fd)
        if not result.ok:
            raise EnvrcctlError(result.failure_reason)
        event_data["prev_hash"] = result.latest_hash
        event_data.pop("hash")
        event_data["hash"] = hash_event_payload(event_data)
        event = parse_event(event_data)
        _write_meta_locked(fd)
        line = (canonical_json(_event_to_serializable(event)) + "\n").encode("utf-8")
        log_fd = _open_file(fd, _AUDIT_FILENAME, os.O_WRONLY | os.O_APPEND, create=True)
        with os.fdopen(log_fd, "ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(fd)
        _atomic_write(fd, _LATEST_HASH_FILENAME, event.hash + "\n")
        return event


def iter_events(platform: str | None = None, home: Path | None = None) -> Iterator[AuditEvent]:
    with _locked_store(platform=platform, home=home) as fd:
        if fd is None:
            return iter(())
        events = []
        text = _read_text(fd, _AUDIT_FILENAME)
        if not text.strip() and _read_text(fd, _LATEST_HASH_FILENAME).strip():
            raise EnvrcctlError("Audit log is missing or empty but the latest hash sidecar is not.")
        for line_number, raw_line in enumerate(text.split("\n"), 1):
            if not raw_line.strip():
                continue
            try:
                payload = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise EnvrcctlError(f"Invalid audit log JSON at line {line_number}.") from exc
            events.append(parse_event(payload))
        return iter(events)


def verify_chain(platform: str | None = None, home: Path | None = None) -> AuditVerifyResult:
    try:
        with _locked_store(platform=platform, home=home) as fd:
            return _verify_locked(fd) if fd is not None else AuditVerifyResult(True, 0, None)
    except EnvrcctlError as exc:
        return AuditVerifyResult(
            ok=False,
            event_count=0,
            latest_hash=None,
            failure_reason=str(exc),
        )


def _verify_locked(fd: int) -> AuditVerifyResult:
    previous_hash: str | None = None
    latest_hash: str | None = None
    event_count = 0
    known_hashes: set[str] = set()
    text = _read_text(fd, _AUDIT_FILENAME)
    for line_number, raw_line in enumerate(text.split("\n"), start=1):
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
            computed_hash = hash_event(event)
        except EnvrcctlError as exc:
            return AuditVerifyResult(
                ok=False,
                event_count=event_count,
                latest_hash=latest_hash,
                failure_reason=str(exc),
                failure_line=line_number,
                failure_event_id=(
                    payload.get("event_id")
                    if isinstance(payload, dict) and isinstance(payload.get("event_id"), str)
                    else None
                ),
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
        known_hashes.add(event.hash)
        event_count += 1

    if text and not text.endswith("\n"):
        return AuditVerifyResult(
            False,
            event_count,
            latest_hash,
            "Audit log has an unterminated tail. Preserve the store and investigate; "
            "restore a verified backup before appending.",
        )

    sidecar_latest_hash = _read_text(fd, _LATEST_HASH_FILENAME).strip() or None
    if sidecar_latest_hash != latest_hash:
        if latest_hash is not None and (
            sidecar_latest_hash is None or sidecar_latest_hash in known_hashes
        ):
            reason = (
                "Audit log extends the latest hash sidecar (possible interrupted append). "
                "Stop all envrcctl writers, back up the audit store, and have an administrator "
                "verify the history before atomically restoring latest_hash to the verified "
                "log tail with mode 0600. No automatic recovery is performed."
            )
        else:
            reason = (
                "Latest hash sidecar does not match audit log tail. "
                "Preserve the store and investigate; restore a verified backup before appending."
            )
        return AuditVerifyResult(
            ok=False,
            event_count=event_count,
            latest_hash=latest_hash,
            failure_reason=reason,
        )

    return AuditVerifyResult(ok=True, event_count=event_count, latest_hash=latest_hash)


def parse_event(payload: Any) -> AuditEvent:
    if not isinstance(payload, dict):
        raise EnvrcctlError("Audit event must be an object.")
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

    version = _expect_int(payload, "schema_version")
    if version not in (1, 2):
        raise EnvrcctlError("Unsupported audit event schema version.")
    allowed = required | ({"operation_id"} if version == 2 else set())
    if set(payload) - allowed:
        raise EnvrcctlError("Audit event contains unsupported fields.")
    if version == 2 and "operation_id" not in payload:
        raise EnvrcctlError("Audit event is missing required fields: operation_id")
    operation_id = payload.get("operation_id")
    if operation_id is not None and not isinstance(operation_id, str):
        raise EnvrcctlError("Audit event operation_id must be a string or null.")

    refs_payload = payload["refs"]
    if not isinstance(refs_payload, list):
        raise EnvrcctlError("Audit event refs must be a list.")

    refs: list[AuditRef] = []
    for item in refs_payload:
        if not isinstance(item, dict):
            raise EnvrcctlError("Audit event ref entry must be an object.")
        if set(item) - {"scheme", "service", "account", "kind"}:
            raise EnvrcctlError("Audit event ref entry contains unsupported fields.")
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
        if set(error_payload) - {"code", "message"}:
            raise EnvrcctlError("Audit event error contains unsupported fields.")
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
            raise EnvrcctlError("Audit event command must be a list of strings or null.")

    prev_hash = payload["prev_hash"]
    if prev_hash is not None and not isinstance(prev_hash, str):
        raise EnvrcctlError("Audit event prev_hash must be a string or null.")

    return AuditEvent(
        schema_version=version,
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
        operation_id=operation_id,
    )


def hash_event(event: AuditEvent) -> str:
    payload = _event_to_serializable(event)
    payload.pop("hash", None)
    return hash_event_payload(payload)


def hash_event_payload(payload: dict[str, Any]) -> str:
    serialized = canonical_json(payload)
    try:
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    except UnicodeEncodeError as exc:
        raise EnvrcctlError("Audit event contains invalid Unicode.") from exc


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def read_latest_hash(platform: str | None = None, home: Path | None = None) -> str | None:
    with _locked_store(platform=platform, home=home) as fd:
        return (_read_text(fd, _LATEST_HASH_FILENAME).strip() or None) if fd is not None else None


def write_meta(platform: str | None = None, home: Path | None = None) -> None:
    with _locked_store(platform=platform, home=home, create=True, exclusive=True) as fd:
        if fd is None:
            raise EnvrcctlError(
                "Audit store is unavailable for writing. Run audit verify before retrying."
            )
        result = _verify_locked(fd)
        if not result.ok:
            raise EnvrcctlError(result.failure_reason)
        _write_meta_locked(fd)


def _write_meta_locked(fd: int) -> None:
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "updated_at": _utc_now_rfc3339(),
    }
    _atomic_write(fd, _META_FILENAME, canonical_json(payload) + "\n")


def _utc_now_rfc3339() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _event_to_serializable(event: AuditEvent) -> dict[str, Any]:
    payload = {
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
    if event.schema_version == 2:
        payload["operation_id"] = event.operation_id
    return payload


def _expect_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise EnvrcctlError(f"Audit event field {key} must be a string.")
    return value


def _expect_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if type(value) is not int:
        raise EnvrcctlError(f"Audit event field {key} must be an integer.")
    return value


def _ensure_secure_stat(
    info: os.stat_result, expected_mode: int, label: str, *, directory: bool = False
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode):
        raise EnvrcctlError(
            f"{label} must be a real {'directory' if directory else 'regular file'}."
        )
    if info.st_uid != os.getuid():
        raise EnvrcctlError(f"{label} must be owned by the current user.")
    if not directory and info.st_nlink != 1:
        raise EnvrcctlError(f"{label} must not have multiple hard links.")
    mode = stat.S_IMODE(info.st_mode)
    if mode != expected_mode:
        raise EnvrcctlError(
            f"{label} permissions are insecure: expected {oct(expected_mode)}, got {oct(mode)}."
        )


@contextmanager
def _locked_store(
    platform: str | None = None,
    home: Path | None = None,
    *,
    create: bool = False,
    exclusive: bool = False,
) -> Iterator[int | None]:
    # Lock the stable directory inode: readers never create or modify a lock file.
    try:
        directory = audit_dir(platform=platform, home=home)
        if create:
            ensure_audit_store_secure(platform=platform, home=home)
        try:
            info = directory.lstat()
        except FileNotFoundError:
            yield None
            return
        _ensure_secure_stat(info, 0o700, "Audit directory", directory=True)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            _ensure_secure_stat(opened, 0o700, "Audit directory", directory=True)
            if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                raise EnvrcctlError("Audit directory changed while opening the store.")
            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            for name in (_AUDIT_FILENAME, _LATEST_HASH_FILENAME, _META_FILENAME):
                try:
                    file_info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _ensure_secure_stat(file_info, 0o600, f"Audit file {name}")
                if name == _META_FILENAME:
                    _validate_meta(fd)
            yield fd
        finally:
            os.close(fd)
    except OSError as exc:
        raise _storage_error(exc) from exc


def _open_file(fd: int, name: str, flags: int, *, create: bool = False) -> int:
    flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        try:
            file_fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
        except FileExistsError:
            file_fd = os.open(name, flags, dir_fd=fd)
    else:
        file_fd = os.open(name, flags, dir_fd=fd)
    try:
        _ensure_secure_stat(os.fstat(file_fd), 0o600, "Audit file")
    except OSError, EnvrcctlError:
        os.close(file_fd)
        raise
    return file_fd


def _read_text(fd: int, name: str) -> str:
    try:
        file_fd = _open_file(fd, name, os.O_RDONLY)
    except FileNotFoundError:
        return ""
    with os.fdopen(file_fd, "r", encoding="utf-8", newline="") as handle:
        try:
            return handle.read()
        except UnicodeDecodeError as exc:
            raise EnvrcctlError("Audit storage is not valid UTF-8.") from exc


def _validate_meta(fd: int) -> None:
    try:
        payload = json.loads(_read_text(fd, _META_FILENAME))
    except json.JSONDecodeError as exc:
        raise EnvrcctlError("Invalid JSON in audit metadata.") from exc
    if (
        not isinstance(payload, dict)
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] not in (1, 2)
        or not isinstance(payload.get("updated_at"), str)
        or set(payload) != {"schema_version", "updated_at"}
    ):
        raise EnvrcctlError("Invalid audit metadata schema.")


def _atomic_write(fd: int, name: str, text: str) -> None:
    temporary = f".{name}.{uuid.uuid4().hex}.new"
    file_fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
    )
    try:
        with os.fdopen(file_fd, "wb") as handle:
            _ensure_secure_stat(os.fstat(handle.fileno()), 0o600, "Audit temporary file")
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def _storage_error(exc: OSError) -> EnvrcctlError:
    category = errno.errorcode.get(exc.errno, "IO_ERROR")
    return EnvrcctlError(
        f"Audit storage I/O failed ({category}); check permissions and available storage. "
        "Run audit verify before retrying."
    )


def _command_metadata(command: list[str] | None) -> list[str] | None:
    if command is None:
        return None
    if not isinstance(command, list) or any(not isinstance(item, str) for item in command):
        raise EnvrcctlError("Audit event command must be a list of strings or null.")
    return [Path(command[0]).name] if command else []


def _safe_error(error: AuditErrorInfo) -> AuditErrorInfo:
    if not isinstance(error.code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error.code):
        raise EnvrcctlError("Audit error code must be a lowercase identifier.")
    messages = {
        # Fixed diagnostic messages, not credentials.
        "secret_not_found": "Secret was not found.",  # nosec B105
        "secret_get_failed": "Secret retrieval failed.",  # nosec B105
        "inject_failed": "Secret injection failed.",
        "exec_failed": "Command execution failed.",
        "exec_cancelled": "Command execution was cancelled.",
    }
    return AuditErrorInfo(error.code, messages.get(error.code, "Operation failed."))
