from __future__ import annotations

import errno
import json
import multiprocessing
import os
import stat
import uuid
from contextlib import nullcontext
from pathlib import Path

import pytest

from envrcctl.audit import (
    AuditErrorInfo,
    AuditEvent,
    AuditRef,
    append_event,
    audit_dir,
    audit_file,
    canonical_json,
    ensure_audit_files_secure,
    ensure_audit_store_secure,
    hash_event,
    hash_event_payload,
    iter_events,
    latest_hash_file,
    meta_file,
    parse_event,
    read_latest_hash,
    state_root,
    verify_chain,
)
from envrcctl.errors import EnvrcctlError


@pytest.fixture(autouse=True)
def isolated_audit_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)


def test_state_root_uses_macos_app_support(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    path = state_root(platform="darwin", home=tmp_path)

    assert path == tmp_path / "Library" / "Application Support" / "envrcctl"


def test_state_root_uses_xdg_state_home(monkeypatch, tmp_path: Path) -> None:
    xdg_state_home = tmp_path / "xdg-state"
    monkeypatch.setenv("XDG_STATE_HOME", str(xdg_state_home))

    path = state_root(platform="linux", home=tmp_path / "ignored-home")

    assert path == xdg_state_home / "envrcctl"


def test_state_root_falls_back_to_local_state(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    path = state_root(platform="linux", home=tmp_path)

    assert path == tmp_path / ".local" / "state" / "envrcctl"


def test_audit_paths_are_derived_from_state_root(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    assert audit_dir(platform="linux", home=tmp_path) == (
        tmp_path / ".local" / "state" / "envrcctl" / "audit"
    )
    assert audit_file(platform="linux", home=tmp_path) == (
        tmp_path / ".local" / "state" / "envrcctl" / "audit" / "audit.jsonl"
    )
    assert latest_hash_file(platform="linux", home=tmp_path) == (
        tmp_path / ".local" / "state" / "envrcctl" / "audit" / "latest_hash"
    )
    assert meta_file(platform="linux", home=tmp_path) == (
        tmp_path / ".local" / "state" / "envrcctl" / "audit" / "meta.json"
    )


def test_ensure_audit_store_secure_creates_directory_with_expected_mode(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    directory = ensure_audit_store_secure(platform="linux", home=tmp_path)

    assert directory.exists()
    assert directory.is_dir()
    assert os.stat(directory).st_mode & 0o777 == 0o700


def test_ensure_audit_files_secure_rejects_insecure_file_modes_without_changes(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    directory = ensure_audit_store_secure(platform="linux", home=tmp_path)
    log_path = directory / "audit.jsonl"
    latest_path = directory / "latest_hash"
    meta_path = directory / "meta.json"

    log_path.write_text("", encoding="utf-8")
    latest_path.write_text("abc\n", encoding="utf-8")
    meta_path.write_text("{}", encoding="utf-8")

    os.chmod(log_path, 0o644)
    os.chmod(latest_path, 0o644)
    os.chmod(meta_path, 0o644)

    with pytest.raises(EnvrcctlError, match="permissions are insecure"):
        ensure_audit_files_secure(platform="linux", home=tmp_path)

    assert os.stat(log_path).st_mode & 0o777 == 0o644
    assert os.stat(latest_path).st_mode & 0o777 == 0o644
    assert os.stat(meta_path).st_mode & 0o777 == 0o644


def test_parse_event_round_trips_valid_payload() -> None:
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": ["TOKEN"],
        "refs": [
            {
                "scheme": "kc",
                "service": "st.rio.envrcctl",
                "account": "acct",
                "kind": "runtime",
            }
        ],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": ["printenv"],
        "error": None,
        "prev_hash": None,
        "hash": "abc123",
    }

    event = parse_event(payload)

    assert event == AuditEvent(
        schema_version=1,
        event_id="evt-1",
        timestamp="2026-03-18T00:00:00Z",
        action="exec",
        status="success",
        vars=["TOKEN"],
        refs=[
            AuditRef(
                scheme="kc",
                service="st.rio.envrcctl",
                account="acct",
                kind="runtime",
            )
        ],
        cwd="/tmp/project",
        platform="linux",
        command=["printenv"],
        error=None,
        prev_hash=None,
        hash="abc123",
    )


def test_parse_event_rejects_missing_required_fields() -> None:
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": [],
        "refs": [],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": None,
        "error": None,
        "prev_hash": None,
    }

    with pytest.raises(EnvrcctlError) as exc:
        parse_event(payload)

    assert "missing required fields" in str(exc.value)


def test_parse_event_rejects_non_list_refs() -> None:
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": [],
        "refs": {},
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": None,
        "error": None,
        "prev_hash": None,
        "hash": "abc123",
    }

    with pytest.raises(EnvrcctlError) as exc:
        parse_event(payload)

    assert "refs must be a list" in str(exc.value)


def test_parse_event_rejects_non_object_ref_entries() -> None:
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": [],
        "refs": ["bad-ref"],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": None,
        "error": None,
        "prev_hash": None,
        "hash": "abc123",
    }

    with pytest.raises(EnvrcctlError) as exc:
        parse_event(payload)

    assert "ref entry must be an object" in str(exc.value)


def test_parse_event_rejects_non_string_vars() -> None:
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": ["TOKEN", 123],
        "refs": [],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": None,
        "error": None,
        "prev_hash": None,
        "hash": "abc123",
    }

    with pytest.raises(EnvrcctlError) as exc:
        parse_event(payload)

    assert "vars must be a list of strings" in str(exc.value)


def test_parse_event_rejects_invalid_command_shape() -> None:
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": [],
        "refs": [],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": ["printenv", 1],
        "error": None,
        "prev_hash": None,
        "hash": "abc123",
    }

    with pytest.raises(EnvrcctlError) as exc:
        parse_event(payload)

    assert "command must be a list of strings or null" in str(exc.value)


def test_parse_event_rejects_invalid_error_shape() -> None:
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "failure",
        "vars": [],
        "refs": [],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": None,
        "error": "bad-error",
        "prev_hash": None,
        "hash": "abc123",
    }

    with pytest.raises(EnvrcctlError) as exc:
        parse_event(payload)

    assert "error must be an object or null" in str(exc.value)


def test_parse_event_rejects_invalid_prev_hash_type() -> None:
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": [],
        "refs": [],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": None,
        "error": None,
        "prev_hash": 123,
        "hash": "abc123",
    }

    with pytest.raises(EnvrcctlError) as exc:
        parse_event(payload)

    assert "prev_hash must be a string or null" in str(exc.value)


def test_canonical_json_sorts_keys_deterministically() -> None:
    payload = {"b": 2, "a": 1}

    serialized = canonical_json(payload)

    assert serialized == '{"a":1,"b":2}'


def test_hash_event_payload_is_stable_for_same_payload() -> None:
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": ["TOKEN"],
        "refs": [],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": ["printenv"],
        "error": None,
        "prev_hash": None,
    }

    first = hash_event_payload(payload)
    second = hash_event_payload(payload)

    assert first == second
    assert len(first) == 64


def test_hash_event_ignores_existing_hash_field() -> None:
    event = AuditEvent(
        schema_version=1,
        event_id="evt-1",
        timestamp="2026-03-18T00:00:00Z",
        action="exec",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd="/tmp/project",
        platform="linux",
        command=["printenv"],
        error=None,
        prev_hash=None,
        hash="placeholder",
    )

    computed = hash_event(event)

    assert computed != "placeholder"
    assert len(computed) == 64


def test_append_event_writes_first_event_and_sidecars(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    event = append_event(
        action="secret_get",
        status="success",
        vars=["TOKEN"],
        refs=[
            AuditRef(
                scheme="kc",
                service="st.rio.envrcctl",
                account="acct",
                kind="runtime",
            )
        ],
        cwd=tmp_path,
        platform="linux",
        command=None,
        error=None,
        timestamp="2026-03-18T00:00:00Z",
        event_id="evt-1",
        home=tmp_path,
    )

    log_path = audit_file(platform="linux", home=tmp_path)
    latest_path = latest_hash_file(platform="linux", home=tmp_path)
    metadata_path = meta_file(platform="linux", home=tmp_path)

    assert event.prev_hash is None
    assert log_path.exists()
    assert latest_path.exists()
    assert metadata_path.exists()

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    payload = json.loads(lines[0])
    assert payload["event_id"] == "evt-1"
    assert payload["hash"] == event.hash
    assert latest_path.read_text(encoding="utf-8").strip() == event.hash

    meta_payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert meta_payload["schema_version"] == 2
    assert "updated_at" in meta_payload

    assert os.stat(log_path).st_mode & 0o777 == 0o600
    assert os.stat(latest_path).st_mode & 0o777 == 0o600
    assert os.stat(metadata_path).st_mode & 0o777 == 0o600


def test_append_event_chains_to_previous_hash(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    first = append_event(
        action="secret_get",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=None,
        error=None,
        timestamp="2026-03-18T00:00:00Z",
        event_id="evt-1",
        home=tmp_path,
    )

    second = append_event(
        action="exec",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=["printenv"],
        error=None,
        timestamp="2026-03-18T00:01:00Z",
        event_id="evt-2",
        home=tmp_path,
    )

    assert second.prev_hash == first.hash
    assert read_latest_hash(platform="linux", home=tmp_path) == second.hash

    events = list(iter_events(platform="linux", home=tmp_path))
    assert [event.event_id for event in events] == ["evt-1", "evt-2"]


def test_iter_events_returns_empty_when_log_is_missing(tmp_path: Path) -> None:
    events = list(iter_events(platform="linux", home=tmp_path))

    assert events == []


def test_iter_events_rejects_invalid_json_line(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    ensure_audit_store_secure(platform="linux", home=tmp_path)
    log_path = audit_file(platform="linux", home=tmp_path)
    log_path.write_text("not-json\n", encoding="utf-8")
    log_path.chmod(0o600)

    with pytest.raises(EnvrcctlError) as exc:
        list(iter_events(platform="linux", home=tmp_path))

    assert "Invalid audit log JSON at line 1." == str(exc.value)


def test_iter_events_skips_blank_lines(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    ensure_audit_store_secure(platform="linux", home=tmp_path)
    log_path = audit_file(platform="linux", home=tmp_path)
    payload = {
        "schema_version": 1,
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": ["TOKEN"],
        "refs": [],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": None,
        "error": None,
        "prev_hash": None,
        "hash": "abc123",
    }
    log_path.write_text("\n" + canonical_json(payload) + "\n\n", encoding="utf-8")
    log_path.chmod(0o600)

    events = list(iter_events(platform="linux", home=tmp_path))

    assert len(events) == 1
    assert events[0].event_id == "evt-1"


def test_verify_chain_succeeds_for_clean_log(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    first = append_event(
        action="secret_get",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=None,
        error=None,
        timestamp="2026-03-18T00:00:00Z",
        event_id="evt-1",
        home=tmp_path,
    )
    second = append_event(
        action="exec",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=["printenv"],
        error=None,
        timestamp="2026-03-18T00:01:00Z",
        event_id="evt-2",
        home=tmp_path,
    )

    result = verify_chain(platform="linux", home=tmp_path)

    assert result.ok is True
    assert result.event_count == 2
    assert result.latest_hash == second.hash
    assert result.failure_reason is None
    assert first.hash != second.hash


def test_verify_chain_detects_invalid_json(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    ensure_audit_store_secure(platform="linux", home=tmp_path)
    log_path = audit_file(platform="linux", home=tmp_path)
    log_path.write_text("not-json\n", encoding="utf-8")
    os.chmod(log_path, 0o600)

    result = verify_chain(platform="linux", home=tmp_path)

    assert result.ok is False
    assert result.failure_reason == "Invalid JSON in audit log."
    assert result.failure_line == 1


def test_verify_chain_skips_blank_lines(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    event = append_event(
        action="secret_get",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=None,
        error=None,
        timestamp="2026-03-18T00:00:00Z",
        event_id="evt-1",
        home=tmp_path,
    )

    log_path = audit_file(platform="linux", home=tmp_path)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    log_path.write_text("\n" + "\n".join(lines) + "\n\n", encoding="utf-8")
    os.chmod(log_path, 0o600)

    result = verify_chain(platform="linux", home=tmp_path)

    assert result.ok is True
    assert result.event_count == 1
    assert result.latest_hash == event.hash


def test_verify_chain_detects_hash_mismatch(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    append_event(
        action="secret_get",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=None,
        error=None,
        timestamp="2026-03-18T00:00:00Z",
        event_id="evt-1",
        home=tmp_path,
    )

    log_path = audit_file(platform="linux", home=tmp_path)
    payload = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    payload["status"] = "failure"
    log_path.write_text(canonical_json(payload) + "\n", encoding="utf-8")
    os.chmod(log_path, 0o600)

    result = verify_chain(platform="linux", home=tmp_path)

    assert result.ok is False
    assert result.failure_reason == "Audit event hash mismatch."
    assert result.failure_line == 1
    assert result.failure_event_id == "evt-1"


def test_verify_chain_detects_prev_hash_mismatch(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    append_event(
        action="secret_get",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=None,
        error=None,
        timestamp="2026-03-18T00:00:00Z",
        event_id="evt-1",
        home=tmp_path,
    )
    append_event(
        action="exec",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=["printenv"],
        error=None,
        timestamp="2026-03-18T00:01:00Z",
        event_id="evt-2",
        home=tmp_path,
    )

    log_path = audit_file(platform="linux", home=tmp_path)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    second_payload = json.loads(lines[1])
    second_payload["prev_hash"] = "bad-prev-hash"
    lines[1] = canonical_json(second_payload)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(log_path, 0o600)

    result = verify_chain(platform="linux", home=tmp_path)

    assert result.ok is False
    assert result.failure_reason == "Audit chain previous hash mismatch."
    assert result.failure_line == 2
    assert result.failure_event_id == "evt-2"


def test_verify_chain_detects_latest_hash_sidecar_mismatch(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    append_event(
        action="secret_get",
        status="success",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=None,
        error=None,
        timestamp="2026-03-18T00:00:00Z",
        event_id="evt-1",
        home=tmp_path,
    )

    latest_path = latest_hash_file(platform="linux", home=tmp_path)
    latest_path.write_text("wrong-hash\n", encoding="utf-8")
    os.chmod(latest_path, 0o600)

    result = verify_chain(platform="linux", home=tmp_path)

    assert result.ok is False
    assert result.failure_reason.startswith("Latest hash sidecar does not match audit log tail.")


def test_verify_chain_detects_insecure_directory_permissions(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    directory = ensure_audit_store_secure(platform="linux", home=tmp_path)
    os.chmod(directory, 0o755)

    result = verify_chain(platform="linux", home=tmp_path)

    assert result.ok is False
    assert "permissions are insecure" in result.failure_reason


def test_verify_chain_accepts_empty_store(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    result = verify_chain(platform="linux", home=tmp_path)

    assert result.ok is True
    assert result.event_count == 0
    assert result.latest_hash is None


def test_append_event_stores_structured_error_info(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    event = append_event(
        action="secret_get",
        status="failure",
        vars=["TOKEN"],
        refs=[],
        cwd=tmp_path,
        platform="linux",
        command=None,
        error=AuditErrorInfo(code="secret_not_found", message="not found"),
        timestamp="2026-03-18T00:00:00Z",
        event_id="evt-1",
        home=tmp_path,
    )

    assert event.error == AuditErrorInfo(code="secret_not_found", message="Secret was not found.")

    stored = list(iter_events(platform="linux", home=tmp_path))
    assert stored[0].error == AuditErrorInfo(
        code="secret_not_found", message="Secret was not found."
    )


def test_verify_chain_reports_parse_error_without_event_id(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    ensure_audit_store_secure(platform="linux", home=tmp_path)

    log_path = audit_file(platform="linux", home=tmp_path)
    payload = {
        "schema_version": 1,
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": [],
        "refs": [],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": None,
        "error": None,
        "prev_hash": None,
        "hash": "abc123",
    }
    log_path.write_text(canonical_json(payload) + "\n", encoding="utf-8")
    os.chmod(log_path, 0o600)

    result = verify_chain(platform="linux", home=tmp_path)

    assert result.ok is False
    assert result.failure_line == 1
    assert result.failure_event_id is None
    assert "missing required fields" in result.failure_reason


def test_expect_str_rejects_missing_string_field() -> None:
    with pytest.raises(EnvrcctlError) as exc:
        parse_event(
            {
                "schema_version": 1,
                "event_id": "evt-1",
                "timestamp": "2026-03-18T00:00:00Z",
                "action": "exec",
                "status": "success",
                "vars": [],
                "refs": [
                    {
                        "scheme": "kc",
                        "service": "svc",
                        "account": "acct",
                    }
                ],
                "cwd": "/tmp/project",
                "platform": "linux",
                "command": None,
                "error": None,
                "prev_hash": None,
                "hash": "abc123",
            }
        )

    assert "Audit event field kind must be a string." == str(exc.value)


def test_expect_int_rejects_non_integer_schema_version() -> None:
    payload = {
        "schema_version": "1",
        "event_id": "evt-1",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": [],
        "refs": [],
        "cwd": "/tmp/project",
        "platform": "linux",
        "command": None,
        "error": None,
        "prev_hash": None,
        "hash": "abc123",
    }

    with pytest.raises(EnvrcctlError) as exc:
        parse_event(payload)

    assert "Audit event field schema_version must be an integer." == str(exc.value)


def _append(home: Path, **kwargs) -> AuditEvent:
    return append_event(
        action="exec",
        status=kwargs.pop("status", "success"),
        vars=[],
        refs=[],
        cwd=home,
        platform="linux",
        home=home,
        **kwargs,
    )


def _snapshot(directory: Path) -> dict:
    return {
        path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode), path.stat().st_mtime_ns)
        for path in directory.iterdir()
        if path.is_file()
    }


def _concurrent_appender(home: str, barrier, count: int) -> None:
    barrier.wait(timeout=15)
    for _ in range(count):
        _append(Path(home))


def _paused_appender(home: str, appended, resume) -> None:
    from envrcctl import audit

    original = audit._atomic_write

    def pause(fd, name, text):
        if name == "latest_hash":
            appended.set()
            if not resume.wait(timeout=15):
                raise RuntimeError("Reader test did not release the writer.")
        original(fd, name, text)

    audit._atomic_write = pause
    _append(Path(home))


def _audit_reader(home: str, kind: str, started, finished, result) -> None:
    started.set()
    if kind == "verify":
        value = verify_chain(platform="linux", home=Path(home))
        result.put((value.ok, value.event_count))
    elif kind == "events":
        result.put(len(list(iter_events(platform="linux", home=Path(home)))))
    else:
        result.put(read_latest_hash(platform="linux", home=Path(home)))
    finished.set()


def _crashing_appender(home: str) -> None:
    from envrcctl import audit

    original = audit._atomic_write

    def crash(fd, name, text):
        if name == "latest_hash":
            os._exit(73)
        original(fd, name, text)

    audit._atomic_write = crash
    _append(Path(home))


def test_multiple_processes_append_one_valid_chain(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(4)
    workers = [
        ctx.Process(target=_concurrent_appender, args=(str(tmp_path), barrier, 6)) for _ in range(4)
    ]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=30)
            assert worker.exitcode == 0
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=10)

    result = verify_chain(platform="linux", home=tmp_path)
    events = list(iter_events(platform="linux", home=tmp_path))
    assert result.ok
    assert result.event_count == 24
    assert len({event.event_id for event in events}) == 24
    assert events[0].prev_hash is None
    assert all(
        right.prev_hash == left.hash for left, right in zip(events, events[1:], strict=False)
    )
    assert all(uuid.UUID(event.event_id).version == 4 for event in events)


@pytest.mark.parametrize("kind", ["verify", "events", "latest"])
def test_readers_wait_for_atomic_sidecar_commit(tmp_path: Path, kind: str) -> None:
    _append(tmp_path)
    ctx = multiprocessing.get_context("spawn")
    appended, resume, started, finished = [ctx.Event() for _ in range(4)]
    result = ctx.Queue()
    writer = ctx.Process(target=_paused_appender, args=(str(tmp_path), appended, resume))
    reader = ctx.Process(
        target=_audit_reader, args=(str(tmp_path), kind, started, finished, result)
    )
    try:
        writer.start()
        assert appended.wait(timeout=15)
        reader.start()
        assert started.wait(timeout=15)
        assert not finished.wait(timeout=0.2)
        resume.set()
        writer.join(timeout=15)
        reader.join(timeout=15)
        assert writer.exitcode == reader.exitcode == 0
        value = result.get(timeout=5)
        expected = {
            "verify": (True, 2),
            "events": 2,
            "latest": read_latest_hash(platform="linux", home=tmp_path),
        }
        assert value == expected[kind]
    finally:
        resume.set()
        for worker in (writer, reader):
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=10)
        result.close()
        result.join_thread()


def test_process_crash_preserves_durable_log_and_requires_explicit_recovery(tmp_path: Path) -> None:
    first = _append(tmp_path)
    ctx = multiprocessing.get_context("spawn")
    writer = ctx.Process(target=_crashing_appender, args=(str(tmp_path),))
    try:
        writer.start()
        writer.join(timeout=15)
        assert writer.exitcode == 73
    finally:
        if writer.is_alive():
            writer.terminate()
            writer.join(timeout=10)
    directory = audit_dir(platform="linux", home=tmp_path)
    before = _snapshot(directory)
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok
    assert result.event_count == 2
    assert "possible interrupted append" in result.failure_reason
    assert "Stop all envrcctl writers" in result.failure_reason
    assert read_latest_hash(platform="linux", home=tmp_path) == first.hash
    with pytest.raises(EnvrcctlError, match="No automatic recovery"):
        _append(tmp_path)
    assert _snapshot(directory) == before


@pytest.mark.parametrize("boundary", range(1, 7))
def test_fsync_failures_preserve_history_and_fail_closed(
    monkeypatch, tmp_path: Path, boundary: int
) -> None:
    from envrcctl import audit

    first = _append(tmp_path)
    directory = audit_dir(platform="linux", home=tmp_path)
    original_log = audit_file(platform="linux", home=tmp_path).read_bytes()
    real_fsync = os.fsync
    calls = 0

    def fail_fsync(fd):
        nonlocal calls
        calls += 1
        info = os.fstat(fd)
        assert stat.S_IMODE(info.st_mode) == (0o700 if stat.S_ISDIR(info.st_mode) else 0o600)
        if calls == boundary:
            raise OSError(errno.ENOSPC, "DUMMY_SECRET_DO_NOT_USE")
        real_fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(audit.os, "fsync", fail_fsync)
        with pytest.raises(EnvrcctlError, match="ENOSPC") as exc:
            _append(tmp_path)
        assert "DUMMY_SECRET_DO_NOT_USE" not in str(exc.value)

    log = audit_file(platform="linux", home=tmp_path).read_bytes()
    assert log.startswith(original_log)
    assert not list(directory.glob(".*.new"))
    result = verify_chain(platform="linux", home=tmp_path)
    if boundary <= 2:
        assert result.ok and result.event_count == 1
        assert result.latest_hash == first.hash
    elif boundary <= 5:
        assert not result.ok and result.event_count == 2
        assert "possible interrupted append" in result.failure_reason
        before = _snapshot(directory)
        with pytest.raises(EnvrcctlError, match="No automatic recovery"):
            _append(tmp_path)
        assert _snapshot(directory) == before
    else:
        assert result.ok and result.event_count == 2


@pytest.mark.parametrize("target", ["meta.json", "latest_hash"])
def test_atomic_replace_failure_never_truncates_sidecars(
    monkeypatch, tmp_path: Path, target
) -> None:
    from envrcctl import audit

    _append(tmp_path)
    directory = audit_dir(platform="linux", home=tmp_path)
    before = (directory / target).read_bytes()
    real_replace = os.replace

    def fail_replace(src, dst, **kwargs):
        if dst == target:
            raise OSError(errno.EIO, "DUMMY_SECRET_DO_NOT_USE")
        real_replace(src, dst, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(audit.os, "replace", fail_replace)
        with pytest.raises(EnvrcctlError, match="EIO"):
            _append(tmp_path)

    assert (directory / target).read_bytes() == before
    assert not list(directory.glob(".*.new"))
    result = verify_chain(platform="linux", home=tmp_path)
    assert result.event_count == (1 if target == "meta.json" else 2)
    assert result.ok is (target == "meta.json")


@pytest.mark.parametrize("tail", ['{"schema_version":', "complete"])
def test_incomplete_tail_is_never_repaired_or_appended(tmp_path: Path, tail: str) -> None:
    _append(tmp_path)
    path = audit_file(platform="linux", home=tmp_path)
    original = path.read_bytes()
    path.write_bytes(original.rstrip(b"\n") if tail == "complete" else original + tail.encode())
    directory = path.parent
    before = _snapshot(directory)
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok
    with pytest.raises(EnvrcctlError):
        _append(tmp_path)
    assert _snapshot(directory) == before


@pytest.mark.parametrize("remove_log", [True, False])
def test_nonempty_sidecar_with_missing_or_empty_log_is_not_empty_history(
    tmp_path: Path, remove_log: bool
) -> None:
    _append(tmp_path)
    path = audit_file(platform="linux", home=tmp_path)
    if remove_log:
        path.unlink()
    else:
        path.write_text("")
    before = _snapshot(path.parent)
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok
    assert "does not match" in result.failure_reason
    assert "possible interrupted append" not in result.failure_reason
    with pytest.raises(EnvrcctlError):
        _append(tmp_path)
    with pytest.raises(EnvrcctlError):
        list(iter_events(platform="linux", home=tmp_path))
    assert _snapshot(path.parent) == before


def test_missing_sidecar_requires_explicit_recovery(tmp_path: Path) -> None:
    _append(tmp_path)
    path = latest_hash_file(platform="linux", home=tmp_path)
    path.unlink()
    before = _snapshot(path.parent)
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok and "possible interrupted append" in result.failure_reason
    with pytest.raises(EnvrcctlError, match="No automatic recovery"):
        _append(tmp_path)
    assert _snapshot(path.parent) == before


def test_verification_of_absent_store_is_read_only(tmp_path: Path) -> None:
    before = list(tmp_path.iterdir())
    ensure_audit_files_secure(platform="linux", home=tmp_path)
    assert verify_chain(platform="linux", home=tmp_path).ok
    assert list(iter_events(platform="linux", home=tmp_path)) == []
    assert read_latest_hash(platform="linux", home=tmp_path) is None
    assert not audit_dir(platform="linux", home=tmp_path).exists()
    assert list(tmp_path.iterdir()) == before


@pytest.mark.parametrize("name", ["audit.jsonl", "latest_hash", "meta.json"])
def test_verify_and_append_do_not_repair_insecure_files(tmp_path: Path, name: str) -> None:
    _append(tmp_path)
    directory = audit_dir(platform="linux", home=tmp_path)
    path = directory / name
    path.chmod(0o644)
    before = _snapshot(directory)
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok and "permissions are insecure" in result.failure_reason
    with pytest.raises(EnvrcctlError, match="permissions are insecure"):
        _append(tmp_path)
    assert _snapshot(directory) == before


def test_existing_insecure_directory_is_never_chmodded(tmp_path: Path) -> None:
    directory = ensure_audit_store_secure(platform="linux", home=tmp_path)
    directory.chmod(0o755)
    with pytest.raises(EnvrcctlError, match="permissions are insecure"):
        ensure_audit_store_secure(platform="linux", home=tmp_path)
    with pytest.raises(EnvrcctlError, match="permissions are insecure"):
        _append(tmp_path)
    assert not verify_chain(platform="linux", home=tmp_path).ok
    assert stat.S_IMODE(directory.stat().st_mode) == 0o755
    assert not list(directory.iterdir())


@pytest.mark.parametrize("name", ["audit.jsonl", "latest_hash", "meta.json"])
@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink", "directory", "fifo"])
def test_unsafe_file_types_are_rejected_without_touching_targets(
    tmp_path: Path, name: str, kind: str
) -> None:
    directory = ensure_audit_store_secure(platform="linux", home=tmp_path)
    target = tmp_path / "target"
    target.write_text("preserved")
    target.chmod(0o600)
    path = directory / name
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "dangling":
        path.symlink_to(tmp_path / "absent")
    elif kind == "hardlink":
        os.link(target, path)
    elif kind == "directory":
        path.mkdir(mode=0o600)
    else:
        os.mkfifo(path, 0o600)
    assert not verify_chain(platform="linux", home=tmp_path).ok
    with pytest.raises(EnvrcctlError):
        _append(tmp_path)
    assert target.read_text() == "preserved"
    assert not (tmp_path / "absent").exists()
    assert list(directory.iterdir()) == [path]


def test_symlink_audit_directory_is_rejected(tmp_path: Path) -> None:
    directory = audit_dir(platform="linux", home=tmp_path)
    directory.parent.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    directory.symlink_to(target, target_is_directory=True)
    assert not verify_chain(platform="linux", home=tmp_path).ok
    with pytest.raises(EnvrcctlError, match="real directory"):
        _append(tmp_path)
    assert not list(target.iterdir())


@pytest.mark.parametrize("payload", [[], None, 1, True, "invalid"])
def test_nonobject_json_returns_a_validation_failure(tmp_path: Path, payload) -> None:
    directory = ensure_audit_store_secure(platform="linux", home=tmp_path)
    path = directory / "audit.jsonl"
    path.write_text(json.dumps(payload) + "\n")
    path.chmod(0o600)
    before = _snapshot(directory)
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok
    assert result.failure_line == 1
    assert result.failure_event_id is None
    assert result.failure_reason == "Audit event must be an object."
    with pytest.raises(EnvrcctlError, match="must be an object"):
        list(iter_events(platform="linux", home=tmp_path))
    assert _snapshot(directory) == before


@pytest.mark.parametrize("version", [True, False, 0, 3, "1", 1.0, None])
def test_unsupported_schema_returns_validation_failure(tmp_path: Path, version) -> None:
    _append(tmp_path)
    path = audit_file(platform="linux", home=tmp_path)
    payload = json.loads(path.read_text())
    payload["schema_version"] = version
    path.write_text(canonical_json(payload) + "\n")
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok and result.failure_line == 1
    assert "schema" in result.failure_reason
    with pytest.raises(EnvrcctlError):
        _append(tmp_path)


def test_invalid_utf8_is_a_domain_failure(tmp_path: Path) -> None:
    _append(tmp_path)
    path = audit_file(platform="linux", home=tmp_path)
    path.write_bytes(b"\xff\n")
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok and "UTF-8" in result.failure_reason
    with pytest.raises(EnvrcctlError, match="UTF-8"):
        list(iter_events(platform="linux", home=tmp_path))


def test_os_read_failures_are_safely_reported(monkeypatch, tmp_path: Path) -> None:
    from envrcctl import audit

    _append(tmp_path)
    real_open = os.open

    def fail_open(path, *args, **kwargs):
        if path == "audit.jsonl":
            raise PermissionError(errno.EACCES, "DUMMY_SECRET_DO_NOT_USE")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(audit.os, "open", fail_open)
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok and "EACCES" in result.failure_reason
    assert "DUMMY_SECRET_DO_NOT_USE" not in result.failure_reason
    with pytest.raises(EnvrcctlError, match="EACCES"):
        list(iter_events(platform="linux", home=tmp_path))
    with pytest.raises(EnvrcctlError, match="EACCES"):
        _append(tmp_path)


def test_schema1_hashes_and_legacy_metadata_remain_unchanged(tmp_path: Path) -> None:
    from envrcctl import audit

    payload = {
        "schema_version": 1,
        "event_id": "legacy",
        "timestamp": "2026-03-18T00:00:00Z",
        "action": "exec",
        "status": "success",
        "vars": ["TOKEN"],
        "refs": [],
        "cwd": "/project",
        "platform": "linux",
        "command": ["tool", "--token", "LEGACY_DUMMY_SECRET"],
        "error": {"code": "old_error", "message": "legacy diagnostic"},
        "prev_hash": None,
    }
    expected_hash = hash_event_payload(payload)
    assert expected_hash == "4c69552b31a767a5a92a9cdb2cac7141d716570db080afafe99099de96090efe"
    payload["hash"] = expected_hash
    serialized = canonical_json(payload) + "\n"
    directory = ensure_audit_store_secure(platform="linux", home=tmp_path)
    path = directory / "audit.jsonl"
    path.write_text(serialized)
    path.chmod(0o600)
    latest = directory / "latest_hash"
    latest.write_text(expected_hash + "\n")
    latest.chmod(0o600)
    event = list(iter_events(platform="linux", home=tmp_path))[0]
    assert event.schema_version == 1 and event.operation_id is None
    assert event.command == payload["command"]
    assert event.error.message == "legacy diagnostic"
    assert hash_event(event) == expected_hash
    assert canonical_json(audit._event_to_serializable(event)) + "\n" == serialized
    assert "operation_id" not in audit._event_to_serializable(event)
    second = _append(tmp_path, operation_id="operation")
    assert second.schema_version == 2 and second.prev_hash == expected_hash
    assert path.read_text().startswith(serialized)
    assert verify_chain(platform="linux", home=tmp_path).ok


@pytest.mark.parametrize("status", ["success", "failure", "cancelled"])
def test_operation_id_correlates_distinct_start_and_end_events(tmp_path: Path, status: str) -> None:
    operation_id = str(uuid.uuid4())
    started = _append(tmp_path, status="started", operation_id=operation_id)
    completed = _append(tmp_path, status=status, operation_id=operation_id)
    assert started.event_id != completed.event_id
    assert completed.prev_hash == started.hash
    events = list(iter_events(platform="linux", home=tmp_path))
    assert [event.operation_id for event in events] == [operation_id, operation_id]
    assert [event.status for event in events] == ["started", status]
    assert all(event.schema_version == 2 for event in events)
    payload = json.loads(audit_file(platform="linux", home=tmp_path).read_text().splitlines()[0])
    payload["operation_id"] = "tampered"
    assert hash_event(parse_event(payload)) != started.hash
    assert verify_chain(platform="linux", home=tmp_path).ok


def test_schema2_defaults_operation_id_to_null(tmp_path: Path) -> None:
    event = _append(tmp_path)
    payload = json.loads(audit_file(platform="linux", home=tmp_path).read_text())
    assert event.operation_id is None
    assert payload["schema_version"] == 2 and payload["operation_id"] is None
    with pytest.raises(EnvrcctlError, match="operation_id"):
        _append(tmp_path, operation_id=[])


def test_new_events_never_persist_argv_or_raw_diagnostics(tmp_path: Path) -> None:
    secret = "DUMMY_SECRET_DO_NOT_USE"
    event = _append(
        tmp_path,
        command=["/usr/bin/tool", "--token", secret, f"inline={secret}"],
        error=AuditErrorInfo("exec_failed", f"stdout/stderr: {secret}"),
    )
    directory = audit_dir(platform="linux", home=tmp_path)
    assert event.command == ["tool"]
    assert event.error == AuditErrorInfo("exec_failed", "Command execution failed.")
    assert all(secret.encode() not in path.read_bytes() for path in directory.iterdir())


def test_custom_validated_error_codes_keep_safe_categories(tmp_path: Path) -> None:
    event = _append(
        tmp_path, error=AuditErrorInfo("backend_unavailable", "DUMMY_SECRET_DO_NOT_USE")
    )
    assert event.error == AuditErrorInfo("backend_unavailable", "Operation failed.")
    with pytest.raises(EnvrcctlError, match="lowercase identifier"):
        _append(tmp_path, error=AuditErrorInfo("untrusted\ncode", "message"))


@pytest.mark.parametrize(
    "metadata",
    [
        "not-json",
        "null",
        "[]",
        "{}",
        '{"schema_version":true,"updated_at":"date"}',
        '{"schema_version":3,"updated_at":"date"}',
        '{"schema_version":2,"updated_at":[]}',
    ],
)
def test_invalid_metadata_is_not_silently_overwritten(tmp_path: Path, metadata: str) -> None:
    _append(tmp_path)
    path = meta_file(platform="linux", home=tmp_path)
    path.write_text(metadata)
    before = _snapshot(path.parent)
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok and "metadata" in result.failure_reason
    with pytest.raises(EnvrcctlError, match="metadata"):
        _append(tmp_path)
    assert _snapshot(path.parent) == before


def test_schema1_metadata_is_still_readable(tmp_path: Path) -> None:
    _append(tmp_path)
    path = meta_file(platform="linux", home=tmp_path)
    path.write_text('{"schema_version":1,"updated_at":"2026-03-18T00:00:00Z"}\n')
    before = _snapshot(path.parent)
    assert verify_chain(platform="linux", home=tmp_path).ok
    assert _snapshot(path.parent) == before
    _append(tmp_path)
    assert verify_chain(platform="linux", home=tmp_path).event_count == 2


def test_unique_temporary_file_collision_cannot_follow_or_remove_symlink(
    monkeypatch, tmp_path: Path
) -> None:
    from envrcctl import audit

    _append(tmp_path)
    target = tmp_path / "preserved"
    target.write_text("unchanged")
    fixed_id = uuid.UUID("ac81f9af-80d9-4939-bfb9-cd0c43f05a3f")
    directory = audit_dir(platform="linux", home=tmp_path)
    collision = directory / f".meta.json.{fixed_id.hex}.new"
    collision.symlink_to(target)
    before = _snapshot(directory)
    monkeypatch.setattr(audit.uuid, "uuid4", lambda: fixed_id)
    with pytest.raises(EnvrcctlError, match="EEXIST"):
        _append(tmp_path)
    assert target.read_text() == "unchanged"
    assert collision.is_symlink()
    assert _snapshot(directory) == before


def test_json_unicode_line_separators_are_not_record_boundaries(tmp_path: Path) -> None:
    command = ["tool\u2028with\u2029unicode"]
    event = _append(tmp_path, command=command)
    assert list(iter_events(platform="linux", home=tmp_path))[0].command == command
    result = verify_chain(platform="linux", home=tmp_path)
    assert result.ok and result.latest_hash == event.hash


def test_invalid_unicode_json_returns_failure_line(tmp_path: Path) -> None:
    _append(tmp_path)
    path = audit_file(platform="linux", home=tmp_path)
    payload = json.loads(path.read_text())
    payload["action"] = "\ud800"
    path.write_text(json.dumps(payload) + "\n")
    result = verify_chain(platform="linux", home=tmp_path)
    assert not result.ok and result.failure_line == 1
    assert "invalid Unicode" in result.failure_reason


@pytest.mark.parametrize("operation", ["event", "metadata"])
def test_audit_writers_reject_unavailable_store(
    monkeypatch, tmp_path: Path, operation: str
) -> None:
    from envrcctl import audit

    monkeypatch.setattr(audit, "_locked_store", lambda **kwargs: nullcontext(None))
    with pytest.raises(EnvrcctlError, match="Audit store is unavailable for writing"):
        if operation == "event":
            _append(tmp_path)
        else:
            audit.write_meta(platform="linux", home=tmp_path)
    assert not audit_dir(platform="linux", home=tmp_path).exists()
