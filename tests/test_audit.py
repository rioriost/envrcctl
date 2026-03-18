from __future__ import annotations

import json
import os
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


def test_ensure_audit_files_secure_applies_expected_file_modes(
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

    ensure_audit_files_secure(platform="linux", home=tmp_path)

    assert os.stat(log_path).st_mode & 0o777 == 0o600
    assert os.stat(latest_path).st_mode & 0o777 == 0o600
    assert os.stat(meta_path).st_mode & 0o777 == 0o600


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


def test_append_event_writes_first_event_and_sidecars(
    monkeypatch, tmp_path: Path
) -> None:
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
    assert meta_payload["schema_version"] == 1
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


def test_verify_chain_detects_latest_hash_sidecar_mismatch(
    monkeypatch, tmp_path: Path
) -> None:
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
    assert result.failure_reason == "Latest hash sidecar does not match audit log tail."


def test_verify_chain_detects_insecure_directory_permissions(
    monkeypatch, tmp_path: Path
) -> None:
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

    assert event.error == AuditErrorInfo(code="secret_not_found", message="not found")

    stored = list(iter_events(platform="linux", home=tmp_path))
    assert stored[0].error == AuditErrorInfo(
        code="secret_not_found", message="not found"
    )


def test_verify_chain_reports_parse_error_without_event_id(
    monkeypatch, tmp_path: Path
) -> None:
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
    payload = {"schema_version": 1}

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
