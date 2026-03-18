from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.audit import AuditErrorInfo, AuditEvent, AuditRef


def _make_event(
    *,
    event_id: str,
    timestamp: str,
    action: str,
    status: str,
    vars: list[str],
    refs: list[AuditRef] | None = None,
    command: list[str] | None = None,
    error: AuditErrorInfo | None = None,
    prev_hash: str | None = None,
    hash_value: str = "hash-value",
) -> AuditEvent:
    return AuditEvent(
        schema_version=1,
        event_id=event_id,
        timestamp=timestamp,
        action=action,
        status=status,
        vars=vars,
        refs=refs or [],
        cwd="/tmp/project",
        platform="linux",
        command=command,
        error=error,
        prev_hash=prev_hash,
        hash=hash_value,
    )


def test_audit_list_renders_recent_events(monkeypatch) -> None:
    runner = CliRunner()
    events = [
        _make_event(
            event_id="evt-1",
            timestamp="2026-03-18T00:00:00Z",
            action="secret_get",
            status="success",
            vars=["TOKEN"],
            command=None,
            hash_value="hash-1",
        ),
        _make_event(
            event_id="evt-2",
            timestamp="2026-03-18T00:01:00Z",
            action="exec",
            status="failure",
            vars=["UV_PUBLISH_TOKEN"],
            command=["uv", "publish"],
            hash_value="hash-2",
            prev_hash="hash-1",
        ),
    ]
    monkeypatch.setattr(cli, "iter_events", lambda: iter(events))

    result = runner.invoke(cli.app, ["audit", "list"])

    assert result.exit_code == 0
    lines = result.stdout.strip().splitlines()
    assert len(lines) == 2
    assert "evt-2" not in result.stdout
    assert "2026-03-18T00:01:00Z" in lines[0]
    assert "exec" in lines[0]
    assert "failure" in lines[0]
    assert "UV_PUBLISH_TOKEN" in lines[0]
    assert "uv publish" in lines[0]
    assert "2026-03-18T00:00:00Z" in lines[1]
    assert "secret_get" in lines[1]
    assert "TOKEN" in lines[1]


def test_audit_list_applies_filters_and_limit(monkeypatch) -> None:
    runner = CliRunner()
    events = [
        _make_event(
            event_id="evt-1",
            timestamp="2026-03-18T00:00:00Z",
            action="secret_get",
            status="success",
            vars=["TOKEN"],
            hash_value="hash-1",
        ),
        _make_event(
            event_id="evt-2",
            timestamp="2026-03-18T00:01:00Z",
            action="inject",
            status="success",
            vars=["TOKEN", "OTHER"],
            hash_value="hash-2",
            prev_hash="hash-1",
        ),
        _make_event(
            event_id="evt-3",
            timestamp="2026-03-18T00:02:00Z",
            action="exec",
            status="failure",
            vars=["TOKEN"],
            command=["printenv"],
            hash_value="hash-3",
            prev_hash="hash-2",
        ),
    ]
    monkeypatch.setattr(cli, "iter_events", lambda: iter(events))

    result = runner.invoke(
        cli.app,
        ["audit", "list", "--action", "exec", "--var", "TOKEN", "--status", "failure"],
    )

    assert result.exit_code == 0
    lines = result.stdout.strip().splitlines()
    assert len(lines) == 1
    assert "exec" in lines[0]
    assert "failure" in lines[0]
    assert "printenv" in lines[0]

    result = runner.invoke(cli.app, ["audit", "list", "--limit", "1"])
    assert result.exit_code == 0
    lines = result.stdout.strip().splitlines()
    assert len(lines) == 1
    assert "2026-03-18T00:02:00Z" in lines[0]


def test_audit_list_json_output(monkeypatch) -> None:
    runner = CliRunner()
    events = [
        _make_event(
            event_id="evt-1",
            timestamp="2026-03-18T00:00:00Z",
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
            hash_value="hash-1",
        )
    ]
    monkeypatch.setattr(cli, "iter_events", lambda: iter(events))

    result = runner.invoke(cli.app, ["audit", "list", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == [
        {
            "action": "secret_get",
            "command": None,
            "cwd": "/tmp/project",
            "error": None,
            "event_id": "evt-1",
            "hash": "hash-1",
            "platform": "linux",
            "prev_hash": None,
            "refs": [
                {
                    "account": "acct",
                    "kind": "runtime",
                    "scheme": "kc",
                    "service": "st.rio.envrcctl",
                }
            ],
            "status": "success",
            "timestamp": "2026-03-18T00:00:00Z",
            "vars": ["TOKEN"],
        }
    ]


def test_audit_show_by_event_id(monkeypatch) -> None:
    runner = CliRunner()
    event = _make_event(
        event_id="evt-1",
        timestamp="2026-03-18T00:00:00Z",
        action="exec",
        status="success",
        vars=["UV_PUBLISH_TOKEN"],
        refs=[
            AuditRef(
                scheme="kc",
                service="st.rio.envrcctl",
                account="uv_token_envrcctl",
                kind="runtime",
            )
        ],
        command=["uv", "publish"],
        hash_value="hash-1",
    )
    monkeypatch.setattr(cli, "iter_events", lambda: iter([event]))

    result = runner.invoke(cli.app, ["audit", "show", "--event-id", "evt-1"])

    assert result.exit_code == 0
    assert "event_id: evt-1" in result.stdout
    assert "action: exec" in result.stdout
    assert "status: success" in result.stdout
    assert "command: uv publish" in result.stdout
    assert "  - UV_PUBLISH_TOKEN" in result.stdout
    assert "kc:st.rio.envrcctl:uv_token_envrcctl:runtime" in result.stdout
    assert "hash: hash-1" in result.stdout


def test_audit_show_by_index_json(monkeypatch) -> None:
    runner = CliRunner()
    event = _make_event(
        event_id="evt-2",
        timestamp="2026-03-18T00:01:00Z",
        action="secret_get",
        status="failure",
        vars=["TOKEN"],
        error=AuditErrorInfo(code="secret_get_failed", message="boom"),
        hash_value="hash-2",
        prev_hash="hash-1",
    )
    monkeypatch.setattr(cli, "iter_events", lambda: iter([event]))

    result = runner.invoke(cli.app, ["audit", "show", "--index", "0", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "action": "secret_get",
        "command": None,
        "cwd": "/tmp/project",
        "error": {"code": "secret_get_failed", "message": "boom"},
        "event_id": "evt-2",
        "hash": "hash-2",
        "platform": "linux",
        "prev_hash": "hash-1",
        "refs": [],
        "status": "failure",
        "timestamp": "2026-03-18T00:01:00Z",
        "vars": ["TOKEN"],
    }


def test_audit_show_requires_selector(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(cli, "iter_events", lambda: iter([]))

    result = runner.invoke(cli.app, ["audit", "show"])

    assert result.exit_code == 1
    assert "Either --event-id or --index is required." in result.stderr


def test_audit_show_rejects_both_selectors(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(cli, "iter_events", lambda: iter([]))

    result = runner.invoke(
        cli.app,
        ["audit", "show", "--event-id", "evt-1", "--index", "0"],
    )

    assert result.exit_code == 1
    assert "Use either --event-id or --index, not both." in result.stderr


def test_audit_show_rejects_missing_event_id(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(cli, "iter_events", lambda: iter([]))

    result = runner.invoke(cli.app, ["audit", "show", "--event-id", "missing"])

    assert result.exit_code == 1
    assert "Audit event not found: missing" in result.stderr


def test_audit_show_rejects_out_of_range_index(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr(cli, "iter_events", lambda: iter([]))

    result = runner.invoke(cli.app, ["audit", "show", "--index", "0"])

    assert result.exit_code == 1
    assert "Audit event index is out of range." in result.stderr


def test_audit_verify_success(monkeypatch) -> None:
    runner = CliRunner()

    class Result:
        ok = True
        event_count = 3
        latest_hash = "hash-3"
        failure_line = None
        failure_event_id = None
        failure_reason = None

    monkeypatch.setattr(cli, "verify_chain", lambda: Result())

    result = runner.invoke(cli.app, ["audit", "verify"])

    assert result.exit_code == 0
    assert result.stdout.strip().splitlines() == [
        "OK",
        "events: 3",
        "latest_hash: hash-3",
    ]


def test_audit_verify_failure(monkeypatch) -> None:
    runner = CliRunner()

    class Result:
        ok = False
        event_count = 2
        latest_hash = "hash-2"
        failure_line = 2
        failure_event_id = "evt-2"
        failure_reason = "Audit event hash mismatch."

    monkeypatch.setattr(cli, "verify_chain", lambda: Result())

    result = runner.invoke(cli.app, ["audit", "verify"])

    assert result.exit_code == 1
    assert result.stdout.strip().splitlines() == [
        "FAIL",
        "line: 2",
        "event_id: evt-2",
        "reason: Audit event hash mismatch.",
    ]
    assert "Audit verification failed." in result.stderr


def test_audit_show_renders_error_details(monkeypatch) -> None:
    runner = CliRunner()
    event = _make_event(
        event_id="evt-3",
        timestamp="2026-03-18T00:02:00Z",
        action="exec",
        status="failure",
        vars=["TOKEN"],
        error=AuditErrorInfo(code="exec_failed", message="boom"),
        hash_value="hash-3",
        prev_hash="hash-2",
    )
    monkeypatch.setattr(cli, "iter_events", lambda: iter([event]))

    result = runner.invoke(cli.app, ["audit", "show", "--event-id", "evt-3"])

    assert result.exit_code == 0
    assert "error:" in result.stdout
    assert "  code: exec_failed" in result.stdout
    assert "  message: boom" in result.stdout
    assert "prev_hash: hash-2" in result.stdout
