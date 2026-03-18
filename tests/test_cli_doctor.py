from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.envrc import ENVRC_FILENAME
from envrcctl.errors import EnvrcctlError
from envrcctl.managed_block import ManagedBlock, render_managed_block


def test_cli_doctor_warns_on_symlink(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    target = tmp_path / "real.envrc"
    target.write_text(
        render_managed_block(ManagedBlock(include_inject=True)), encoding="utf-8"
    )
    envrc_path = tmp_path / ENVRC_FILENAME
    envrc_path.symlink_to(target)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "symlink" in result.stderr


def test_cli_doctor_warns_on_group_writable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    envrc_path = tmp_path / ENVRC_FILENAME
    envrc_path.chmod(0o660)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "group-writable" in result.stderr


def test_cli_doctor_warns_for_unmanaged_and_missing_inject(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=False)
    content = "\n".join(
        [
            "export UNMANAGED=1",
            render_managed_block(block).rstrip(),
            "# trailing",
        ]
    )
    (tmp_path / ENVRC_FILENAME).write_text(content, encoding="utf-8")

    monkeypatch.setattr(cli, "is_world_writable", lambda _: True)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "world-writable" in result.stderr
    assert "inject line missing" in result.stderr
    assert "unmanaged exports outside block" in result.stderr


def test_cli_doctor_warns_for_plaintext_secrets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(exports={"API_TOKEN": "plaintext"}, include_inject=True)
    (tmp_path / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "possible plaintext secrets" in result.stderr


def test_doctor_warns_when_no_managed_block(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    (tmp_path / ENVRC_FILENAME).write_text("export FOO=bar\n", encoding="utf-8")

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "Managed block not found" in result.stderr


def test_doctor_warns_for_unmanaged_secret_refs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=True)
    content = "\n".join(
        [
            "export ENVRCCTL_SECRET_API_KEY=kc:svc:acct",
            render_managed_block(block).rstrip(),
        ]
    )
    (tmp_path / ENVRC_FILENAME).write_text(content, encoding="utf-8")

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "unmanaged secret refs outside block" in result.stderr


def test_doctor_ok_when_no_warnings(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=True)
    (tmp_path / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )
    monkeypatch.setattr(
        cli,
        "verify_chain",
        lambda: type(
            "AuditVerifyResultStub",
            (),
            {
                "ok": True,
                "event_count": 0,
                "latest_hash": None,
                "failure_line": None,
                "failure_event_id": None,
                "failure_reason": None,
            },
        )(),
    )
    monkeypatch.setattr(cli, "ensure_audit_store_secure", lambda: None)

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "OK"


def test_doctor_warns_when_audit_chain_verification_fails(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=True)
    (tmp_path / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )
    monkeypatch.setattr(
        cli,
        "verify_chain",
        lambda: type(
            "AuditVerifyResultStub",
            (),
            {
                "ok": False,
                "event_count": 1,
                "latest_hash": "hash-1",
                "failure_line": 2,
                "failure_event_id": "evt-2",
                "failure_reason": "Audit event hash mismatch.",
            },
        )(),
    )

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "audit chain verification failed" in result.stderr
    assert "line=2" in result.stderr
    assert "event_id=evt-2" in result.stderr
    assert "reason=Audit event hash mismatch." in result.stderr


def test_doctor_warns_when_audit_store_is_not_secure(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    block = ManagedBlock(include_inject=True)
    (tmp_path / ENVRC_FILENAME).write_text(
        render_managed_block(block), encoding="utf-8"
    )
    monkeypatch.setattr(
        cli,
        "verify_chain",
        lambda: type(
            "AuditVerifyResultStub",
            (),
            {
                "ok": True,
                "event_count": 0,
                "latest_hash": None,
                "failure_line": None,
                "failure_event_id": None,
                "failure_reason": None,
            },
        )(),
    )

    def fake_ensure_audit_store_secure() -> None:
        raise EnvrcctlError("permissions are insecure")

    monkeypatch.setattr(
        cli, "ensure_audit_store_secure", fake_ensure_audit_store_secure
    )

    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "audit store is not secure" in result.stderr
    assert "permissions are insecure" in result.stderr
