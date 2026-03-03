from __future__ import annotations

from pathlib import Path

import pytest

from envrctl import cli
from envrctl.envrc import ENVRC_FILENAME
from envrctl.errors import EnvrcctlError


def test_find_nearest_envrc_dir_returns_none(tmp_path: Path) -> None:
    start = tmp_path / "a" / "b"
    start.mkdir(parents=True)

    found = cli._find_nearest_envrc_dir(start)
    assert found is None


def test_find_nearest_envrc_dir_finds_parent(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)

    (parent / ENVRC_FILENAME).write_text("# placeholder", encoding="utf-8")

    found = cli._find_nearest_envrc_dir(child)
    assert found == parent


def test_mask_secret_short_value() -> None:
    assert cli._mask_secret("abcd") == "****"


def test_mask_secret_long_value() -> None:
    assert cli._mask_secret("supersecretvalue") == "supe...alue"


def test_clipboard_command_prefers_pbcopy(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(
        cli.shutil, "which", lambda cmd: "/usr/bin/pbcopy" if cmd == "pbcopy" else None
    )
    assert cli._clipboard_command() == ["pbcopy"]


def test_clipboard_command_uses_xclip(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(
        cli.shutil, "which", lambda cmd: "/usr/bin/xclip" if cmd == "xclip" else None
    )
    assert cli._clipboard_command() == ["xclip", "-selection", "clipboard"]


def test_clipboard_command_uses_xsel(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(
        cli.shutil, "which", lambda cmd: "/usr/bin/xsel" if cmd == "xsel" else None
    )
    assert cli._clipboard_command() == ["xsel", "--clipboard", "--input"]


def test_clipboard_command_none(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli.shutil, "which", lambda cmd: None)
    assert cli._clipboard_command() is None


def test_copy_to_clipboard_missing_tool(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_clipboard_command", lambda: None)
    with pytest.raises(EnvrcctlError):
        cli._copy_to_clipboard("value")


def test_copy_to_clipboard_runs_command(monkeypatch) -> None:
    calls = {}

    def fake_run_command(
        args, input_text=None, allowed_commands=None, error_message=None
    ):
        calls["args"] = args
        calls["input_text"] = input_text
        calls["allowed_commands"] = allowed_commands
        calls["error_message"] = error_message
        return ""

    monkeypatch.setattr(cli, "_clipboard_command", lambda: ["pbcopy"])
    monkeypatch.setattr(cli, "run_command", fake_run_command)

    cli._copy_to_clipboard("value")
    assert calls["args"] == ["pbcopy"]
    assert calls["input_text"] == "value"
    assert calls["allowed_commands"] == {"pbcopy"}


def test_confirm_or_abort_rejects(monkeypatch) -> None:
    monkeypatch.setattr(cli.typer, "confirm", lambda message, default=False: False)
    with pytest.raises(EnvrcctlError):
        cli._confirm_or_abort("confirm?", False)


def test_confirm_or_abort_assume_yes_skips(monkeypatch) -> None:
    called = {"ok": False}

    def fake_confirm(message, default=False):
        called["ok"] = True
        return True

    monkeypatch.setattr(cli.typer, "confirm", fake_confirm)
    cli._confirm_or_abort("confirm?", True)
    assert called["ok"] is False


def test_write_envrc_raises_when_world_writable_after_write(
    tmp_path: Path, monkeypatch
) -> None:
    from envrctl.envrc import load_envrc
    from envrctl.managed_block import ManagedBlock

    envrc_path = tmp_path / ENVRC_FILENAME
    doc = load_envrc(envrc_path)
    block = ManagedBlock()

    monkeypatch.setattr(cli, "_envrc_path", lambda: envrc_path)
    monkeypatch.setattr(cli, "write_envrc", lambda path, doc, block: True)

    with pytest.raises(EnvrcctlError):
        cli._write_envrc(doc, block)
