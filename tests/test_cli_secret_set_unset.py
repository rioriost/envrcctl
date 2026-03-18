from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envrcctl import cli
from envrcctl.envrc import ENVRC_FILENAME
from tests.helpers.cli_support import DummyBackend, read_envrc


def test_cli_secret_set_inject_unset(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)

    runner.invoke(cli.app, ["init"])

    result = runner.invoke(
        cli.app,
        [
            "secret",
            "set",
            "OPENAI_API_KEY",
            "--account",
            "openai:prod",
            "--stdin",
            "--inject",
        ],
        input="secretvalue",
    )
    assert result.exit_code == 0
    envrc_text = read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_OPENAI_API_KEY" in envrc_text
    assert 'eval "$(envrcctl inject)"' in envrc_text

    monkeypatch.setattr(cli.sys, "platform", "linux")

    result = runner.invoke(cli.app, ["inject", "--force"])
    assert result.exit_code == 0
    assert "export OPENAI_API_KEY=secretvalue" in result.stdout

    result = runner.invoke(cli.app, ["secret", "unset", "OPENAI_API_KEY"])
    assert result.exit_code == 0
    envrc_text = read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_OPENAI_API_KEY" not in envrc_text


def test_cli_secret_unset_preserves_shared_keychain_item(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)

    runner.invoke(cli.app, ["init"])
    runner.invoke(
        cli.app,
        ["secret", "set", "TEST_TOKEN", "--account", "acct", "--stdin"],
        input="sharedsecret",
    )

    envrc_path = tmp_path / ENVRC_FILENAME
    envrc_text = read_envrc(envrc_path)
    envrc_text = envrc_text.replace(
        "export ENVRCCTL_SECRET_TEST_TOKEN=kc:st.rio.envrcctl:acct:runtime",
        "\n".join(
            [
                "export ENVRCCTL_SECRET_TEST_TOKEN=kc:st.rio.envrcctl:acct:runtime",
                "export ENVRCCTL_SECRET_UV_PUBLISH_TOKEN=kc:st.rio.envrcctl:acct:runtime",
            ]
        ),
    )
    envrc_path.write_text(envrc_text, encoding="utf-8")

    result = runner.invoke(cli.app, ["secret", "unset", "TEST_TOKEN"])
    assert result.exit_code == 0

    result = runner.invoke(
        cli.app,
        ["secret", "get", "UV_PUBLISH_TOKEN", "--plain"],
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "sharedsecret"


def test_secret_set_uses_getpass(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    values = iter(["secretvalue", "secretvalue"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(values))

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "set", "TOKEN", "--account", "acct"])
    assert result.exit_code == 0

    envrc_text = read_envrc(tmp_path / ENVRC_FILENAME)
    assert "ENVRCCTL_SECRET_TOKEN" in envrc_text


def test_secret_set_rejects_mismatched_confirmation(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    dummy = DummyBackend()

    monkeypatch.setattr(cli, "resolve_backend", lambda: ("kc", dummy))
    monkeypatch.setattr(cli, "backend_for_ref", lambda ref: dummy)
    values = iter(["secretvalue", "different"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(values))

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "set", "TOKEN", "--account", "acct"])
    assert result.exit_code == 1
    assert "does not match confirmation" in result.stderr


def test_secret_unset_missing_ref(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    runner.invoke(cli.app, ["init"])
    result = runner.invoke(cli.app, ["secret", "unset", "MISSING"])
    assert result.exit_code == 1
    assert "has no secret reference" in result.stderr
