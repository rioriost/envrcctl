import fcntl
import importlib.util
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location(
    "generate_completions",
    ROOT / "scripts/generate_completions.py",
)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


@pytest.fixture
def completion_environment(tmp_path, monkeypatch):
    for name in (
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "TMPDIR",
    ):
        directory = tmp_path / name.lower()
        directory.mkdir()
        monkeypatch.setenv(name, str(directory))
    monkeypatch.setenv("PYTHONPATH", str(ROOT / "src"))
    monkeypatch.setenv("ZDOTDIR", str(tmp_path / "home"))
    monkeypatch.setenv("HISTFILE", str(tmp_path / "shell-history"))
    monkeypatch.setenv("TERM", "xterm")
    commands = tmp_path / "bin"
    commands.mkdir()
    entrypoint = commands / "envrcctl"
    entrypoint.write_text(
        f"#!{sys.executable}\nfrom envrcctl.main import main\nmain()\n",
    )
    entrypoint.chmod(0o755)
    monkeypatch.setenv("PATH", str(commands) + os.pathsep + os.environ["PATH"])
    output = tmp_path / "completions"
    generator.generate(output)
    return tmp_path, output, entrypoint


@pytest.mark.parametrize("shell", generator.SHELLS)
def test_completion_is_official_typer_protocol(completion_environment, shell):
    _, output, entrypoint = completion_environment
    result = subprocess.run(
        [str(entrypoint)],
        env={**os.environ, "_ENVRCCTL_COMPLETE": f"source_{shell}"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (output / f"envrcctl.{shell}").read_text().strip()
    assert (ROOT / f"completions/envrcctl.{shell}").read_text() == (
        output / f"envrcctl.{shell}"
    ).read_text()


@pytest.mark.parametrize(
    "arguments,expected",
    [("envrcctl ini", "init"), ("envrcctl init --ye", "--yes")],
)
def test_fish_protocol_returns_cli_candidates_without_fish(
    completion_environment,
    arguments,
    expected,
):
    root, _, entrypoint = completion_environment
    env = {
        **os.environ,
        "_ENVRCCTL_COMPLETE": "complete_fish",
        "_TYPER_COMPLETE_ARGS": arguments,
    }
    result = subprocess.run(
        [str(entrypoint)],
        cwd=root,
        capture_output=True,
        text=True,
        env={**env, "_TYPER_COMPLETE_FISH_ACTION": "get-args"},
    )
    assert result.returncode == 0, result.stderr
    assert expected in [line.split("\t", 1)[0] for line in result.stdout.splitlines()]
    condition = subprocess.run(
        [str(entrypoint)],
        cwd=root,
        capture_output=True,
        text=True,
        env={**env, "_TYPER_COMPLETE_FISH_ACTION": "is-args"},
    )
    assert condition.returncode == 0, condition.stderr


def test_fish_protocol_enables_native_path_fallback(completion_environment):
    root, _, entrypoint = completion_environment
    (root / "completion-path-fixture.txt").write_text("harmless path fixture\n")
    env = {
        **os.environ,
        "_ENVRCCTL_COMPLETE": "complete_fish",
        "_TYPER_COMPLETE_ARGS": "envrcctl exec -- ./completion-path-",
    }
    result = subprocess.run(
        [str(entrypoint)],
        cwd=root,
        capture_output=True,
        text=True,
        env={**env, "_TYPER_COMPLETE_FISH_ACTION": "get-args"},
    )
    assert result.returncode == 0, result.stderr
    assert not result.stdout.strip()
    condition = subprocess.run(
        [str(entrypoint)],
        cwd=root,
        capture_output=True,
        text=True,
        env={**env, "_TYPER_COMPLETE_FISH_ACTION": "is-args"},
    )
    assert condition.returncode == 1
    assert not condition.stderr


def read_until(fd, expected, timeout=15):
    deadline = time.monotonic() + timeout
    output = b""
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
        if readable:
            output += os.read(fd, 65536)
            visible = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", output)
            if expected in visible:
                return visible
    raise AssertionError(f"Shell did not produce {expected!r}: {output!r}")


def claim_controlling_terminal():
    # Popen's start_new_session runs setsid before this child-only callback.
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


@pytest.mark.parametrize("shell", generator.SHELLS)
def test_real_shell_completes_commands_options_and_paths(completion_environment, shell):
    root, output, _ = completion_environment
    executable = "/bin/bash" if shell == "bash" else shutil.which(shell)
    if not executable:
        pytest.skip(f"{shell} is not installed")
    (root / "completion-path-fixture.txt").write_text("harmless path completion fixture\n")
    if shell == "bash":
        args = ["--noprofile", "--norc", "-i"]
        setup = f"PS1='READY> '; source '{output}/envrcctl.bash'"
    elif shell == "zsh":
        args = ["-dfi"]
        setup = (
            f"autoload -Uz compinit; compinit -D -i; source '{output}/envrcctl.zsh'; PS1='READY> '"
        )
    else:
        args = ["--no-config", "--interactive"]
        setup = f"function fish_prompt; printf 'READY> '; end; source '{output}/envrcctl.fish'"
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [executable, *args],
        cwd=root,
        env=os.environ.copy(),
        stdin=slave,
        stdout=slave,
        stderr=slave,
        start_new_session=True,
        preexec_fn=claim_controlling_terminal,
    )
    os.close(slave)
    try:
        os.write(master, (setup + "\n").encode())
        # A separate marker avoids mistaking the echoed setup command for its final prompt.
        os.write(master, b"printf 'SETUP_%s\\n' 'DONE'\n")
        read_until(master, b"SETUP_DONE")
        for text, expected in (
            (b"envrcctl ini\t", b"init "),
            (b"envrcctl init --ye\t", b"--yes "),
            (b"envrcctl exec -- ./completion-path-\t", b"fixture.txt"),
        ):
            os.write(master, text)
            read_until(master, expected)
            os.write(master, b"\x15\n")
            read_until(master, b"READY>")
    finally:
        # Closing the PTY sends hangup and unblocks terminal I/O before waiting.
        os.close(master)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
