from __future__ import annotations

import getpass
import re
import shlex
import sys
from pathlib import Path
from typing import Callable

import typer

from .envrc import ENVRC_FILENAME, ensure_managed_block, load_envrc, write_envrc
from .errors import EnvrcctlError
from .managed_block import ManagedBlock
from .secrets import DEFAULT_SERVICE, format_ref, get_default_backend, parse_ref

app = typer.Typer(add_completion=False, help="Manage .envrc with managed blocks.")
secret_app = typer.Typer(help="Manage secret references.")
app.add_typer(secret_app, name="secret")

ENV_VAR_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _envrc_path() -> Path:
    return Path.cwd() / ENVRC_FILENAME


def _run(action: Callable[[], None]) -> None:
    try:
        action()
    except EnvrcctlError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _validate_env_var(name: str) -> None:
    if not ENV_VAR_RE.match(name):
        raise EnvrcctlError(f"Invalid environment variable name: {name}")


def _warn_if_world_writable() -> None:
    typer.echo("WARN: .envrc is world-writable.", err=True)


def _write_envrc(doc, block: ManagedBlock) -> None:
    warn = write_envrc(_envrc_path(), doc, block)
    if warn:
        _warn_if_world_writable()


@app.command()
def init() -> None:
    """Create .envrc if missing and insert managed block."""

    def action() -> None:
        path = _envrc_path()
        doc = load_envrc(path)
        block = ensure_managed_block(doc)
        block.include_inject = True
        _write_envrc(doc, block)

    _run(action)


@app.command()
def inherit(state: str = typer.Argument(..., help="on/off")) -> None:
    """Toggle source_up inheritance in the managed block."""

    def action() -> None:
        if state not in ("on", "off"):
            raise EnvrcctlError("inherit expects 'on' or 'off'.")
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        block.inherit = state == "on"
        _write_envrc(doc, block)

    _run(action)


@app.command()
def set(var: str, value: str) -> None:
    """Set a non-secret export in the managed block."""

    def action() -> None:
        _validate_env_var(var)
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        block.exports[var] = value
        block.include_inject = True
        _write_envrc(doc, block)

    _run(action)


@app.command()
def unset(var: str) -> None:
    """Unset a non-secret export in the managed block."""

    def action() -> None:
        _validate_env_var(var)
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        block.exports.pop(var, None)
        _write_envrc(doc, block)

    _run(action)


@app.command()
def get(var: str) -> None:
    """Get a non-secret export value from the managed block."""

    def action() -> None:
        _validate_env_var(var)
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        if var not in block.exports:
            raise EnvrcctlError(f"{var} is not set in the managed block.")
        typer.echo(block.exports[var])

    _run(action)


@app.command("list")
def list_exports() -> None:
    """List non-secret exports in the managed block."""

    def action() -> None:
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        for key in sorted(block.exports.keys()):
            value = block.exports[key]
            typer.echo(f"{key}={value}")

    _run(action)


@secret_app.command("set")
def secret_set(
    var: str,
    account: str = typer.Option(..., "--account", help="Keychain account name."),
    service: str = typer.Option(
        DEFAULT_SERVICE, "--service", help="Keychain service name."
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read secret from stdin."),
) -> None:
    """Store a secret and add its reference to the managed block."""

    def action() -> None:
        _validate_env_var(var)
        if stdin:
            value = sys.stdin.read()
        else:
            value = getpass.getpass("Secret value: ")
        value = value.rstrip("\n")
        if not value:
            raise EnvrcctlError("Secret value is empty.")
        ref = format_ref(service, account)
        backend = get_default_backend()
        backend.set(parse_ref(ref), value)

        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        block.secret_refs[var] = ref
        block.include_inject = True
        _write_envrc(doc, block)

    _run(action)


@secret_app.command("unset")
def secret_unset(var: str) -> None:
    """Remove a secret reference and delete it from the backend."""

    def action() -> None:
        _validate_env_var(var)
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        ref = block.secret_refs.get(var)
        if not ref:
            raise EnvrcctlError(f"{var} has no secret reference.")
        backend = get_default_backend()
        backend.delete(parse_ref(ref))
        block.secret_refs.pop(var, None)
        _write_envrc(doc, block)

    _run(action)


@secret_app.command("list")
def secret_list() -> None:
    """List secret references in the managed block."""

    def action() -> None:
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        for key in sorted(block.secret_refs.keys()):
            typer.echo(f"{key}={block.secret_refs[key]}")

    _run(action)


@app.command()
def inject() -> None:
    """Emit export statements for all secret references."""

    def action() -> None:
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        backend = get_default_backend()
        for key in sorted(block.secret_refs.keys()):
            ref = parse_ref(block.secret_refs[key])
            value = backend.get(ref)
            typer.echo(f"export {key}={shlex.quote(value)}")

    _run(action)
