from __future__ import annotations

import getpass
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

import typer

from .command_runner import run_command
from .envrc import (
    ENVRC_FILENAME,
    ensure_managed_block,
    extract_unmanaged_exports,
    is_group_writable,
    is_world_writable,
    load_envrc,
    write_envrc,
)
from .errors import EnvrcctlError
from .managed_block import ManagedBlock
from .secrets import (
    DEFAULT_SERVICE,
    backend_for_ref,
    format_ref,
    parse_ref,
    resolve_backend,
)

app = typer.Typer(add_completion=True, help="Manage .envrc with managed blocks.")
secret_app = typer.Typer(help="Manage secret references.")
app.add_typer(secret_app, name="secret")

ENV_VAR_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
RISKY_EXPORT_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|API_KEY|ACCESS_KEY|PRIVATE_KEY)", re.IGNORECASE
)


def _envrc_path() -> Path:
    return Path.cwd() / ENVRC_FILENAME


def _find_nearest_envrc_dir(start_dir: Path) -> Path | None:
    current = start_dir
    while True:
        if (current / ENVRC_FILENAME).exists():
            return current
        if current.parent == current:
            return None
        current = current.parent


def _run(action: Callable[[], None]) -> None:
    try:
        action()
    except EnvrcctlError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _clipboard_command() -> list[str] | None:
    if sys.platform == "darwin" and shutil.which("pbcopy"):
        return ["pbcopy"]
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard"]
    if shutil.which("xsel"):
        return ["xsel", "--clipboard", "--input"]
    return None


def _copy_to_clipboard(value: str) -> None:
    cmd = _clipboard_command()
    if not cmd:
        raise EnvrcctlError(
            "Clipboard tool not available. Install pbcopy/xclip/xsel or use --plain."
        )
    run_command(
        cmd,
        input_text=value,
        allowed_commands={cmd[0]},
        error_message="Clipboard command failed.",
    )


def _validate_env_var(name: str) -> None:
    if not ENV_VAR_RE.match(name):
        raise EnvrcctlError(f"Invalid environment variable name: {name}")


def _confirm_or_abort(message: str, assume_yes: bool) -> None:
    if assume_yes:
        return
    if not typer.confirm(message, default=False):
        raise EnvrcctlError("Operation cancelled.")


def _ensure_not_world_writable(path: Path) -> None:
    if path.exists() and is_world_writable(path):
        raise EnvrcctlError(
            ".envrc is world-writable; refusing to write. Fix permissions and retry."
        )


def _write_envrc(doc, block: ManagedBlock) -> None:
    path = _envrc_path()
    _ensure_not_world_writable(path)
    warn = write_envrc(path, doc, block)
    if warn:
        raise EnvrcctlError(
            ".envrc is world-writable after write. Fix permissions and retry."
        )


@app.command()
def init(
    yes: bool = typer.Option(False, "--yes", help="Confirm modifying existing .envrc."),
) -> None:
    """Create .envrc if missing and insert managed block."""

    def action() -> None:
        path = _envrc_path()
        if path.exists():
            _confirm_or_abort(".envrc exists; proceed with managed block update?", yes)
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
    kind: str = typer.Option("runtime", "--kind", help="Secret kind (runtime/admin)."),
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
        scheme, backend = resolve_backend()
        ref = format_ref(service, account, scheme=scheme, kind=kind)
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
        parsed = parse_ref(ref)
        backend = backend_for_ref(parsed)
        backend.delete(parsed)
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


@secret_app.command("get")
def secret_get(
    var: str,
    plain: bool = typer.Option(False, "--plain", help="Print the secret value."),
    show: bool = typer.Option(False, "--show", help="Alias for --plain."),
    force_plain: bool = typer.Option(
        False, "--force-plain", help="Allow plaintext output in non-interactive runs."
    ),
) -> None:
    """Get a secret value (masked by default, clipboard-only)."""

    def action() -> None:
        _validate_env_var(var)
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        ref = block.secret_refs.get(var)
        if not ref:
            raise EnvrcctlError(f"{var} has no secret reference.")
        parsed = parse_ref(ref)
        backend = backend_for_ref(parsed)
        value = backend.get(parsed)

        if not _is_interactive():
            if not force_plain:
                raise EnvrcctlError(
                    "secret get is blocked in non-interactive environments. Use --force-plain to override."
                )
            typer.echo(value)
            return

        if plain or show:
            typer.echo(value)
            return

        _copy_to_clipboard(value)
        masked = _mask_secret(value)
        typer.echo(f"Copied to clipboard: {var}={masked}")

    _run(action)


@app.command()
def inject(
    force: bool = typer.Option(
        False, "--force", help="Allow inject in non-interactive environments."
    ),
) -> None:
    """Emit export statements for all secret references."""

    def action() -> None:
        if not _is_interactive() and not force:
            raise EnvrcctlError(
                "inject is blocked in non-interactive environments. Use --force to override."
            )
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        for key in sorted(block.secret_refs.keys()):
            ref = parse_ref(block.secret_refs[key])
            if ref.kind != "runtime":
                continue
            backend = backend_for_ref(ref)
            value = backend.get(ref)
            typer.echo(f"export {key}={shlex.quote(value)}")

    _run(action)


@app.command(
    "exec",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def exec_cmd(
    ctx: typer.Context,
    key: list[str] = typer.Option(
        None,
        "-k",
        "--key",
        help="Limit injected secrets to specific variables.",
    ),
) -> None:
    """Execute a command with managed secrets injected into the environment."""

    def action() -> None:
        if not ctx.args:
            raise EnvrcctlError("No command provided. Use -- to separate the command.")
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)

        selected_keys = {item for item in key} if key else None
        if selected_keys is not None:
            available_keys = {item for item in block.secret_refs.keys()}
            missing = selected_keys - available_keys
            if missing:
                missing_list = ", ".join(sorted(missing))
                raise EnvrcctlError(
                    f"Secrets not found in managed block: {missing_list}"
                )

        env = os.environ.copy()
        for name, value in block.exports.items():
            env[name] = value
        for name in sorted(block.secret_refs.keys()):
            if selected_keys is not None and name not in selected_keys:
                continue
            ref = parse_ref(block.secret_refs[name])
            if ref.kind != "runtime":
                if selected_keys is not None and name in selected_keys:
                    raise EnvrcctlError(
                        f"Secret {name} is admin and cannot be injected via exec."
                    )
                continue
            backend = backend_for_ref(ref)
            env[name] = backend.get(ref)

        result = subprocess.run(list(ctx.args), env=env)
        if result.returncode != 0:
            raise typer.Exit(code=result.returncode)

    _run(action)


@app.command()
def eval() -> None:
    """Show the effective environment (masked secrets)."""

    def action() -> None:
        cwd = Path.cwd()
        doc = load_envrc(_envrc_path())
        if not doc.has_block:
            raise EnvrcctlError("Managed block not found in .envrc.")
        block = ensure_managed_block(doc)

        chain: list[tuple[Path, ManagedBlock]] = [(cwd, block)]
        inherit = block.inherit
        search_dir = cwd.parent
        while inherit:
            parent_dir = _find_nearest_envrc_dir(search_dir)
            if parent_dir is None:
                break
            parent_doc = load_envrc(parent_dir / ENVRC_FILENAME)
            if parent_doc.managed is None:
                break
            parent_block = ensure_managed_block(parent_doc)
            chain.append((parent_dir, parent_block))
            inherit = parent_block.inherit
            search_dir = parent_dir.parent

        merged: dict[str, tuple[str, str, bool]] = {}
        for path, block in reversed(chain):
            source = "current" if path == cwd else str(path)
            for key, value in block.exports.items():
                merged[key] = (value, source, False)
            for key, ref in block.secret_refs.items():
                merged[key] = (ref, source, True)

        for key in sorted(merged.keys()):
            value, source, is_secret = merged[key]
            display = "******" if is_secret else value
            kind = "secret" if is_secret else "export"
            typer.echo(f"{key} = {display} (from {source}, {kind})")

    _run(action)


@app.command()
def doctor() -> None:
    """Run security and consistency checks for .envrc."""

    def action() -> None:
        warnings = 0
        path = _envrc_path()
        if not path.exists():
            raise EnvrcctlError(".envrc not found.")
        if path.is_symlink():
            typer.echo(
                "WARN: .envrc is a symlink. Writes are blocked; use a regular file.",
                err=True,
            )
            warnings += 1
        if is_group_writable(path):
            typer.echo(
                "WARN: .envrc is group-writable. Consider chmod g-w .envrc.",
                err=True,
            )
            warnings += 1
        if is_world_writable(path):
            typer.echo(
                "WARN: .envrc is world-writable. Fix permissions (chmod o-w .envrc).",
                err=True,
            )
            warnings += 1

        doc = load_envrc(path)
        block = ensure_managed_block(doc)
        if not doc.has_block:
            typer.echo(
                "WARN: Managed block not found in .envrc. Run `envrcctl init`.",
                err=True,
            )
            warnings += 1
        elif doc.managed and not doc.managed.include_inject:
            typer.echo(
                "WARN: inject line missing in managed block. Run `envrcctl init` to add it.",
                err=True,
            )
            warnings += 1

        before_clean, before_exports, before_secrets = extract_unmanaged_exports(
            doc.before
        )
        after_clean, after_exports, after_secrets = extract_unmanaged_exports(doc.after)
        unmanaged = {**before_exports, **after_exports}
        unmanaged_secrets = {**before_secrets, **after_secrets}
        if unmanaged:
            keys = ", ".join(sorted(unmanaged.keys()))
            typer.echo(
                f"WARN: unmanaged exports outside block: {keys}. Run `envrcctl migrate` to move them.",
                err=True,
            )
            warnings += 1
        if unmanaged_secrets:
            keys = ", ".join(sorted(unmanaged_secrets.keys()))
            typer.echo(
                f"WARN: unmanaged secret refs outside block: {keys}. Run `envrcctl migrate` to move them.",
                err=True,
            )
            warnings += 1

        risky_exports = {
            key
            for key in {**block.exports, **unmanaged}
            if RISKY_EXPORT_RE.search(key) and key not in block.secret_refs
        }
        if risky_exports:
            keys = ", ".join(sorted(risky_exports))
            typer.echo(
                "WARN: possible plaintext secrets in exports: "
                f"{keys}. Consider `envrcctl secret set` for these values.",
                err=True,
            )
            warnings += 1

        if warnings == 0:
            typer.echo("OK")

    _run(action)


@app.command()
def migrate(
    yes: bool = typer.Option(
        False, "--yes", help="Confirm migrating unmanaged exports."
    ),
) -> None:
    """Move unmanaged exports into the managed block."""

    def action() -> None:
        path = _envrc_path()
        if not path.exists():
            raise EnvrcctlError(".envrc not found.")
        doc = load_envrc(path)
        block = ensure_managed_block(doc)

        before_clean, before_exports, before_secrets = extract_unmanaged_exports(
            doc.before
        )
        after_clean, after_exports, after_secrets = extract_unmanaged_exports(doc.after)

        if before_exports or after_exports or before_secrets or after_secrets:
            _confirm_or_abort("Migrate unmanaged exports into the managed block?", yes)

        for key, value in {**before_exports, **after_exports}.items():
            block.exports.setdefault(key, value)
        for key, ref in {**before_secrets, **after_secrets}.items():
            block.secret_refs.setdefault(key, ref)

        doc.before = before_clean
        doc.after = after_clean
        block.include_inject = True
        _write_envrc(doc, block)

    _run(action)
