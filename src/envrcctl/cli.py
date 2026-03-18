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

from .audit import (
    AuditErrorInfo,
    AuditRef,
    append_event,
    ensure_audit_store_secure,
    iter_events,
    verify_chain,
)
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
audit_app = typer.Typer(help="Inspect tamper-evident audit records.")
app.add_typer(secret_app, name="secret")
app.add_typer(audit_app, name="audit")

ENV_VAR_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
RISKY_EXPORT_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|API_KEY|ACCESS_KEY|PRIVATE_KEY)", re.IGNORECASE
)


def _audit_ref(ref) -> AuditRef:
    return AuditRef(
        scheme=ref.scheme,
        service=ref.service,
        account=ref.account,
        kind=ref.kind,
    )


def _audit_error(code: str, exc: Exception) -> AuditErrorInfo:
    return AuditErrorInfo(code=code, message=str(exc))


def _record_secret_access_event(
    *,
    action: str,
    status: str,
    vars: list[str],
    refs: list,
    command: list[str] | None = None,
    error: AuditErrorInfo | None = None,
) -> None:
    append_event(
        action=action,
        status=status,
        vars=vars,
        refs=[_audit_ref(ref) for ref in refs],
        cwd=Path.cwd(),
        platform=sys.platform,
        command=command,
        error=error,
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


def _format_audit_command(command: list[str] | None) -> str:
    if not command:
        return "-"
    return shlex.join(command)


def _require_secret_access_auth(reason: str) -> str | None:
    if sys.platform != "darwin":
        return None
    return reason


def _get_secret_value(
    backend,
    ref,
    auth_reason: str | None,
) -> str:
    if sys.platform == "darwin":
        return backend.get_with_auth(ref, auth_reason)
    return backend.get(ref)


def _get_secret_values(
    refs: list,
    auth_reason: str | None,
) -> dict[tuple[str, str], str]:
    if not refs:
        return {}
    backend = backend_for_ref(refs[0])
    if sys.platform == "darwin":
        if hasattr(backend, "get_many_with_auth"):
            return backend.get_many_with_auth(refs, auth_reason)
    values: dict[tuple[str, str], str] = {}
    for ref in refs:
        ref_backend = backend_for_ref(ref)
        values[(ref.service, ref.account)] = _get_secret_value(
            ref_backend,
            ref,
            auth_reason,
        )
    return values


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


def _ensure_direnv_available() -> None:
    if shutil.which("direnv"):
        return
    raise EnvrcctlError(
        "direnv not found in PATH. Install it (e.g. brew install direnv) and ensure it is on PATH."
    )


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
    inject: bool = typer.Option(
        False, "--inject", help="Add inject line to managed block."
    ),
) -> None:
    """Create .envrc if missing and insert managed block."""

    def action() -> None:
        _ensure_direnv_available()
        path = _envrc_path()
        if path.exists():
            _confirm_or_abort(".envrc exists; proceed with managed block update?", yes)
        doc = load_envrc(path)
        block = ensure_managed_block(doc)
        if inject:
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
def set(
    var: str,
    value: str,
    inject: bool = typer.Option(
        False, "--inject", help="Add inject line to managed block."
    ),
) -> None:
    """Set a non-secret export in the managed block."""

    def action() -> None:
        _validate_env_var(var)
        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        block.exports[var] = value
        if inject:
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
    inject: bool = typer.Option(
        False, "--inject", help="Add inject line to managed block."
    ),
) -> None:
    """Store a secret and add its reference to the managed block."""

    def action() -> None:
        _validate_env_var(var)
        if stdin:
            value = sys.stdin.read()
        else:
            value = getpass.getpass("Secret value: ")
            confirm = getpass.getpass("Confirm secret value: ")
            if confirm != value:
                raise EnvrcctlError("Secret value does not match confirmation.")
        value = value.rstrip("\n")
        if not value:
            raise EnvrcctlError("Secret value is empty.")
        scheme, backend = resolve_backend()
        ref = format_ref(service, account, scheme=scheme, kind=kind)
        backend.set(parse_ref(ref), value)

        doc = load_envrc(_envrc_path())
        block = ensure_managed_block(doc)
        block.secret_refs[var] = ref
        if inject:
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

        shared_ref_in_use = any(
            name != var and other_ref == ref
            for name, other_ref in block.secret_refs.items()
        )

        if not shared_ref_in_use:
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

        try:
            if not _is_interactive():
                if not force_plain:
                    raise EnvrcctlError(
                        "secret get is blocked in non-interactive environments. Use --force-plain to override."
                    )
                if sys.platform == "darwin":
                    raise EnvrcctlError(
                        "secret get on macOS requires an interactive shell and device owner authentication."
                    )
                value = backend.get(parsed)
                _record_secret_access_event(
                    action="secret_get",
                    status="success",
                    vars=[var],
                    refs=[parsed],
                )
                typer.echo(value)
                return

            auth_reason = _require_secret_access_auth(
                f"Access secret {var} with envrcctl"
            )
            value = _get_secret_value(backend, parsed, auth_reason)
            _record_secret_access_event(
                action="secret_get",
                status="success",
                vars=[var],
                refs=[parsed],
            )

            if plain or show:
                typer.echo(value)
                return

            _copy_to_clipboard(value)
            masked = _mask_secret(value)
            typer.echo(f"Copied to clipboard: {var}={masked}")
        except EnvrcctlError as exc:
            status = "cancelled" if "cancelled" in str(exc).lower() else "failure"
            _record_secret_access_event(
                action="secret_get",
                status=status,
                vars=[var],
                refs=[parsed],
                error=_audit_error("secret_get_failed", exc),
            )
            raise

    _run(action)


@app.command()
def inject(
    force: bool = typer.Option(
        False, "--force", help="Allow inject in non-interactive environments."
    ),
) -> None:
    """Emit export statements for all secret references."""

    def action() -> None:
        runtime_refs: list[tuple[str, object]] = []
        try:
            if not _is_interactive() and not force:
                raise EnvrcctlError(
                    "inject is blocked in non-interactive environments. Use --force to override."
                )
            if sys.platform == "darwin" and not _is_interactive():
                raise EnvrcctlError(
                    "inject on macOS requires an interactive shell and device owner authentication."
                )
            auth_reason = _require_secret_access_auth("Inject secrets with envrcctl")
            doc = load_envrc(_envrc_path())
            block = ensure_managed_block(doc)

            for key in sorted(block.secret_refs.keys()):
                ref = parse_ref(block.secret_refs[key])
                if ref.kind != "runtime":
                    continue
                runtime_refs.append((key, ref))

            values = _get_secret_values(
                [ref for _, ref in runtime_refs],
                auth_reason,
            )
            _record_secret_access_event(
                action="inject",
                status="success",
                vars=[key for key, _ in runtime_refs],
                refs=[ref for _, ref in runtime_refs],
            )
            for key, ref in runtime_refs:
                value = values[(ref.service, ref.account)]
                typer.echo(f"export {key}={shlex.quote(value)}")
        except EnvrcctlError as exc:
            status = "cancelled" if "cancelled" in str(exc).lower() else "failure"
            _record_secret_access_event(
                action="inject",
                status=status,
                vars=[key for key, _ in runtime_refs],
                refs=[ref for _, ref in runtime_refs],
                error=_audit_error("inject_failed", exc),
            )
            raise

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
        runtime_refs: list[tuple[str, object]] = []
        command = list(ctx.args)
        try:
            if not ctx.args:
                raise EnvrcctlError(
                    "No command provided. Use -- to separate the command."
                )
            if not _is_interactive():
                if sys.platform == "darwin":
                    raise EnvrcctlError(
                        "exec on macOS requires an interactive shell and device owner authentication."
                    )
                raise EnvrcctlError("exec is blocked in non-interactive environments.")
            auth_reason = _require_secret_access_auth("Execute command with envrcctl")
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
                runtime_refs.append((name, ref))

            values = _get_secret_values(
                [ref for _, ref in runtime_refs],
                auth_reason,
            )
            for name, ref in runtime_refs:
                env[name] = values[(ref.service, ref.account)]

            result = subprocess.run(command, env=env)
            status = "success" if result.returncode == 0 else "failure"
            _record_secret_access_event(
                action="exec",
                status=status,
                vars=[name for name, _ in runtime_refs],
                refs=[ref for _, ref in runtime_refs],
                command=command,
            )
            if result.returncode != 0:
                raise typer.Exit(code=result.returncode)
        except EnvrcctlError as exc:
            status = "cancelled" if "cancelled" in str(exc).lower() else "failure"
            _record_secret_access_event(
                action="exec",
                status=status,
                vars=[name for name, _ in runtime_refs],
                refs=[ref for _, ref in runtime_refs],
                command=command or None,
                error=_audit_error("exec_failed", exc),
            )
            raise

    _run(action)


@audit_app.command("list")
def audit_list(
    limit: int = typer.Option(20, "--limit", min=1, help="Maximum events to show."),
    action: str | None = typer.Option(None, "--action", help="Filter by audit action."),
    var: str | None = typer.Option(None, "--var", help="Filter by variable name."),
    status: str | None = typer.Option(None, "--status", help="Filter by audit status."),
    json_output: bool = typer.Option(
        False, "--json", help="Emit matching events as JSON."
    ),
) -> None:
    """List recent audit events."""

    def action_fn() -> None:
        events = list(iter_events())
        if action is not None:
            events = [event for event in events if event.action == action]
        if var is not None:
            events = [event for event in events if var in event.vars]
        if status is not None:
            events = [event for event in events if event.status == status]

        events = list(reversed(events))[:limit]

        if json_output:
            import json

            typer.echo(
                json.dumps(
                    [
                        {
                            "event_id": event.event_id,
                            "timestamp": event.timestamp,
                            "action": event.action,
                            "status": event.status,
                            "vars": event.vars,
                            "refs": [
                                {
                                    "scheme": ref.scheme,
                                    "service": ref.service,
                                    "account": ref.account,
                                    "kind": ref.kind,
                                }
                                for ref in event.refs
                            ],
                            "cwd": event.cwd,
                            "platform": event.platform,
                            "command": event.command,
                            "error": (
                                {
                                    "code": event.error.code,
                                    "message": event.error.message,
                                }
                                if event.error is not None
                                else None
                            ),
                            "prev_hash": event.prev_hash,
                            "hash": event.hash,
                        }
                        for event in events
                    ],
                    indent=2,
                    sort_keys=True,
                )
            )
            return

        for event in events:
            vars_display = ",".join(event.vars) if event.vars else "-"
            command_display = _format_audit_command(event.command)
            typer.echo(
                f"{event.timestamp}  {event.action:<10}  {event.status:<9}  "
                f"{vars_display:<20}  {command_display}"
            )

    _run(action_fn)


@audit_app.command("show")
def audit_show(
    event_id: str | None = typer.Option(
        None, "--event-id", help="Show a specific audit event by id."
    ),
    index: int | None = typer.Option(
        None, "--index", min=0, help="Show an event by zero-based index."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit the selected event as JSON."
    ),
) -> None:
    """Show one audit event in detail."""

    def action_fn() -> None:
        events = list(iter_events())
        if event_id is not None and index is not None:
            raise EnvrcctlError("Use either --event-id or --index, not both.")
        if event_id is None and index is None:
            raise EnvrcctlError("Either --event-id or --index is required.")

        selected = None
        if event_id is not None:
            for event in events:
                if event.event_id == event_id:
                    selected = event
                    break
            if selected is None:
                raise EnvrcctlError(f"Audit event not found: {event_id}")
        else:
            if index is None or index >= len(events):
                raise EnvrcctlError("Audit event index is out of range.")
            selected = events[index]

        if json_output:
            import json

            typer.echo(
                json.dumps(
                    {
                        "event_id": selected.event_id,
                        "timestamp": selected.timestamp,
                        "action": selected.action,
                        "status": selected.status,
                        "vars": selected.vars,
                        "refs": [
                            {
                                "scheme": ref.scheme,
                                "service": ref.service,
                                "account": ref.account,
                                "kind": ref.kind,
                            }
                            for ref in selected.refs
                        ],
                        "cwd": selected.cwd,
                        "platform": selected.platform,
                        "command": selected.command,
                        "error": (
                            {
                                "code": selected.error.code,
                                "message": selected.error.message,
                            }
                            if selected.error is not None
                            else None
                        ),
                        "prev_hash": selected.prev_hash,
                        "hash": selected.hash,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return

        typer.echo(f"event_id: {selected.event_id}")
        typer.echo(f"timestamp: {selected.timestamp}")
        typer.echo(f"action: {selected.action}")
        typer.echo(f"status: {selected.status}")
        typer.echo(f"cwd: {selected.cwd}")
        typer.echo(f"platform: {selected.platform}")
        typer.echo(f"command: {_format_audit_command(selected.command)}")
        typer.echo("vars:")
        for item in selected.vars:
            typer.echo(f"  - {item}")
        typer.echo("refs:")
        for ref in selected.refs:
            typer.echo(f"  - {ref.scheme}:{ref.service}:{ref.account}:{ref.kind}")
        if selected.error is not None:
            typer.echo("error:")
            typer.echo(f"  code: {selected.error.code}")
            typer.echo(f"  message: {selected.error.message}")
        typer.echo(f"prev_hash: {selected.prev_hash or '-'}")
        typer.echo(f"hash: {selected.hash}")

    _run(action_fn)


@audit_app.command("verify")
def audit_verify() -> None:
    """Verify audit chain integrity."""

    def action_fn() -> None:
        result = verify_chain()
        if not result.ok:
            typer.echo("FAIL")
            if result.failure_line is not None:
                typer.echo(f"line: {result.failure_line}")
            if result.failure_event_id is not None:
                typer.echo(f"event_id: {result.failure_event_id}")
            if result.failure_reason is not None:
                typer.echo(f"reason: {result.failure_reason}")
            raise EnvrcctlError("Audit verification failed.")

        typer.echo("OK")
        typer.echo(f"events: {result.event_count}")
        typer.echo(f"latest_hash: {result.latest_hash or '-'}")

    _run(action_fn)


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
                "WARN: inject line missing in managed block. direnv auto-injection is not enabled. Run `envrcctl init --inject` to add it.",
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

        audit_result = verify_chain()
        if not audit_result.ok:
            typer.echo(
                "WARN: audit chain verification failed."
                + (
                    f" line={audit_result.failure_line}"
                    if audit_result.failure_line is not None
                    else ""
                )
                + (
                    f" event_id={audit_result.failure_event_id}"
                    if audit_result.failure_event_id is not None
                    else ""
                )
                + (
                    f" reason={audit_result.failure_reason}"
                    if audit_result.failure_reason is not None
                    else ""
                ),
                err=True,
            )
            warnings += 1
        else:
            try:
                ensure_audit_store_secure()
            except EnvrcctlError as exc:
                typer.echo(f"WARN: audit store is not secure: {exc}", err=True)
                warnings += 1

        if warnings == 0:
            typer.echo("OK")

    _run(action)


@app.command()
def migrate(
    yes: bool = typer.Option(
        False, "--yes", help="Confirm migrating unmanaged exports."
    ),
    inject: bool = typer.Option(
        False, "--inject", help="Add inject line to managed block."
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
        if inject:
            block.include_inject = True
        _write_envrc(doc, block)

    _run(action)
