# envrcctl

envrcctl is a macOS-first (Linux-ready) CLI tool for secure, structured
management of `.envrc` files used with direnv.

Inspired by:
https://zenn.dev/yottayoshida/articles/llm-key-ring-secure-api-key-management

## Goals

- Securely manage secrets (stored in OS key store)
- Manage non-secret environment variables
- Support parent directory inheritance (`source_up`)
- Provide CRUD operations
- Keep `.envrc` safe via managed block editing only
- Allow future Linux support via pluggable secret backends

## Architecture

### Core (OS-independent)

Responsible for:

- Managed block detection and regeneration
- Non-secret CRUD
- Secret reference management
- Inheritance toggling (source_up on/off)
- Atomic `.envrc` writes
- `inject` command (produces export statements)
- `eval` command (effective merged view)
- CLI interface

### Secret Backend Interface

Abstract interface:

    class SecretBackend:
        def get(ref) -> str
        def set(ref, value)
        def delete(ref)
        def list(prefix=None)

Initial implementation:

- macOS: KeychainBackend using `/usr/bin/security` CLI

Future Linux:

- SecretServiceBackend (secret-tool / libsecret)
- Possibly pass or keyring-based backend

## Managed Block Format

`.envrc` will contain a managed section:

    # >>> envrcctl:begin
    # managed: true

    source_up  # optional (inherit on)

    export BREWFILE="$PWD/Brewfile"

    export ENVRCCTL_SECRET_OPENAI_API_KEY="kc:com.rio.envrcctl:openai:prod"

    eval "$(envrcctl inject)"

    # <<< envrcctl:end

Rules:

- Tool only edits content between begin/end
- Everything else is preserved
- Block is fully regenerated on each mutation

## Secret Storage Model

Ref format:

    kc:<service>:<account>

Example:

    kc:com.rio.envrcctl:openai:prod

Keychain mapping:

- service = com.rio.envrcctl
- account = openai:prod
- value = actual secret

Secrets are never written to `.envrc`.

## CLI Command Design

### init

- Create `.envrc` if missing
- Insert managed block
- Optional: suggest `direnv allow`

### inherit

    envrcctl inherit on
    envrcctl inherit off

Adds/removes `source_up` in managed block.

### Non-Secret CRUD

    envrcctl set VAR value
    envrcctl unset VAR
    envrcctl list
    envrcctl get VAR

Stored as plain export lines in managed block.

### Secret CRUD

    envrcctl secret set OPENAI_API_KEY --account openai:prod
    envrcctl secret unset OPENAI_API_KEY
    envrcctl secret list
    envrcctl secret rotate OPENAI_API_KEY

Secret input modes:

- `--prompt` (default; uses getpass)
- `--stdin` (CI safe)

### inject

Prints export statements for all secret refs:

    export OPENAI_API_KEY='...'
    export GITHUB_TOKEN='...'

Used via:

    eval "$(envrcctl inject)"

### eval

Shows effective environment including inheritance.

Secrets masked by default:

    OPENAI_API_KEY = ****** (from parent, secret)
    GITHUB_TOKEN   = ****** (from current dir, secret)

## Security Principles

- No secrets in CLI arguments
- No secrets written to `.envrc`
- Atomic writes for file updates
- TTY check for any --plain secret output
- Optional warning if `.envrc` is world-writable
- Managed block isolation

## Implementation Phases

### Phase 1 (MVP)

- init
- set/unset/list (non-secret)
- secret set/unset/list
- inject
- inherit on/off
- macOS Keychain backend

### Phase 2

- eval command
- doctor (security diagnostics)
- migrate existing `.envrc`
- shell completion

### Phase 3

- Linux SecretService backend
- Pluggable backend detection
- Ref schema extension

## Packaging Strategy

- Python 3.10+
- CLI via Typer or Click
- Installable via pipx
- Single-package distribution

## Future Expansion

- Policy enforcement mode (no unmanaged exports allowed)
- CI-safe mode
- Team-managed secret namespaces
- Ref validation and rotation workflows

## Development

This project is managed with `uv`.

## License

See `LICENSE`.