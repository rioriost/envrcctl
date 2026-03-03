# envrcctl

envrcctl is a CLI tool that manages `.envrc` files safely through a managed
block, with secrets stored in your OS key store instead of the file.

It is designed for macOS first, with Linux support via SecretService.

## Features

- Safe, structured edits to `.envrc` (managed block only)
- Non-secret environment variables (CRUD)
- Secrets stored in Keychain (macOS) or SecretService (Linux)
- Inheritance control (`source_up` on/off)
- Exec-based secret injection (`envrcctl exec -- ...`)
- Secret injection for direnv (`eval "$(envrcctl inject)"`, TTY-guarded)
- Secret kinds (runtime/admin), with exec injecting runtime only
- Secret get with clipboard default and TTY guard
- Diagnostics and migration helpers
- Shell completion scripts

## Requirements

- Python 3.14+
- `direnv` (for `.envrc` usage)
- macOS Keychain (built-in) or Linux SecretService (`secret-tool`)

## Installation

### macOS (Homebrew)

A Homebrew formula template exists at `Formula/envrcctl.rb`. Replace the URL/SHA256 with a release tarball, then install:

```sh
brew install --formula ./Formula/envrcctl.rb
```

### Linux (pipx, recommended)

```sh
pipx install envrcctl
```

### Linux (uv)

```sh
uv tool install envrcctl
```

### From source (macOS/Linux)

```sh
git clone <REPO_URL>
cd envrcctl
uv sync
uv run python -m envrctl.main --help
```

## Quick Start

1. Initialize a managed block in `.envrc`:

```sh
envrcctl init
```

If `.envrc` already exists, you'll be prompted to confirm. Use `--yes` to skip the prompt in non-interactive runs.

2. Add non-secret variables:

```sh
envrcctl set FOO bar
envrcctl get FOO
envrcctl list
```

3. Enable inheritance:

```sh
envrcctl inherit on
```

4. Store a secret:

```sh
envrcctl secret set OPENAI_API_KEY --account openai:prod
```

5. Ensure your `.envrc` includes:

```sh
eval "$(envrcctl inject)"
```

6. Allow direnv:

```sh
direnv allow
```

## Commands

### Non-secret variables

```sh
envrcctl set VAR value
envrcctl unset VAR
envrcctl get VAR
envrcctl list
```

### Secrets

```sh
envrcctl secret set OPENAI_API_KEY --account openai:prod --kind runtime
envrcctl secret set OPENAI_API_KEY --account openai:admin --kind admin
envrcctl secret unset OPENAI_API_KEY
envrcctl secret list
envrcctl secret get OPENAI_API_KEY
envrcctl secret get OPENAI_API_KEY --plain
```

For CI-safe input:

```sh
echo -n "$OPENAI_API_KEY" | envrcctl secret set OPENAI_API_KEY --account openai:prod --stdin
```

### Exec secrets without stdout

```sh
envrcctl exec -- python script.py
envrcctl exec -k OPENAI_API_KEY -- python script.py
```

Exec injects runtime secrets only.

### Inject secrets for direnv

```sh
envrcctl inject
```

Non-interactive runs are blocked unless `--force` is provided.

### Effective view (masked)

```sh
envrcctl eval
```

### Diagnostics

```sh
envrcctl doctor
```

### Migration

```sh
envrcctl migrate
```

You'll be prompted when unmanaged exports or secret refs are detected. Use `--yes` to confirm in non-interactive runs.

## Backend Selection (macOS/Linux)

envrcctl selects a backend automatically by platform, or via `ENVRCCTL_BACKEND`.

Supported schemes:

- `kc` — macOS Keychain
- `ss` — SecretService via `secret-tool`

Example:

```sh
ENVRCCTL_BACKEND=ss envrcctl secret set OPENAI_API_KEY --account openai:prod
```

Secret references are stored as:

```
<scheme>:<service>:<account>:<kind>
```

`kind` is `runtime` or `admin` (default: `runtime`).

Example:

```
kc:st.rio.envrcctl:openai:prod:runtime
kc:st.rio.envrcctl:openai:admin:admin
```

## Shell Completion

```sh
envrcctl --install-completion
envrcctl --show-completion bash
envrcctl --show-completion zsh
envrcctl --show-completion fish
```

Generated scripts are stored under `completions/`. To refresh:

```sh
uv run python scripts/generate_completions.py
```

## Security Notes

- Secrets are never written to `.envrc`
- Secrets are never passed in CLI arguments
- `.envrc` updates are atomic
- `inject` is blocked in non-interactive environments unless `--force` is provided
- `secret get` is clipboard-only by default; plaintext output is TTY-guarded
- The tool refuses to write to world-writable `.envrc`

## Development

```sh
uv sync
.venv/bin/envrcctl --help
```

## License

See `LICENSE`.