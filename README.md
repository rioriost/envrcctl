# envrcctl

envrcctl is a CLI tool that manages `.envrc` files safely through a managed
block, with secrets stored in your OS key store instead of the file.

It is designed for macOS first, with Linux support via SecretService.

## Features

- Safe, structured edits to `.envrc` (managed block only)
- Non-secret environment variables (CRUD)
- Secrets stored in Keychain (macOS) or SecretService (Linux)
- Inheritance control (`source_up` on/off)
- Exec-based secret injection (`envrcctl exec -- ...`, TTY-guarded on Linux, TTY + macOS auth on macOS)
- Secret injection for direnv (`eval "$(envrcctl inject)"`, TTY-guarded on Linux, TTY + macOS auth on macOS)
- Secret kinds (runtime/admin), with exec injecting runtime only
- Secret get with clipboard default and TTY guard on Linux, plus macOS auth on macOS
- On macOS, `inject` and `exec` retrieve multiple runtime secrets with a single device owner authentication prompt
- Tamper-evident local audit log for secret access events
- Diagnostics and migration helpers
- Shell completion scripts

## Requirements

- Python 3.14+
- `direnv`
- macOS Keychain (built-in) or Linux SecretService (`secret-tool`)
- device owner authentication (TouchID or Apple Watch)

## Installation

### macOS (Homebrew, Apple Silicon)

Tap and install:

```sh
brew tap rioriost/tap
brew install envrcctl
```

This Homebrew path is intended for:

- Apple Silicon (`arm64`) Macs
- macOS installs that should not require a full Xcode.app build dependency

Intel Macs are not a target for this Homebrew distribution path.

Install direnv with Homebrew:

```sh
brew install direnv
```

### Linux (pipx, recommended)

```sh
pipx install envrcctl
```

### Linux (uv)

```sh
uv tool install envrcctl
```

### About the macOS auth helper (Apple Silicon macOS only)

The macOS device owner authentication flow requires a native helper named
`envrcctl-macos-auth`.

Homebrew on Apple Silicon is intended to install this helper automatically, so
you should not need to build it yourself in the common case.

Manual helper installation is still useful when:

- you want to place the helper in a custom location
- you are not using the Apple Silicon Homebrew distribution path

If you are building the helper yourself, use Apple Silicon (`arm64`) macOS and place the binary at either:

- `src/envrcctl/envrcctl-macos-auth`
- or a custom path set via `ENVRCCTL_MACOS_AUTH_HELPER`

Example build flow on Apple Silicon macOS:

```sh
swiftc -O -framework LocalAuthentication -framework Security \
  scripts/macos/envrcctl-macos-auth.swift \
  -o src/envrcctl/envrcctl-macos-auth
chmod +x src/envrcctl/envrcctl-macos-auth
```

If you install the helper elsewhere, set:

```sh
export ENVRCCTL_MACOS_AUTH_HELPER=/path/to/envrcctl-macos-auth
```

## Quick Start

1. Initialize a managed block in `.envrc`:

```sh
envrcctl init
```

If `.envrc` already exists, you'll be prompted to confirm. Use `--yes` to skip the prompt in non-interactive runs. Add `--inject` to explicitly insert the inject line.

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

5. Add the inject line explicitly:

```sh
envrcctl init --inject
```

This inserts `eval "$(envrcctl inject)"` into the managed block.

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

`envrcctl secret get` behavior is platform-specific:

- On Linux, the current TTY-based behavior remains in place.
- On macOS, `secret get` requires the existing interactive-shell check and successful macOS device owner authentication before revealing or copying the secret.

In practice, macOS authentication may use Touch ID and, when supported by your system configuration, Apple Watch approval or password fallback.

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

`envrcctl exec` behavior is platform-specific:

- On Linux, the current behavior remains in place.
- On macOS, `exec` requires the existing interactive-shell check and successful macOS device owner authentication before runtime secrets are injected into the child process.
- When multiple runtime secrets are selected, macOS performs a single authentication step and then retrieves all requested secrets in one helper call.

In practice, macOS authentication may use Touch ID and, when supported by your system configuration, Apple Watch approval or password fallback.

### Inject secrets for direnv

```sh
envrcctl inject
```

Linux keeps the current behavior: non-interactive runs are blocked unless `--force` is provided.

On macOS, `envrcctl inject` requires both:
- the existing interactive-shell check
- successful macOS device owner authentication

When multiple runtime secrets are present, `inject` performs one authentication step and retrieves all eligible secrets in a single bulk helper request.

That authentication is expected to be satisfied through macOS mechanisms such as Touch ID and, when your system offers it, Apple Watch approval or password fallback.

If the native helper is missing or not executable, `inject` fails closed with an
authentication-helper error. Build or install `envrcctl-macos-auth` before using
macOS-authenticated secret commands.

### Effective view (masked)

```sh
envrcctl eval
```

### Audit log

```sh
envrcctl audit list
envrcctl audit show --index 0
envrcctl audit verify
```

`envrcctl` records tamper-evident local audit events for:

- `secret get`
- `inject`
- `exec`

The audit log:

- never stores plaintext secret values
- stores variable names, secret ref metadata, working directory, and `exec` command metadata
- chains events with `prev_hash` and `hash` so silent modification or deletion is detectable

Default audit log storage locations:

- macOS: `~/Library/Application Support/envrcctl/audit/`
- Linux: `$XDG_STATE_HOME/envrcctl/audit/` when `XDG_STATE_HOME` is set
- Linux fallback: `~/.local/state/envrcctl/audit/`

The audit store currently uses:

- `audit.jsonl` for append-only event records
- `latest_hash` for the latest chain hash
- `meta.json` for metadata

`envrcctl audit verify` checks the hash chain and reports failures if audit records appear to have been modified.

### Diagnostics

```sh
envrcctl doctor
```

`doctor` also checks audit health and warns when:

- the audit chain does not verify
- the audit store permissions are insecure

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
- On Linux, `inject` is blocked in non-interactive environments unless `--force` is provided
- On macOS, `inject` requires both the interactive-shell check and successful device owner authentication
- On Linux, `secret get` is clipboard-only by default and plaintext output is TTY-guarded
- On macOS, `secret get` requires both the interactive-shell check and successful device owner authentication
- On Linux, `exec` keeps the current behavior
- On macOS, `exec` requires both the interactive-shell check and successful device owner authentication before runtime secrets are injected into the child process
- On macOS, authentication is mediated by the OS and may use Touch ID, Apple Watch approval, or password fallback depending on system support and configuration
- On macOS, authenticated commands require the native helper `envrcctl-macos-auth`
- The helper is discovered from `ENVRCCTL_MACOS_AUTH_HELPER` or `src/envrcctl/envrcctl-macos-auth`
- If the helper is missing, invalid, or not executable, macOS secret-accessing commands fail closed
- Secret-access actions are recorded in a local tamper-evident audit log
- Audit records never include plaintext secret values
- Audit integrity is based on a hash chain and can be checked with `envrcctl audit verify`
- The tool refuses to write to world-writable `.envrc`



## Acknowledgements

Based on the article below, I added commands such as `exec`. Thank you for the helpful hints.  
“[もう.envにAPIキーを平文で置くのはやめた — macOS Keychain管理CLI「LLM Key Ring」](https://zenn.dev/yottayoshida/articles/llm-key-ring-secure-api-key-management)”

## License

MIT
