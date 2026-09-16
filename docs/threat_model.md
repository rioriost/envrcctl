# Threat Model — envrcctl

## Overview
envrcctl manages `.envrc` files via a managed block and stores secrets in the OS key store.
This document enumerates assets, trust boundaries, threat scenarios, and mitigations.

## Assets
- Secret values stored in OS key stores (Keychain / SecretService)
- Secret references in `.envrc` managed block
- Non-secret environment variables (integrity)
- Local filesystem integrity for `.envrc` and parent directories
- CLI output (must not leak secrets)

## Trust Boundaries
- Local filesystem boundary: `.envrc` and its parent directories
- OS key store boundary: Keychain / SecretService
- External command boundary: native authentication helper, `security` deletion,
  `secret-tool`, clipboard tools, and explicitly requested `exec` children
- User input boundary: CLI arguments, stdin, environment variables

## Entry Points
- `envrcctl` CLI commands (init/set/unset/get/list/secret/migrate/inject/eval/doctor)
- Environment variables (e.g., backend selection)
- `.envrc` file contents (existing unmanaged content)

## Threats and Mitigations

### 1) Secret disclosure via CLI output
**Threat:** secrets printed in non-inject commands.  
**Mitigations:**
- `inject` and explicitly requested `secret get` plaintext modes can emit values.
- Clipboard-default retrieval masks its status output.
- Shell capture requires a controlling terminal; macOS still requires owner authentication.
- Backend errors and exception chains do not retain secret-bearing argv or output.

### 2) Unsafe writes to `.envrc`
**Threat:** overwriting through symlinks or world-writable files.  
**Mitigations:**
- Reject symlinked `.envrc` paths and symlinked parent directories.
- Refuse writes when `.envrc` is world-writable.
- Atomic write strategy to avoid partial writes.
- Exclusive temporary files preserve modes and do not follow fixed-name symlinks.
- Read-modify-write conflicts are detected under a process lock.
- Secret reference transactions restore the original document if the backend fails.

### 3) Unmanaged secrets outside managed block
**Threat:** plaintext secrets in `.envrc`.  
**Mitigations:**
- `doctor` warns on unmanaged secret refs and suspicious export names.
- `migrate` moves only unambiguous literal exports; dynamic shell expressions,
  control flow and conflicting assignments are rejected without modifying the file.

### 4) Command injection / unsafe subprocess usage
**Threat:** external commands invoked with attacker-controlled input.  
**Mitigations:**
- Centralized command runner with argument allowlists.
- Validation on user-provided parts for secret refs and environment variables.
- Keychain writes use stdin to the native Security-framework helper, not password argv.
- Helper paths are made absolute before both validation and execution.
- Shell text is never executed to parse or migrate a managed value.

### 5) Incorrect backend selection or misuse
**Threat:** silent fallback to unsupported backend.  
**Mitigations:**
- Fail-fast backend selection with explicit errors.
- Scheme validation for secret refs.
- Backend identity includes scheme, service and account. macOS SecretService is
  rejected because its authentication policy is unsupported.
- `kind` controls injection, not OS-store identity or independent authorization.
- Reference removal preserves shared items; store deletion is explicit and warns
  that other projects may still use the item.

### 6) Missing, conflicting or sensitive audit records
**Threat:** concurrent access corrupts the chain, a child runs without an access
record, or command arguments accidentally become a second secret store.
**Mitigations:**
- Lock and durable append before publishing the audit tail.
- `exec` records its start before launch and correlates the result with `operation_id`.
- New events omit arguments and raw external diagnostics.
- Verification is read-only; malformed records and inconsistent state fail closed.
- Schema-1 history remains readable and is not rewritten during upgrade.

## Residual Risks
- Local users with filesystem access can modify `.envrc`.
- OS key store availability and access controls are platform-dependent.
- A local hash chain cannot detect an actor rewriting all records and sidecars,
  rolling back the entire store, or deleting it completely.
- Historical audit records may contain raw argv; upgrading does not redact history.
- A started event without a result means completion is unknown.
- `.envrc` and OS stores do not share a transaction manager. Backend operations
  must report failure accurately; failed compensation is reported explicitly.

## Operational Guidance
- Keep `.envrc` permissions restrictive (avoid group/world write).
- Prefer `envrcctl secret set` for sensitive values.
- Run `envrcctl doctor` regularly in new repositories.
- Use `./.zed/scripts/verify` and `./.zed/scripts/verify-release` before release.

## Out of Scope
- Remote attackers with no local access.
- OS key store internal vulnerabilities.