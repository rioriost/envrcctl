# envrcctl Implementation Plan

This plan expands `docs/draft.md` into concrete, phased execution steps. Each phase is designed to deliver a coherent set of user-facing capabilities with minimal risk, clear interfaces, and testable outcomes.

---

## Phase 1 — MVP (macOS)

**Goal:** Provide a safe, minimal CLI that manages `.envrc` via a managed block, supports non-secret and secret CRUD, inheritance toggling, and secret injection. Uses macOS Keychain.

### Scope
- CLI skeleton with subcommands: `init`, `set`, `unset`, `list`, `get`, `inherit on/off`, `secret set/unset/list`, `inject`
- Managed block generation and parsing
- Non-secret export CRUD within managed block
- Secret references stored in managed block (no secret values)
- Secret backend interface and Keychain implementation
- Atomic `.envrc` write behavior
- Input handling for secrets (`--prompt` default, `--stdin` optional)

### Deliverables
- Functional CLI for macOS
- Managed block format enforced
- Keychain-backed secret CRUD
- `inject` prints exports for resolved secrets
- Minimal documentation and usage examples

### Implementation Steps
1. **Project layout & CLI entrypoint**
   - Establish Python package structure
   - Choose CLI framework (Typer/Click)
   - Define top-level command and subcommand routing

2. **Managed block module**
   - Define block markers (`# >>> envrcctl:begin` / `# <<< envrcctl:end`)
   - Parse existing `.envrc`
   - Regenerate managed block from internal model
   - Preserve unmanaged content outside block

3. **Model for managed entries**
   - Represent:
     - `inherit` state (`source_up`)
     - non-secret exports
     - secret refs (e.g., `ENVRCCTL_SECRET_<VAR>=<ref>`)
     - `eval "$(envrcctl inject)"` line

4. **Atomic writer**
   - Write to temp file then atomic replace
   - Optional warning if `.envrc` is world-writable

5. **Non-secret CRUD**
   - `set VAR value`
   - `unset VAR`
   - `get VAR`
   - `list`

6. **Secret backend interface**
   - Define `SecretBackend` class with `get/set/delete/list`
   - Implement macOS Keychain backend using `/usr/bin/security`
   - Define ref format: `kc:<service>:<account>`

7. **Secret CRUD**
   - `secret set VAR --account` → set keychain secret + add managed ref
   - `secret unset VAR` → delete keychain secret + remove ref
   - `secret list` → list refs from managed block

8. **Inject**
   - Resolve refs via backend
   - Print `export VAR='value'` for each secret ref
   - Ensure secret value only emitted to stdout

9. **Init / inherit**
   - `init` creates `.envrc` if missing and inserts block
   - `inherit on/off` toggles `source_up` in managed block

### Exit Criteria
- All MVP commands work on macOS
- `.envrc` never contains secret values
- `inject` yields valid export lines
- Managed block updates are safe and deterministic

---

## Phase 2 — Diagnostics & Quality of Life

**Goal:** Provide visibility, safety checks, and migration assistance.

### Scope
- `eval` command for effective environment view (masked secrets)
- `doctor` command for security diagnostics
- `.envrc` migration helper
- Shell completion scripts

### Deliverables
- `eval` prints merged env with source attribution
- `doctor` warns on insecure `.envrc` permissions and unmanaged exports
- Migration command to retrofit managed block
- Completion scripts for supported shells

### Implementation Steps
1. **Eval**
   - Compute effective view (current + parent if `source_up`)
   - Mask secrets by default
   - Show source (current vs parent)

2. **Doctor**
   - Detect world-writable `.envrc`
   - Detect unmanaged exports inside managed block
   - Report missing `eval "$(envrcctl inject)"`

3. **Migrate**
   - Parse existing `.envrc`
   - Move exports into managed block
   - Preserve external content

4. **Shell completion**
   - Generate completions for major shells
   - Document install instructions

### Exit Criteria
- `eval` and `doctor` behave predictably
- Migration reduces manual work safely
- Shell completions shipped

---

## Phase 3 — Linux Support & Extensibility

**Goal:** Enable Linux secret backend and pluggable selection.

### Scope
- SecretService backend implementation
- Backend auto-detection and configuration
- Ref schema extension for multi-backend support

### Deliverables
- Linux-compatible secret backend
- Configurable backend selection
- Expanded ref format if needed

### Implementation Steps
1. **SecretService backend**
   - Implement `get/set/delete/list` via `secret-tool` or libsecret
   - Map to ref schema

2. **Backend selection**
   - Detect OS and available backend
   - Allow explicit override via config or env var

3. **Ref schema extension**
   - Support backend prefix in refs
   - Maintain backward compatibility

### Exit Criteria
- Linux usage parity with macOS
- Pluggable backend support validated

---

## Phase 4 — Test & Coverage Workflow

**Goal:** Align dev dependencies, verify flow, and coverage target.

### Scope
- Move pytest/pytest-cov to dev-only dependencies
- Add work loop-appropriate tests for verify
- Add verify-release coverage script and tasks.json entry
- Enforce 90% coverage improvement loop
- Assess feasibility of 100% coverage

### Deliverables
- Dev-only pytest dependencies
- Stable verify test set
- `.zed/scripts/verify-release` and tasks.json wiring
- Coverage policy documented (>= 90%)
- 100% feasibility assessment and remaining gaps list

### Implementation Steps
1. **Dev deps**
   - Move pytest/pytest-cov into dev-only dependency group
2. **Verify tests**
   - Add a stable test set for the verify loop
3. **Verify-release**
   - Add coverage script and tasks.json entry
4. **Coverage loop**
   - Document policy and enforce >= 90%
5. **100% assessment**
   - Enumerate uncovered lines and feasibility

### Exit Criteria
- `verify` and `verify-release` are documented and stable
- Coverage policy is enforced and tracked
- 100% feasibility assessment is recorded

---

## Phase 5 — Security Hardening

**Goal:** Reduce tool-side security risks and strengthen safe-by-default behavior.

### Scope
- Tighten external command execution boundaries
- Prevent secret leakage via outputs/errors
- Harden `.envrc` filesystem safety checks
- Strengthen backend validation and selection
- Add safety UX for destructive or risky operations
- Add security-focused checks to tooling

### Deliverables
- Sanitized error handling for secret flows
- Strict `.envrc` permission and path validations
- Explicit backend selection failures (no silent fallback)
- Safer defaults for `init`/`migrate` with explicit confirmation
- Security checks documented and automated

### Implementation Steps
1. **Command execution hardening**
   - Centralize external command invocations
   - Validate arguments and reduce dynamic input paths
2. **Secret leakage prevention**
   - Ensure errors/logs never include secret values
   - Confirm only `inject` emits secret material
3. **Filesystem safety**
   - Enforce stricter world-writable `.envrc` handling
   - Validate realpaths to avoid unexpected write targets
4. **Backend validation**
   - Fail fast on missing backends or unsupported schemes
   - Improve ref validation and error messaging
5. **Safe UX**
   - Require explicit confirmation for destructive ops
   - Strengthen `doctor` checks for risky patterns
6. **Security tooling**
   - Add static analysis (e.g., security linting)
   - Add a release checklist for security-sensitive paths

### Exit Criteria
- Security-sensitive paths are guarded by strict checks
- Documented threat model and operational guidance
- Automated checks cover common security regressions

---

## Phase 6 — Exec Mode & TTY Guard

**Goal:** Add a safe-by-default execution path that injects secrets without stdout output, and gate plaintext secret emission in non-interactive environments.

### Scope
- New `exec` command that injects secrets into a child process environment
- TTY guard for `inject` (and any future plaintext secret outputs)
- Safe defaults with explicit override flags for non-interactive use
- Compatibility plan for direnv users (retain `inject` with guard)
- Documentation and tests for new flows and safety checks

### Deliverables
- `envrcctl exec -- <command>` with filtered secret injection
- Non-interactive blocking behavior for `inject` (with `--force` override)
- Clear UX messaging for blocked plaintext output
- Unit and CLI tests for exec + TTY guard behaviors
- Updated docs describing recommended safe workflow

### Implementation Steps
1. **CLI design and routing**
   - Define `exec` command signature (`--` passthrough)
   - Add optional `-k/--key` filtering and `--all` default
2. **Exec runner**
   - Build env map from managed block exports + resolved secret refs
   - Run child process with injected env (no stdout emission of secrets)
   - Preserve exit code and stderr behavior
3. **TTY guard for plaintext output**
   - Block `inject` in non-interactive environments
   - Add `--force` to bypass with explicit acknowledgement
4. **Tests**
   - Unit tests for TTY checks and behavior switching
   - CLI tests for exec env injection and exit codes
5. **Documentation**
   - Recommend `exec` as the safest workflow
   - Explain `inject` restrictions and overrides

### Exit Criteria
- `exec` works end-to-end without plaintext secret output
- `inject` is blocked in non-interactive sessions unless forced
- Tests cover both interactive and non-interactive paths
- Docs clearly explain the new safe default behavior

## Cross-Cutting Considerations

### Project Management
- This project is managed with `uv`.
- Versioning starts at `0.0.1`.

### Security
- Avoid secrets in CLI args
- Ensure prompts use non-echo input
- TTY checks for plain output (if ever added)
- No secret values written to `.envrc`

### Testing Strategy
- Unit tests for managed block parsing/regeneration
- Integration tests for CLI flow
- Mock backend tests
- End-to-end tests for `.envrc` editing

### Documentation
- Update `README`/usage docs per phase
- Provide examples and troubleshooting

---

## Milestone Summary

- **Phase 1:** Core functionality (MVP) on macOS
- **Phase 2:** Diagnostics, eval, migration, completion
- **Phase 3:** Linux backend + extensibility
- **Phase 4:** Test & coverage workflow
- **Phase 5:** Security hardening