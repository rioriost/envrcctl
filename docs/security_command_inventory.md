# External Command Inventory — envrcctl 0.4.0

## Native Keychain helper

Python resolves the configured helper to an absolute path before checking and
executing it. The helper uses the Security framework and LocalAuthentication.

- Authenticated reads carry service/account metadata and an authentication reason.
  A batch shares one `LAContext` and emits no partial results.
- Writes carry the value through stdin, never command arguments, and use native
  create/update operations. They do not change the read-authentication policy.
- Structured transport preserves UTF-8 values and distinguishes data from framing.
- Foreign backend schemes and invalid protocol responses are rejected.
- Process-launch failures and helper failures become sanitized domain errors.
  Secret-bearing output and lower-level exception chains are not retained.

Keychain deletion uses `/usr/bin/security delete-generic-password` with only
service/account metadata. It is invoked only for explicit `secret unset --delete`.

## SecretService (Linux only)

The `secret-tool` operations use service/account metadata:

- `lookup`: captured output is decoded without trimming secret whitespace.
- `store`: stdin carries the exact value through EOF, with no added newline.
- `clear`: deletes an item after explicit destructive confirmation.

The backend is not supported on macOS, where all secret reads require device
owner authentication. Selecting it fails rather than using inherited no-op
protocol methods or bypassing authentication.

## Clipboard

`pbcopy`, `xclip`, or `xsel` receives the retrieved value through stdin. The
program is selected from known platform tools. Command arguments contain no value.

## User-requested child process

`envrcctl exec -- ...` launches the explicit argv without `shell=True`.
Managed exports and selected runtime secrets are supplied in the child environment.
The CLI does not print the injected values. A durable correlated audit start
precedes process creation; launch failures, interruption and completion are recorded.

New audit metadata stores the executable name, not argv or raw external errors.
Users should still avoid passing secrets in their own command arguments, since
the child process and operating system can expose those independently of logging.

## Build and release tools

Release orchestration runs dependency/build tools, the Swift compiler, signing
tools, archive creation and formula generation. Signing/notarization credentials
must come from the operator's configured credential store, never source files or
release assets. A release consumes completed artifacts whose provenance and
checksums have been verified.
