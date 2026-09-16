# Release Checklist — envrcctl

## Pre-release
- [ ] Update version in `pyproject.toml` and any release notes.
- [ ] Ensure dependencies are up to date (`uv.lock` refreshed if needed).
- [ ] Confirm module/package naming is consistent (`envrcctl`, `src/envrcctl`).
- [ ] Confirm README examples are accurate.

## Security Review
- [ ] Review `docs/threat_model.md` for accuracy.
- [ ] Review `docs/security_command_inventory.md` for accuracy.
- [ ] Run `envrcctl doctor` on a representative repo to confirm warnings are helpful.
- [ ] Verify that no secrets are written to `.envrc`.
- [ ] Ensure secret ref validation rules are unchanged or documented.

## Verification
- [ ] Run `./.zed/scripts/verify` on this branch.
- [ ] Run `./.zed/scripts/verify-release` for coverage and security linting.
- [ ] Run `uv run python -m envrcctl.main --help` (or `envrcctl --help`) to verify entry point.
- [ ] Confirm no new warnings in tests related to secret handling.

## Packaging
- [ ] Finish all source, manifest, lockfile and completion edits before the final build.
- [ ] Use the ordered release pipeline below; do not run independent build targets concurrently.
- [ ] Build sdist/wheel with `hatchling` via `uv build`.
- [ ] Verify artifacts include `src/envrcctl/**` and the `envrcctl.main:main` entry point.
- [ ] Verify neither Python archive includes the native helper or any of its backups.
- [ ] Install from the built artifact and run a smoke test:
  - `envrcctl init`
  - `envrcctl set FOO bar`
  - `envrcctl secret set TOKEN --account test --stdin`

## Documentation
- [ ] Update `docs/impl_tickets.json` status for completed work.
- [ ] Review `README.md` and `README.jp.md` for any required changes.
- [ ] Regenerate shell completions with `uv run python scripts/generate_completions.py` when CLI changes.

## Release Steps
- [ ] Tag the release in git (annotated tag).
- [ ] Publish artifacts to the chosen distribution channel.
- [ ] Verify Homebrew formula (if applicable) references correct URL/SHA256.

## Safe build and formula workflow

Prerequisites: Python 3.14+, `uv`, the committed `uv.lock`, and, for a full/helper
build, Apple Silicon macOS 26+ with Xcode Command Line Tools (`xcrun`, `swiftc`,
`vtool`, `lipo`). The helper must have an **arm64, macOS 26.0** deployment target;
the generator checks the actual Mach-O metadata and runs only its harmless
`--help` smoke test. The formula declares `depends_on macos: :tahoe` for its
Apple Silicon macOS helper. It does not impose that helper requirement on Linux.

```sh
uv sync --locked --extra test --group dev
make PYTHON=.venv/bin/python
# Equivalent: .venv/bin/python scripts/release_artifacts.py
```

The default (also selectable explicitly with `--build`) always rebuilds, even
when files for the same version already exist.
One Python process owns sync → completions → Python build/validation → helper
build/metadata check → optional signing/notarization → helper archive/validation
→ provenance → formula. `make -j` and inherited parallel `MAKEFLAGS` cannot
reorder those stages. No target launches an automatic competing build.

Staging directories are created **inside `dist/`**, not the system temporary
directory. Existing artifacts are not deleted before building. Failed copy,
chmod, tar or archive validation stops the pipeline; cleanup preserves the
failing command's status. Only validated files replace their final names.
The tracked `src/envrcctl/envrcctl-macos-auth` and any existing backups are never
renamed, rebuilt in place, or removed by these targets. Both Python packaging
targets explicitly exclude the helper and all similarly named backups.

`make dist` only rebuilds Python artifacts; `make helper` / `make helper-archive`
only rebuild and package the helper. These partial builds invalidate release
provenance and cannot be followed by formula-only generation without a full build.
They are useful checks, not substitutes for the final pipeline.

To regenerate **only** the formula without rebuilding:

```sh
make formula PYTHON=.venv/bin/python
# Equivalent: .venv/bin/python scripts/release_artifacts.py --formula-only
```

This fails closed unless `dist/release-provenance.json` matches the current
version, source/scripts/tests/completions, build configuration, README/license,
`uv.lock`, and all three artifact SHA256 hashes. Missing provenance, changed
inputs, missing artifacts, or changed artifacts require a fresh build. The
record is an accidental-staleness check, not a cryptographic attestation against
someone able to rewrite both artifacts and provenance. Never edit hashes to
bypass validation.

The generated `src/envrcctl/envrcctl-macos-auth*` files (including `.bak` and other
backups) are excluded from input fingerprints, consistently with wheel/sdist
packaging. After the final signed build, the release operator may update the
tracked helper from the **validated signed release archive** so source checkouts
use the new native protocol. That update does not invalidate provenance. Do not
recompile the checkout helper independently: use the exact archived signed bytes,
verify its Developer ID signature and harmless `--help`, then run `--formula-only`
to recheck provenance. The Swift source and build script remain fingerprinted.

### Signed and notarized release build

The [0.3.2 validation record](releases/0.3.2-validation.md) documents a
Developer ID signed and Apple-notarized helper, built with the macOS 27 SDK and
minimum macOS 26. Preserve those distribution guarantees.

Before invoking these commands, an authorized release operator must have a
valid **Developer ID Application** identity and its private key in their
Keychain, plus an existing `notarytool` Keychain credential profile. Discover
available signing identities with `security find-identity -v -p codesigning`;
check the chosen profile using `xcrun notarytool history --keychain-profile
"PROFILE"`. Do not store credentials in the repository or command arguments.

```sh
MACOSX_DEPLOYMENT_TARGET=26.0 .venv/bin/python scripts/release_artifacts.py --build \
  --signing-identity "Developer ID Application: YOUR NAME (TEAMID)" \
  --notary-profile "YOUR_EXISTING_KEYCHAIN_PROFILE"
```

The generator freshly builds a staged helper, signs with hardened runtime and
timestamp, verifies its signature, submits a ZIP via `notarytool --wait`, and
requires JSON status `Accepted` **before** producing the final helper tarball,
hashes, provenance and formula. Record the notarization ID from its output in
release validation notes. A standalone Mach-O helper cannot be stapled; preserve
the accepted notarization result and exact signed bytes. Do not rebuild or
re-sign the helper after final hashes are generated. Running the default without
signing options is for development/validation, not for publishing a signed release.
These commands do not commit, tag, push, upload release assets or publish packages.

### Signed candidate when notarization credentials are unavailable

There is no configured/default notarytool profile in this repository. Do not
guess profile labels, inspect secret tokens, or publish an unnotarized helper.
A private signed candidate can be built with `--build --signing-identity` and
**without** `--notary-profile`. The provenance file records input/artifact hashes;
it is **not** a signing certificate or a notarization receipt. Keep the successful
signature-verification log separately, and do not treat it as Apple approval.

Once an authorized operator supplies an existing Keychain profile, notarize the
already-signed helper without rebuilding, re-signing, or replacing any artifact:

```sh
(
  set -eu
  : "${NOTARY_PROFILE:?Supply an existing authorized notarytool Keychain profile}"
  .venv/bin/python scripts/release_artifacts.py --formula-only
  VERSION=$(.venv/bin/python -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
  mkdir .notary-stage
  trap 'status=$?; trap - 0; rm -rf .notary-stage || :; exit "$status"' 0
  tar -xzf "dist/envrcctl-macos-auth-$VERSION-arm64.tar.gz" -C .notary-stage
  codesign --verify --strict --verbose=2 .notary-stage/envrcctl-macos-auth
  codesign --display --verbose=4 .notary-stage/envrcctl-macos-auth \
    2> "dist/helper-signature-$VERSION.txt"
  ditto -c -k --keepParent .notary-stage/envrcctl-macos-auth .notary-stage/helper.zip
  xcrun notarytool submit .notary-stage/helper.zip \
    --keychain-profile "$NOTARY_PROFILE" --wait --output-format json \
    > "dist/helper-notarization-$VERSION.json"
  .venv/bin/python -c 'import json, sys; result = json.load(open(sys.argv[1])); sys.exit("Notarization not accepted") if result.get("status") != "Accepted" else print(result["id"])' \
    "dist/helper-notarization-$VERSION.json"
  .venv/bin/python scripts/release_artifacts.py --formula-only
)
```

The first provenance check validates the exact archive members before extraction.
Notarization applies to the embedded signed helper bytes; the ZIP is only a
submission container. The original tarball, wheel, sdist, formula hashes and
provenance remain unchanged. Preserve the separate signature metadata,
notarization JSON with status `Accepted`, and release artifact checksums together
in release validation records. No valid profile means the candidate remains
private and publication stays blocked. Do not rerun `--build` merely to notarize
an existing candidate.

### Isolated release/completion tests

Verification scripts support stock macOS `/bin/bash` 3.2, including NUL-delimited
Git paths containing spaces. For Python changes, `verify` uses the project's
`.venv/bin/python`, or `uv run --no-sync python` when the project executable is
absent. Both pytest and Bandit must be available in that interpreter; missing
prerequisites fail with an actionable `uv sync --locked --extra test --group dev`
message instead of silently skipping checks. `verify` does not install
dependencies automatically.

Completion generation uses Typer's own completion
API and protocol; tests connect the scripts to the real CLI and exercise command,
option and path completion in real Bash/Zsh/Fish shells when installed.
Fish's command/option response and native-path-fallback protocol are also tested
against the real CLI without requiring Fish to be installed.

Keep test state and temporary files under a disposable project-local work
directory, with isolated HOME/XDG paths:

```sh
mkdir -p .release-test-work/home .release-test-work/config \
  .release-test-work/data .release-test-work/state .release-test-work/cache \
  .release-test-work/runtime .release-test-work/scratch
HOME="$PWD/.release-test-work/home" \
XDG_CONFIG_HOME="$PWD/.release-test-work/config" \
XDG_DATA_HOME="$PWD/.release-test-work/data" \
XDG_STATE_HOME="$PWD/.release-test-work/state" \
XDG_CACHE_HOME="$PWD/.release-test-work/cache" \
XDG_RUNTIME_DIR="$PWD/.release-test-work/runtime" \
TMPDIR="$PWD/.release-test-work/scratch" \
  .venv/bin/python -m pytest tests/test_release_artifacts.py tests/test_completions.py \
    --basetemp="$PWD/.release-test-work/pytest" -q
```

The tests build only copied fixture projects and never touch real release
artifacts, the tracked helper, user shell configuration or OS secret stores.
The archive integration test requires `uv` and a cached or downloadable Hatchling
build backend. Remove only the disposable `.release-test-work` directory after
validation; never delete the real `dist/` as a test cleanup step.

## Post-release
- [ ] Monitor issue tracker for regressions.
- [ ] Archive release notes and test logs.