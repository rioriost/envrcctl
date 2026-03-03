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
- [ ] Build sdist/wheel with `hatchling` (or release toolchain).
- [ ] Verify artifacts include `src/envrcctl/**` and the `envrcctl.main:main` entry point.
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

## Post-release
- [ ] Monitor issue tracker for regressions.
- [ ] Archive release notes and test logs.