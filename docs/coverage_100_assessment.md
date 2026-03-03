# 100% Coverage Feasibility Assessment

## Snapshot
- Command: `.zed/scripts/verify-release`
- Total coverage: **98.43%** (8 misses)
- Missing lines reported:
  - `src/envrctl/keychain.py`: line 59
  - `src/envrctl/main.py`: line 9
  - `src/envrctl/secrets.py`: lines 72-74, 78-80, 85
  - `src/envrctl/secretservice.py`: line 56

## Gaps and Proposed Coverage

| Area | Missing line(s) | Why missed | Feasible coverage strategy |
| --- | --- | --- | --- |
| Keychain backend list | `keychain.py:59` | `KeychainBackend.list()` not called | Add a unit test that instantiates the backend and asserts `list()` returns `[]`. No external dependencies. |
| SecretService backend list | `secretservice.py:56` | `SecretServiceBackend.list()` not called | Add a unit test that instantiates the backend and asserts `list()` returns `[]`. No external dependencies. |
| Backend selection errors | `secrets.py:72-74, 78-80, 85` | Error branches not exercised | Add tests that monkeypatch `sys.platform` and `_have_cmd` to force: non-macOS for `kc`, missing `secret-tool` for `ss`, and unsupported scheme. Assert the error messages. |
| CLI entrypoint guard | `main.py:9` | `if __name__ == "__main__"` not executed | Use `runpy.run_module("envrctl.main", run_name="__main__")` while monkeypatching `envrctl.cli.app` to a no-op to avoid CLI execution. |

## Feasibility Conclusion
Reaching 100% coverage is **feasible with small, deterministic unit tests** and **no external OS dependencies**. The remaining misses are all trivial branches or guard code that can be safely exercised via monkeypatching and `runpy`.

## Recommendation
Implement 4–5 targeted tests to cover the lines above. No code changes are required beyond tests, and coverage should reach 100% without relying on real Keychain/SecretService availability.