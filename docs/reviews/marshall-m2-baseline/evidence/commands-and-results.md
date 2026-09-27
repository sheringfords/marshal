# Evidence — commands and results (MARSHALL_M2_BASELINE_RECONCILIATION_V1)

Baselines: worktree `/tmp/marshall-m2-baseline` (detached HEAD `eee20cf982562959b4da489cb5f5e6f190e2dabd`); review worktree `/tmp/marshall-integration-v1` retained; primary checkout `review/marshall-integration-v1` (`29bb371`) untouched. Toolchain: rustc/cargo 1.90.0, node v20.19.5, python 3.11.6, macOS (no `openat2`; Linux-only guarantees noted as unverified here).

## 1. Fetch + SHAs

```
$ git fetch --all --prune   # origin + rapture-fx updated
$ git ls-remote origin | grep -E "main|hardening"
eee20cf982562959b4da489cb5f5e6f190e2dabd  HEAD / refs/heads/main
32d0aae86cbe0560490b2402e44991ba82c61865  refs/heads/hardening/production-readiness
$ git log --oneline origin/main -5
eee20cf Merge PR #7 (hardening -> main) / ea857ee Merge PR #1 / e994a7c Merge PR #5 / fc33b14 Merge PR #6 / b56c082 ...
```

## 2. Diff summary

- `b56c082..origin/main`: +12 audit-doc files, +491 lines, zero implementation delta.
- `b56c082..origin/hardening`: same +12 docs, zero implementation delta.
- `origin/main` vs `origin/hardening`: empty diff.
- Hash check (`shasum -a 256`, `git show <sha>:<path>`): server 994e534eac3b, backend de6e49f32cc2, policy 911434e52941, shell 0892f11200ff, registry 0edabdf93a3e, limits cfc071a1fbad, tests/server 602716e857d9, js-sdk c7fe53fa66e0, py-sdk 768422b95e1b, Cargo fad3e0d8b733, deny a5d723facf5f — identical both sides.

## 3. Validation (exact `eee20cf`)

| Command | Result |
|---------|--------|
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets -- -D warnings` | PASS |
| `cargo test --lib` | 131 passed, 0 failed |
| `cargo test --doc` | 1 passed |
| `cargo test --test escapes` | 14 passed |
| `cargo test --test server` | 43 passed |
| `cargo test --test stress` | 1 passed |
| `cargo test --features experiment --test validation` | 17 passed |
| `cargo check --features wasm` | PASS |
| `cargo clippy --all-targets --features wasm -- -D warnings` | PASS |
| `cargo test --features wasm --lib` | 136 passed |
| `node --test sdk/js/` | 4 passed |
| `python3 sdk/python/test_sdk_auth.py` | 4 passed |
| `cargo deny check` | advisories/bans/licenses/sources ok |
| `cargo audit` | SKIPPED (binary not installed) |

## 4. Live reproductions (daemon from exact baseline, `concurrency: 1`, token `m2token`, :3459, disposable `/tmp/marshall-m2`)

- MAR-REV-001: batch 8×`sleep 6` (`max_concurrency: 8`) → `ps` showed **8 concurrent `/bin/sleep`**; concurrent single execute → **503**; batch finished 8/8 success, no orphans.
- MAR-REV-004: session S + `shared.txt` outside S → single read **403**; batch per-step override (no top) **200 + file content**; sequence **200**.
- SDKs live: JS (execute/batch/sequence/session/delete/policy 2222 bytes) OK; Python (execute/batch/session/delete/policy/stream summary-chunk-done) OK. Tokenless compat not re-run on this tree (verified on identical `b56c082` tree in V1 mission).

## 5. Skipped / limitations

`cargo audit` (missing binary); Linux-`openat2` read path and WASM runtime limits re-verified by suite only (macOS host); MAR-REV-004 extended boundaries (`..`, symlink, `working_dir`) trace-confirmed, runtime pending; draft PR unpublished (no push access); no production changes made.
