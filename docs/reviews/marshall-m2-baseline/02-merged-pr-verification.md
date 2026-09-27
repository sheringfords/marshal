# Merged PR Verification (baseline `eee20cf`)

Method: byte-hash comparison (`shasum -a 256`) of every implementation file between the previously verified integration `b56c082` and `origin/main` `eee20cf`, plus full validation of the exact baseline in `/tmp/marshall-m2-baseline` (detached HEAD `eee20cf`).

## File identity (all IDENTICAL)

`src/server.rs` (994e534eac3b), `src/backend.rs` (de6e49f32cc2), `src/policy.rs` (911434e52941), `src/shell.rs` (0892f11200ff), `src/registry.rs` (0edabdf93a3e), `src/limits.rs` (cfc071a1fbad), `tests/server.rs` (602716e857d9), `sdk/js/index.js` (c7fe53fa66e0), `sdk/python/marshall_sdk.py` (768422b95e1b), `Cargo.toml` (fad3e0d8b733), `deny.toml` (a5d723facf5f). Tree delta `b56c082..eee20cf` = 12 audit-doc files only.

## Per-PR confirmation in the merged tree

- PR #2 (admission): shared pipeline `admit_edge` → `admit_concurrency` → session → egress on all four endpoints (`src/server.rs:607–772`); stream calls `admit_item` (`:1073`); per-item audit/metrics for batch/sequence. Parity tests green (server suite 43/43).
- PR #3 (WASM): fuel/epoch/memory/link-time denial/fail-closed present (`src/backend.rs:346–669`); `--features wasm` suite green (see validation below).
- PR #4 (container): `execute` always bails `isolation_unavailable` (`:737–760`); no `watchdog` in `Cargo.toml`/`Cargo.lock`; no `container` cargo feature; no `is_isolated` API. Refusal tests green.
- PR #5 (SDK): Bearer headers on all paths; stub suites green; live-daemon exercise in this mission (see `evidence/commands-and-results.md` for full smoke output).
- PR #1: docs only, present on both main and hardening.

## Validation (exact baseline — final numbers in `evidence/commands-and-results.md`)

Part 1: fmt PASS; clippy PASS; lib 131/0; doc 1/0; escapes 14/0; server 43/0. Part 2: stress 1/0; experiment-validation 17/0; wasm check PASS; wasm clippy PASS; wasm lib 136/0; JS SDK 4/4; Python SDK 4/4; `cargo deny` PASS (advisories/bans/licenses/sources). `cargo audit` skipped (binary absent).

No integration or merge commit reintroduced an original P0 defect. No false isolation guarantees present (verified by grep + refusal tests).
