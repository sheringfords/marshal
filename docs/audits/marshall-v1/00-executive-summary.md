# Marshall Execution Runtime Audit — Executive Summary

- **Baseline SHA:** `fb350018c22d5ea7b88c17dfaed20df95174cfec`
- **Branch at audit start:** `hardening/production-readiness` (clean tree); audit written on `audit/marshall-execution-runtime-v1`
- **Remote:** `origin = https://github.com/wiramahendra/execution-tool.git`; `rapture-fx = https://github.com/rapture-fx/Marshall.git`
- **Date / platform:** 2026-09-26, macOS 22.6.0 x86_64, rustc 1.90.0, default features (no KVM)
- **Scope:** audit only. No production code changed. Working tree contains only `docs/audits/`.

## One-paragraph verdict

Marshall is a **well-tested, deny-by-default tool-policy gateway** with genuinely careful SSRF and path-containment code — and it is **not an execution runtime with OS-level isolation**. Policy is enforced in-process; a bug past the policy has the daemon's privileges (`src/lib.rs:26-29` says so explicitly). The two advertised isolating backends do not hold up: `--features wasm` **does not compile** (13 errors, missing imports + a variable-name bug in `src/backend.rs:380-441`), and `--features container` depends on an unpublished `watchdog` revision nobody else can build (`Cargo.toml:59`, `README.md:285`). On top of that, the SSE endpoint (`src/server.rs:1082-1161`) skips session, egress, idempotency, audit, and metrics checks that the other three execution endpoints perform. Until those are fixed, Marshall is suitable as a policy layer for semi-trusted callers (or inside a container/VM), not as a boundary for untrusted code.

## Validation results

| Command | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets -- -D warnings` | PASS |
| `cargo test --lib` | PASS — 131 passed |
| `cargo test --doc` | PASS — 1 passed |
| `cargo test --test escapes` | PASS — 14 passed |
| `cargo test --test server` | PASS — 32 passed |
| `cargo test --test stress` | PASS — 1 passed (10k idempotent execs, ~6.5 s) |
| `cargo test --features experiment --test validation` | PASS — 17 passed |
| `cargo run --example agent_tools` | PASS |
| `marshalld --validate-config ./marshall.yaml` | PASS via prebuilt binary (fresh `cargo run` exceeded 60 s on cold compile; not a product defect) |
| `cargo check --features wasm` | **FAIL — 13 compile errors** (`src/backend.rs:380-441`) |
| `cargo check --features container` | **FAIL — 3 compile errors** (`src/backend.rs:722,752,758`; `watchdog` API drift at pinned rev) |
| `cargo test --all-targets` (single invocation) | Timed out at 300 s in this environment (individual suites pass; see evidence log) |

## Confirmed P0/P1 defects (all reproduced or verified in source)

| ID | Severity | Finding |
|---|---|---|
| MAR-P0-001 | P0 | `--features wasm` does not compile: missing `wasmtime::{Config, Engine, Module, Store, Linker, Caller}` imports, `_effective_fuel`/`effective_fuel` name mismatch, missing `Mutex` import (`src/backend.rs:380-441`). CI never checks the feature, so the breakage is uncaught. |
| MAR-P0-002 | P0 | `container` backend is unshippable: `watchdog` pinned to an unpublished-repo revision (`Cargo.toml:59`); without KVM/feature it **silently falls back to local execution** while reporting `name() == "container"` (`src/backend.rs:679,686-707`). Downgrade without attestation. |
| MAR-P0-003 | P0 | `POST /v1/execute/stream` bypasses all per-request policy beyond auth/rate-limit: no `purge_expired_sessions`, no `check_session_path`, no `validate_destination`/egress allowlist, no `idempotency_key`, no audit log, no metrics (`src/server.rs:1082-1111` vs `594-738`). |
| MAR-P1-001 | P1 | Local-backend `code` execution bypasses filesystem+HTTP policy by design; only guard is `allow_unsandboxed: true` config ack (`src/policy.rs:462-469`). Off by default — correct default, but one flag away from decoration. |
| MAR-P1-002 | P1 | Filesystem writes are check-then-use: `resolve_*` then `tokio::fs::{write,copy,rename}` on the path (`src/fs.rs:316,348,389-481,628-704`). `openat2` fd is dropped, not retained (`src/sandbox.rs:242-274`). TOCTOU window on all platforms including Linux. |
| MAR-P1-003 | P1 | Timeout kills the direct child only (`kill_on_drop`, `src/backend.rs:191,258-266`). No process-group/cgroup kill: grandchildren and daemonized processes survive. |
| MAR-P1-004 | P1 | Both SDKs (JS + Python) send no `Authorization` header, so they cannot talk to any token-protected deployment (`sdk/js/index.js`, `sdk/python/marshall_sdk.py` vs `src/server.rs:124-156`). SDKs also lack `deleteSession`/`getPolicy`. |
| MAR-P1-005 | P1 | Session isolation is advisory: `check_session_path` inspects only `path`/`destination` keys without canonicalization (`src/server.rs:548-571`); the global `FileSystemTool` sandbox is the shared workspace, so session A can read session B's files. Batch-without-top-session and sequence paths skip the path check entirely. |
| MAR-P1-006 | P1 | Idempotency key is caller-chosen and not namespaced by tool/args (`src/registry.rs:164-196`); same key + different payload returns a stale success. Batch/sequence drop `idempotency_key` silently (`src/server.rs:899-900,1045-1046`). |

## Demonstrated guarantees (actually tested)

- **Path containment:** `openat2 RESOLVE_BENEATH` on Linux, `canonicalize` + component comparison elsewhere; sibling-prefix and symlink escapes refused; 14 escape tests pass (`src/sandbox.rs:107-274`, `tests/escapes.rs`).
- **SSRF:** scheme allowlist, numeric-IP/octal/hex rejection, IPv4-mapped/6to4/Teredo/NAT64 block coverage, all-addresses-must-pass, allowlist-before-DNS, redirect disabled, connection pinned to validated addresses (`src/destination.rs`, `src/http.rs:123-130,232-271`).
- **Shell:** no intermediate shell, absolute paths only, `ArgumentPolicy` enforced in both `validate` and `execute`, env cleared, stdin/output caps, timeout with child cleanup, `RLIMIT_CPU/AS` (`src/shell.rs`, `src/backend.rs:176-278`).
- **Service hardening:** loopback-by-default with refusal of unauthenticated non-loopback bind, constant-shape bearer compare, per-client token buckets, concurrency shedding with 503, single-generation audit rotation (`src/server.rs:98-206,608-621`).
- **Correctness:** batch order preservation + caps, sequence stop/continue semantics, success-only idempotency cache bounded at 1024 entries/300 s TTL, session TTL + sweeper (`src/registry.rs`, `src/server.rs:330-355`).

## Unverified / absent claims

- No seccomp, namespaces, chroot, or cgroup containment in-crate (documented as absent — honest).
- WASM fuel/memory/timeout enforcement: **untestable** — the feature does not compile.
- Firecracker isolation, VM lifecycle, resource enforcement: **untestable here** (no KVM on macOS; unpublished dep).
- Any multi-tenancy: absent by documentation (one token, one trust domain).
- Any durability: session/agent state is in-memory and lost on restart.

## Benchmarks (this machine, debug build, local backends)

- Filesystem read: p50 ~0.67 ms, mean ~1.7 ms (n=200, skewed by warmup); shell `/bin/echo`: p50 ~7.8 ms, mean ~8.9 ms (n=50).
- 32 parallel shells: ~57 ms wall (~560 exec/s).
- Timeout accuracy: 300 ms request → 305 ms observed, `timed_out` code. Good.
- Full methodology, hardware, and raw numbers: `05-performance.md`.

## Product feasibility (summary)

E2B (Firecracker microVMs, ~$0.05/vCPU-hr + $150/mo Pro), Daytona (containers + VM classes + GPUs + BYOC, usage-only), Modal (gVisor + VM beta, no BYOC, ~3× CPU cost), and plain Docker (shared kernel) all solve **blast radius**; none sells a **deny-by-default tool policy with content-free audit**. Marshall's defensible position is the layer in front: policy decision + bounded execution + provable audit, composing with a real isolation backend for untrusted code. Three candidate use cases (enterprise coding-agent gateway, regulated/air-gapped deployment, per-tenant MCP gateway) are hypotheses, not validated demand. Do not pursue hosted multi-tenant execution against funded incumbents. Details and sources: `07-market-research.md`.

## Recommended first engineering slice

1. Fix `execute_stream` to share the exact pre-check pipeline as `execute` (one function, four callers) — MAR-P0-003.
2. Make `wasm` compile under CI (`--features wasm` check job) or delete the feature — MAR-P0-001.
3. Resolve `watchdog`: publish it or remove the `container` feature; make fallback explicit (error or `fallback: true` in response), never silent — MAR-P0-002.
4. Add bearer-token auth to both SDKs + `deleteSession`/`getPolicy` — MAR-P1-004.
5. Scope `check_session_path` to canonicalized paths and all path-carrying keys; document single-workspace model — MAR-P1-005.

Kill criteria: if no design partner will run the policy-gateway in front of their existing sandbox within the slice, stop; the hosted-runtime path is out of scope.

## Files in this audit

`00-executive-summary.md` (this file) · `01-codebase-inventory.md` · `02-architecture.md` · `03-security-and-isolation.md` · `04-correctness-and-reliability.md` · `05-performance.md` · `06-developer-experience.md` · `07-market-research.md` · `08-proposed-engineering-plan.md` · `evidence/commands-and-results.md`
