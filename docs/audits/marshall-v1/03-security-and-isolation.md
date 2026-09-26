# 03 — Security and Isolation

Conventions: **CONFIRMED** = verified in source/tests this audit. **SUSPECTED** = visible in code but not exploited. No destructive experiments were run (macOS dev host, no disposable Linux VM available); nothing below required executing an exploit.

## MAR-P0-001 [P0, CONFIRMED] — `wasm` feature does not compile

- **File:** `src/backend.rs:371-585` (feature `wasm`, `Cargo.toml:37`)
- **Reproduction:** `cargo check --features wasm` → 13 errors: `Config`, `Engine`, `Module`, `Store`, `Linker`, `Caller`, `Mutex` undeclared; `effective_fuel` vs `_effective_fuel` mismatch (`:380,385,416`).
- **Impact:** the documented WASM isolation path (`README.md:199`, `docs/ARCHITECTURE.md`) cannot be built, tested, or deployed. CI never checks the feature (`.github/workflows/ci.yml` has no wasm job), so the breakage is uncaught.
- **Fix:** add the missing `wasmtime::{...}` imports under `#[cfg(feature = "wasm")]`, fix the variable name, add a CI job `cargo check --features wasm` (and `clippy`, plus a fuel-exhaustion test).
- **Acceptance:** `cargo check --features wasm` and `cargo clippy --features wasm --all-targets -- -D warnings` green in CI.

## MAR-P0-002 [P0, CONFIRMED] — `container` backend unbuildable AND silently downgrades

- **File:** `Cargo.toml:59`, `src/backend.rs:667-779`
- **Reproduction:** `cargo check --features container` → 3 errors against the pinned `watchdog` rev `ae5ea2f`: `watchdog::{Config, Limits, Pool}` unresolved, `watchdog::{ExecRequest, ResourceLimits}` not found (`src/backend.rs:722,752,758`). The API the code assumes does not exist at the pinned revision; the repo is unpublished so no third party can resolve this.
- **Fallback hazard:** without KVM or the feature, `ContainerBackend::execute` warns and delegates to `LocalProcessBackend` (`:686-707`) while `name()` still returns `"container"` (`:679`). A policy that assumes microVM isolation gets unsandboxed execution with no signal in the response.
- **Impact:** Firecracker isolation is not shippable and the failure mode is silent downgrade.
- **Fix:** publish `watchdog` or delete the feature; on fallback return an error or set `fallback: true` in outcome metadata; add per-request pool lifecycle (today `Pool::new` per request with a fixed `/tmp/firecracker.sock`, no cleanup).
- **Acceptance:** `cargo check --features container` green on a public dep; fallback path covered by a test asserting explicit opt-in.

## MAR-P0-003 [P0, CONFIRMED] — `execute_stream` skips the policy pipeline

- **File:** `src/server.rs:1082-1111`
- **Reproduction:** compare the pre-check blocks of `execute` (`:623-704`: session purge/lookup/path, destination+egress, idempotency, audit, metrics) with `execute_stream` (auth + rate-limit + semaphore, then direct `registry.execute`). Send an `http` request to an unallowlisted host via `/v1/execute/stream` on a policy that denies it via `/v1/execute`; observe 200-stream vs 403.
- **Impact:** every per-request control the service advertises (session scoping, egress allowlist, audit trail, metrics) is bypassed over SSE.
- **Fix:** extract one `admit_request()` used by all four handlers.
- **Acceptance:** parity test — each denial over `/v1/execute` reproduces over `/v1/execute/stream`, and audit contains one record per streamed execution.

## Filesystem

- **Containment CONFIRMED:** component-wise comparison + symlink resolution (`src/sandbox.rs:107-134`); `openat2 RESOLVE_BENEATH` on Linux with fd-backed read (`:199-253`, `src/fs.rs:242-253`); 14 escape tests pass.
- **MAR-P1-002 [P1, CONFIRMED] — check-then-use writes:** `resolve_*` then `tokio::fs::{write,copy,rename,read}` on paths (`src/fs.rs:316,348,389-481,628-704`); the `openat2` fd is converted via `/proc/self/fd` and dropped (`src/sandbox.rs:242-274`, `README.md:286` admits the window). Concurrent rename/swap wins. **Fix:** retain the fd and perform I/O through it (`openat2` + `O_PATH`/fd-relative ops); regression test: racing writer swapping a symlink mid-write stays inside the root.
- **SUSPECTED — search/glob/list TOCTOU:** canonical-check then use of non-canonical `p`/`entry` (`src/fs.rs:525-610`); `append` read+write non-atomic (`:464-468`). Lower severity (read-side), same fix family.
- **SUSPECTED — oracle:** `exists` maps `Outside → error` vs `Unresolvable → exists:false` (`src/fs.rs:746-759`); `validate` merges to `path_not_allowed` (`:771-781`), so the oracle is only visible on direct-library `execute`. Minor.

## Shell

- **CONFIRMED:** absolute-path allowlist, `ArgumentPolicy` in validate+execute, no intermediate shell, `env_clear`, stdin/output caps, timeout+`kill_on_drop`, `working_dir` containment, `RLIMIT_CPU/AS` (`src/shell.rs`, `src/backend.rs:176-278`).
- **MAR-P1-003 [P1, CONFIRMED] — no process-tree kill:** timeout drops the `Child` handle (`src/backend.rs:258-266`); grandchildren, `setsid`/`nohup` children, and `cmd &` survive. Existing test (`src/shell.rs:693-713`) proves only the direct child dies. **Fix:** spawn in a process group (`setsid`) and kill the group on timeout (Unix); document the residual risk on other platforms. **Acceptance:** `sh -c 'sleep 30 & wait'`-style grandchild reaped after a 300 ms timeout.
- **SUSPECTED — `NoFlags` heuristic:** documented as heuristic (`src/shell.rs:41-44`, `README.md:192`); binaries treating bare positionals as scripts (`env`, `find -exec`, `git --exec-path`) stay exploitable; `INTERPRETER_BINARIES` (`:69-82`) misses versioned names (`ruby3.2`, `php8.1`, `node20`, `busybox`); `allowed_env` has no deny-list (`LD_PRELOAD`, `GIT_SSH_*`). **Fix:** per-binary profiles; refuse `NoFlags`/`Unrestricted` for interpreters outright.
- **SUSPECTED — binary substitution:** allowlist stores paths; a symlink/rename swap between policy load and `spawn` is not pinned (no hash check).

## Network / SSRF

- **CONFIRMED strong:** scheme restriction, `@`/control/`%`-host/numeric-IP rejection (`src/destination.rs:145-252`), loopback-only `http` vs public-only `https` with port allowlists (`:89-126`), full v4/v6 block table with normalization (`:290-380`), allowlist-before-DNS + `redirect::Policy::none` + address pinning (`src/http.rs:123-271`), header allowlist + CRLF check + streaming body cap, server-side re-validation (`src/server.rs:655-686`, `src/egress.rs:42-60`).
- **SUSPECTED — double-resolution window:** server pre-check resolves, then `HttpTool` resolves again — a DNS change between the two validations can rebind. **Fix:** resolve once per request and share the pinned addresses (or document the residual TOCTOU).
- **By design (P1-001):** `code`/`shell` egress bypasses `http`/egress policy entirely; only the `allow_unsandboxed` ack stands guard.
- Residual: loopback port-scan across the 9 permitted dev ports remains possible by design.

## Service

- **CONFIRMED:** loopback-default + non-loopback refusal without token (`src/server.rs:98-121`), constant-shape bearer compare (`:134-141`), token-hash client keys (`:165-179`), per-client quotas, 503 shedding, CORS same-origin default, atomic hot-reload with fail-closed bad policy (`:1434-1480`).
- **MAR-P1-005 [P1, CONFIRMED] — session scoping is advisory:** `check_session_path` (`:548-571`) inspects only `path`/`destination` keys via non-canonical `starts_with`; global `FileSystemTool` sandbox is the shared workspace, so cross-session reads succeed; batch-without-top-session checks existence only; sequence-with-top-session never checks per-step sessions. **Fix:** canonicalize against the session root, cover all path carriers (`working_dir`, `source`, `program`, `code` tempfile dir), scope tool sandboxes per session or document single-workspace semantics.
- **SUSPECTED — audit secrecy:** `fs search` embeds 512-char line text in `summary` (`src/fs.rs:507,564`), which lands in the JSONL audit log — file secrets in the audit trail, contradicting redaction-by-default. **Fix:** hashes + counts only in summaries.
- **SUSPECTED — DoS edges:** 1-permit batch fan-out (up to 32 procs per permit), SSE task outliving its permit (`:1094,1125`), `audit_lock` held across `spawn_blocking`+rotation, uncapped `list`, 30 s `sleep` × 32 sequence steps stalling a worker. Each is bounded but worth a cap.
- **`process_kill`:** gated, refuses 0/1/self, Linux descendant-only (`src/system.rs:447-522`) — but non-Linux can signal any permitted pid, and `pid as i32` truncation (`src/system.rs:362`) can alias large pids past validation. SUSPECTED, low severity on the supported Linux target.

## WASM (claimed, unverifiable)

With the feature broken, fuel/memory/WASI/timeout claims (`src/backend.rs:380-541`) are **NOT_VERIFIED**. Code review notes (to re-check once it compiles): `req.program` read with no sandbox check (`:377-379`); `fuel=None` + `cpu_time=None` → unbounded (`:381,404`); `total_written` updated after truncation (`:478`); fuel/epoch/OOM conflated to `timed_out` (`:514-541`).
