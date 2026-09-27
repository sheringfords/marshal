# Engineering Recovery V1 — Baseline, Audit, Benchmarks

Baseline: `main` @ `aabb9dfb56902417fde12fe6ae90c0b306c93bc1` (PR #11 merged).
Branch: `fix/marshall-engineering-baseline`. No new worktrees; host target
cache reused; no `cargo clean`.

## 1. Baseline reproduction (this host + Linux container)

- macOS (stable 1.90.0): lib 145, server 59 — green at `aabb9df` before changes.
- MSRV 1.88 (`cargo +1.88 check --all-targets`): PASS, 0 errors.
- Linux (rust:1.88-bookworm container, native gcc, exact HEAD): fmt PASS;
  clippy PASS (default, wasm, experiment); lib 145; server 59; toctou 5
  (including the Linux-only fd-stability test); escapes 14; stress 1;
  experiment-validation 17; wasm-lib 150. Node absent from the image (JS
  stubs covered on macOS); Python present.
- Cross-compile check from macOS (`--target x86_64-unknown-linux-gnu`) is
  NOT a substitute: it fails in the `ring` build script (missing
  `x86_64-linux-gnu-gcc`), an infrastructure gap, not a code defect. Native
  container builds are the supported Linux path.
- `cargo run --example agent_tools`: PASS. `marshalld --validate-config`: PASS.
- Cross-compile check from macOS (`--target x86_64-unknown-linux-gnu`) is
  NOT a substitute: it fails in the `ring` build script (missing
  `x86_64-linux-gnu-gcc`), an infrastructure gap, not a code defect. Native
  container builds are the supported Linux path.

## 2. Confirmed defects corrected

1. **Linux-only compile error — deleted-but-live `openat2_resolve`**
   (`src/sandbox.rs`, `E0425`). M2-003 dead-code removal deleted the helper
   while `resolve_with_openat2` (Linux-gated) still calls it. macOS never
   compiles that caller, so it went unnoticed. Restored verbatim; the helper
   serves the `resolve_existing` Linux fast path.
2. **Linux-only moved-value error — `open_child_dir(parent: impl AsFd)`**
   (`src/sandbox.rs`, `E0382`). The `openat2` attempt moves `parent`, and the
   `openat` fallback uses it again. Invisible on macOS where the first block
   is compiled out. Signature narrowed to `BorrowedFd<'_>` (Copy; all
   callers already pass `fd.as_fd()`).
3. **CI never ran `tests/toctou.rs`.** The adversarial race suite existed
   since M2-003 but no workflow step invoked it — the exact failure mode the
   wasm backend once suffered (code present, never executed). Added
   `cargo test --test toctou` to the OS matrix in `ci.yml`.
4. **Dockerfile floated dependencies.** `Cargo.lock` was copied but both
   builds ran without `--locked`; the `|| true` warm-up layer could additionally
   mask a cold-build failure. Added `--locked` to both invocations (the
   second still fails loudly).

## 3. Architecture and complexity audit

(Findings; proposal in `docs/rfcs/EXECUTION_ARCHITECTURE_V2.md`.)

- **Four endpoints, one pipeline, four copies.** `execute`, `execute_batch`,
  `execute_sequence`, `execute_stream` (`src/server.rs:880-1310`) each
  reimplement edge → session → egress → scope-bind → execute → audit →
  metrics with per-endpoint drift (e.g. batch holds no request permit while
  sequence holds one; `inc_request` placement differs). One coordinator
  owning the stage order would remove ~200 lines of near-duplicate
  admission/binding/audit code.
- **Trusted context travels as reserved JSON** (`__session_root` inside
  `args`, `src/server.rs:557`, `src/fs.rs`). Strip-then-inject works, but
  every new tool/route must remember the protocol, and direct registry
  callers get a different (weaker, documented) contract. A typed `ExecCtx`
  threaded `server → registry → Tool::execute` would make the authority
  unforgeable by construction; cost is a `Tool` trait change across ~10
  tools + experiment harness (migration risk noted in RFC).
- **Two filesystem authorities.** `Sandbox::resolve_*` classifies (error
  shapes, admission) while `BoundDir` executes (fds). The split is deliberate
  (classification needs canonical paths; execution needs descriptors) but
  every op now pays two resolutions. Consolidation candidate: bind-first,
  classify from walk errors — changes `Unresolvable`-vs-`Outside` shapes in
  edge cases; optional, not correctness-required.
- **Registry mixes lookup, policy re-validation, idempotency cache, fan-out
  and sequencing** (`src/registry.rs:151-357`). The cache is global/key-only/
  success-only with arbitrary-order eviction — adequate for retries, wrong
  for authoritative dedup (M2-005 scope, unchanged here).
- **Lifetimes are consistent after M2-001**: permits are RAII in item tasks;
  batch tasks abort with the handler (`AbortOnDrop`); audit runs per
  completed item only (post-disconnect completions are aborted, not silently
  dropped — verified by test). Stream permits cover execution, not SSE
  delivery (comment-corrected in M2 review).
- **M2-001…M2-003 production deltas**: +475/−39 (registry+server),
  +832/−155 (server+fs), +2222/−353 (fs+sandbox). `fs.rs` 1165→2091 lines,
  `sandbox.rs` ~360→1025. Growth is tested (145 lib + 59 server + 4 toctou +
  14 escapes) but concentrated in two files — the simplification budget.

## 4. Benchmarks

See `docs/engineering/EXECUTION_BASELINE_V1.md` (release daemon,
loopback, warm-up, p50/p95/p99 + variance; cache effects separated).

## 5. Dependency and build-system assessment

- `cargo deny`: clean except pre-existing RUSTSEC-2026-0285 (rustls 0.23.43
  via reqwest; reachable only through the allowlisted `http` tool and the
  healthcheck client; no dep changes in this slice).
- Dead weight confirmed by usage audit: `wasmtime-wasi`, `cap-std`
  (zero `use` in `src/`), `arbitrary` (not even fuzz uses it), tokio dev
  `test-util` (no `pause`/`advance` anywhere), `tower`/`tower-http` `limit`
  features, Python `httpx`. Removed in separate commits on this branch;
  each removal re-validated (wasm build + full matrix).
- Investigate-later (no change): `clap` unconditional for one gated bin,
  `tempfile` as main dep for experiment tests, axum `query`, uuid `serde`,
  reqwest `charset`/`http2`, `backend-wasm` alias, un-run research bins
  (notably `mcp_bounded_sequence`, ungated and untested).
- `Cargo.lock` v4 committed and now enforced (`--locked` in Docker);
  MSRV 1.88 pinned in CI and reproduced locally.
