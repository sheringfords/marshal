# M2-001 — Workload-Bounded Concurrency

Branch: `fix/marshall-m2-workload-concurrency`, base `main` @ `eee20cf982562959b4da489cb5f5e6f190e2dabd` (reverified by fetch before work).

## Root cause

`admit_concurrency` issued one global-semaphore permit per admitted HTTP
request, and `execute_batch` fanned out to `max_concurrency` (≤ 32)
concurrent tool executions on a request-local semaphore. The global cap
therefore bounded admitted *requests*, never running *workloads*: one batch
under one permit ran up to 32 children (measured: 8 sleeps under
`concurrency: 1`; worst case 32 × 32 = 1024 processes at defaults).

## Architecture decisions

- `concurrency` now measures **concurrently executing workloads** (tool
  executions). Single/sequence/stream each run one workload per permit
  (unchanged). Batch items each acquire their own permit from the shared
  global semaphore as they start; queued items hold nothing.
- Batch handlers hold **no** request-level permit across fan-out (holding one
  would deadlock at `concurrency: 1`: items would wait for the permit the
  handler holds). A fail-fast burst gate returns the existing
  `503 concurrency_limited` (metered as shed, like before) when zero workload
  permits are free at admission; admitted items then queue on the semaphore.
- Per-request `max_concurrency` (≤ 32) is kept as a second, local semaphore
  for fairness (one large batch cannot grab all global slots). Acquisition
  order is local-then-global everywhere, so waiters cannot deadlock.
- Cancellation: `execute_batch` drives a `JoinSet` wrapped in an
  abort-on-drop guard — dropping the future (HTTP disconnect, shutdown)
  aborts queued/running items. Permits are RAII guards inside item tasks:
  released on success, tool error, panic and abort. Panics are attributed to
  their exact slot via task-id mapping, preserving order byte-for-byte with
  the success path.
- Sequence is serial (one workload at a time) and unchanged. Quota contract
  documented, behavior unchanged: one token per HTTP request regardless of
  item count (`src/policy.rs`, `ServerConfig::rate_limit` docs).
- Queue bounds: batch ≤ 64 items, `max_concurrency` ≤ 32, burst gate sheds at
  zero free permits; admitted items wait holding nothing. Overload behavior:
  `503 {error: too many concurrent executions, code: concurrency_limited}`,
  identical shape for singles and batches.

## Reproduction (before)

Daemon from baseline, `concurrency: 1`: batch of 8 × `sleep 6`
(`max_concurrency: 8`) → 8 concurrent `/bin/sleep` processes under 1 permit;
concurrent single → 503. (Recorded in M2 baseline mission evidence.)

## After (this branch, measured live)

Daemon from this branch, `concurrency: 1`, batch of 8 × `sleep 6`
(`max_concurrency: 32`): **1 concurrent `/bin/sleep` process** observed
mid-flight (was 8 on baseline); concurrent single → 503; all 8 outcomes
success in order; 0 sleep processes after; no orphans.

## Test results (final, this branch)

- `cargo fmt --check` PASS; `cargo clippy --all-targets -- -D warnings` PASS;
  `cargo clippy --all-targets --features wasm -- -D warnings` PASS.
- `cargo test --lib`: 135 passed (131 + 4 new); `--test server`: 47 passed
  (43 + 4 new); `--test stress`: 1; `--test escapes`: 14;
  `--features experiment --test validation`: 17;
  `--features wasm --lib`: 140 passed (135 + 5 wasm).
- `node --test sdk/js/`: 4 passed; `python3 sdk/python/test_sdk_auth.py`:
  4 passed.
- No existing test weakened; ordering (`batch_results_come_back_in_request_order`),
  sequence stop/continue, audit-per-item and metrics tests all green.

## Known limitations (not in M2-001 scope)

- Process-*tree* termination is M2-004: abort kills the direct child
  (`kill_on_drop`); daemonized grandchildren can survive. No orphan *tasks*
  remain (this slice), but orphan *processes* are still possible.
- Session-path gap (M2-002), TOCTOU (M2-003), idempotency namespace (M2-005):
  untouched, still open.
- Burst gate is best-effort (`available_permits` check-then-act); the exact
  guarantee is running workloads ≤ cap, enforced by per-item acquisition.
- Batch items queue without deadline; a saturated server sheds new batches
  (503) rather than queueing them — clients must retry.
