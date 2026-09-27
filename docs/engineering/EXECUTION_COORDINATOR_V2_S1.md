# Execution Coordinator V2 — Slice 1

Branch: `refactor/marshall-execution-coordinator-v2-s1`, base `main` @
`a788eb8` (PR #13 merged before branching; no overlap to manage).
No new worktrees; no Tool-trait change; no ExecCtx yet; registry idempotency
untouched; no dependency changes.

## Before and after

Before: each of the four handlers inlined its own strip → session/egress →
scope-bind → dispatch → audit/metrics sequence (~4 copies, drifting:
permit models, `inc_request` placement, rejection shapes).
After: handlers do transport shaping, size caps, workload admission and
response construction only. Shared logic lives in four coordinator items:

- `prepare_one` — single-item strip/admit/bind (single + stream).
- `preflight_all` — strip all, require top-level session, per-item
  `admit_item` with effective session, per-item scope bind (batch + sequence).
- `run_one` — registry dispatch with idempotency-key routing.
- `record_outcome` — audit + metrics + serialized value for every executed
  outcome on every endpoint.

Deliberately NOT unified (endpoint contracts): workload admission
(HoldOne vs burst gate), rejection shapes (400 vs per-item entries vs SSE
error event vs `success:false`), response envelopes, SSE replay, sequence
templating/stop semantics, `inc_request` placement.

## Files changed and code removed

- `src/server.rs` only (production): per-item admission 4 inline variants
  → 1 (`admit_item` via `prepare_one`/`preflight_all`); outcome recording
  4 copies → 1 (`record_outcome`); removed dead `ExecuteResponse` struct.
- Net production delta: +2 lines (coordinator types + docs offset the
  removed duplication; the win is structural — one implementation per
  stage, enforced by construction).
- `tests/server.rs`: +15 characterization tests (all passing pre-refactor).

## Characterization tests (new, all green pre- and post-refactor)

Oversize-sequence refusal + audit purity; unknown/expired session codes on
all endpoints; batch/sequence egress codes; forged scope on all four;
per-item and empty-request session gates; partial-batch audit/metric counts;
permit release on item error and sequence abort; request-count semantics
(edge rejections skip, shed counts); in-session template execution.

## Security, concurrency, cross-platform

- Full suite green on macOS; Linux matrix (incl. toctou, escapes, wasm)
  re-run on the final tree before PR.
- Live adversarial check at `concurrency: 1`: single+batch+sequence+stream
  fired simultaneously → exactly 1 running workload, other three shed with
  identical 503s, zero orphans, no deadlock.
- M2-001 timing tests, session suites, escape suites: green, unmodified
  in behavior (only moved through the coordinator).

## Performance

Bench harness `bench_exec.sh` against release daemons (recovery baseline
vs post-refactor, same machine/harness; curl-spawn overhead dominates, so
comparison is relative only):

| workload | pre (p50) | post (p50) | verdict |
|----------|-----------|------------|---------|
| single echo (n=100) | 18.01 ms | 19.47 ms | within noise+load |
| fs read (n=100) | 16.42 ms | 16.56 ms | no change |
| fs write (n=50) | 16.96 ms | 16.84 ms | no change |
| batch-8 (n=30) | 17.13 ms | 19.28 ms | within noise+load |

No statistically credible regression; server-side work is a small fraction
of every row (HTTP/JSON plumbing dominates).

## Remaining duplication and limitations

- Rejection JSON construction still per-endpoint (shapes differ by design).
- `strip_scope_key` loops live in `preflight_all` (batch/sequence) and
  `prepare_one` (single/stream) — two call sites, one function.
- Workload admission still two mechanisms (HoldOne permit vs burst gate +
  per-item permits) — unification is the WorkloadGuard slice, explicitly
  out of scope here.
- The reserved-JSON scope protocol is preserved untouched for Slice 2
  (typed ExecCtx).
