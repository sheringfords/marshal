# RFC: Execution Architecture V2

Status: draft (ENGINEERING_RECOVERY_V1 Phase 6). Grounded in the audit in
`docs/engineering/ENGINEERING_RECOVERY_V1.md` §3 and the benchmark baseline
in `docs/engineering/EXECUTION_BASELINE_V1.md`.

## Goals

One lifecycle, one authority, one filesystem boundary — with fewer lines,
fewer features, and no behavior change except documented security
corrections.

## Decisions

### D1. One execution coordinator

All four endpoints (`execute`, `batch`, `sequence`, `stream`) funnel through
a single `coordinate(request) -> response` pipeline owning stage order:
edge → workload → session → egress → scope-bind → dispatch → audit/meter.
Endpoint handlers keep only shaping (batch fan-out width, sequence
stop/continue, SSE framing). Expected: delete ~200 lines of drifted
duplication; risk: behavior drift during migration — pin with the existing
59 server tests plus per-stage unit tests before consolidating.

### D2. Typed execution context

Replace the `__session_root` reserved JSON key with
`ExecCtx { session_root: Option<PathBuf>, workload_permit, .. }` threaded
`server → registry → Tool::execute`. Forgery becomes unrepresentable;
direct library callers get an explicit `ExecCtx::unscoped()` constructor
documenting the trusted-local contract. Cost: `Tool` trait change across
~10 tools + experiment harness + bins. Migration: add `execute_ctx` with a
default blanket impl delegating to `execute`, migrate tools one by one,
then remove the JSON protocol. Acceptance: scope tests green with the key
absent from all args.

### D3. Workload ownership and cancellation

Retain M2-001 semantics (per-workload permits, abort-on-drop task set, RAII
release). Unify the three permit shapes (single/sequence/stream hold-one,
batch per-item) behind one `WorkloadGuard` type so future endpoints cannot
reintroduce request-counted fan-out. Child-process ownership stays direct
child until M2-004 (process groups) resumes.

### D4. Filesystem authority boundary

Retain the `Sandbox`-classifies / `BoundDir`-executes split (error shapes
vs descriptors serve different callers), but remove the double resolution
where shapes allow: bind-first, classify walk errors. Requires auditing
every `Unresolvable`-vs-`Outside` expectation in `tests/escapes.rs` first —
optional, not correctness-required.

### D5. Supported execution modes

Marshall supports: single tool calls, bounded batch fan-out, ordered
sequences with templating, and buffered SSE replay — all session-scoped,
all workload-bounded, all audited. It does NOT support: OS isolation,
multi-tenancy, cross-session sharing, trailing-link traversal on creates,
or unbounded queues. The docs and the `code`-tool gating already say most
of this; the RFC makes the list normative and removes anything implying
otherwise.

### D6. Retain / consolidate / delete

- Retain: `BoundDir`, workload semaphore + abort set, per-item audit,
  hot-reload watcher, supply-chain gates.
- Consolidate: four admission paths → coordinator (D1); JSON scope → `ExecCtx`
  (D2); `Sandbox`+`BoundDir` overlap (D4, optional).
- Delete (done in recovery baseline): `wasmtime-wasi`, `cap-std`,
  `arbitrary`, tokio `test-util`, `tower`/`tower-http` `limit` features.
- Delete candidates (separate slices): `backend-wasm` alias,
  `mcp_bounded_sequence` (ungated, untested) or gate it under `experiment`,
  axum `query`, uuid `serde`, reqwest `charset`/`http2` (verify use first).

## Sequencing (small PRs, each independently testable)

1. Coordinator extraction behind the existing handlers (no behavior change;
   gate: 59 server tests green).
2. `ExecCtx` introduction with blanket-impl migration (gate: scope tests
   green, JSON key gone from args).
3. `WorkloadGuard` unification (gate: M2-001 timing tests green).
4. Optional: bind-first classification (gate: escapes suite green).
5. Optional: dependency/feature deletions from D6 (gate: full matrix).

## Non-goals

M2-004 (process groups), M2-005 (idempotency redesign), new backends,
multi-tenancy, billing. Performance work follows the benchmark baseline and
touches only measured bottlenecks.
