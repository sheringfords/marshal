# M2 Implementation and Integration Plan

## Reconciliation (no code changed)

`origin/main` (`eee20cf`) and `origin/hardening` (`32d0aae`) are content-identical (empty diff; implementation files hash-identical to verified `b56c082`; delta is audit docs only). No merge performed. M2 branches cut from `eee20cf`. `hardening/production-readiness` left untouched (recommend fast-forward/retire after M2 — maintainer decision).

## Workstream dependency map

| Slice | Files | Depends on | Parallel-safe with |
|-------|-------|-----------|-------------------|
| M2-001 concurrency | `server.rs` (admission/quota), `registry.rs` (batch) | — (first) | M2-002, M2-003 |
| M2-002 session boundary | `server.rs` (admission only) | — | M2-001, M2-003, M2-004, M2-005 |
| M2-003 TOCTOU | `fs.rs`, `sandbox.rs` | — | all (exclusive files) |
| M2-004 proctree | `backend.rs`, `registry.rs`, `server.rs` (disconnect) | M2-001's batch cancellation scope (or include it) | M2-002, M2-003 |
| M2-005 idempotency | `registry.rs`, `server.rs` (key plumbing) | sequence after M2-001 (same `registry.rs` batch region) | M2-002, M2-003 |

Suggested: three concurrent workstreams — (A) M2-001 → M2-005 → M2-004 backend-half; (B) M2-002; (C) M2-003. Fast-track docs/SDK items independently.

## Per-slice gates

Each slice lands only with: its drafted acceptance tests green, full mission validation matrix green (`fmt`, `clippy` ± `wasm`, `lib`, `doc`, `escapes`, `server`, `stress`, `experiment-validation`, wasm `check/clippy/test`, JS/Python SDK suites, `deny`), no weakened security test, and an explicit cross-slice integration run (batch × session × idempotency matrix) before milestone close.

## Release gates for M2

Close only when: M2-001–005 acceptance tests green on the integrated tree; concurrency claims match measured behavior; session scoping enforced at the operation boundary (not just admission); TOCTOU racer tests pass on Linux (residual non-Linux risk documented); no orphan processes after timeout/disconnect; idempotency contract updated (existing replay-pinning test revised); SDK packaging fixed (MAR-REV-009) before any external release claim.
