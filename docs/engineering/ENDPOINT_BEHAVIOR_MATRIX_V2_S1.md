# Endpoint Behavior Matrix (baseline a788eb8, traced from source)

## Stage order per endpoint (all deny-before-execute)

| stage | single | batch | sequence | stream |
|-------|--------|-------|----------|--------|
| edge (auth, quota) | yes | yes | yes | yes |
| `inc_request` | before concurrency | after admission, pre-dispatch | after admission, pre-dispatch | before concurrency |
| concurrency | 1 permit held whole call | burst gate only (503 iff 0 free), items take per-workload permits | 1 permit held whole call | 1 permit held for execution (not SSE delivery) |
| session purge + `inject_session_id` | — | yes | yes | — |
| strip `__session_root` | yes | per item | per item | yes |
| top-level session must exist | n/a (single id) | yes, even empty batch | yes, even empty sequence | n/a |
| per-item session+path admission | via `admit_item` | effective session per item | effective session per item | via `admit_item` |
| per-item egress | via `admit_item` | per item | separate loop per step | via `admit_item` |
| bind trusted scope root | yes (fs only) | per fs item | per fs item | yes (fs only) |
| size caps | — | 64 → 400 `batch_too_large` | 32 → 400 `sequence_too_large` | — |
| dispatch | `execute_once`/`execute` | `execute_batch(inner, max, semaphore)` | `execute_sequence(inner, continue)` | `execute_once`/`execute` then SSE replay |
| registry rejection | 400 + code | per-item `Err` entry (200 envelope) | per-item `Err` entry (200 envelope) | SSE `error` event (200) |
| audit | 1 record per executed outcome | 1 per executed item | 1 per executed step | 1 per executed outcome |
| metrics | `observe_with_tool` | per item; `Err` items metered `("",false,0)` | per step; `Err` metered `("",false,0)`; shed metered on 503 | `observe_with_tool` |
| response | 200 + outcome | 200 + outcomes[] | 200 + outcomes/executed/total | SSE summary/chunk*/done |

## Intentional differences (must survive the refactor)

1. Batch holds no request permit; sequence/single/stream hold one.
2. Batch/sequence deny whole-request at preflight (403/404/503); single
   denies per-call (401/404/403/503/400); stream denies per-call except
   registry rejection → SSE error event.
3. `inc_request` placement differs (single/stream count shed load, batch/
   sequence do not).
4. Sequence `executed` may be `< total` (early stop); batch always runs all
   admitted items concurrently up to `max`.
5. Stream replays a buffered outcome as SSE; never live-tails execution.
6. Idempotency keys honored by single/stream only; batch/sequence strip them
   (documented M2-005 gap, unchanged).

## Ownership boundaries

- Request data: owned by handler (`Json(req)`), consumed by dispatch.
- Sessions: `Mutex<HashMap>`; helpers take it per lookup, never across
  execution awaits (purge takes it briefly too).
- Registry: `RwLock<Arc<ToolRegistry>>` cloned per dispatch (hot-reload
  snapshot semantics); batch items abort with the handler future.
- Permits: `OwnedSemaphorePermit` RAII; single/sequence/stream hold across
  execution; batch items hold per-workload permits from the shared semaphore.
- Audit: `audit_lock` mutex per record; metrics atomic/Arc.

## Contract guarantees by tests vs undocumented

Tested (59 server tests): auth on all endpoints, quota, shed, sessions
(unknown/expired on all four), path scoping (single+stream; batch/sequence
per-item since M2-002), egress (single+stream), idempotency (single/stream),
ordering, stop/continue, audit parity, cancel liveness, forged scope,
templated paths, working-dir scoping.
To be characterized in Phase 2 (gaps): per-endpoint denial shape
uniformity, preflight side-effect-freedom proofs, egress on batch/sequence/
stream, stream error-event shape, audit counts on partial completion,
disconnect-during-batch audit absence, quota-vs-items contract.
