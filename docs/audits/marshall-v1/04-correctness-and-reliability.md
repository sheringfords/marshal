# 04 — Correctness and Reliability

## Exit / timeout / cancellation semantics (CONFIRMED in source)

- Shell: exit 0 → success; nonzero → `failure/nonzero_exit`; signal (`exit_code: None`) → metadata `"signal"` (`src/shell.rs:476-492`).
- Timeout: `tokio::time::timeout` around collection; on expiry partial output is **discarded**, `{timed_out: true, exit_code: None}` → `failure/timed_out` (`src/backend.rs:258-266`, `src/shell.rs:459-461`, `src/code.rs:424-428`). Measured: 300 ms request → 305 ms observed (see `05-performance.md`).
- `spawn_failed` → `failure/spawn_failed`; other backend errors `bail` → HTTP 400 (`src/shell.rs:444-456`).
- No cancel endpoint, no `tower::Timeout`, no graceful shutdown wiring. Client disconnect drops the handler future (Axum default); buffered SSE (`src/server.rs:1108-1111`) cannot preempt in-flight work.

## Disconnect / restart

- All durable state is in-memory: idempotency cache (`src/registry.rs:48`), agent tools (`src/agent.rs:146,443,681`), sessions (`src/server.rs:1395-1397`). Restart loses everything; session workspace dirs orphan on disk (sweeper only tracks the live map, `:330-344`).
- Hot-reload atomically swaps the registry `Arc` (`:1468`), so in-flight handlers finish on the old policy — correct — but `egress_hosts` swaps under a separate `Mutex` (`:1469`), allowing mid-request skew.
- `SIGTERM` kills in-flight tools; children rely on `kill_on_drop` (direct child only — see MAR-P1-003).

## MAR-P1-006 [P1, CONFIRMED] — idempotency namespace and scope gaps

- Key is a bare caller string, not namespaced by tool/args (`src/registry.rs:164-196`): same key + different payload returns a stale success. Enshrined in `tests/server.rs:831-853`.
- Concurrent same-key callers all execute (mutex released during run `:173`); only the result is deduped (`:180-182`) — thundering herd, correct result.
- Only successes cached (good — failures retry, tested `:468-479`); bound holds (10k execs → ≤1024, `tests/stress.rs`).
- Batch/sequence silently drop `idempotency_key` (`src/server.rs:899-900,1045-1046`).
- **Fix:** namespace the key as `(tool, canonical_args, key)`; thread idempotency through batch/sequence or reject the field explicitly. **Acceptance:** same-key-different-payload executes twice; replayed identical call hits cache.

## Batch / sequence under partial failure (CONFIRMED)

- Batch: never stops; per-slot `Result` (`Ok` even when `success == false`; `Err` only for validate/unknown-tool/join failure). Server always 200 with per-item `{error, code}`. Caps consistent (HTTP 64/registry 64; concurrency clamp 1–32 both layers).
- Sequence: strict order, default stops on first failure; `{outcomes, executed, total}` with `executed = len(results)` truncating on stop. Server default `continue_on_error = false` contradicts the registry doc comment claiming default true (`src/registry.rs:252-253` vs `src/server.rs:1043`) — doc bug, behavior consistent.
- Templating is single-pass with a 32-placeholder cap — output-injected `{{steps[]}}` is not re-expanded (tested `tests/server.rs:647-692`). Good.

## Sessions (CONFIRMED)

- TTL default 3600 s (`MARSHALLD_SESSION_TTL_SECS`, `:77-83`), 60 s sweeper (`:347-355`), opportunistic purge in execute/batch/sequence (not stream/delete). No sliding window (creation-only). `DELETE` → 204 + `remove_dir_all`.
- Agent state (`memory` ≤256 keys/scope + 16 KiB values, `todo` ≤64, `plan` ≤32) is per-process `RwLock<HashMap>`; `MemoryTool::evict_expired` (all scopes) is dead code, never called (`src/agent.rs:190-203`) — unbounded `session_id` cardinality grows the map. Sessions map itself uncapped.

## Resource exhaustion (CONFIRMED)

- Global semaphore (default 32) sheds with 503 (tested `tests/server.rs:696-724`). Documented weakness: one permit per batch/sequence with up to 32-way inner fan-out (`:767-770`) — up to ~1024 procs under full fan-out.
- Rate limiter: 10k buckets, 600 s idle + LRU-quarter evict; poisoned lock fails open (`src/ratelimit.rs:106-109`); auth precedes quota so failed auth doesn't burn budget (tested `:788-826`).
- `read_capped` bounds memory but keeps draining a fast producer until timeout — a fast infinite writer costs CPU until the deadline. Audit lock serializes all executions on slow disks (`:1219-1238`).

## In-flight recovery

Absent: no checkpointing, no reconciliation, no replay. The minimum contract (proposed in `08-proposed-engineering-plan.md`) should state crash-recovery as at-most-once with explicit loss, not imply resumability the code cannot provide.
