# Security and Concurrency Findings (baseline `eee20cf`, verified live)

## Measured concurrency behavior (MAR-REV-001 — live reproduction)

Daemon built from exact baseline, config `concurrency: 1`, token auth, disposable workspace:

- Batch of 8 × `/bin/sleep 6` with `max_concurrency: 8` → **8 concurrent `/bin/sleep` processes** observed via `ps` mid-flight, all under **1 global permit**.
- Second single `execute` during the batch → **503** (`concurrency_limited`): the permit is held, yet 8 workloads run.
- Batch completed: 8 outcomes, all success; no orphans after.
- Worst-case arithmetic at defaults (`concurrency: 32`, `max_concurrency: 32`): 32 admitted batches × 32 = **1024 simultaneous child processes**. Severity P1/HIGH; exploit prerequisites: any authenticated client (or loopback caller) able to submit batches — no quota bypass needed (batch = 1 token). → M2-001.

## Session-path gap (MAR-REV-004 — upgraded to runtime-CONFIRMED)

Live PoC on the same daemon (session S, file `shared.txt` in workspace root, outside S):

- Single `execute` with `session_id: S` reading the file → **403** `path_not_allowed`.
- Batch with per-step `session_id: S`, no top-level session → **200 with file content** (`success:true`, content bytes of `shared`).
- Sequence, same shape → **200**.

So the gap is a live cross-endpoint inconsistency, not just a trace. Severity: moderate for multi-agent single-host / shared-token deployments (any live session UUID suffices; UUID secrecy is the only barrier); low for single-user CLI. Extended boundaries (same code, trace-confirmed, runtime pending): `..` lexical bypass, symlink-across-sessions, `working_dir`/non-`path` keys unchecked, batch/sequence override asymmetry (`server.rs:903` vs `:989`). → M2-002 with 8 drafted acceptance tests.

## Remaining P0/P1 findings

- No P0 open: streaming bypass fixed + pinned; no downgrade; no new bypass.
- P1: MAR-REV-001 (measured above), M2-002 session boundary (runtime-confirmed), M2-003 TOCTOU (write/append/copy/move/delete/mkdir/patch re-resolve between check and I/O on all platforms; Linux `read` only is fd-safe), M2-004 process-tree (no `setsid`/`killpg` anywhere; grandchildren survive timeout/disconnect; batch tasks detached; post-disconnect completions skip audit).
- P2: quota-by-request, idempotency global-namespace silent replay + key stripping, WASM truncation/cancellation, SDK packaging/errors. P3/DOCS: audit semantics, stale watchdog wording, unused deps.
- Full per-operation TOCTOU table, kill-scope analysis, severity × deployment model, and all drafted acceptance tests: preserved from the specialist analyses into the M2 backlog (`05-m2-engineering-backlog.md`); session/idempotency test drafts (13) and TOCTOU/proctree drafts (5) are recorded there by reference.
