# Review Finding Disposition (V1 review @ `29bb371` → merged baseline `eee20cf`)

V1 review (8 docs + evidence) is preserved intact on local branch `review/marshall-integration-v1` (`29bb371`, parent `b56c082`). It is not on any remote — draft-PR publication is blocked (no push access to the mission repository from this workspace; pushing to an unrelated remote would be wrong). Nothing was fabricated: all material below comes from the preserved review plus re-trace against `eee20cf` (implementation byte-identical to `b56c082`, so every file:line reference still holds).

## Disposition

| ID | V1 status | Now | Notes |
|----|-----------|-----|-------|
| MAR-REV-001 (batch fan-out bypasses global cap) | CONFIRMED FOLLOW_UP | **Still open** — code unchanged (`src/server.rs:874–881`, `src/registry.rs:203–243`). Live measurement pending in this mission (Phase 4). → M2-001. | Load-bearing for production claims. |
| MAR-REV-002 (batch tasks survive disconnect) | CONFIRMED FOLLOW_UP | **Still open** — unchanged. → M2-004 scope (cancellation). | |
| MAR-REV-003 (quota charges requests, not work) | CONFIRMED FOLLOW_UP | **Still open** — unchanged. → M2-001 adjacent. | |
| MAR-REV-004 (per-step session path gap) | SUSPECTED FOLLOW_UP | **Upgraded to CONFIRMED-by-trace** against `eee20cf`: no-top-level overrides call existence-only `require_session` (`:908–920`, `:994–1002`); tool layer is workspace-rooted so the request executes (PoC: single → 403 vs batch/sequence → 200, trace-airtight, runtime execution pending). Extended: `..` lexical bypass, symlink-across-sessions, `working_dir`/non-`path` keys unchecked, batch/sequence override asymmetry (`:903` vs `:989`). → M2-002. | Strongest M2 input; acceptance tests drafted in `03`. |
| MAR-REV-005 (batch/sequence strip idempotency keys) | CONFIRMED FOLLOW_UP | **Still open** — `:921–922`, `:1011–1012` unchanged. Extended: global key-only namespace, silent conflicting-payload replay (pinned by existing test `:1291–1327`, which the new contract must update), arbitrary eviction order, check-then-act race. → M2-005. | |
| MAR-REV-006 (audit/metering semantics) | CONFIRMED DOCUMENTATION | **Still open** — `:600–603`, `:635`, `:785`/`:1066` vs `:923`/`:1013` unchanged. Needs operator-doc paragraph; optionally `denied_total`. | Must precede any production claim. |
| MAR-REV-007 (WASM `stdout_truncated`) | CONFIRMED FOLLOW_UP | **Still open** — unchanged. Small fix, no M2 dependency. | |
| MAR-REV-008 (WASM cancellation leak) | CONFIRMED FOLLOW_UP | **Still open** — unchanged. Overlaps M2-004 (generalize to process groups). | |
| MAR-REV-009 (Python SDK packaging) | CONFIRMED FOLLOW_UP | **Still open** — verify on `eee20cf` during validation (re-check `pyproject.toml`). Blocks external SDK release only. | |
| MAR-REV-010 (Python delete URL-encoding) | CONFIRMED FOLLOW_UP | **Still open** — unchanged. | |
| MAR-REV-011 (error-shape inconsistency) | CONFIRMED FOLLOW_UP | **Still open** — unchanged. | |
| MAR-REV-012 (stale watchdog wording) | CONFIRMED DOCUMENTATION | **Still open** — `limits.rs`, `backend.rs:696`, `README.md:168`, `DEPLOYMENT.md:144`, `shell.rs:233/239` unchanged. | |
| MAR-REV-013 (unused wasmtime-wasi/cap-std) | FOLLOW_UP | **Still open** — unchanged. | |

## Resolved by subsequent commits

None. The merged implementation is byte-identical to the reviewed integration commit, so no finding was resolved by merging. (The V1 gate status CHANGES_REQUIRED therefore carries over as the starting posture of this mission.)

## Accuracy of the V1 review against the merged tree

Accurate in full: every cited file:line, reproduction, and test reference re-resolves against `eee20cf`. The one status change (MAR-REV-004 suspected → confirmed-by-trace) strengthens rather than corrects the review. No V1 claim was contradicted.
