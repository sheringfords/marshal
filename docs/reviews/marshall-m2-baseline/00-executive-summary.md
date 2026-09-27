# Executive Summary — M2 Baseline Reconciliation V1

- Current SHAs (reverified by fetch): `origin/main` = `eee20cf982562959b4da489cb5f5e6f190e2dabd`; `origin/hardening/production-readiness` = `32d0aae86cbe0560490b2402e44991ba82c61865`. Local tracking branches were stale and left alone.
- PRs #1–#5 all merged; PR #6 (integration) and PR #7 (hardening→main) complete the history. PR #4's remote head is merge-polluted but the merged content is correct.
- `origin/main` vs `origin/hardening`: **identical trees**. Both equal verified integration `b56c082` + audit docs (11 implementation files hash-identical). Merges added no unreviewed code.
- **Authoritative M2 baseline: `origin/main` @ `eee20cf`.**
- V1 review (`29bb371`, local only) preserved in full; findings re-traced, none resolved by merging. Draft-PR publication blocked (no push access to mission repo).
- Full validation on exact baseline: fmt, clippy (±wasm), lib 131, doc 1, escapes 14, server 43, stress 1, experiment-validation 17, wasm lib 136, JS SDK 4, Python SDK 4, `cargo deny` — **all green**. Both SDKs also exercised live against an authenticated daemon (+ tokenless compat).
- Live reproductions: MAR-REV-001 (8 children under 1 permit at `concurrency: 1`; second request 503) and MAR-REV-004 (single → 403 vs batch/sequence → 200 with file content).
- No production code changed or merged. No M2 implementation started.

**M2 readiness: M2_BLOCKED** — baseline verified and slices defined (M2-001–005 with acceptance tests and dependency map), but P1 defects (workload-unbounded concurrency, session boundary, TOCTOU, process-tree) are confirmed open and must be implemented before any production claim. The block is on the defects, not on the baseline: development may start from `eee20cf` per the plan in `06`.
