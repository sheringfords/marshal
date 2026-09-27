# M2 Engineering Backlog

Source: V1 findings (preserved in `04-review-finding-disposition.md`) re-traced against `eee20cf` + two read-only deep analyses (session/idempotency, TOCTOU/process-tree). No implementation performed.

## M2-001 — Workload-bounded concurrency (from MAR-REV-001/002/003)

- Requirement: global limits must account for actual concurrent executions, not only incoming HTTP requests.
- Scope: `src/server.rs:874–881` (1 permit per batch, `max` ≤ 32), `src/registry.rs:203–243` (request-local semaphore + detached `tokio::spawn`), quota (`src/server.rs:182–206`, `src/ratelimit.rs`) charging 1 token per request.
- Acceptance: with `concurrency: 1`, a `max_concurrency: 32` batch is rejected or observably serialized; concurrent child count ≤ cap under batch load; batch consumes >1 quota token (or a dedicated in-flight workload counter exists); disconnect mid-batch aborts detached tasks (no further audit lines, no live children).
- Dependencies: none on other M2 items. Overlaps files with M2-004 (registry batch structure) — sequence accordingly (M2-001 first, M2-004 builds on its cancellation scope) or assign both to one workstream.

## M2-002 — Session isolation (from MAR-REV-004)

- Requirement: session identity must be enforced at the actual filesystem operation boundary, including batch and sequence overrides.
- Scope: `src/server.rs:548–571` (`check_session_path`: `path`/`destination` keys only, lexical `starts_with`, no canonicalization), `:908–920`/`:994–1002` (no-top-level overrides skip path check), `:903` vs `:989` asymmetry, `working_dir`/shell operands/code snippets unchecked; `src/fs.rs` + `src/sandbox.rs` workspace-rooted enforcement.
- Acceptance (8 tests drafted in `03-security-and-concurrency-findings.md`): per-step overrides path-checked with and without top-level session; top-level scoping pinned; batch/sequence override contract unified; `..` escape rejected; symlink escape rejected; shell `working_dir` scoped; `destination` key covered via overrides.
- Dependencies: none. Can run concurrently with M2-001/004/005 (different files: `server.rs` admission vs `registry.rs` vs `fs.rs` — note M2-002 touches `server.rs` admission only, M2-003 touches `fs.rs`/`sandbox.rs`; safe to parallelize).

## M2-003 — Filesystem TOCTOU protection (pre-existing MAR-P1-002, confirmed)

- Requirement: use descriptor-relative operations where supported and prevent path replacement between authorization and I/O.
- Scope: `src/fs.rs` (validate-then-re-resolve-then-path-I/O for write/append/mkdir/copy/move/patch/delete; only Linux `read` is fd-backed via `openat2`), `src/sandbox.rs:146–327` (resolve-fd dropped after `readlink`; no `WRONLY|CREAT` writer).
- Acceptance (3 tests drafted): symlink-swap racer yields zero out-of-root writes across all mutating ops; descriptor-relative I/O on Linux (read precedent `sandbox.rs:242–274` generalized to writes); non-Linux residual risk documented, never silent escape.
- Dependencies: independent of M2-001/002/004/005 (files `fs.rs`/`sandbox.rs` touched by no other item). Parallelizable.

## M2-004 — Process-tree termination (from MAR-REV-002/008, pre-existing MAR-P1-003, confirmed)

- Requirement: timeouts and cancellations must terminate the entire execution process group and reclaim resources.
- Scope: `src/backend.rs:190–286` (`kill_on_drop` = direct child only; no `setsid`/`killpg`; zero hits in `src/`), `src/registry.rs:225` (detached batch tasks), `src/server.rs` SSE/batch/sequence disconnect paths, WASM blocking-thread leak (`backend.rs:542–554`).
- Acceptance (2 tests drafted): `setsid` grandchild dead within grace after timeout; disconnect mid-batch leaves no live children and no post-disconnect audit growth.
- Dependencies: builds on M2-001's batch cancellation scope if M2-001 does that first; otherwise include it here. WASM half (MAR-REV-008) can ride along or stay separate.

## M2-005 — Idempotency correctness (from MAR-REV-005, extended)

- Requirement: keys must be namespaced and bound to canonical request identity. Conflicting payloads must be rejected.
- Scope: `src/registry.rs:42–48`, `:164–196` (global key-only map, silent replay, success-only caching, arbitrary eviction, check-then-act race), `src/server.rs:921–922`/`:1011–1012` (batch/sequence strip keys).
- Acceptance (5 tests drafted): key bound to tool + args (+ session per design); conflicting payload → re-execute or `409`, never silent replay (existing test `:1291–1327` updated to new contract); per-item keys honored in batch/sequence; deterministic eviction + TTL.
- Dependencies: independent files (`registry.rs` + server key plumbing). Coordinate with M2-001 on `registry.rs` batch structure to avoid merge conflicts (same file, adjacent lines) — prefer sequencing M2-001 before M2-005, or one owner for both.

## Non-M2 follow-ups (fast track, no M2 dependency)

MAR-REV-006/012 (docs), MAR-REV-007 (WASM truncation flag), MAR-REV-009/010/011 (SDK packaging + errors), MAR-REV-013 (unused deps). None blocks M2 slicing.
