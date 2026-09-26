# 08 — Proposed Engineering Plan

## Minimum production execution contract

For semi-trusted callers behind the gateway (the only posture the code supports today):

1. Every execution path enforces the same admission: auth → quota → concurrency → session → egress → audit → metrics.
2. At-most-once per idempotency key scoped to (tool, args); crash loss is explicit, never silent replay.
3. Timeouts kill the whole process tree within a bounded grace; tempfiles/sessions are reclaimed or explicitly orphaned-and-listed.
4. Audit contains one tamper-evident record per execution with no payload bytes.
5. `wasm`/`container` features compile and are covered in CI, or they do not exist.

## Priority order (confirmed defects first)

| # | Item | Finding | Size |
|---|---|---|---|
| 1 | Unify admission: one `admit_request()` for execute/batch/sequence/stream | MAR-P0-003 | S — one function + parity tests |
| 2 | Fix `wasm` build (imports, fuel var) + CI `--features wasm` job | MAR-P0-001 | S |
| 3 | Publish `watchdog` or delete `container`; explicit fallback signal | MAR-P0-002 | M (decision + cleanup) |
| 4 | SDK auth (`token` option both SDKs) + `deleteSession`/`getPolicy` | MAR-P1-004 | S |
| 5 | Canonicalized, all-keys session path check; document workspace model | MAR-P1-005 | M |
| 6 | Retain `openat2` fd for I/O; close write TOCTOU | MAR-P1-002 | M |
| 7 | Process-group kill on timeout | MAR-P1-003 | S |
| 8 | Namespaced idempotency keys; thread through batch/sequence or reject | MAR-P1-006 | S |
| 9 | `allow_unsandboxed` semantics at the README example, not just Security notes; error-code registry doc | DX | S |
| 10 | Single-resolution egress pinning; audit-summary secret scrub | Suspected | M |

## Retain

`destination.rs` + `sandbox.rs` + escape attack suite (the moat); redaction-by-default outcome shape; deny-by-default policy loader + `--validate-config` + hot-reload; batch/sequence semantics + single-pass templating; per-client quotas + 503 shedding; bearer/loopback/CORS defaults.

## Redesign

Isolation composition (delegate to E2B/Firecracker-as-a-service for untrusted `code`/`shell` instead of owning microVMs); multi-credential tenancy with hashed token store; durable session store (SQLite/JSONL snapshots); audit shipping beyond single-generation rotation; SDK architecture (auth, parity, publishable packaging).

## First slice (2–3 weeks, one engineer)

Items 1–4 above. Acceptance: (a) denial-parity test across all four execution endpoints; (b) `cargo check/clippy --features wasm` green in CI; (c) `container` decision recorded (publish or remove) with fallback test; (d) SDKs authenticate against a token-protected daemon in an integration test; (e) all existing suites stay green. Milestones after: session hardening + fd-retained I/O (M2); tenancy + durability design (M3); crates.io 0.3.0 + framework-landing post (M4).

## Kill criteria (explicit)

- No design partner runs the gateway in front of an existing sandbox within the slice → stop; hosted multi-tenancy is out of scope.
- Any P0 without an owner after the slice → no 1.0 claims, library-only positioning.
- If untrusted-code execution is required before an isolating backend exists → refuse the workload; policy-only is not isolation.
