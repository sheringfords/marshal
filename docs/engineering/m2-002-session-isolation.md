# M2-002 — Session Isolation at the Tool Boundary

Branch: `fix/marshall-m2-session-isolation`, base `main` @ `3e4bc64`
(PR #9 / M2-001 included; primary worktree synced with `--ff-only`).

## Baseline and original vulnerability reproduction (MAR-REV-004, P1)

Before the fix, on `3e4bc64`: single `execute` with a session rejected
workspace-outside-session reads (403), while batch/sequence with only a
per-item session ID executed them (200 + file content) — per-step overrides
without a top-level session called existence-only `require_session`, never a
path check. Lexical `starts_with` additionally admitted `<root>/../shared`
and symlinks landing outside the root. 8 of 11 new regression tests failed
pre-fix (3 passed as existing-guard controls); all 11 pass post-fix.

## Session isolation contract

- A session maps to `<workspace_root>/<uuid>`, created server-side; the root
  is derived exclusively from trusted session state, never caller input.
- No session ID → unchanged workspace-scoped behavior.
- Effective session per item = per-item override if present, else top-level.
  The contract is identical on batch and sequence: paths are checked against
  the *effective* session only. Cross-session access is deny-by-default with
  no grant mechanism in this slice.
- Every execution endpoint applies the same admission (edge → workload →
  session → egress) plus execution-time tool enforcement; denial shape is
  uniform (`403 path_not_allowed`, `404 session_not_found/expired`).
- Policy hot reload swaps the registry/egress list only; the sessions table
  (absolute per-session roots) is untouched, so reload cannot expand existing
  session permissions.
- Trust boundary: session scoping is filesystem access control *within the
  daemon's OS privileges*. It is not OS-level isolation, process isolation,
  or multi-tenant isolation: shell operands, locally executed code, and
  symlinks raced between check and I/O are constrained as documented below,
  not contained.

## Implementation and trust boundaries

- `src/server.rs`: `check_session_path` now resolves through the session's
  own `Sandbox` (canonical, symlink-aware) instead of lexical prefix;
  `{{`-templates skip admission (tool enforces resolved values); shell
  `working_dir` checked; batch/sequence unified on effective session;
  caller-supplied `__session_root` stripped pre-admission and the trusted
  canonical root injected post-admission (`bind_session_scope`, fail-closed
  on lapsed sessions) for `filesystem` items on all four endpoints.
- `src/fs.rs`: `__session_root` enforced in `validate()` and on every
  re-resolved path in `execute()` (read/write/append/copy/move/delete/mkdir/
  patch/stat/list/search/glob/exists, both ends of copy/move); search/glob
  walks filtered to effective roots; session-root self-delete/move refused;
  `exists` probes outside the scope denied rather than reported absent.
- `src/registry.rs`: untouched — scope flows in args (survives sequence
  templating); M2-001 workload accounting preserved verbatim.
- Shell operands (`cat /etc/passwd` via allowlisted binaries) and the `code`
  tool are *not* session-confined: allowlisted shell runs workspace-wide and
  `code` runs unsandboxed when enabled. Session scoping covers the
  `filesystem` tool plus shell `working_dir` only — anything stronger is
  M2-003/M2-004 or a new backend.

## Regression tests (tests/server.rs, 11 new; server suite 58 total)

Per-item batch/sequence scoping; override-wins contract parity;
cross-session read/write; `..` traversal (single + stream); symlink escape;
copy/move both ends; search/glob scoping + no cross-session enumeration;
shell `working_dir`; absolute registry-independent roots; concurrent
batches. 8 of 11 failed pre-fix (reproducing MAR-REV-004 and its
traversal/symlink/cwd extensions); all 11 pass post-fix. Existing M2-001,
escape, audit and parity suites untouched and green.

## Live integration verification (patched daemon, token auth)

- Single/batch/sequence read outside session → 403 (batch/sequence were 200
  pre-fix — the original vulnerability, now eliminated on all endpoints).
- Forged `__session_root: "/"` in caller args → 403 (forgery ignored).
- In-session batch read+list and sequence write→read → all success;
  executed/total accounting intact.
- Full matrix: fmt, clippy (±wasm) PASS; lib 135, doc 1, server 58,
  escapes 14, stress 1, experiment-validation 17, wasm-lib 140, JS SDK 4,
  Python SDK 4, all green. `cargo deny` fails on a pre-existing rustls TLS
  advisory also present on clean `main` (environmental, unrelated).

## Remaining security limitations

- TOCTOU between scope check and I/O (M2-003): check-then-act on all
  platforms except Linux `read` via `openat2`. A raced symlink swap can
  still redirect I/O; the scope check narrows *what may be named*, not the
  race itself.
- Process tree (M2-004): kills direct child only.
- Idempotency namespace/payload binding (M2-005): unchanged; a replayed key
  replays the cached outcome regardless of session.
- No per-caller session ownership: any holder of a session UUID (same
  trust domain) may use it — UUID secrecy is not the boundary; the root
  binding is. Shared-token deployments share the session table.

## Follow-up dependencies

M2-003 (descriptor-retained I/O generalizes the scope check), M2-004
(process groups), M2-005 (session-bound keys). None required for this slice.
