# M2-003 — Filesystem Safety

Baseline: `main` @ `57f7303` (PRs #9 M2-001 and #10 M2-002 merged; verified by
fetch + ff-only sync of the clean primary worktree). Branch:
`fix/marshall-m2-filesystem-safety`. No worktrees created; target cache
reused; no `cargo clean`.

## Verified baseline

`origin/main` = `57f7303d328b5f8033bae6e7d52a2a6eed861238` (matched expected
SHA). History contains PR #9 (M2-001 workload concurrency) and PR #10
(M2-002 session isolation). Implementation started from that SHA; no
unrelated work touched (`git status` shows only `src/fs.rs`,
`src/sandbox.rs`, `tests/server.rs`, `tests/toctou.rs`,
`docs/engineering/m2-003-filesystem-safety.md`).

## M2-002 security review (P0 gate — passed, no blocking bypass)

- Original batch/sequence bypass re-verified fixed: 11/11 session tests green
  on merged main before any M2-003 change; full server suite green.
- `__session_root` propagation traced end to end: strip pre-admission →
  admit against session sandbox → inject canonical root from session table →
  enforce in `FileSystemTool::validate` + every execution path.
- Direct registry calls: omitted key → workspace-sandbox behavior
  (documented trusted-local contract); forged absolute key → still confined
  by the tool sandbox (cannot widen past it, only narrow); malformed key →
  now fails closed (`Scope::Malformed` denies everything; previously read as
  no-scope). New fs unit tests pin all three.
- Templated sequence paths: covered by execution-time enforcement; new test
  proves an outside path smuggled via `{{steps[0].stdout}}` is denied with
  the effective session scope.
- Session expiry mid-execution: scope is bound post-admission from live
  state; a lapsed session fails closed at injection; mid-batch expiry leaves
  absolute-root operations that fail on the swept directory (documented).
- M2-001 interplay: untouched (scope is per-item data; permits orthogonal).
- Decisions: the HTTP server is authoritative for network execution context;
  direct library callers get the documented trusted-local contract; a typed
  `ExecCtx` is deferred (forgery cannot exceed the sandbox backstop, so it is
  not a prerequisite); session IDs are NOT bound to caller identities
  (shared token ⇒ shared session table) — documented limitation.

## Original TOCTOU reproductions (`tests/toctou.rs`, new)

Racer alternates a directory between real and symlink-to-outside (plain
rename cannot replace a non-empty dir with a link, so the cycle is
remove-and-recreate). Pre-fix evidence: `write` escaped the workspace root
AND the session scope (failed tests recorded); `append` did not align in the
sampled runs (kept as post-fix guard). Single-path ops re-resolve before use,
so the exploitable shape is intermediate-directory replacement between the
two resolves, plus un-re-resolved uses (search-walk stack, glob strings).
All fixtures under temp dirs, removed on drop. Post-fix: 4/4 pass.

## Architecture decision (BoundDir)

- `Sandbox::resolve_*` stays for error classification (workspace + scope,
  canonical); all I/O moves to `BoundDir` (new, `src/sandbox.rs`): bind the
  containing root once per op, walk/operate on retained `OwnedFd`s.
- Intermediates: never traversed through symlinks for creates; followed only
  through per-level open-then-verify (true path via `/proc/self/fd` or
  `F_GETPATH`) for reads — preserving in-root-link semantics race-free.
- Final create-target leaves: `O_NOFOLLOW`/`O_EXCL` semantics, fail closed on
  links (documented changes: write/append/mkdir/copy-dest/move-dest no longer
  traverse trailing links; move-source links are renamed as links, POSIX
  `mv` semantics, instead of moving the target).
- Linux: `openat2(BENEATH|NO_SYMLINKS|NO_MAGICLINKS)` for opens, `ENOSYS`
  falls back to the identical no-follow `openat` walk (documented, never
  path-based). Other platforms: `openat` walk + `F_GETPATH` verification
  (best-effort documented; no true BENEATH primitive).
- Descriptors are per-operation RAII: errors and cancellation release
  everything; no shared fd caches, no new `unsafe` (one pre-existing
  `BorrowedFd::borrow_raw` site untouched).
- Read-your-writes: tokio's `File` acknowledges `write_all` once bytes reach
  its in-memory buffer while the kernel write runs on a spawned task, so
  every content mutation ends with `flush()` before success is reported.
  Without this, success + immediate read races the background task under
  load (reproduced as empty files in the test suite; root-caused via tokio's
  `poll_write` source, fixed, 8/8 stable). `flush` gives kernel acceptance
  (same-host coherence, matching one-shot-write semantics), not disk
  durability — no `fsync` cost added.
- Quota/concurrency/audit/metrics paths untouched.

## Operation containment matrix

| op | mechanism | guarantee |
|----|-----------|-----------|
| read/stat | verified open + fd read/fstat | swap-proof both platforms |
| write/append | nofollow create-target open + fd write; append O_APPEND (also fixes lost-update) | swap-proof; trailing-link write now denied (was: followed) |
| mkdir -p | per-level mkdirat + verified reopen | swap-proof; trailing-link mkdir now denied |
| delete | NOFOLLOW classify + unlinkat / recursive fd removal | swap-proof; same shapes incl. root refusal |
| copy/move | verified src open + nofollow dest + dev/ino same-file check / renameat between pinned parents; dest links refused | swap-proof; dest-link and move-src-link semantics tightened (documented) |
| patch | verified O_RDWR fd; read/truncate/rewrite on the descriptor | swap-proof |
| list/search/glob | Dir-fd traversal, verified descent, verified file opens | swap-proof enumeration; same shapes/counts |
| exists | NOFOLLOW stat + readlink-against-true-parent for links | same true/false/deny shapes |

## Implementation details

- `src/sandbox.rs` (+~470): `BoundDir`, `BoundError`, leaf validation, verified
  descent, verified/no-follow opens, mkdir/unlink/rename/stat/read_dir, true-path
  verification, plus 6 deterministic unit tests.
- `src/fs.rs` (+~700 net): scope tri-state (`Scope::Malformed` fails closed),
  `bind_for`, per-op fd execution for all 13 operations, `search_fd` /
  `glob_fd` traversal helpers, `file_flush` read-your-writes barrier.
- `tests/toctou.rs` (new): 2 swap-race tests (workspace + session), append
  race guard, concurrent-scoped-writes test, Linux fd-stability test.
- `tests/server.rs` (+62): templated-path session test.
- `src/fs.rs` unit tests (+4): omitted/forged/narrow/malformed scope contract.
- Superseded code removed: path-based `read_file_capped`, Linux-only
  `open_existing_file`/`openat2_open_file` (callers migrated to `BoundDir`).

## Linux and macOS verification

- macOS (this host): full matrix green; swap races hold via the portable
  no-follow walk + `F_GETPATH` verification; fd-count test compiles but
  skips (no `/proc`).
- Linux: `openat2` paths compile (`cargo check`/`clippy --features wasm`
  cover the `cfg(target_os = "linux")` arms on macOS only for syntax —
  full type-checking of those arms requires a Linux target).
  Runtime verification of `RESOLVE_BENEATH` enforcement, the fd-count test,
  and the race suite under a Linux kernel is REQUIRED before release
  claims (CI runner). The portable walk is the guarantee floor everywhere;
  `openat2` is defense in depth, not the sole mechanism.

## Adversarial regression results

- Pre-fix: workspace + session write races escaped (failed-test evidence).
- Post-fix (macOS): 4/4 race tests pass repeatedly; 6/6 BoundDir unit tests;
  lib suite 8/8 consecutive green (previously ~25% flake from the tokio
  buffering issue the flush barrier fixed — itself a read-your-writes
  hardening independent of TOCTOU).
- No existing escape, session, concurrency, or SDK regression.

## Remaining limitations

Shell operands, `code` tool, process tree (M2-004), idempotency namespace
(M2-005), no per-caller session ownership, hard-link aliasing, macOS
best-effort (no BENEATH primitive), pre-`openat2` kernels (loud fallback).

## Dependencies for M2-004 and M2-005

- M2-004 (process tree): unaffected by this slice; timeouts still kill the
  direct child only. Note: fd-retained files make post-kill cleanup safer
  (no half-written renames), but grandchildren remain M2-004 scope.
- M2-005 (idempotency): cache keys still bind neither scope nor payload;
  a replayed key replays across sessions. Unchanged by this slice.


## Full integration-test matrix (this branch, macOS host)

fmt PASS; clippy PASS (±wasm); lib 145 (135 + 6 BoundDir + 4 scope);
server 59 (47 + 11 session + 1 template); toctou 4; escapes 14; doc 1;
stress 1; experiment-validation 17; wasm-lib 150; JS SDK 4; Python SDK 4.
`cargo deny` fails solely on pre-existing RUSTSEC-2026-0285 (rustls 0.23.43
via reqwest; reproduced on clean main; no dependency changes in this PR).
Linux-only tests (fd-count) skip on macOS; Linux race/guarantee verification
requires a Linux runner (CI) — the openat2 paths compile under
`--features wasm` and `cargo check` but their runtime behavior is unverified
here. Live daemon: single/batch outside-read 403 (was 200 pre-M2-002),
in-session sequence write→read success, forged scope ignored.
