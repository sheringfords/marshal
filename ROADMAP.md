# Roadmap

## Where this stands

Marshall is a Rust library and an HTTP service that put agent tools behind
explicit policy. The library is good: `src/destination.rs` handles SSRF more
carefully than most things that claim to, `src/sandbox.rs` closes both of the
escapes it was extracted from, and redaction-by-default means the cheap thing to
do with an outcome — log it — is also the safe thing.

248 tests: 131 lib (166 with `--features experiment`), 14 escapes, 32 server,
17 validation, 1 stress. `cargo clippy --all-targets -D warnings`, `cargo fmt`,
`cargo audit`, and `cargo deny` all clean, all blocking in CI.

**Not yet production-ready for untrusted callers.** The gap is isolation, and
it is a real one: see [Isolation](#1-isolation-the-actual-blocker).

## What is honest about the current state

| | Status |
|---|---|
| Policy correctness (paths, hosts, commands) | Good. Tested as attacks, not assertions. |
| Auditability | Good. Digests not payloads, stable error codes, `redaction_policy_version` on every record. |
| Service hardening | Adequate. Auth, quotas, admission control, closed defaults, tested. |
| OS-level isolation | **Absent.** Policy is enforced in-process. |
| Multi-tenancy | **Absent.** One token, one trust domain. |
| Durability | **Absent.** Agent state is in-memory. |
| Release engineering | **Absent.** No tags, not published, one unpublished dependency. |

---

## 1. Isolation — the actual blocker

Every tool enforces policy in-process, with no seccomp filter, namespace, or
chroot. A bug past the policy has the daemon's privileges. The README has always
said so; what changed is that the consequences are now visible in the config
file rather than only in prose.

The `code` tool made this concrete. On the local backend it reads any file the
daemon can read and reaches any host the daemon can reach, so enabling it turned
`filesystem` and `http` policy into decoration. It is now off by default and
refuses to enable without `code.allow_unsandboxed: true`. That is a guardrail,
not a fix.

**The fix is to stop trying to be an isolation product.** E2B, Modal, Daytona,
and every Firecracker-based runner solve isolation better than this codebase
will, and they are funded to keep doing so. The defensible position is the layer
in front: policy, allowlists, and an audit trail that survives review.

Concretely:
- [ ] `ExecutionBackend` implementations for E2B and Firecracker-as-a-service,
      so `code` and `shell` run somewhere else and Marshall stays the thing
      that decides whether they may run at all.
- [x] Remove or publish `watchdog`. Removed: the pinned revision exposes a
      cgroup-supervisor API, not the Firecracker `Pool`/`Config` API the code
      called, so the `container` feature never compiled; the silent local
      fallback was a downgrade. `ContainerBackend` now fails closed with
      `isolation_unavailable` (MAR-P0-002).
- [ ] Retain the `openat2` descriptor for the subsequent I/O. Today it is
      resolved, converted through `/proc/self/fd`, and dropped, which leaves a
      check-then-use window that `RESOLVE_BENEATH` was meant to close.
- [ ] Decide about `NoFlags`. It documents itself as a heuristic and it is one:
      a binary that treats a bare positional as a script is still exploitable.
      Either per-binary profiles, or drop it for interpreters.

## 2. Tenancy

Quotas are per client, and clients are told apart by a digest of their bearer
token — but there is one token, so in practice there is one client.

- [ ] Multiple credentials with per-credential policy: a token names a scope,
      a workspace, and a quota. This is the smallest change that turns "an
      executor" into "an executor several teams can share".
- [ ] Store token hashes, never tokens. The comparison is already constant-time;
      the store should not hold anything worth stealing.
- [ ] Scope `process_kill` to session children. It currently signals any pid the
      policy permits.

## 3. Durability

`memory`, `todo`, and `plan` are `RwLock<HashMap>` in process. A restart wipes
agent state mid-task, which for a long-running agent is worse than an error —
it is a silent loss.

- [ ] SQLite behind the session store, or JSONL snapshots per session.
- [ ] Audit log rotation keeps one generation (`.jsonl.1`). Ship to something
      durable, or say plainly that it is not a retention system.

## 4. Release engineering

- [ ] Publish to crates.io. There are no tags and no releases; the library
      cannot be depended on.
- [ ] Pick one repository. `Cargo.toml` now points at `rapture-fx/Marshall`,
      which matches the README badge, but `origin` is still
      `wiramahendra/execution-tool`.
- [ ] Finish `missing_docs`. `agent`, `backend`, `egress`, `error`, and `limits`
      still carry `#![allow(missing_docs)]`. `policy` and `code` no longer do.
- [ ] Publish an OpenAPI document. Two SDKs are maintained by hand against an
      undocumented API.

---

## Product

### The moat is not the sandbox

Everyone shipping an agent framework currently has tool execution with roughly
the security posture this codebase started with: string-prefix path checks and
blocklist SSRF. What almost nobody has is **policy plus auditability** —
allowlists, stable error codes, sha256-attested outcomes, a redaction policy
version stamped on every record. That is a compliance story, and it is the one
asset here that is hard to copy in an afternoon.

Lead with it. `src/destination.rs`'s table of "here's the bypass, here's why the
naive check misses it" is the best sales material in the repository.

### Three paths, in order of odds

**1. Open-source library, land in a framework.** Lowest effort, highest
strategic value. A Rust agent runtime adopting `marshall` for tool policy makes
it the default. The library is close: publish it, finish the docs, and write the
post that walks through the five SSRF spellings and the two sandbox escapes.

**2. Self-hosted policy gateway for regulated teams.** Fintech and health teams
running agents inside a VPC, where the audit trail is the sale. Needs tenancy,
durability, and the isolation composition above — three to six months.

**3. Hosted multi-tenant execution.** Don't. That is fighting funded incumbents
on their strongest axis with a single-tenant daemon and no isolation primitive
of its own.

### The next decision

Path 1 and path 2 share all their work; path 3 shares none of it. Nothing below
1.0 needs to choose between 1 and 2, which is a good reason to do both and defer
the question.

---

## Done

Kept short, because a roadmap is about what is next.

- **0.2.x hardening** — Fixed the policy loader failing open (an empty
  `code.allowed_languages` enabled every language; an empty `shell.commands`
  granted `echo` and `cat`). Stopped logging bearer tokens through
  `tracing::instrument`. Bind loopback by default and refuse an unauthenticated
  non-loopback bind. CORS same-origin unless configured. Per-client token-bucket
  quotas. Moved the daemon into the library and wrote the 32 endpoint tests it
  never had. Feature-gated the validation harness out of the public API. Fixed
  RUSTSEC-2026-0258. `Dockerfile`, `docs/DEPLOYMENT.md`, `deny.toml`, and a CI
  job that fails on any of it.
- **0.2.0** — Renamed `execution-tool` to Marshall. `SystemTool`.
- **Phases 0–5** — Policy-as-code with hot reload, egress proxy, session
  workspaces, batch and sequence execution, Prometheus metrics, JSONL audit,
  `openat2` path resolution on Linux, WASM and container backend scaffolding,
  JS and Python SDKs. See git history.
