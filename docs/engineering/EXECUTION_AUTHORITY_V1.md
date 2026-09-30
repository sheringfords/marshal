# Execution Authority V1 (baseline 65d2ccf, branch `refactor/marshall-execution-authority-v1`)

One typed execution identity — `ExecutionContract` — is now authoritative
from HTTP admission through registry dispatch to the tool boundary. Caller
arguments describe requested work; trusted authority is runtime state that
never appears inside those arguments.

## 1. Adversarial findings before implementation (Phase 1)

Regression tests were written first in `tests/authority.rs`, asserting
correct behavior. 9 failed pre-change (defects), 6 passed (already safe).
No defect below was fixed on inspection alone; each was reproduced.

### CONFIRMED_DEFECT (all reproduced, all fixed)

1. **Same key + different tool → silent cross-tool replay.** Registry and
   HTTP: `execute_once("k", beta)` returned alpha's outcome; beta never ran
   but the caller was told it did.
2. **Same key + different arguments → silent replay.** A second filesystem
   write with different content returned the first outcome; the write never
   happened. The pre-existing `server.rs` idempotency test *enshrined* this
   (rewritten in this slice to the conflict semantic).
3. **Same key across sessions → cross-session replay.** Session B's write
   returned session A's outcome; B's file was never created.
4. **Stream shares the broken identity.** Conflicting reuse through
   `/v1/execute/stream` replayed instead of conflicting.
5. **No single-flight: N=16 concurrent identical same-key calls executed
   16 times.** `execute_once` dropped the map mutex before executing; the
   "second check" only deduplicated the cache insert, never execution.
6. **N=16 concurrent conflicting same-key calls produced 16 side effects**,
   with losers handed the winner's foreign outcome.
7. **Sequence-templated `working_dir` escapes the session.** Step 0 reads a
   planted pointer file; step 1 `shell` with
   `working_dir: {{steps[0].content}}` ran `/bin/pwd` with cwd at the
   workspace root — outside the session. Admission skips `{{…}}` values and
   the shell tool had no session concept, so nothing checked the resolved
   directory. This was the only true privilege-boundary bypass found.

### NOT_REPRODUCED (already safe, kept as regressions)

- Forged `__session_root` in caller JSON: stripped pre-admission, inert.
- Cross-session filesystem read/write via single execute: denied.
- Sequence-templated filesystem path: denied at execution time (the old
  scope-key check already covered resolved values).
- Concurrent batch with mixed per-item sessions: denied whole-request at
  preflight, zero side effects.
- Swapped-registry execution of bound args: still confined (scope traveled
  with the args even before; now with the contract).
- Identical-key-identical-work replay without re-execution: correct, kept.

## 2. Final `ExecutionContract` (`src/execution.rs`)

```rust
pub struct ExecutionContract {
    execution_id: String,       // private; read via execution_id()
    scope: ExecutionScope,      // private; read via scope()
    request_fingerprint: String,// private; read via request_fingerprint()
    policy_identity: String,    // private; read via policy_identity()
}
```

Fields are private with read-only accessors; fingerprint minting
(`fingerprint()`) is private to the module. The only public constructors,
`admit` and `local`, always derive the fingerprint from exactly the tool,
arguments and scope they are given, so a contract can never disagree with
the call it was built for. The registry executes the single
[`ContractedCall`] unit (tool + args + contract) rather than accepting the
three independently — `ContractedCall::new` admits the contract internally
from exactly the tool, arguments and scope the call carries, and the
contract field itself is private. There is no public constructor that takes
an independently built contract, and the only argument-substitution path
(`with_args`, sequence template expansion) is `pub(crate)`. The call's
`tool` and `args` fields are likewise private: after construction,
external callers cannot change any value covered by the request
fingerprint. Read-only `tool()`, `args()` and `contract()` accessors
cover legitimate inspection; ownership (destructuring) happens only
inside the registry module, and no public setter or mutable reference to
tool, args, contract, fingerprint, scope or policy identity exists. A
contract/call mismatch is therefore unrepresentable through the public
API — not validated-away, but inexpressible. Trusted library callers
keep the explicit `ContractedCall::local` / `ExecutionContract::local`
Workspace APIs.

Execution identity vs request occurrence: every admission mints a fresh
`execution_id` (a carrier for that attempt), but the *execution* identity
is the origin id — the first actual side effect's id, which every replay
references. V1 introduces no separate attempt/request identifier: a fresh
run reports `replayed: false` with its own id as origin; a retry reports
`replayed: true` with the stored origin id.

Why each field exists (every field has a consumer in this slice):

- `execution_id`: minted at admission (`admit`), shared by dispatch,
  replay matching and audit. Replays reuse the *original* id — a replay
  never mints a side effect, so it never mints an id for one.
- `scope`: the only authority the filesystem and shell boundaries read.
  `Session(root)` confines; `Workspace` is the *explicit* trusted-local
  grant for session-less and direct-library calls. There is no absent
  scope, so absence-by-accident is unrepresentable.
- `request_fingerprint`: `sha256(canonical(tool, scope, args))`, computed
  at admission. The replay identity (key + fingerprint) and the conflict
  signal. Excludes volatile `execution_id` so retries join; includes scope
  so cross-session/cross-tool/cross-argument reuse conflicts.
- `policy_identity`: content hash of the effective `ExecutionPolicy`,
  computed in `build_registry_from_policy` and carried on the registry
  snapshot; `ADHOC_POLICY_IDENTITY` for hand-built registries. Consumer:
  audit (answers "under which rules did this run").

Constraints honored: immutable after admission; no principal/tenant; no
permits or handles; never serialized into caller JSON.

## 3. Before / after authority flow

Before: `admit (session table) → strip key → inject __session_root into
args (fs only) → registry (name, args) → tool reads scope from JSON`.
Shell `working_dir` had *no* execution-time scope at all; only admission
preflight (which skips templates) constrained it.

After: `admit (session table + egress) → ExecutionContract::admit(scope,
tool, args, registry.policy_identity) → ContractedCall{tool, args,
contract} → registry.execute_with / execute_batch / execute_sequence →
tool.execute_with(ctx, args)`. Admission preflight is unchanged (still
denies unresolved-bad values early); the boundary enforces the contract on
*resolved* values, so templated paths and working dirs get exactly the
step's authority — no more, no less.

## 4. Removed JSON authority machinery (deleted, not wrapped)

- `SESSION_SCOPE_KEY` const, `strip_scope_key`, `bind_session_scope`
  (`src/server.rs`).
- `Scope` enum, `scope_state`/`scope_root`/`check_scope_wellformed`
  (`src/fs.rs`); all scope helpers now take `Option<&PathBuf>`.
- Production references to the key/strip/bind/scope-from-JSON: **29 → 0**
  (`server.rs` 12 → 0, `fs.rs` 17 → 0; the remaining `session_scope_root`
  is the session-*table* lookup feeding contract binding, and the only
  `__session_root` literals left are inert-key test payloads).
- Direct `Tool::execute` can no longer manufacture scope: it runs explicit
  trusted-local (tool sandbox bounds) and never reads scope-looking JSON.

Compatibility path: `Tool::validate`/`execute` keep working; new default
`validate_with`/`execute_with` delegate to them. Only filesystem and shell
override. `ContractedCall::local` / `ExecutionContract::local` give direct
library and experiment-harness callers an explicit Workspace contract.

## 5. Replay fingerprint contract

- Identity = `(idempotency_key, request_fingerprint)`.
- Canonical JSON sorts object keys recursively at every level, so insertion
  order cannot change the digest; the digest is hex sha256 (no caller
  material, safe to log).
- Semantics: same key + same fingerprint after success → REPLAY (original
  outcome, original execution id, `replayed: true`); same key +
  different fingerprint → `idempotency_conflict`, HTTP 409 on
  `/v1/execute`, SSE `error` event on `/v1/execute/stream`, zero execution;
  different key + same work → independent execution; failure/unsuccessful
  outcome → never cached, retry re-executes (unchanged).
- TTL (300s) and capacity (1024 completed outcomes) preserved; capacity now
  counts completed outcomes only and evicts oldest-first instead of
  arbitrary entries.
- Wire format unchanged: `idempotency_key` stays a top-level request field;
  batch/sequence never took keys (unchanged).

## 6. Single-flight design (`ToolRegistry::execute_once`)

State per `(key, fingerprint)`: `InFlight{notify: Arc<Notify>}` or
`Done{outcome, inserted}`. Exactly one caller inserts `InFlight` and
becomes executor; identical concurrent callers subscribe via
`Notified::enable()` *before* re-checking (no lost wakeup), then await the
same result. Conflicting same-key callers fail immediately — they never
wait and never execute. The map mutex is `std` (critical sections are
synchronous map work only) and is never held across tool execution, so
different keys stay fully concurrent.

- Executor success → `Done` + `notify_waiters`; failure/tool-error →
  marker removed, waiters retry as new executors (failure semantics
  unchanged).
- Cancellation/panic: an `InflightGuard` (RAII, `Drop` re-locks briefly
  and notifies unless disarmed) removes the marker on unwind or abort, so
  waiters deterministically wake and one retries. Proven by
  `cancelled_executor_releases_waiters_to_retry` (abort mid-flight →
  waiter completes, exactly 1 execution, 5s wedge-timeout).
- Eviction never touches `InFlight` (evicting would strand waiters into
  parallel executors); in-flight markers are bounded by live concurrency.
- Required test: 16 simultaneous identical requests → counter ends at 1;
  16 conflicting → 1 side effect, 1 winner + 15 conflicts
  (`tests/authority.rs`).

## 7. Dynamic path enforcement results

- Filesystem: all 15+ resolve sites now take the contract root; descriptor
  binding (`bind_for`) pins the session root at open time (Linux
  descriptor path retained). Templated escape test denies after expansion.
- Shell: `parse_with` resolves `working_dir` against the tool sandbox as
  before, then requires containment in the contract root when the value is
  explicit (both canonical → component-wise). The proven escape now denies
  with `path_not_allowed` at validation *and* execution.
- Deliberately unchanged: a session-scoped shell call *without*
  `working_dir` still inherits the daemon cwd (parity with admission,
  which only constrains explicit values). Forcing cwd into the session
  would change endpoint behavior (G6) — recorded below as the smallest
  next task if wanted.

## 8. Audit: executed vs replayed

`audit_log` records `execution_id`, `request_fingerprint`,
`policy_identity` (all digests/opaque — payload redaction untouched) and
`execution_status: "executed" | "replayed"`. The recorded `execution_id`
is the *originating* id: the executor's id for a fresh run, the stored
origin id for a replay. A cache hit therefore references the execution
that actually ran and can never be mistaken for a new side effect — this
was Finding 1 of the closure review (replays previously minted fresh
ids); the replay store persists the origin id alongside each completed
outcome, which is the only additional state replay keeps. No
tamper-resistance, durability, COMMITTED/UNKNOWN, or exactly-once claims
(all out of scope).

## 9. Representation-collapse analysis

| authority representation | before | after |
|---|---|---|
| trusted scope in flight | `__session_root` JSON string, injected per fs item | `ExecutionScope` in `ExecutionContract`, every item |
| scope readers | `scope_state`/`scope_root` (JSON), admission preflight (table), shell: none | tools read contract; admission reads table |
| replay identity | key alone | key + fingerprint, same contract |
| audit identity | none (tool/time/summary only) | execution_id + fingerprint + policy, same contract |
| request identity | none | execution_id, same contract |

Production refs to JSON scope machinery: 29 → 0. Independent identity
constructions: replay-key-only (+ none + none) → one contract minted once
per admitted item, consumed by dispatch, replay, and audit.

Diff (excluding new files): `src/` +1064/−414 for the V1 slice
(registry replay + coordinator dominate; fs/shell churn is mechanical
scope-threading), plus +232/−168 for the closure slice (single-unit
registry APIs, origin-id replay, private contract fields). `tests/`
+133/−48 then +166/−33 (conflict semantics, API migration, origin-id and
binding tests), experiment/bins trusted-local wrapping. New:
`src/execution.rs` (226+), `tests/authority.rs` (18 tests).

Impossible states removed, each by the API rather than by validation:

- Scope that is both present and unvalidated: no tool reads scope from
  JSON anywhere (`Scope` enum and key readers deleted; 29 → 0 production
  references), so there is nothing malformed to fail closed on.
- Replay that names different work: `execute_once`/`execute_with` take one
  `ContractedCall` whose fingerprint was derived from exactly its
  tool/args/scope at construction; no public API accepts an independent
  fingerprint, contract, or argument set alongside it. (Tool-level
  `execute_with(ctx, args)` still takes both — deliberately: tools never
  consume fingerprints, so a skewed pair there cannot corrupt replay
  identity, which lives only in the registry's single-unit APIs.)
- Audit that mints ids for non-executions: replays carry the stored
  origin id; `IdempotentOutcome.execution_id` is the origin in both the
  executed and replayed cases.
- Waiter stranded by a dead executor: `InflightGuard` + notify on drop.
- In-flight entry evicted under waiters: eviction only touches completed
  outcomes.

## 10. Verification

Full matrix green on macOS (this slice): fmt; clippy default/wasm/
experiment; lib 152; server 75; authority 18; escapes 14; toctou 4;
stress; validation 17; wasm lib 161; doc; MSRV 1.88 (default/experiment/
wasm); Python + JS SDK; `cargo audit --deny warnings` exit 0; `cargo deny
check` clean; container build + both smoke checks. Linux + final CI run
recorded in the PR report.

## 11. Remaining limitations (not in this slice)

- Session shell without `working_dir` inherits daemon cwd (see §7).
- Replay store is in-memory per process (unchanged); no durability.
- `policy_identity` is a content hash of the whole policy — precise, but
  coarse for "which rule admitted this"; fine for audit, not for
  per-rule attribution.
- No workload permits, process groups, effect receipts, or Landlock
  (explicitly out of scope).

## 12. Smallest justified next task

Bind the default shell cwd for session-scoped executions (run without
explicit `working_dir` inside the session root or reject): it is the one
remaining path where an execution can act outside its contract without a
dynamically resolved value. Needs one endpoint-behavior decision (reject
vs chdir) and a matrix entry update — no new machinery.

## 13. Closure review: two gaps found and closed (same branch)

Independent review of the V1 slice found two places where the authority
claim outran the implementation. Both were reproduced with throwaway
probes (deleted after use) before fixing, on this branch.

1. **Replay attribution lost the originating id.** The handler audited
   replays under the retry's freshly admitted id, so `executed` and
   `replayed` lines for one side effect carried different ids — and §8
   above wrongly claimed otherwise. Fix: the replay store persists the
   executor's id (`Done.origin`, the only added replay state) and
   `IdempotentOutcome.execution_id` is the origin in both cases; audit
   records it. Proven by `executed_audit_id_equals_replay_audit_origin_id`
   and `concurrent_identical_http_retries_share_one_origin_id` (16
   callers → 1 executed + 15 replayed, one id).
2. **Contract and call arguments could disagree.** `execute_once(key,
   ctx, name, args)` accepted three independent representations, and the
   probe showed a contract admitted for `(alpha, {})` executing
   `(beta, {x: 1})` — poisoning the cache so an honest alpha retry
   replayed beta's outcome with alpha running 0×. Fix by deletion, not
   validation: contract fields are private with accessors, fingerprint
   minting is module-private, and the registry takes one
   `ContractedCall` whose contract is admitted internally from exactly
   its tool/args/scope (`ContractedCall::new`; `local` for trusted-local
   use; `with_args` is `pub(crate)` for sequence expansion only, where
   replay identity is never consulted). Proven by
   `contracted_calls_bind_fingerprint_to_their_own_work` plus the
   unchanged conflict/origin test battery.
