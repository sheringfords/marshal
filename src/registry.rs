//! Holding tools and dispatching to them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;

use crate::{ExecutionContract, ExecutionScope, Tool, ToolOutcome, ADHOC_POLICY_IDENTITY};

/// A tool described for a planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Invocation name.
    pub name: String,
    /// One-line description.
    pub description: String,
    /// JSON Schema for arguments.
    pub parameters: Value,
}

impl ToolDefinition {
    /// Describe a tool.
    pub fn from_tool(tool: &dyn Tool) -> Self {
        ToolDefinition {
            name: tool.name().to_string(),
            description: tool.description().to_string(),
            parameters: tool.parameters_schema(),
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    outcome: ToolOutcome,
    inserted: Instant,
}

/// Replay identity: the caller's idempotency key *plus* the contract's
/// request fingerprint. A key alone can never name two different executions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplayId {
    key: String,
    fingerprint: String,
}

/// One replay slot: either an executor is running (waiters follow it) or a
/// completed outcome is available for replay.
enum ReplayState {
    InFlight {
        notify: Arc<Notify>,
    },
    /// A completed execution. `origin` is the executor's execution id — the
    /// minimal attribution replays reference instead of minting fresh ids.
    Done {
        entry: CacheEntry,
        origin: String,
    },
}

/// One idempotent execution: the outcome plus whether it actually ran.
/// `replayed == true` means this exact execution ran before under the same
/// key and fingerprint — no new side effect occurred.
#[derive(Debug, Clone)]
pub struct IdempotentOutcome {
    /// The executed (or replayed) outcome.
    pub outcome: ToolOutcome,
    /// True when served from a previous execution rather than run now.
    pub replayed: bool,
    /// Originating execution id: the executor's id, referenced by every
    /// replay of that completed execution. A replay never mints an id.
    pub execution_id: String,
}

/// A tool call bound to its execution contract: the unit the coordinator
/// admits and the registry runs. Batch and sequence items travel as these so
/// scope, replay identity and audit identity stay attached to the same
/// execution instead of being reconstructed per layer.
///
/// The contract is admitted inside [`ContractedCall::new`] from exactly the
/// tool, arguments and scope the call carries — there is no constructor that
/// accepts an independently built contract, so a contract/call mismatch is
/// unrepresentable through the public API. All three fields are private
/// with read-only accessors: after construction through a public safe API,
/// no external caller can change any value covered by the request
/// fingerprint. The contract field itself is private and
/// [`ExecutionContract`] fields are private, so admitted state cannot be
/// mutated after construction either.
#[derive(Debug, Clone)]
pub struct ContractedCall {
    /// Invocation name.
    tool: String,
    /// Caller arguments (requested work only — never trusted authority).
    args: Value,
    /// The admitted execution this call runs under.
    contract: ExecutionContract,
}

impl ContractedCall {
    /// Admit a call: mint a fresh execution id and derive the replay
    /// fingerprint from exactly this tool, these arguments and this scope.
    pub fn new(tool: String, args: Value, scope: ExecutionScope, policy_identity: &str) -> Self {
        let contract = ExecutionContract::admit(scope, &tool, &args, policy_identity.to_string());
        ContractedCall {
            tool,
            args,
            contract,
        }
    }

    /// Explicit trusted-local call for direct library use without HTTP
    /// admission: a fresh id, Workspace scope, and this registry's policy
    /// identity. The Workspace scope is stated, not defaulted.
    pub fn local(registry: &ToolRegistry, tool: &str, args: Value) -> Self {
        Self::new(
            tool.to_string(),
            args,
            ExecutionScope::Workspace,
            registry.policy_identity(),
        )
    }

    /// The admitted execution this call runs under.
    pub fn contract(&self) -> &ExecutionContract {
        &self.contract
    }

    /// The invocation name this call was admitted with.
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// The caller arguments this call was admitted with.
    pub fn args(&self) -> &Value {
        &self.args
    }

    /// Substitute caller arguments after admission (sequence template
    /// expansion). The admitted contract — id, scope, fingerprint over the
    /// admitted step, policy — is preserved as-is. Crate-private: only the
    /// registry's sequence path expands templates, and replay identity is
    /// never consulted there, so no public caller can skew a cached
    /// fingerprint away from executed work.
    pub(crate) fn with_args(self, args: Value) -> Self {
        ContractedCall {
            tool: self.tool,
            args,
            contract: self.contract,
        }
    }
}

/// Whether an error is an idempotency conflict (same key, different
/// fingerprint). The coordinator maps this to HTTP 409; the code extraction
/// picks up the `idempotency_conflict` prefix everywhere else.
pub fn is_idempotency_conflict(err: &anyhow::Error) -> bool {
    err.to_string().starts_with("idempotency_conflict")
}

fn idempotency_conflict(key: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "idempotency_conflict: key `{key}` was already admitted for a different execution"
    )
}

/// Removes an in-flight replay marker unless the executor completed.
///
/// The guard owns no lock: cleanup re-locks briefly in `drop`, so a panic
/// inside tool execution or an abort of the executor future still removes
/// the marker and wakes waiters instead of wedging them. `disarm` is called
/// once the `Done` entry is inserted, so a completed execution is never
/// removed by its own guard.
struct InflightGuard<'a> {
    map: &'a StdMutex<HashMap<ReplayId, ReplayState>>,
    id: ReplayId,
    notify: Arc<Notify>,
    disarmed: bool,
}

impl<'a> InflightGuard<'a> {
    fn new(
        map: &'a StdMutex<HashMap<ReplayId, ReplayState>>,
        id: ReplayId,
        notify: Arc<Notify>,
    ) -> Self {
        InflightGuard {
            map,
            id,
            notify,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        // Never panic in drop: a poisoned or contended lock still wakes
        // waiters, which re-resolve (and re-execute if the marker survived).
        if let Ok(mut map) = self.map.lock() {
            map.remove(&self.id);
        }
        self.notify.notify_waiters();
    }
}

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
const DEFAULT_CACHE_MAX_ENTRIES: usize = 1024;

/// A `JoinSet` that aborts its tasks when dropped.
///
/// A bare `JoinSet` detaches survivors on drop, leaving work running with no
/// owner to report to. Batch handlers are cancelled on HTTP client
/// disconnect, so the set must own task lifetimes: dropping the future that
/// drives `join_next` aborts every item still queued or running. Permits held
/// inside the tasks release via RAII during abort.
struct AbortOnDrop<T: 'static>(tokio::task::JoinSet<T>);

impl<T: 'static> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort_all();
    }
}

/// The set of tools an agent may call.
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
    completed: Arc<StdMutex<HashMap<ReplayId, ReplayState>>>,
    cache_ttl: Duration,
    cache_max_entries: usize,
    /// Identity of the policy snapshot this registry was built from: the
    /// content hash of the effective policy, or [`ADHOC_POLICY_IDENTITY`]
    /// for hand-built registries. Copied into every admitted contract and
    /// recorded in audit.
    policy_identity: String,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// An empty registry. Nothing is callable until something is registered.
    /// The policy identity marks ad-hoc construction; server-built
    /// registries carry the effective policy's content hash instead.
    pub fn new() -> Self {
        ToolRegistry {
            tools: HashMap::new(),
            completed: Arc::new(StdMutex::new(HashMap::new())),
            cache_ttl: DEFAULT_CACHE_TTL,
            cache_max_entries: DEFAULT_CACHE_MAX_ENTRIES,
            policy_identity: ADHOC_POLICY_IDENTITY.to_string(),
        }
    }

    /// Identity of the policy snapshot backing this registry.
    pub fn policy_identity(&self) -> &str {
        &self.policy_identity
    }

    /// Set the policy identity (content hash of the effective policy).
    /// Used by the server when building from a policy file; direct library
    /// users keep the ad-hoc marker.
    pub fn with_policy_identity(mut self, identity: String) -> Self {
        self.policy_identity = identity;
        self
    }

    /// Set cache TTL for `execute_once`.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Set max cached entries. Oldest evicted when exceeded.
    pub fn with_cache_capacity(mut self, max: usize) -> Self {
        self.cache_max_entries = max;
        self
    }

    /// Purge expired completed outcomes and report replay bookkeeping in a
    /// single pass: whether another fingerprint already claims `key`
    /// (a conflict, whether Done or still in flight) and how many completed
    /// outcomes are cached. In-flight markers are never purged or counted:
    /// evicting one would strand its waiters into becoming parallel
    /// executors and duplicate the side effect.
    ///
    /// The mutex is a plain `std` mutex: every critical section is
    /// synchronous map work, and it is never held across tool execution.
    fn purge_and_count(
        &self,
        map: &mut HashMap<ReplayId, ReplayState>,
        key: &str,
        fingerprint: &str,
    ) -> (bool, usize) {
        let now = Instant::now();
        let mut conflict = false;
        let mut done_count = 0usize;
        map.retain(|e, s| match s {
            ReplayState::Done { entry, .. } => {
                if now.duration_since(entry.inserted) >= self.cache_ttl {
                    return false;
                }
                done_count += 1;
                if e.key == key && e.fingerprint != fingerprint {
                    conflict = true;
                }
                true
            }
            ReplayState::InFlight { .. } => {
                if e.key == key && e.fingerprint != fingerprint {
                    conflict = true;
                }
                true
            }
        });
        (conflict, done_count)
    }

    /// Evict the oldest completed outcomes until `excess` slots are free.
    /// In-flight markers are load-bearing for single-flight and are never
    /// evicted; they are bounded by live concurrency and removed
    /// deterministically when the executor finishes, fails, panics or is
    /// cancelled.
    fn evict_oldest_done(&self, map: &mut HashMap<ReplayId, ReplayState>, excess: usize) {
        if excess == 0 {
            return;
        }
        let mut done: Vec<(ReplayId, Instant)> = map
            .iter()
            .filter_map(|(id, s)| match s {
                ReplayState::Done { entry, .. } => Some((id.clone(), entry.inserted)),
                ReplayState::InFlight { .. } => None,
            })
            .collect();
        done.sort_by_key(|(_, inserted)| *inserted);
        for (id, _) in done.into_iter().take(excess) {
            map.remove(&id);
        }
    }

    /// Register a tool, replacing any tool of the same name.
    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    /// Every registered tool, described for a planner, sorted by name.
    pub fn definitions(&self) -> Vec<ToolDefinition> {
        let mut defs: Vec<ToolDefinition> = self
            .tools
            .values()
            .map(|t| ToolDefinition::from_tool(t.as_ref()))
            .collect();
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        defs
    }

    /// Whether a tool is registered.
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Registered tool names, sorted.
    pub fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.tools.keys().cloned().collect();
        names.sort();
        names
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Validate and run a tool.
    pub async fn execute(&self, name: &str, args: Value) -> Result<ToolOutcome> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("tool_not_found: {name}"))?;

        // Validate here as well as inside the tool: a tool may be called
        // directly, and policy must hold on both paths.
        tool.validate(&args).await?;

        let outcome = tool.execute(args).await;
        match &outcome {
            Ok(o) => tracing::info!(
                tool = %name, success = o.success, duration_ms = o.duration_ms, "tool executed"
            ),
            Err(e) => tracing::warn!(tool = %name, error = %e, "tool rejected"),
        }
        outcome
    }

    /// Validate and run a tool under an execution contract.
    ///
    /// The contract's trusted scope is enforced at the tool boundary;
    /// caller arguments never carry authority. This is the only path the
    /// coordinator uses — [`ToolRegistry::execute`] stays as the explicit
    /// trusted-local entry point for direct library callers.
    pub async fn execute_with(&self, call: ContractedCall) -> Result<ToolOutcome> {
        // Destructure once: the contract, tool name and arguments below all
        // come from the same admitted call — no independent representations.
        let ContractedCall {
            tool: name,
            args,
            contract,
        } = call;
        let tool = self
            .tools
            .get(&name)
            .ok_or_else(|| anyhow::anyhow!("tool_not_found: {name}"))?;

        // Validate here as well as inside the tool: a tool may be called
        // directly, and policy must hold on both paths.
        tool.validate_with(&contract, &args).await?;

        let outcome = tool.execute_with(&contract, args).await;
        match &outcome {
            Ok(o) => tracing::info!(
                tool = %name, success = o.success, duration_ms = o.duration_ms, "tool executed"
            ),
            Err(e) => tracing::warn!(tool = %name, error = %e, "tool rejected"),
        }
        outcome
    }

    /// Run a contracted call once per (`key`, request fingerprint),
    /// returning the prior outcome on identical retries and a stable
    /// conflict — without running anything — when the same key names a
    /// different execution.
    ///
    /// The replay identity comes from the call's own contract, so the cached
    /// fingerprint always describes the work actually executed. The first
    /// actual side effect owns one execution id; every replay references
    /// that origin id rather than minting a fresh one.
    ///
    /// For retrying a step whose tool has a side effect. The cache is
    /// in-memory and per-process: it does not survive a restart, so it
    /// protects against a retried step, not against a crashed one.
    ///
    /// Single-flight: exactly one caller becomes the executor for a
    /// key/fingerprint; concurrent identical callers await that result
    /// instead of duplicating the side effect. Different keys stay fully
    /// concurrent, and the map mutex is only ever held for synchronous map
    /// work — never across tool execution.
    ///
    /// Only successful calls are cached. A failure (or tool error) removes
    /// the in-flight marker and wakes waiters, which retry as new executors —
    /// the pre-existing failure-retry semantics, unchanged.
    pub async fn execute_once(&self, key: &str, call: ContractedCall) -> Result<IdempotentOutcome> {
        // The replay identity comes from the call's own contract — derived
        // at construction from exactly the tool, arguments and scope being
        // executed. There is no independent fingerprint parameter to skew.
        let id = ReplayId {
            key: key.to_string(),
            fingerprint: call.contract().request_fingerprint().to_string(),
        };
        // Resolve to executor or follower. Executors break out holding the
        // new slot's notify; followers subscribe, re-check, and await.
        let executor_notify: Arc<Notify> = loop {
            let waiter = {
                let mut map = self.completed.lock().unwrap();
                let (conflict, _) = self.purge_and_count(&mut map, &id.key, &id.fingerprint);
                // Same key, different fingerprint — Done or in flight — is a
                // different execution: fail before running anything.
                if conflict {
                    return Err(idempotency_conflict(key));
                }
                match map.get(&id) {
                    Some(ReplayState::Done { entry, origin }) => {
                        return Ok(IdempotentOutcome {
                            outcome: entry.outcome.clone(),
                            replayed: true,
                            execution_id: origin.clone(),
                        });
                    }
                    Some(ReplayState::InFlight { notify }) => Some(notify.clone()),
                    None => {
                        let notify = Arc::new(Notify::new());
                        map.insert(
                            id.clone(),
                            ReplayState::InFlight {
                                notify: notify.clone(),
                            },
                        );
                        break notify;
                    }
                }
            };
            // Follower: the executor breaks out of the loop above.
            let notify = waiter.expect("executor breaks out of the loop");
            // Subscribe before re-checking so a completion landing in
            // between cannot be missed (no lost wakeup).
            tokio::pin! {
                let notified = notify.notified();
            }
            notified.as_mut().enable();
            let done = {
                let map = self.completed.lock().unwrap();
                match map.get(&id) {
                    Some(ReplayState::Done { entry, origin }) => {
                        Some((entry.outcome.clone(), origin.clone()))
                    }
                    _ => None,
                }
            };
            if let Some((outcome, origin)) = done {
                return Ok(IdempotentOutcome {
                    outcome,
                    replayed: true,
                    execution_id: origin,
                });
            }
            notified.await;
            // Executor finished, failed, panicked or was cancelled: loop and
            // re-resolve (replay, follow a new executor, or execute).
        };

        // Executor: the map mutex is not held from here until completion.
        // The origin id is the call's own admitted id — the one identity
        // this side effect will ever own.
        let origin = call.contract().execution_id().to_string();
        let mut guard = InflightGuard::new(&self.completed, id.clone(), executor_notify.clone());
        let outcome = self.execute_with(call).await;
        match outcome {
            Ok(o) if o.success => {
                {
                    let mut map = self.completed.lock().unwrap();
                    let (_, done_count) = self.purge_and_count(&mut map, &id.key, &id.fingerprint);
                    // Make room before inserting: the post-insert count is
                    // then exactly within capacity (the new entry is the
                    // newest, so oldest-first eviction never takes it).
                    let excess = (done_count + 1).saturating_sub(self.cache_max_entries);
                    self.evict_oldest_done(&mut map, excess);
                    map.insert(
                        id,
                        ReplayState::Done {
                            entry: CacheEntry {
                                outcome: o.clone(),
                                inserted: Instant::now(),
                            },
                            origin: origin.clone(),
                        },
                    );
                }
                guard.disarm();
                executor_notify.notify_waiters();
                Ok(IdempotentOutcome {
                    outcome: o,
                    replayed: false,
                    execution_id: origin,
                })
            }
            other => {
                // Failure or tool error: never cached. Dropping the guard
                // removes the in-flight marker and wakes waiters, which
                // retry as new executors.
                drop(guard);
                match other {
                    Ok(o) => Ok(IdempotentOutcome {
                        outcome: o,
                        replayed: false,
                        execution_id: origin,
                    }),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Execute a batch of contracted calls concurrently, preserving order.
    ///
    /// Concurrency is bounded by `max_concurrency`
    /// (cap of 32 mirrors `marshalld` pool). Useful for agent batch steps like
    /// `read N files` without serial RTT.
    ///
    /// `workload` is the server-global semaphore sized to the configured
    /// `concurrency` cap. Every item acquires one workload permit immediately
    /// before validating and executing its tool and releases it when the tool
    /// finishes; items waiting for a permit hold nothing, so the global cap
    /// bounds actually-running workloads rather than admitted requests. The
    /// per-batch `max_concurrency` semaphore is acquired first and bounds how
    /// many of *this* batch's items may compete at once (fairness between one
    /// large batch and concurrent single requests).
    ///
    /// Cancellation: spawned item tasks are aborted when the returned future
    /// is dropped (e.g. HTTP client disconnect), so no task keeps running
    /// unaccounted for. Permits are RAII guards held inside the item tasks,
    /// hence released on success, tool error, panic and abort alike.
    pub async fn execute_batch(
        &self,
        requests: Vec<ContractedCall>,
        max_concurrency: usize,
        workload: &Arc<tokio::sync::Semaphore>,
    ) -> Vec<Result<ToolOutcome>> {
        // Guard against OOM from huge batch
        if requests.len() > 64 {
            return requests
                .into_iter()
                .map(|_| Err(anyhow::anyhow!("batch_too_large")))
                .collect();
        }
        let max = max_concurrency.clamp(1, 32);
        let local = Arc::new(tokio::sync::Semaphore::new(max));
        let n = requests.len();
        let mut set = tokio::task::JoinSet::new();
        let mut slot_of = std::collections::HashMap::new();
        for (index, call) in requests.into_iter().enumerate() {
            let local = local.clone();
            let workload = workload.clone();
            // Destructure once: the spawned task owns one admitted call —
            // tool, arguments and contract cannot drift apart.
            let ContractedCall {
                tool: name,
                args,
                contract,
            } = call;
            // Clone registry internals via Arc self? We need `self` to be Sync.
            // Since `&self` is shared, we spawn a task that holds a cloned reference
            // to the needed tool Arc.
            let tool = self.tools.get(&name).cloned();
            let handle = set.spawn(async move {
                // Local slot first, then global workload permit: a single global
                // order, so waiters can never deadlock against each other.
                // Neither guard is held while queued for the other.
                let _slot = local.acquire_owned().await.unwrap();
                let _work = workload.acquire_owned().await.unwrap();
                let outcome = if let Some(tool) = tool {
                    match tool.validate_with(&contract, &args).await {
                        Ok(()) => tool.execute_with(&contract, args).await,
                        Err(e) => Err(e),
                    }
                } else {
                    Err(anyhow::anyhow!("tool_not_found: {name}"))
                };
                (index, outcome)
            });
            slot_of.insert(handle.id(), index);
        }
        // Abort survivors if this future is dropped (client disconnect,
        // shutdown): a bare `JoinSet` would detach them instead.
        let mut set = AbortOnDrop(set);
        let mut results: Vec<Option<Result<ToolOutcome>>> = (0..n).map(|_| None).collect();
        while let Some(joined) = set.0.join_next().await {
            match joined {
                Ok((index, outcome)) => results[index] = Some(outcome),
                Err(e) if e.is_cancelled() => {
                    // Ourselves dropped mid-join; remaining tasks are aborted
                    // by the guard. Report what never ran as cancelled.
                    for slot in results.iter_mut().filter(|r| r.is_none()) {
                        *slot = Some(Err(anyhow::anyhow!("cancelled")));
                    }
                    break;
                }
                Err(e) => {
                    // Task panicked: its permits dropped during unwind. The
                    // task id maps back to its slot, so ordering is preserved
                    // exactly as in the success path.
                    let index = slot_of.get(&e.id()).copied();
                    let slot = match index.and_then(|i| results.get_mut(i)) {
                        Some(slot) => Some(slot),
                        None => results.iter_mut().find(|r| r.is_none()),
                    };
                    if let Some(slot) = slot {
                        *slot = Some(Err(anyhow::anyhow!("join_failed: {e}")));
                    }
                }
            }
        }
        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(anyhow::anyhow!("cancelled"))))
            .collect()
    }

    /// Execute a sequence of contracted calls **in order**, stopping on first
    /// error unless `continue_on_error` is true. Unlike `execute_batch` which
    /// runs concurrently, this preserves strict ordering and allows an agent
    /// to express `write -> read -> shell` workflows without extra RTTs.
    ///
    /// Supports templating `{{steps[0].stdout}}` where `steps[N].stdout`/
    /// `content` is previous stdout as UTF-8, `summary` is JSON. Templating
    /// resolves caller data only: every step already carries its contract,
    /// and the tool enforces that contract on the *resolved* values at the
    /// execution boundary — a dynamically generated path gets no more
    /// authority than the contract attached to its step. (The replay
    /// fingerprint is bound at admission on the unexpanded step; sequence
    /// steps are not idempotent across calls.)
    ///
    /// Returns results in input order; if `stop_on_error` (default `true`) a
    /// failed `Err` or `success==false` outcome aborts remaining steps.
    pub async fn execute_sequence(
        &self,
        requests: Vec<ContractedCall>,
        continue_on_error: bool,
    ) -> Vec<Result<ToolOutcome>> {
        if requests.len() > 32 {
            return requests
                .into_iter()
                .map(|_| Err(anyhow::anyhow!("sequence_too_large")))
                .collect();
        }
        let mut results = Vec::with_capacity(requests.len());
        let mut prev_outcomes: Vec<ToolOutcome> = Vec::new();
        for call in requests {
            let templated = apply_templates(&call.args, &prev_outcomes);
            let name = call.tool.clone();
            let res = self.execute_with(call.with_args(templated)).await;
            let placeholder = match &res {
                Ok(o) => o.clone(),
                Err(e) => ToolOutcome::failure(
                    name.clone(),
                    e.to_string().split(':').next().unwrap_or("error").trim(),
                    0,
                ),
            };
            prev_outcomes.push(placeholder);
            let should_stop = if let Ok(outcome) = &res {
                !outcome.success && !continue_on_error
            } else {
                !continue_on_error
            };
            results.push(res);
            if should_stop {
                break;
            }
        }
        results
    }

    /// Number of cached idempotency entries (for testing/metrics).
    pub async fn cache_len(&self) -> usize {
        self.completed.lock().unwrap().len()
    }
}

fn apply_templates(value: &Value, prev: &[ToolOutcome]) -> Value {
    match value {
        Value::String(s) => {
            // Single-pass replacement to avoid injection re-expansion. Capped at 32 placeholders.
            let mut out = String::with_capacity(s.len());
            let mut remaining = s.as_str();
            let mut count = 0;
            while let Some(start) = remaining.find("{{steps[") {
                if count >= 32 {
                    out.push_str(remaining);
                    break;
                }
                out.push_str(&remaining[..start]);
                let after_start = &remaining[start..];
                if let Some(end_rel) = after_start.find("}}") {
                    let end = end_rel + 2;
                    let placeholder = &after_start[..end];
                    let inner = &placeholder[2..placeholder.len() - 2]; // steps[N].field
                    let mut replacement = String::new();
                    if let Some(bracket) = inner.find('[') {
                        if let Some(close) = inner.find(']') {
                            if let Ok(idx) = inner[bracket + 1..close].parse::<usize>() {
                                if idx < prev.len() {
                                    let field = inner[close + 1..].trim_start_matches('.');
                                    let outcome = &prev[idx];
                                    replacement = match field {
                                        "stdout" | "content" | "output" => outcome
                                            .content
                                            .as_ref()
                                            .map(|b| String::from_utf8_lossy(b).to_string())
                                            .unwrap_or_default(),
                                        "summary" => serde_json::to_string(&outcome.summary)
                                            .unwrap_or_default(),
                                        "success" => outcome.success.to_string(),
                                        "error_code" => {
                                            outcome.error_code.clone().unwrap_or_default()
                                        }
                                        "tool" => outcome.tool.clone(),
                                        "duration_ms" => outcome.duration_ms.to_string(),
                                        _ => String::new(),
                                    };
                                }
                            }
                        }
                    }
                    out.push_str(&replacement);
                    remaining = &after_start[end..];
                    count += 1;
                } else {
                    // No closing }}, push rest and break
                    out.push_str(after_start);
                    remaining = "";
                    break;
                }
            }
            if !remaining.is_empty() {
                out.push_str(remaining);
            }
            Value::String(out)
        }
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                new_map.insert(k.clone(), apply_templates(v, prev));
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|v| apply_templates(v, prev)).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter {
        calls: AtomicUsize,
        succeed: bool,
    }

    #[async_trait::async_trait]
    impl Tool for Counter {
        fn name(&self) -> &str {
            "counter"
        }
        fn description(&self) -> &str {
            "counts calls"
        }
        fn parameters_schema(&self) -> Value {
            json!({"type": "object"})
        }
        async fn validate(&self, args: &Value) -> Result<()> {
            if args.get("bad").is_some() {
                anyhow::bail!("rejected_by_policy");
            }
            Ok(())
        }
        async fn execute(&self, _args: Value) -> Result<ToolOutcome> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(if self.succeed {
                ToolOutcome::success("counter", json!({ "calls": n }), 0)
            } else {
                ToolOutcome::failure("counter", "always_fails", 0)
            })
        }
    }

    fn registry(succeed: bool) -> (ToolRegistry, Arc<Counter>) {
        let tool = Arc::new(Counter {
            calls: AtomicUsize::new(0),
            succeed,
        });
        let mut registry = ToolRegistry::new();
        registry.register(tool.clone());
        (registry, tool)
    }

    fn call(reg: &ToolRegistry, tool: &str, args: Value) -> ContractedCall {
        ContractedCall::local(reg, tool, args)
    }

    /// A tool that sleeps `args["ms"]` while recording peak concurrency.
    struct Sleeper {
        current: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Tool for Sleeper {
        fn name(&self) -> &str {
            "sleeper"
        }
        fn description(&self) -> &str {
            "sleeps while tracking concurrency"
        }
        fn parameters_schema(&self) -> Value {
            json!({"type": "object"})
        }
        async fn validate(&self, _args: &Value) -> Result<()> {
            Ok(())
        }
        async fn execute(&self, args: Value) -> Result<ToolOutcome> {
            let ms = args.get("ms").and_then(Value::as_u64).unwrap_or(0);
            let n = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(n, Ordering::SeqCst);
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(ms)).await;
            self.current.fetch_sub(1, Ordering::SeqCst);
            Ok(ToolOutcome::success("sleeper", json!({}), 0))
        }
    }

    fn sleep_registry() -> (ToolRegistry, Arc<Sleeper>) {
        let tool = Arc::new(Sleeper {
            current: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            calls: AtomicUsize::new(0),
        });
        let mut registry = ToolRegistry::new();
        registry.register(tool.clone());
        (registry, tool)
    }

    fn sleep_reqs(reg: &ToolRegistry, n: usize, ms: u64) -> Vec<ContractedCall> {
        (0..n)
            .map(|_| call(reg, "sleeper", json!({"ms": ms})))
            .collect()
    }

    #[tokio::test]
    async fn batch_items_share_one_global_permit() {
        // M2-001: workload cap 1 serializes items even with max_concurrency 32.
        let (registry, tool) = sleep_registry();
        let workload = Arc::new(tokio::sync::Semaphore::new(1));
        let started = Instant::now();
        let results = registry
            .execute_batch(sleep_reqs(&registry, 3, 200), 32, &workload)
            .await;
        assert_eq!(results.len(), 3);
        for r in results {
            assert!(r.unwrap().success);
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 3);
        assert_eq!(tool.peak.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() >= Duration::from_millis(550));
        assert_eq!(workload.available_permits(), 1);
    }

    #[tokio::test]
    async fn batch_items_run_in_parallel_up_to_both_caps() {
        // max_concurrency and workload cap compose: peak is the minimum.
        let (registry, tool) = sleep_registry();
        let workload = Arc::new(tokio::sync::Semaphore::new(8));
        let started = Instant::now();
        let results = registry
            .execute_batch(sleep_reqs(&registry, 3, 200), 3, &workload)
            .await;
        assert!(results.into_iter().all(|r| r.unwrap().success));
        assert_eq!(tool.peak.load(Ordering::SeqCst), 3);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(workload.available_permits(), 8);
    }

    #[tokio::test]
    async fn dropping_batch_aborts_items_and_releases_permits() {
        // Disconnect mid-batch: spawned tasks must not outlive the future,
        // and every permit must come back.
        let (registry, tool) = sleep_registry();
        let workload = Arc::new(tokio::sync::Semaphore::new(2));
        {
            let fut = registry.execute_batch(sleep_reqs(&registry, 4, 500), 4, &workload);
            tokio::pin!(fut);
            tokio::select! {
                _ = &mut fut => panic!("batch finished before the drop"),
                _ = tokio::time::sleep(Duration::from_millis(150)) => {}
            }
            // `fut` (and its abort-on-drop task set) is dropped here.
        }
        // Let aborts land; tasks must stop starting new work.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(workload.available_permits(), 2);
        let calls = tool.calls.load(Ordering::SeqCst);
        assert!(calls < 4, "aborted batch kept executing ({calls} calls)");
        let peak = tool.peak.load(Ordering::SeqCst);
        assert!(peak <= 2, "workload cap exceeded ({peak})");
    }

    #[tokio::test]
    async fn batch_errors_and_timeouts_release_permits() {
        let (registry, _) = registry(true);
        let workload = Arc::new(tokio::sync::Semaphore::new(2));
        let reqs = vec![
            call(&registry, "counter", json!({})),
            call(&registry, "nope", json!({})),
            call(&registry, "counter", json!({"bad": true})),
        ];
        let results = registry.execute_batch(reqs, 3, &workload).await;
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert!(results[2].is_err());
        assert_eq!(workload.available_permits(), 2);
    }

    #[tokio::test]
    async fn an_unknown_tool_is_an_error() {
        let (registry, _) = registry(true);
        let err = registry.execute("nope", json!({})).await.unwrap_err();
        assert!(err.to_string().contains("tool_not_found"));
    }

    #[tokio::test]
    async fn the_registry_enforces_validation() {
        // Not just the tool: a tool reached through the registry must get the
        // same policy check as one called directly.
        let (registry, tool) = registry(true);
        assert!(registry
            .execute("counter", json!({"bad": 1}))
            .await
            .is_err());
        assert_eq!(
            tool.calls.load(Ordering::SeqCst),
            0,
            "policy ran after execute"
        );
    }

    #[tokio::test]
    async fn execute_once_runs_a_tool_only_once() {
        let (registry, tool) = registry(true);
        let mut origin = String::new();
        for _ in 0..5 {
            let outcome = registry
                .execute_once("k1", call(&registry, "counter", json!({})))
                .await
                .unwrap();
            if outcome.replayed {
                // Every replay references the originating execution id.
                assert_eq!(outcome.execution_id, origin);
            } else {
                origin = outcome.execution_id.clone();
            }
            assert!(tool.calls.load(Ordering::SeqCst) == 1);
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 1);
        assert!(!origin.is_empty());
    }

    #[tokio::test]
    async fn different_keys_run_separately() {
        let (registry, tool) = registry(true);
        for key in ["a", "b"] {
            let outcome = registry
                .execute_once(key, call(&registry, "counter", json!({})))
                .await
                .unwrap();
            assert!(!outcome.replayed);
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failures_are_not_cached() {
        // Caching a failure turns a transient outage into a permanent one.
        let (registry, tool) = registry(false);
        for _ in 0..3 {
            let outcome = registry
                .execute_once("k", call(&registry, "counter", json!({})))
                .await
                .unwrap();
            assert!(!outcome.replayed);
            assert!(!outcome.outcome.success);
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn same_key_different_fingerprint_conflicts_without_executing() {
        let (registry, tool) = registry(true);
        registry
            .execute_once("k", call(&registry, "counter", json!({"v": 1})))
            .await
            .unwrap();
        let err = registry
            .execute_once("k", call(&registry, "counter", json!({"v": 2})))
            .await
            .unwrap_err();
        assert!(is_idempotency_conflict(&err), "{err}");
        assert_eq!(tool.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_executor_releases_waiters_to_retry() {
        // The tool sleeps; abort the executor mid-flight. The waiter must
        // wake and complete the work itself — never hang — and exactly one
        // execution runs in total. The count increments after the sleep so
        // an aborted executor cannot count.
        struct Slow {
            calls: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl Tool for Slow {
            fn name(&self) -> &str {
                "slow"
            }
            fn description(&self) -> &str {
                "slow"
            }
            fn parameters_schema(&self) -> Value {
                json!({})
            }
            async fn execute(&self, _args: Value) -> Result<ToolOutcome> {
                tokio::time::sleep(Duration::from_millis(300)).await;
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(ToolOutcome::success("slow", json!({}), 0))
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(Slow {
            calls: calls.clone(),
        }));
        let registry = Arc::new(registry);

        let r1 = registry.clone();
        let executor = tokio::spawn(async move {
            r1.execute_once("k", ContractedCall::local(&r1, "slow", json!({})))
                .await
        });
        // Let the executor pass admission and block inside the tool.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let r2 = registry.clone();
        let waiter = tokio::spawn(async move {
            r2.execute_once("k", ContractedCall::local(&r2, "slow", json!({})))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        executor.abort();
        let settled = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter wedged after executor cancellation")
            .unwrap()
            .unwrap();
        assert!(
            !settled.replayed,
            "waiter should have executed, not replayed"
        );
        assert!(settled.outcome.success);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn definitions_and_names_are_sorted() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(Counter {
            calls: AtomicUsize::new(0),
            succeed: true,
        }));
        assert_eq!(registry.tool_names(), vec!["counter"]);
        assert_eq!(registry.definitions()[0].name, "counter");
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test]
    async fn an_empty_registry_offers_nothing() {
        let registry = ToolRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.definitions().is_empty());
        assert!(!registry.has_tool("anything"));
    }

    #[tokio::test]
    async fn batch_executes_concurrently_and_preserves_order() {
        let (registry, tool) = registry(true);
        let reqs = vec![
            call(&registry, "counter", json!({})),
            call(&registry, "counter", json!({})),
            call(&registry, "counter", json!({})),
        ];
        let workload = Arc::new(tokio::sync::Semaphore::new(8));
        let results = registry.execute_batch(reqs, 2, &workload).await;
        assert_eq!(results.len(), 3);
        for r in results {
            assert!(r.unwrap().success);
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn batch_reports_missing_tool_as_error() {
        let (registry, _) = registry(true);
        let reqs = vec![call(&registry, "nope", json!({}))];
        let workload = Arc::new(tokio::sync::Semaphore::new(8));
        let results = registry.execute_batch(reqs, 4, &workload).await;
        assert!(results[0].is_err());
        assert!(
            results[0]
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("tool_not_existent")
                || results[0]
                    .as_ref()
                    .unwrap_err()
                    .to_string()
                    .contains("tool_not_found")
        );
    }

    #[tokio::test]
    async fn sequence_executes_in_order_and_stops_on_error() {
        let (registry, tool) = registry(true);
        let reqs = vec![
            call(&registry, "counter", json!({})),
            call(&registry, "counter", json!({"bad": 1})),
            call(&registry, "counter", json!({})),
        ];
        let results = registry.execute_sequence(reqs, false).await;
        // second fails validation -> stops, third never runs
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert_eq!(tool.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sequence_continues_when_requested() {
        let (registry, tool) = registry(true);
        let reqs = vec![
            call(&registry, "counter", json!({})),
            call(&registry, "counter", json!({"bad": 1})),
            call(&registry, "counter", json!({})),
        ];
        let results = registry.execute_sequence(reqs, true).await;
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert!(results[2].is_ok());
        assert_eq!(tool.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn sequence_templates_previous_stdout() {
        struct Echo;
        #[async_trait::async_trait]
        impl Tool for Echo {
            fn name(&self) -> &str {
                "echo"
            }
            fn description(&self) -> &str {
                "echo"
            }
            fn parameters_schema(&self) -> Value {
                json!({})
            }
            async fn execute(&self, args: Value) -> Result<ToolOutcome> {
                let msg = args
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(ToolOutcome::success("echo", json!({}), 0).with_content(msg.into_bytes()))
            }
        }
        let mut reg = ToolRegistry::new();
        reg.register(std::sync::Arc::new(Echo));
        let steps = vec![
            ContractedCall::local(&reg, "echo", json!({"msg": "hello"})),
            ContractedCall::local(&reg, "echo", json!({"msg": "{{steps[0].stdout}} world"})),
        ];
        let res = reg.execute_sequence(steps, false).await;
        assert_eq!(res.len(), 2);
        let out1 = res[0].as_ref().unwrap();
        let out2 = res[1].as_ref().unwrap();
        assert_eq!(out1.content.as_deref().unwrap(), b"hello");
        // templated second step should have content "hello world"
        assert_eq!(out2.content.as_deref().unwrap(), b"hello world");
    }
}
