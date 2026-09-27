//! Holding tools and dispatching to them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::{Tool, ToolOutcome};

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
    completed: Arc<Mutex<HashMap<String, CacheEntry>>>,
    cache_ttl: Duration,
    cache_max_entries: usize,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// An empty registry. Nothing is callable until something is registered.
    pub fn new() -> Self {
        ToolRegistry {
            tools: HashMap::new(),
            completed: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl: DEFAULT_CACHE_TTL,
            cache_max_entries: DEFAULT_CACHE_MAX_ENTRIES,
        }
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

    /// Clear expired entries; evict oldest if over capacity.
    async fn evict_expired(&self, map: &mut HashMap<String, CacheEntry>) {
        let now = Instant::now();
        map.retain(|_, e| now.duration_since(e.inserted) < self.cache_ttl);
        if map.len() > self.cache_max_entries {
            // evict arbitrary (HashMap) entries until under limit - LRU would
            // need `lru` dep; this bounds memory which is the P0 requirement.
            let to_remove = map.len() - self.cache_max_entries;
            let keys: Vec<String> = map.keys().take(to_remove).cloned().collect();
            for k in keys {
                map.remove(&k);
            }
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

    /// Run a tool once per `key`, returning the cached outcome on repeat calls.
    ///
    /// For retrying a step whose tool has a side effect. The cache is in-memory
    /// and per-process: it does not survive a restart, so it protects against a
    /// retried step, not against a crashed one.
    ///
    /// Only successful calls are cached. A failure that is cached would make a
    /// transient outage permanent for the lifetime of the process.
    pub async fn execute_once(&self, key: &str, name: &str, args: Value) -> Result<ToolOutcome> {
        // Single mutex guards check+insert to close RwLock read->write race where
        // N concurrent callers all miss then all execute.
        let mut map = self.completed.lock().await;
        self.evict_expired(&mut map).await;
        if let Some(entry) = map.get(key) {
            tracing::debug!(tool = %name, key = %key, "idempotency cache hit");
            return Ok(entry.outcome.clone());
        }
        drop(map);

        let outcome = self.execute(name, args).await?;
        if outcome.success {
            let mut map = self.completed.lock().await;
            self.evict_expired(&mut map).await;
            // second check: another task may have inserted while we executed
            if let Some(entry) = map.get(key) {
                return Ok(entry.outcome.clone());
            }
            map.insert(
                key.to_string(),
                CacheEntry {
                    outcome: outcome.clone(),
                    inserted: Instant::now(),
                },
            );
            // Ensure we never exceed capacity (evict_expired was before insert)
            if map.len() > self.cache_max_entries {
                self.evict_expired(&mut map).await;
            }
        }
        Ok(outcome)
    }

    /// Execute a batch of tool calls concurrently, preserving order.
    ///
    /// Each entry is `(name, args)`. Concurrency is bounded by `max_concurrency`
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
        requests: Vec<(String, Value)>,
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
        for (index, (name, args)) in requests.into_iter().enumerate() {
            let local = local.clone();
            let workload = workload.clone();
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
                    match tool.validate(&args).await {
                        Ok(()) => tool.execute(args).await,
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

    /// Execute a sequence of tool calls **in order**, stopping on first error
    /// unless `continue_on_error` is true. Unlike `execute_batch` which runs
    /// concurrently, this preserves strict ordering and allows an agent to
    /// express `write -> read -> shell` workflows without extra RTTs.
    ///
    /// Each step is `(name, args)`. Supports templating `{{steps[0].stdout}}`
    /// where `steps[N].stdout`/`content` is previous stdout as UTF-8, `summary`
    /// is JSON. Returns results in input order; if `stop_on_error` (default
    /// `true`) a failed `Err` or `success==false` outcome aborts remaining steps.
    pub async fn execute_sequence(
        &self,
        requests: Vec<(String, Value)>,
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
        for (name, args) in requests {
            let templated = apply_templates(&args, &prev_outcomes);
            let res = self.execute(&name, templated).await;
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
        self.completed.lock().await.len()
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

    fn sleep_reqs(n: usize, ms: u64) -> Vec<(String, Value)> {
        (0..n)
            .map(|_| ("sleeper".to_string(), json!({"ms": ms})))
            .collect()
    }

    #[tokio::test]
    async fn batch_items_share_one_global_permit() {
        // M2-001: workload cap 1 serializes items even with max_concurrency 32.
        let (registry, tool) = sleep_registry();
        let workload = Arc::new(tokio::sync::Semaphore::new(1));
        let started = Instant::now();
        let results = registry
            .execute_batch(sleep_reqs(3, 200), 32, &workload)
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
            .execute_batch(sleep_reqs(3, 200), 3, &workload)
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
            let fut = registry.execute_batch(sleep_reqs(4, 500), 4, &workload);
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
            ("counter".to_string(), json!({})),
            ("nope".to_string(), json!({})),
            ("counter".to_string(), json!({"bad": true})),
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
        for _ in 0..5 {
            registry
                .execute_once("k1", "counter", json!({}))
                .await
                .unwrap();
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_keys_run_separately() {
        let (registry, tool) = registry(true);
        registry
            .execute_once("a", "counter", json!({}))
            .await
            .unwrap();
        registry
            .execute_once("b", "counter", json!({}))
            .await
            .unwrap();
        assert_eq!(tool.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failures_are_not_cached() {
        // Caching a failure turns a transient outage into a permanent one.
        let (registry, tool) = registry(false);
        for _ in 0..3 {
            let outcome = registry
                .execute_once("k", "counter", json!({}))
                .await
                .unwrap();
            assert!(!outcome.success);
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 3);
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
            ("counter".to_string(), json!({})),
            ("counter".to_string(), json!({})),
            ("counter".to_string(), json!({})),
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
        let reqs = vec![("nope".to_string(), json!({}))];
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
            ("counter".to_string(), json!({})),
            ("counter".to_string(), json!({"bad": 1})),
            ("counter".to_string(), json!({})),
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
            ("counter".to_string(), json!({})),
            ("counter".to_string(), json!({"bad": 1})),
            ("counter".to_string(), json!({})),
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
            ("echo".to_string(), json!({"msg": "hello"})),
            (
                "echo".to_string(),
                json!({"msg": "{{steps[0].stdout}} world"}),
            ),
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
