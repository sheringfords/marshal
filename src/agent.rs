#![allow(missing_docs)]
//! Agentic meta-tools — `think` / `memory` / `todo`
//!
//! These are not execution primitives but planning primitives. They give an
//! LLM agent a place to reason, remember, and plan without touching the
//! sandbox. All are `Tool` impls so they appear in `/v1/tools` and work
//! with `ToolRegistry::execute`, `batch` and `sequence` (including
//! `{{steps[0].stdout}}` templating). No filesystem or network access.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde_json::{json, Value};
use tokio::sync::RwLock;

use crate::{sha256_hex, Tool, ToolOutcome};

// ---------------------------------------------------------------------------
// ThinkTool — scratchpad
// ---------------------------------------------------------------------------

/// Private reasoning scratchpad. No side effects, always succeeds.
/// Use before `code`/`filesystem`/`shell` to avoid tool loops.
pub struct ThinkTool;

#[async_trait::async_trait]
impl Tool for ThinkTool {
    fn name(&self) -> &str {
        "think"
    }
    fn description(&self) -> &str {
        "Record private reasoning — plan, reflect, decompose, or choose next tool. No side effects. Use before every tool call to avoid loops; include confidence and alternatives for self-correction."
    }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "thought": {
                    "type": "string",
                    "description": "Your reasoning (1..4096 chars). Be specific: what you observed, what remains, and why the next tool is right.",
                    "minLength": 1,
                    "maxLength": 4096,
                    "examples": ["We have read a.txt (16B, sha256 ab12...). Need to parse JSON and write b.txt. Next: filesystem write /tmp/work/b.txt with transformed content."]
                },
                "next_action": {
                    "type": "string",
                    "description": "Intended next tool + args in one line — self-check. Optional.",
                    "examples": ["filesystem write /tmp/work/b.txt", "code python print(json.loads(open('a.txt').read()))"]
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence in this plan 0.0..1.0. Low (<0.5) signals need to gather more info or ask user. Optional.",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "examples": [0.85]
                },
                "alternatives": {
                    "type": "array",
                    "items": {"type":"string"},
                    "description": "Alternative actions considered and why rejected. Helps avoid retrying same failure. Optional, max 3.",
                    "maxItems": 3
                }
            },
            "required": ["thought"]
        })
    }
    async fn validate(&self, args: &Value) -> Result<()> {
        let t = args
            .get("thought")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'thought'"))?;
        if t.trim().is_empty() {
            bail!("thought_empty");
        }
        if t.len() > 4096 {
            bail!("thought_too_long");
        }
        if let Some(n) = args.get("next_action").and_then(Value::as_str) {
            if n.len() > 512 {
                bail!("next_action_too_long");
            }
        }
        if let Some(c) = args.get("confidence").and_then(Value::as_f64) {
            if !(0.0..=1.0).contains(&c) {
                bail!("confidence_out_of_range");
            }
        }
        if let Some(alts) = args.get("alternatives").and_then(Value::as_array) {
            if alts.len() > 3 {
                bail!("too_many_alternatives");
            }
            for a in alts {
                if !a.is_string() || a.as_str().unwrap().len() > 256 {
                    bail!("invalid_alternative");
                }
            }
        }
        Ok(())
    }
    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        self.validate(&args).await?;
        let thought = args.get("thought").and_then(Value::as_str).unwrap();
        let next_action = args
            .get("next_action")
            .and_then(Value::as_str)
            .unwrap_or("");
        let confidence = args.get("confidence").and_then(Value::as_f64);
        let alternatives = args
            .get("alternatives")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let digest = sha256_hex(thought.as_bytes());
        let summary = json!({
            "thought_bytes": thought.len(),
            "thought_sha256": digest,
            "next_action": next_action,
            "confidence": confidence,
            "alternatives": alternatives,
            "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
        });
        let mut outcome = ToolOutcome::success("think", summary, elapsed(started))
            .with_content(thought.as_bytes().to_vec())
            .with_metadata("thought_sha256", digest);
        if let Some(c) = confidence {
            outcome = outcome.with_metadata("confidence", c.to_string());
        }
        Ok(outcome)
    }
}

// ---------------------------------------------------------------------------
// MemoryTool — per-process KV with optional TTL
// ---------------------------------------------------------------------------

struct MemoryEntry {
    value: Value,
    inserted: Instant,
    ttl: Option<Duration>,
}

pub struct MemoryTool {
    // session_id -> (key -> entry). "global" for no session.
    store: Arc<RwLock<HashMap<String, HashMap<String, MemoryEntry>>>>,
    max_keys: usize,
    max_value_bytes: usize,
}

impl std::fmt::Debug for MemoryTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTool")
            .field("max_keys", &self.max_keys)
            .finish()
    }
}

impl Default for MemoryTool {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryTool {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            max_keys: 256,
            max_value_bytes: 16 * 1024,
        }
    }
    pub fn with_max_keys(mut self, n: usize) -> Self {
        self.max_keys = n.clamp(1, 1024);
        self
    }
    pub fn with_max_value_bytes(mut self, n: usize) -> Self {
        self.max_value_bytes = n.clamp(256, 64 * 1024);
        self
    }

    fn scope(args: &Value) -> String {
        args.get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("global")
            .to_string()
    }

    #[allow(dead_code)]
    async fn evict_expired(&self) {
        let mut m = self.store.write().await;
        for inner in m.values_mut() {
            inner.retain(|_, e| {
                if let Some(ttl) = e.ttl {
                    e.inserted.elapsed() < ttl
                } else {
                    true
                }
            });
        }
        m.retain(|_, inner| !inner.is_empty());
    }

    async fn evict_expired_scope(&self, scope: &str) {
        let mut m = self.store.write().await;
        if let Some(inner) = m.get_mut(scope) {
            inner.retain(|_, e| {
                if let Some(ttl) = e.ttl {
                    e.inserted.elapsed() < ttl
                } else {
                    true
                }
            });
            if inner.is_empty() {
                m.remove(scope);
            }
        }
    }
}

#[async_trait::async_trait]
impl Tool for MemoryTool {
    fn name(&self) -> &str {
        "memory"
    }
    fn description(&self) -> &str {
        "Session-aware key-value memory for the agent — store, recall, list, search, forget. Use global scope to share across sessions or session_id to isolate per-agent. Persists for process lifetime. Use to remember file paths, parsed results, or decisions."
    }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "operation": { "type": "string", "enum": ["store","recall","list","search","forget"], "description": "store: save, recall: get, list: keys, search: substring search over keys+values, forget: delete" },
                "key": { "type": "string", "description": "Key (1..128 chars, a-z0-9 _ - . /). Required for store/recall/forget.", "minLength": 1, "maxLength": 128 },
                "value": { "description": "Value to store (any JSON, max 16KiB). Required for store." },
                "ttl_ms": { "type": "integer", "description": "Optional TTL ms (1000..3600000). After expiry recall→not_found.", "minimum": 1000, "maximum": 3600000 },
                "session_id": { "type": "string", "description": "Optional session scope. If omitted uses global. Use same SID as marshalld session to isolate per-agent." },
                "query": { "type": "string", "description": "Substring to search for (search op only, 1..256 chars)." }
            },
            "required": ["operation"]
        })
    }
    async fn validate(&self, args: &Value) -> Result<()> {
        let op = args
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'operation'"))?;
        if !matches!(op, "store" | "recall" | "list" | "search" | "forget") {
            bail!("unsupported_operation: {op}");
        }
        if matches!(op, "store" | "recall" | "forget") {
            let k = args
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing 'key'"))?;
            if k.trim().is_empty() || k.len() > 128 {
                bail!("invalid_key");
            }
            if !k
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
            {
                bail!("invalid_key_chars");
            }
        }
        if op == "store" && args.get("value").is_none() {
            bail!("missing 'value'");
        }
        if op == "search" && args.get("query").and_then(Value::as_str).is_none() {
            bail!("missing 'query'");
        }
        if let Some(q) = args.get("query").and_then(Value::as_str) {
            if q.len() > 256 || q.trim().is_empty() {
                bail!("invalid_query");
            }
        }
        if let Some(v) = args.get("value") {
            let s = serde_json::to_string(v).unwrap_or_default();
            if s.len() > self.max_value_bytes {
                bail!("value_too_large");
            }
        }
        if let Some(ttl) = args.get("ttl_ms").and_then(Value::as_u64) {
            if !(1000..=3600000).contains(&ttl) {
                bail!("ttl_out_of_range");
            }
        }
        if let Some(sid) = args.get("session_id").and_then(Value::as_str) {
            if sid.len() > 128 {
                bail!("invalid_session_id");
            }
        }
        Ok(())
    }
    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        self.validate(&args).await?;
        let scope = Self::scope(&args);
        self.evict_expired_scope(&scope).await;
        let op = args.get("operation").and_then(Value::as_str).unwrap();
        match op {
            "store" => {
                let key = args.get("key").and_then(Value::as_str).unwrap().to_string();
                let value = args.get("value").unwrap().clone();
                let ttl = args
                    .get("ttl_ms")
                    .and_then(Value::as_u64)
                    .map(Duration::from_millis);
                let mut m = self.store.write().await;
                let inner = m.entry(scope.clone()).or_insert_with(HashMap::new);
                if inner.len() >= self.max_keys && !inner.contains_key(&key) {
                    if let Some(oldest) = inner
                        .iter()
                        .min_by_key(|(_, e)| e.inserted)
                        .map(|(k, _)| k.clone())
                    {
                        inner.remove(&oldest);
                    }
                }
                inner.insert(
                    key.clone(),
                    MemoryEntry {
                        value: value.clone(),
                        inserted: Instant::now(),
                        ttl,
                    },
                );
                let summary = json!({"operation":"store","key":key,"scope":scope,"value_type": value_type(&value), "ttl_ms": ttl.map(|d| d.as_millis())});
                Ok(ToolOutcome::success("memory", summary, elapsed(started))
                    .with_metadata("operation", "store"))
            }
            "recall" => {
                let key = args.get("key").and_then(Value::as_str).unwrap();
                let m = self.store.read().await;
                let inner = m.get(&scope);
                if let Some(entry) = inner.and_then(|map| map.get(key)) {
                    if let Some(ttl) = entry.ttl {
                        if entry.inserted.elapsed() >= ttl {
                            drop(m);
                            let mut w = self.store.write().await;
                            if let Some(map) = w.get_mut(&scope) {
                                map.remove(key);
                                if map.is_empty() {
                                    w.remove(&scope);
                                }
                            }
                            return Ok(ToolOutcome::failure(
                                "memory",
                                "not_found",
                                elapsed(started),
                            ));
                        }
                    }
                    let summary =
                        json!({"operation":"recall","key":key,"scope":scope,"found":true});
                    Ok(ToolOutcome::success("memory", summary, elapsed(started))
                        .with_content(serde_json::to_vec(&entry.value).unwrap_or_default())
                        .with_metadata("operation", "recall"))
                } else {
                    Ok(ToolOutcome::failure(
                        "memory",
                        "not_found",
                        elapsed(started),
                    ))
                }
            }
            "list" => {
                let m = self.store.read().await;
                let keys: Vec<String> = m
                    .get(&scope)
                    .map(|map| map.keys().cloned().collect())
                    .unwrap_or_default();
                let summary = json!({"operation":"list","scope":scope,"keys":keys, "count": m.get(&scope).map(|map| map.len()).unwrap_or(0)});
                Ok(ToolOutcome::success("memory", summary, elapsed(started))
                    .with_metadata("operation", "list"))
            }
            "search" => {
                let query = args.get("query").and_then(Value::as_str).unwrap();
                let m = self.store.read().await;
                let mut matches = Vec::new();
                if let Some(inner) = m.get(&scope) {
                    for (k, entry) in inner {
                        let v_str = serde_json::to_string(&entry.value).unwrap_or_default();
                        if k.contains(query) || v_str.contains(query) {
                            matches.push(json!({"key":k,"value":entry.value}));
                            if matches.len() >= 50 {
                                break;
                            }
                        }
                    }
                }
                let summary = json!({"operation":"search","scope":scope,"query":query,"matches":matches,"count":matches.len()});
                Ok(ToolOutcome::success("memory", summary, elapsed(started))
                    .with_metadata("operation", "search"))
            }
            "forget" => {
                let key = args.get("key").and_then(Value::as_str).unwrap();
                let mut m = self.store.write().await;
                let removed = if let Some(inner) = m.get_mut(&scope) {
                    let r = inner.remove(key).is_some();
                    if inner.is_empty() {
                        m.remove(&scope);
                    }
                    r
                } else {
                    false
                };
                let summary =
                    json!({"operation":"forget","key":key,"scope":scope,"removed":removed});
                Ok(ToolOutcome::success("memory", summary, elapsed(started))
                    .with_metadata("operation", "forget"))
            }
            _ => unreachable!(),
        }
    }
}

fn value_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// TodoTool — ordered todo list for the agent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TodoItem {
    id: String,
    task: String,
    status: String,   // pending | in_progress | done
    priority: String, // high | medium | low
    created_ms: u64,
}

pub struct TodoTool {
    // session_id -> todos
    store: Arc<RwLock<HashMap<String, Vec<TodoItem>>>>,
    max_items: usize,
}

impl std::fmt::Debug for TodoTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TodoTool")
            .field("max_items", &self.max_items)
            .finish()
    }
}

impl Default for TodoTool {
    fn default() -> Self {
        Self::new()
    }
}

impl TodoTool {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            max_items: 64,
        }
    }
    pub fn with_max_items(mut self, n: usize) -> Self {
        self.max_items = n.clamp(1, 256);
        self
    }
    fn scope(args: &Value) -> String {
        args.get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("global")
            .to_string()
    }
}

#[async_trait::async_trait]
impl Tool for TodoTool {
    fn name(&self) -> &str {
        "todo"
    }
    fn description(&self) -> &str {
        "Session-aware todo list for planning — add, list, update status, done, clear. Priority-aware (high/medium/low) and session-scoped. Use to break task into steps, track progress, avoid loops. Prefer over free-form thought."
    }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "operation": { "type": "string", "enum": ["add","list","update","done","clear","get"], "description": "add: create task (with priority), list: show all, get: fetch one by id, update: change status, done: complete, clear: remove done" },
                "task": { "type": "string", "description": "Task description for add (1..512 chars)", "minLength": 1, "maxLength": 512 },
                "priority": { "type": "string", "enum": ["high","medium","low"], "description": "Priority for add/update. Default medium.", "default": "medium" },
                "id": { "type": "string", "description": "Todo id for get/update/done." },
                "status": { "type": "string", "enum": ["pending","in_progress","done"], "description": "New status for update." },
                "session_id": { "type": "string", "description": "Optional session scope for isolation. Uses marshalld session_id if set." }
            },
            "required": ["operation"]
        })
    }
    async fn validate(&self, args: &Value) -> Result<()> {
        let op = args
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'operation'"))?;
        if !matches!(op, "add" | "list" | "update" | "done" | "clear" | "get") {
            bail!("unsupported_operation: {op}");
        }
        if op == "add" {
            let t = args
                .get("task")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing 'task'"))?;
            if t.trim().is_empty() || t.len() > 512 {
                bail!("invalid_task");
            }
            if let Some(p) = args.get("priority").and_then(Value::as_str) {
                if !matches!(p, "high" | "medium" | "low") {
                    bail!("invalid_priority");
                }
            }
        }
        if matches!(op, "update" | "done" | "get")
            && args.get("id").and_then(Value::as_str).is_none()
        {
            bail!("missing 'id'");
        }
        if op == "update" && args.get("status").and_then(Value::as_str).is_none() {
            bail!("missing 'status'");
        }
        Ok(())
    }
    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        self.validate(&args).await?;
        let op = args.get("operation").and_then(Value::as_str).unwrap();
        let scope = Self::scope(&args);
        match op {
            "add" => {
                let task = args
                    .get("task")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_string();
                let priority = args
                    .get("priority")
                    .and_then(Value::as_str)
                    .unwrap_or("medium")
                    .to_string();
                let mut store = self.store.write().await;
                let s = store.entry(scope.clone()).or_insert_with(Vec::new);
                if s.len() >= self.max_items {
                    s.remove(0);
                }
                let id = format!("t{}", s.len() + 1);
                let id = if s.iter().any(|i| i.id == id) {
                    format!(
                        "t{}-{}",
                        s.len() + 1,
                        Instant::now().elapsed().as_millis() % 1000
                    )
                } else {
                    id
                };
                let item = TodoItem {
                    id: id.clone(),
                    task: task.clone(),
                    status: "pending".into(),
                    priority: priority.clone(),
                    created_ms: Instant::now().elapsed().as_millis() as u64,
                };
                s.push(item);
                // keep high priority first for list? sort not needed, keep insertion order
                let summary = json!({"operation":"add","id":id,"task":task,"priority":priority,"scope":scope,"count":s.len()});
                Ok(ToolOutcome::success("todo", summary, elapsed(started))
                    .with_metadata("operation", "add"))
            }
            "list" => {
                let store = self.store.read().await;
                let s = store.get(&scope);
                let list = s.map(|v| v.as_slice()).unwrap_or(&[]);
                let summary =
                    json!({"operation":"list","scope":scope,"todos": list, "count": list.len()});
                Ok(ToolOutcome::success("todo", summary, elapsed(started))
                    .with_metadata("operation", "list"))
            }
            "get" => {
                let id = args.get("id").and_then(Value::as_str).unwrap();
                let store = self.store.read().await;
                if let Some(item) = store
                    .get(&scope)
                    .and_then(|v| v.iter().find(|i| i.id == id))
                {
                    let summary = json!({"operation":"get","scope":scope,"todo": item});
                    Ok(ToolOutcome::success("todo", summary, elapsed(started))
                        .with_metadata("operation", "get"))
                } else {
                    Ok(ToolOutcome::failure("todo", "not_found", elapsed(started)))
                }
            }
            "update" => {
                let id = args.get("id").and_then(Value::as_str).unwrap();
                let status = args.get("status").and_then(Value::as_str).unwrap();
                let mut store = self.store.write().await;
                if let Some(item) = store
                    .get_mut(&scope)
                    .and_then(|v| v.iter_mut().find(|i| i.id == id))
                {
                    item.status = status.to_string();
                    if let Some(p) = args.get("priority").and_then(Value::as_str) {
                        item.priority = p.to_string();
                    }
                    let summary =
                        json!({"operation":"update","id":id,"status":status,"scope":scope});
                    Ok(ToolOutcome::success("todo", summary, elapsed(started))
                        .with_metadata("operation", "update"))
                } else {
                    Ok(ToolOutcome::failure("todo", "not_found", elapsed(started)))
                }
            }
            "done" => {
                let id = args.get("id").and_then(Value::as_str).unwrap();
                let mut store = self.store.write().await;
                if let Some(item) = store
                    .get_mut(&scope)
                    .and_then(|v| v.iter_mut().find(|i| i.id == id))
                {
                    item.status = "done".into();
                    let summary = json!({"operation":"done","id":id,"scope":scope});
                    Ok(ToolOutcome::success("todo", summary, elapsed(started))
                        .with_metadata("operation", "done"))
                } else {
                    Ok(ToolOutcome::failure("todo", "not_found", elapsed(started)))
                }
            }
            "clear" => {
                let mut store = self.store.write().await;
                let (removed, remaining) = if let Some(v) = store.get_mut(&scope) {
                    let before = v.len();
                    v.retain(|i| i.status != "done");
                    (before - v.len(), v.len())
                } else {
                    (0, 0)
                };
                if remaining == 0 {
                    store.remove(&scope);
                }
                let summary =
                    json!({"operation":"clear","scope":scope,"removed":removed,"count": remaining});
                Ok(ToolOutcome::success("todo", summary, elapsed(started))
                    .with_metadata("operation", "clear"))
            }
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// PlanTool — structured task plan with dependencies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PlanStep {
    id: String,
    description: String,
    depends_on: Vec<String>,
    status: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Plan {
    id: String,
    goal: String,
    steps: Vec<PlanStep>,
    created_ms: u64,
}

pub struct PlanTool {
    store: Arc<RwLock<HashMap<String, HashMap<String, Plan>>>>, // scope -> plan_id -> Plan
    max_plans: usize,
}

impl std::fmt::Debug for PlanTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanTool").finish()
    }
}
impl Default for PlanTool {
    fn default() -> Self {
        Self::new()
    }
}
impl PlanTool {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            max_plans: 32,
        }
    }
    fn scope(args: &Value) -> String {
        args.get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("global")
            .to_string()
    }
}

#[async_trait::async_trait]
impl Tool for PlanTool {
    fn name(&self) -> &str {
        "plan"
    }
    fn description(&self) -> &str {
        "Structured plan — create goal with ordered steps and dependencies, list/get, add_step, update_status. Use before todo to design full execution strategy; links to todo for tracking."
    }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "operation": {"type":"string","enum":["create","list","get","add_step","update_step","clear"],"description":"create: goal+steps, list: all plans, get: by id, add_step: append step, update_step: status, clear: delete plan"},
                "goal": {"type":"string","description":"Goal for create (1..512 chars)","minLength":1,"maxLength":512},
                "steps": {"type":"array","items":{"type":"string"},"description":"Initial steps for create (each 1..256 chars, max 16).","maxItems":16},
                "plan_id": {"type":"string","description":"Plan id for get/add_step/update_step/clear"},
                "description": {"type":"string","description":"Step description for add_step","minLength":1,"maxLength":256},
                "depends_on": {"type":"array","items":{"type":"string"},"description":"Step ids this step depends on"},
                "status": {"type":"string","enum":["pending","in_progress","done","blocked"],"description":"New status for update_step"},
                "session_id": {"type":"string","description":"Optional session scope"}
            },
            "required": ["operation"]
        })
    }
    async fn validate(&self, args: &Value) -> Result<()> {
        let op = args
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'operation'"))?;
        if !matches!(
            op,
            "create" | "list" | "get" | "add_step" | "update_step" | "clear"
        ) {
            bail!("unsupported_operation: {op}");
        }
        if op == "create" {
            let g = args
                .get("goal")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing 'goal'"))?;
            if g.trim().is_empty() || g.len() > 512 {
                bail!("invalid_goal");
            }
            if let Some(steps) = args.get("steps").and_then(Value::as_array) {
                if steps.len() > 16 {
                    bail!("too_many_steps");
                }
                for s in steps {
                    if !s.is_string() || s.as_str().unwrap().len() > 256 {
                        bail!("invalid_step");
                    }
                }
            }
        }
        if matches!(op, "get" | "clear") && args.get("plan_id").and_then(Value::as_str).is_none() {
            bail!("missing 'plan_id'");
        }
        if op == "add_step" {
            if args.get("plan_id").and_then(Value::as_str).is_none() {
                bail!("missing 'plan_id'");
            }
            let d = args
                .get("description")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing 'description'"))?;
            if d.trim().is_empty() || d.len() > 256 {
                bail!("invalid_description");
            }
        }
        if op == "update_step" {
            if args.get("plan_id").and_then(Value::as_str).is_none() {
                bail!("missing 'plan_id'");
            }
            if args.get("description").is_none() && args.get("status").is_none() {
                bail!("missing 'description' or 'status'");
            }
        }
        Ok(())
    }
    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        self.validate(&args).await?;
        let op = args.get("operation").and_then(Value::as_str).unwrap();
        let scope = Self::scope(&args);
        match op {
            "create" => {
                let goal = args
                    .get("goal")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_string();
                let steps_raw: Vec<String> = args
                    .get("steps")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut store = self.store.write().await;
                let inner = store.entry(scope.clone()).or_insert_with(HashMap::new);
                if inner.len() >= self.max_plans {
                    if let Some(k) = inner.keys().next().cloned() {
                        inner.remove(&k);
                    }
                }
                let plan_id = format!("p{}", inner.len() + 1);
                let steps: Vec<PlanStep> = steps_raw
                    .into_iter()
                    .enumerate()
                    .map(|(i, s)| PlanStep {
                        id: format!("s{}", i + 1),
                        description: s,
                        depends_on: vec![],
                        status: "pending".into(),
                    })
                    .collect();
                let plan = Plan {
                    id: plan_id.clone(),
                    goal: goal.clone(),
                    steps,
                    created_ms: Instant::now().elapsed().as_millis() as u64,
                };
                inner.insert(plan_id.clone(), plan);
                Ok(ToolOutcome::success(
                    "plan",
                    json!({"operation":"create","plan_id":plan_id,"goal":goal,"scope":scope}),
                    elapsed(started),
                )
                .with_metadata("operation", "create"))
            }
            "list" => {
                let store = self.store.read().await;
                let list: Vec<&Plan> = store
                    .get(&scope)
                    .map(|m| m.values().collect())
                    .unwrap_or_default();
                Ok(ToolOutcome::success(
                    "plan",
                    json!({"operation":"list","scope":scope,"plans": list, "count": list.len()}),
                    elapsed(started),
                )
                .with_metadata("operation", "list"))
            }
            "get" => {
                let pid = args.get("plan_id").and_then(Value::as_str).unwrap();
                let store = self.store.read().await;
                if let Some(plan) = store.get(&scope).and_then(|m| m.get(pid)) {
                    Ok(ToolOutcome::success(
                        "plan",
                        json!({"operation":"get","scope":scope,"plan": plan}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "get"))
                } else {
                    Ok(ToolOutcome::failure("plan", "not_found", elapsed(started)))
                }
            }
            "add_step" => {
                let pid = args.get("plan_id").and_then(Value::as_str).unwrap();
                let desc = args
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_string();
                let depends: Vec<String> = args
                    .get("depends_on")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut store = self.store.write().await;
                if let Some(plan) = store.get_mut(&scope).and_then(|m| m.get_mut(pid)) {
                    let sid = format!("s{}", plan.steps.len() + 1);
                    plan.steps.push(PlanStep {
                        id: sid.clone(),
                        description: desc.clone(),
                        depends_on: depends,
                        status: "pending".into(),
                    });
                    Ok(ToolOutcome::success("plan", json!({"operation":"add_step","plan_id":pid,"step_id":sid,"description":desc,"scope":scope}), elapsed(started)).with_metadata("operation","add_step"))
                } else {
                    Ok(ToolOutcome::failure("plan", "not_found", elapsed(started)))
                }
            }
            "update_step" => {
                let pid = args.get("plan_id").and_then(Value::as_str).unwrap();
                let desc = args.get("description").and_then(Value::as_str);
                let status = args.get("status").and_then(Value::as_str);
                let mut store = self.store.write().await;
                if let Some(plan) = store.get_mut(&scope).and_then(|m| m.get_mut(pid)) {
                    // try by step id if provided as description is actually id? Use status update by id
                    // For simplicity, find step by id == description if status provided
                    if let Some(sid) = desc {
                        if let Some(step) = plan.steps.iter_mut().find(|s| s.id == sid) {
                            if let Some(st) = status {
                                step.status = st.to_string();
                            }
                            return Ok(ToolOutcome::success("plan", json!({"operation":"update_step","plan_id":pid,"step_id":sid,"status":status}), elapsed(started)).with_metadata("operation","update_step"));
                        }
                    }
                    // fallback: update first pending
                    if let Some(step) = plan.steps.iter_mut().find(|s| s.status != "done") {
                        if let Some(st) = status {
                            step.status = st.to_string();
                        }
                        if let Some(d) = desc {
                            step.description = d.to_string();
                        }
                    }
                    Ok(ToolOutcome::success(
                        "plan",
                        json!({"operation":"update_step","plan_id":pid,"scope":scope}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "update_step"))
                } else {
                    Ok(ToolOutcome::failure("plan", "not_found", elapsed(started)))
                }
            }
            "clear" => {
                let pid = args.get("plan_id").and_then(Value::as_str).unwrap();
                let mut store = self.store.write().await;
                let removed = store
                    .get_mut(&scope)
                    .map(|m| m.remove(pid).is_some())
                    .unwrap_or(false);
                Ok(ToolOutcome::success(
                    "plan",
                    json!({"operation":"clear","plan_id":pid,"removed":removed,"scope":scope}),
                    elapsed(started),
                )
                .with_metadata("operation", "clear"))
            }
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// ReflectTool — post-execution critique
// ---------------------------------------------------------------------------

pub struct ReflectTool;

#[async_trait::async_trait]
impl Tool for ReflectTool {
    fn name(&self) -> &str {
        "reflect"
    }
    fn description(&self) -> &str {
        "Critique last outcome — analyze success/failure, what was learned, what to try next. Use after a tool fails or to avoid repeating errors; produces next_action suggestion."
    }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "outcome": {"type":"object","description":"The ToolOutcome summary to reflect on (or any JSON). Required."},
                "thought": {"type":"string","description":"Your interpretation of why it succeeded/failed (1..1024 chars).","minLength":1,"maxLength":1024},
                "next_action": {"type":"string","description":"Suggested next tool+args. Example: retry with different path."}
            },
            "required": ["outcome"]
        })
    }
    async fn validate(&self, args: &Value) -> Result<()> {
        if args.get("outcome").is_none() {
            bail!("missing 'outcome'");
        }
        if let Some(t) = args.get("thought").and_then(Value::as_str) {
            if t.len() > 1024 {
                bail!("thought_too_long");
            }
        }
        Ok(())
    }
    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        self.validate(&args).await?;
        let outcome_val = args.get("outcome").unwrap().clone();
        let thought = args
            .get("thought")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let next_action = args
            .get("next_action")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let success = outcome_val
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let critique = if success {
            "Outcome succeeded — extract reusable pattern."
        } else {
            "Outcome failed — diagnose error_code and adjust parameters."
        };
        let summary = json!({
            "critique": critique,
            "success": success,
            "thought": thought,
            "next_action": next_action,
            "outcome_type": outcome_val.get("tool").and_then(Value::as_str).unwrap_or("unknown"),
            "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
        });
        let content = json!({"critique": critique, "thought": thought, "next_action": next_action, "outcome": outcome_val}).to_string();
        Ok(ToolOutcome::success("reflect", summary, elapsed(started))
            .with_content(content.into_bytes())
            .with_metadata("success", success.to_string()))
    }
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn think_records_thought() {
        let t = ThinkTool;
        let out = t
            .execute(json!({"thought":"plan: read then write","next_action":"filesystem read"}))
            .await
            .unwrap();
        assert!(out.success);
        assert_eq!(out.content.as_ref().unwrap(), b"plan: read then write");
    }

    #[tokio::test]
    async fn memory_store_recall() {
        let m = MemoryTool::new();
        let out = m
            .execute(json!({"operation":"store","key":"k1","value":{"a":1}}))
            .await
            .unwrap();
        assert!(out.success);
        let out = m
            .execute(json!({"operation":"recall","key":"k1"}))
            .await
            .unwrap();
        assert!(out.success);
        let v: Value = serde_json::from_slice(out.content.as_ref().unwrap()).unwrap();
        assert_eq!(v["a"], 1);
    }

    #[tokio::test]
    async fn todo_add_list_done() {
        let t = TodoTool::new();
        t.execute(json!({"operation":"add","task":"first"}))
            .await
            .unwrap();
        t.execute(json!({"operation":"add","task":"second"}))
            .await
            .unwrap();
        let out = t.execute(json!({"operation":"list"})).await.unwrap();
        assert_eq!(out.summary["count"], 2);
        let id = out.summary["todos"][0]["id"].as_str().unwrap().to_string();
        let out = t
            .execute(json!({"operation":"done","id": id}))
            .await
            .unwrap();
        assert!(out.success);
    }
}
