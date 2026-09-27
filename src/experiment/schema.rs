#![allow(missing_docs)]
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Current measurement schema version. Must be explicit in every event.
pub const SCHEMA_VERSION: &str = "validation.v1";

/// Event types that can appear in a JSONL trace. The file must be
/// chronologically ordered; a task is bounded by `task_started` /
/// `task_completed` — never inferred from EOF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    TaskStarted,
    AgentTurnStarted,
    AgentTurnCompleted,
    ToolCallStarted,
    ToolCallCompleted,
    VerificationStarted,
    VerificationCompleted,
    TaskCompleted,
    /// Phase 2 treatment: bounded sequence parent (counts as ONE handoff)
    BoundedSequenceStarted,
    BoundedSequenceCompleted,
    /// Phase 3: verify_change parent
    VerifyChangeStarted,
    VerifyChangeCompleted,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TaskStarted => "task_started",
            Self::AgentTurnStarted => "agent_turn_started",
            Self::AgentTurnCompleted => "agent_turn_completed",
            Self::ToolCallStarted => "tool_call_started",
            Self::ToolCallCompleted => "tool_call_completed",
            Self::VerificationStarted => "verification_started",
            Self::VerificationCompleted => "verification_completed",
            Self::TaskCompleted => "task_completed",
            Self::BoundedSequenceStarted => "bounded_sequence_started",
            Self::BoundedSequenceCompleted => "bounded_sequence_completed",
            Self::VerifyChangeStarted => "verify_change_started",
            Self::VerifyChangeCompleted => "verify_change_completed",
        }
    }
}

/// Task outcome — explicit, never inferred from tool success alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskOutcome {
    Success,
    Failure,
    Partial,
    InvalidRun,
    #[default]
    Unknown,
}

/// Optional per-turn token usage. Every field is optional; unknown stays `null`, never zero.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
}

/// Verification record attached to verification events.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
}

/// Repository state snapshot (before/after). Fails gracefully outside git.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoStateSnapshot {
    /// Full HEAD SHA if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Branch name if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Whether working tree is dirty.
    pub dirty: bool,
    /// Number of changed files (status porcelain lines).
    pub changed_count: usize,
    /// Changed file paths (porcelain second column parsed).
    #[serde(default)]
    pub changed_files: Vec<String>,
    /// Insertions from `git diff --numstat` sum, if collected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines_added: Option<u64>,
    /// Deletions from `git diff --numstat` sum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines_deleted: Option<u64>,
    /// Raw `git status --porcelain` output, truncated to 8 KiB if needed (no secrets).
    #[serde(default)]
    pub status_porcelain: String,
}

/// One append-only JSONL record. Flat shape for easy `jq`.
///
/// Many fields are `Option` because they apply only to specific `event_type`s.
/// The illustrative shape in the spec is honoured:
///
/// ```json
/// { schema_version, experiment_id, task_id, variant, event_id, event_type,
///   timestamp, turn_id, call_id, tool, operation, duration_ms, success, ... }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentEvent {
    pub schema_version: String,
    pub experiment_id: String,
    pub task_id: String,
    pub variant: String,
    pub event_id: String,
    pub event_type: EventType,
    /// RFC3339 wall-clock timestamp (UTC, `chrono`).
    pub timestamp: String,
    /// Monotonic milliseconds since task_started (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monotonic_ms: Option<u64>,

    // ── correlations ───────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// For retry accounting: parent call this is a retry of, if explicit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_of: Option<String>,
    /// Phase 2: child tool calls carry parent sequence id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_call_id: Option<String>,
    /// Phase 2: sequence identifier (parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_steps: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_steps: Option<usize>,

    // ── tool fields ────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Filesystem operation, shell program, etc., when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    /// Whether `execute_once` served from cache, if known cleanly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached: Option<bool>,

    // ── agent-turn token/model fields ──────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,

    // ── verification ───────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    // ── task outcome ───────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_success: Option<TaskOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_or_external_judge: Option<String>,

    // ── repo/task metadata ─────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_or_fixture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_before: Option<RepoStateSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_after: Option<RepoStateSnapshot>,

    // ── free-form metadata (never raw secrets/content) ──
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ExperimentEvent {
    pub fn new(
        experiment_id: impl Into<String>,
        task_id: impl Into<String>,
        variant: impl Into<String>,
        event_type: EventType,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            experiment_id: experiment_id.into(),
            task_id: task_id.into(),
            variant: variant.into(),
            event_id: format!("evt_{}", uuid::Uuid::new_v4()),
            event_type,
            timestamp: now,
            monotonic_ms: None,
            turn_id: None,
            call_id: None,
            retry_of: None,
            parent_call_id: None,
            sequence_id: None,
            requested_steps: None,
            executed_steps: None,
            tool: None,
            operation: None,
            duration_ms: None,
            success: None,
            error_code: None,
            input_bytes: None,
            output_bytes: None,
            output_sha256: None,
            cached: None,
            model: None,
            provider: None,
            input_tokens: None,
            output_tokens: None,
            cached_input_tokens: None,
            reasoning_tokens: None,
            verification_id: None,
            command: None,
            exit_code: None,
            task_success: None,
            human_or_external_judge: None,
            task_category: None,
            task_description: None,
            repo_or_fixture: None,
            base_revision: None,
            executor: None,
            harness_version: None,
            environment: None,
            repo_before: None,
            repo_after: None,
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_round_trip() {
        let mut e =
            ExperimentEvent::new("exp_1", "task_1", "baseline", EventType::ToolCallCompleted);
        e.tool = Some("shell".into());
        e.operation = Some("execute".into());
        e.duration_ms = Some(182);
        e.success = Some(true);
        e.input_bytes = Some(84);
        e.output_bytes = Some(1214);
        e.output_sha256 = Some("abc".into());
        e.call_id = Some("call_1".into());
        e.turn_id = Some("turn_1".into());
        let s = serde_json::to_string(&e).unwrap();
        let d: ExperimentEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(e, d);
        assert_eq!(d.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn unknown_tokens_remain_null() {
        let mut e =
            ExperimentEvent::new("exp_1", "task_1", "baseline", EventType::AgentTurnCompleted);
        e.turn_id = Some("turn_1".into());
        // leave token fields None
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("input_tokens").is_none());
        assert!(v.get("output_tokens").is_none());
        let d: ExperimentEvent = serde_json::from_value(v).unwrap();
        assert_eq!(d.input_tokens, None);
    }

    #[test]
    fn token_serde_preserves_some() {
        let mut e =
            ExperimentEvent::new("exp_1", "task_1", "baseline", EventType::AgentTurnCompleted);
        e.input_tokens = Some(100);
        e.output_tokens = Some(50);
        e.cached_input_tokens = None;
        e.reasoning_tokens = Some(10);
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["input_tokens"], 100);
        assert!(v.get("cached_input_tokens").is_none());
        let d: ExperimentEvent = serde_json::from_value(v).unwrap();
        assert_eq!(d.input_tokens, Some(100));
        assert_eq!(d.cached_input_tokens, None);
    }
}
