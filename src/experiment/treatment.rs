#![allow(missing_docs)]
use serde_json::{json, Value};
use std::time::Instant;

use crate::{ContractedCall, ToolOutcome, ToolRegistry};

use super::recorder::TaskRecorder;

/// Request contract for bounded sequence treatment.
#[derive(Debug, Clone)]
pub struct BoundedSequenceRequest {
    pub steps: Vec<(String, Value)>,
}

/// Response contract — compact evidence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BoundedSequenceResponse {
    pub success: bool,
    pub requested_steps: usize,
    pub executed_steps: usize,
    pub per_step: Vec<StepResult>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StepResult {
    pub tool: String,
    pub operation: Option<String>,
    pub success: bool,
    pub error_code: Option<String>,
    pub duration_ms: u64,
    pub output_bytes: Option<usize>,
    pub output_sha256: Option<String>,
}

/// Execute a bounded sequence (2-3 steps) as ONE handoff.
/// Stops on first failure (Err or success==false). No retry, branch, loop.
pub async fn execute_bounded_sequence(
    registry: &ToolRegistry,
    recorder: &TaskRecorder,
    turn_id: Option<String>,
    sequence_id: &str,
    steps: Vec<(String, Value)>,
) -> anyhow::Result<ToolOutcome> {
    // Validation: 2..=3
    if steps.len() < 2 {
        anyhow::bail!("bounded_sequence requires at least 2 steps");
    }
    if steps.len() > 3 {
        anyhow::bail!("bounded_sequence exceeds maximum 3 steps");
    }
    // No branching/loop already enforced by flat vec; continue_on_error false.

    let requested = steps.len();
    let start = Instant::now();
    let _ = recorder.bounded_sequence_started(sequence_id, turn_id.clone(), requested);

    let mut executed = 0usize;
    let mut per_step: Vec<StepResult> = Vec::new();
    let mut overall_success = true;
    let mut error_code: Option<String> = None;

    for (idx, (tool, args)) in steps.iter().enumerate() {
        let op = args
            .get("operation")
            .and_then(Value::as_str)
            .or_else(|| args.get("program").and_then(Value::as_str))
            .or_else(|| args.get("language").and_then(Value::as_str))
            .map(|s| s.to_string());
        let input_bytes = Some(serde_json::to_string(args).unwrap_or_default().len());
        let call_id = format!("{}_step{}", sequence_id, idx + 1);
        // Emit child started
        let _ = recorder.tool_call_started(
            call_id.clone(),
            turn_id.clone(),
            tool.clone(),
            op.clone(),
            input_bytes,
        );
        // Execute child via registry (normal policy enforcement)
        let res = registry.execute(tool, args.clone()).await;
        executed += 1;
        let (outcome, is_err) = match res {
            Ok(o) => (o, false),
            Err(e) => {
                let code = e
                    .to_string()
                    .split(':')
                    .next()
                    .unwrap_or("error")
                    .trim()
                    .to_string();
                let fake = ToolOutcome::failure(tool.clone(), code.clone(), 0);
                (fake, true)
            }
        };
        // success is outcome.success; Err already mapped to failure
        let success = outcome.success && !is_err;
        if !success && error_code.is_none() {
            error_code = outcome
                .error_code
                .clone()
                .or_else(|| Some("step_failed".into()));
            overall_success = false;
        }
        // Emit child completed with parent linking
        let _ = recorder.tool_call_completed_with_parent(
            call_id.clone(),
            turn_id.clone(),
            tool.clone(),
            op.clone(),
            &outcome,
            input_bytes,
            None,
            None,
            Some(sequence_id.to_string()),
        );
        // Record per-step compact evidence
        let output_bytes = outcome
            .content
            .as_ref()
            .map(|b| b.len())
            .or_else(|| {
                outcome
                    .summary
                    .get("bytes")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize)
            })
            .or_else(|| {
                outcome
                    .summary
                    .get("stdout_bytes")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize)
            });
        let output_sha256 = outcome
            .content
            .as_ref()
            .map(|b| crate::sha256_hex(b))
            .or_else(|| {
                outcome
                    .summary
                    .get("sha256")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                outcome
                    .summary
                    .get("stdout_sha256")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });
        per_step.push(StepResult {
            tool: tool.clone(),
            operation: op,
            success,
            error_code: outcome.error_code.clone(),
            duration_ms: outcome.duration_ms,
            output_bytes,
            output_sha256,
        });

        if !success {
            // stop-on-failure
            break;
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    // Build parent summary
    let success = overall_success && executed == requested && per_step.iter().all(|s| s.success);
    // If stopped early due to failure, success false
    if executed < requested {
        // already marked
    }
    let _ = recorder.bounded_sequence_completed(
        sequence_id,
        turn_id.clone(),
        requested,
        executed,
        success,
        duration_ms,
        error_code.clone(),
        per_step
            .iter()
            .map(|s| {
                json!({
                    "tool": s.tool,
                    "operation": s.operation,
                    "success": s.success,
                    "error_code": s.error_code,
                    "duration_ms": s.duration_ms,
                    "output_bytes": s.output_bytes,
                    "output_sha256": s.output_sha256
                })
            })
            .collect(),
    );

    // Build ToolOutcome for agent: compact evidence, bounded
    let summary = json!({
        "sequence_success": success,
        "requested_steps": requested,
        "executed_steps": executed,
        "per_step": per_step.iter().map(|s| json!({
            "tool": s.tool,
            "operation": s.operation,
            "success": s.success,
            "error_code": s.error_code,
            "duration_ms": s.duration_ms,
            "output_bytes": s.output_bytes,
            "output_sha256": s.output_sha256
        })).collect::<Vec<_>>(),
        "duration_ms": duration_ms,
        "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
    });
    let mut outcome = if success {
        ToolOutcome::success("bounded_sequence", summary, duration_ms)
    } else {
        let mut f = ToolOutcome::failure(
            "bounded_sequence",
            error_code.unwrap_or_else(|| "sequence_failed".into()),
            duration_ms,
        );
        f.summary = summary;
        f
    };
    // Bounded content: up to 8 KiB of per-step hashes, not raw outputs
    let content = serde_json::to_vec(&per_step).unwrap_or_default();
    let truncated = if content.len() > 8192 {
        &content[..8192]
    } else {
        &content[..]
    };
    outcome = outcome.with_content(truncated.to_vec());
    Ok(outcome)
}

/// Tool wrapper exposing bounded_sequence as a registrable Tool.
pub struct BoundedSequenceTool {
    registry: std::sync::Arc<ToolRegistry>,
    recorder: Option<std::sync::Arc<TaskRecorder>>,
}

impl BoundedSequenceTool {
    pub fn new(registry: std::sync::Arc<ToolRegistry>) -> Self {
        Self {
            registry,
            recorder: None,
        }
    }
    pub fn with_recorder(mut self, rec: std::sync::Arc<TaskRecorder>) -> Self {
        self.recorder = Some(rec);
        self
    }
}

#[async_trait::async_trait]
impl crate::Tool for BoundedSequenceTool {
    fn name(&self) -> &str {
        "bounded_sequence"
    }
    fn description(&self) -> &str {
        "Bounded deterministic sequence (2-3 steps, stop-on-failure, no branching). Use for search→read or read→write→shell bundles."
    }
    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "steps": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 3,
                    "items": {
                        "type": "object",
                        "properties": {
                            "tool": {"type":"string"},
                            "args": {"type":"object"}
                        },
                        "required": ["tool","args"]
                    }
                }
            },
            "required": ["steps"]
        })
    }
    async fn validate(&self, args: &Value) -> anyhow::Result<()> {
        let steps = args
            .get("steps")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("missing 'steps'"))?;
        if steps.len() < 2 || steps.len() > 3 {
            anyhow::bail!("bounded_sequence requires 2-3 steps");
        }
        for s in steps {
            let tool = s
                .get("tool")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing tool in step"))?;
            if !self.registry.has_tool(tool) {
                anyhow::bail!("tool_not_found: {tool}");
            }
            if tool == "bounded_sequence" {
                anyhow::bail!("nested bounded_sequence not allowed");
            }
            let a = s
                .get("args")
                .ok_or_else(|| anyhow::anyhow!("missing args in step"))?;
            // Validate step via registry's tool validate
            // We can't call async validate without clone, so just check presence
            let _ = a;
        }
        Ok(())
    }
    async fn execute(&self, args: Value) -> anyhow::Result<ToolOutcome> {
        let steps_val = args
            .get("steps")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("missing 'steps'"))?;
        let mut steps: Vec<(String, Value)> = Vec::new();
        for s in steps_val {
            let tool = s.get("tool").and_then(Value::as_str).unwrap().to_string();
            let a = s.get("args").cloned().unwrap_or(Value::Null);
            steps.push((tool, a));
        }
        // If recorder available, use it for measurement; otherwise run without
        if let Some(rec) = &self.recorder {
            let seq_id = format!("seq_{}", uuid::Uuid::new_v4());
            execute_bounded_sequence(&self.registry, rec, None, &seq_id, steps).await
        } else {
            // No recorder: explicit trusted-local calls, no HTTP admission.
            let contracted: Vec<ContractedCall> = steps
                .iter()
                .map(|(tool, a)| ContractedCall::local(&self.registry, tool, a.clone()))
                .collect();
            let res = self.registry.execute_sequence(contracted, false).await;
            // Build summary similar
            let mut per_step = Vec::new();
            let mut success = true;
            for r in &res {
                match r {
                    Ok(o) => {
                        if !o.success {
                            success = false;
                        }
                        per_step.push(json!({"tool": o.tool, "success": o.success, "duration_ms": o.duration_ms}));
                    }
                    Err(e) => {
                        success = false;
                        per_step.push(json!({"error": e.to_string()}));
                    }
                }
            }
            let summary = json!({"sequence_success": success, "steps": per_step});
            if success {
                Ok(ToolOutcome::success("bounded_sequence", summary, 0))
            } else {
                Ok(ToolOutcome::failure(
                    "bounded_sequence",
                    "sequence_failed",
                    0,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiment::recorder::{read_jsonl, ExperimentRecorder};
    use crate::{FileSystemTool, Sandbox};
    use std::sync::Arc;

    fn test_registry(tmp: &std::path::Path) -> ToolRegistry {
        let sandbox = Sandbox::new([tmp]).unwrap();
        let fs = FileSystemTool::new(sandbox).writable();
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(fs));
        reg
    }

    #[tokio::test]
    async fn two_step_success() {
        let dir = std::env::temp_dir().join(format!("treat_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_t", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t1").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        let reg = test_registry(&dir);
        std::fs::write(dir.join("a.txt"), "hello").unwrap();
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"write","path": dir.join("b.txt").to_string_lossy(), "content":"hi"}),
            ),
        ];
        let outcome = execute_bounded_sequence(&reg, &task, Some("turn_1".into()), "seq_1", steps)
            .await
            .unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.summary["requested_steps"], 2);
        assert_eq!(outcome.summary["executed_steps"], 2);
        task.task_completed(crate::experiment::schema::TaskOutcome::Success, None, None)
            .unwrap();
        let evs = read_jsonl(task.path()).unwrap();
        assert!(evs.iter().any(
            |e| e.event_type == crate::experiment::schema::EventType::BoundedSequenceCompleted
        ));
        // children should have parent_call_id
        let children: Vec<_> = evs
            .iter()
            .filter(|e| e.event_type == crate::experiment::schema::EventType::ToolCallCompleted)
            .collect();
        assert_eq!(children.len(), 2);
        assert!(children
            .iter()
            .all(|e| e.parent_call_id.as_deref() == Some("seq_1")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn three_step_success() {
        let dir = std::env::temp_dir().join(format!("treat3_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_t3", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t3").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        let reg = test_registry(&dir);
        std::fs::write(dir.join("a.txt"), "hello").unwrap();
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"write","path": dir.join("b.txt").to_string_lossy(), "content":"hi"}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("b.txt").to_string_lossy()}),
            ),
        ];
        let outcome = execute_bounded_sequence(&reg, &task, None, "seq_3", steps)
            .await
            .unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.summary["executed_steps"], 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rejects_four_steps() {
        let dir = std::env::temp_dir().join(format!("treat4_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_t4", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t4").unwrap();
        let reg = test_registry(&dir);
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
        ];
        let res = execute_bounded_sequence(&reg, &task, None, "seq_4", steps).await;
        assert!(res.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rejects_one_step() {
        let dir = std::env::temp_dir().join(format!("treat1_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_t1", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t1b").unwrap();
        let reg = test_registry(&dir);
        let steps = vec![(
            "filesystem".to_string(),
            serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
        )];
        let res = execute_bounded_sequence(&reg, &task, None, "seq_1", steps).await;
        assert!(res.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn stop_on_failure() {
        let dir = std::env::temp_dir().join(format!("treat_fail_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_f", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("tf").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        let reg = test_registry(&dir);
        // first step reads non-existent -> fails
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("no.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"write","path": dir.join("b.txt").to_string_lossy(), "content":"hi"}),
            ),
        ];
        let outcome = execute_bounded_sequence(&reg, &task, None, "seq_f", steps)
            .await
            .unwrap();
        assert!(!outcome.success);
        assert_eq!(outcome.summary["executed_steps"], 1);
        // ensure second file not created
        assert!(!dir.join("b.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sandbox_denial_stops() {
        let dir = std::env::temp_dir().join(format!("treat_sand_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("safe")).unwrap();
        let sandbox = Sandbox::new([dir.join("safe")]).unwrap();
        let fs = FileSystemTool::new(sandbox).writable();
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(fs));
        let exp = ExperimentRecorder::new("exp_s", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("ts").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("outside.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"write","path": dir.join("safe/b.txt").to_string_lossy(), "content":"hi"}),
            ),
        ];
        let outcome = execute_bounded_sequence(&reg, &task, None, "seq_s", steps)
            .await
            .unwrap();
        assert!(!outcome.success);
        assert_eq!(outcome.summary["executed_steps"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn step2_failure_prevents_step3() {
        let dir = std::env::temp_dir().join(format!("treat_s2_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_s2", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t_s2").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        let reg = test_registry(&dir);
        std::fs::write(dir.join("a.txt"), "hi").unwrap();
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("missing.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"write","path": dir.join("c.txt").to_string_lossy(), "content":"hi"}),
            ),
        ];
        let outcome = execute_bounded_sequence(&reg, &task, None, "seq_s2", steps)
            .await
            .unwrap();
        assert!(!outcome.success);
        assert_eq!(outcome.summary["executed_steps"], 2);
        assert!(!dir.join("c.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn policy_denial_stops() {
        let dir = std::env::temp_dir().join(format!("treat_pol_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_pol", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t_pol").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        let sandbox = Sandbox::new([&dir]).unwrap();
        let fs = FileSystemTool::new(sandbox).writable();
        let http = crate::HttpTool::new(Vec::<String>::new()); // deny all
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(fs));
        reg.register(Arc::new(http));
        std::fs::write(dir.join("a.txt"), "hi").unwrap();
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
            (
                "http".to_string(),
                serde_json::json!({"url": "https://example.com/"}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"write","path": dir.join("b.txt").to_string_lossy(), "content":"hi"}),
            ),
        ];
        let outcome = execute_bounded_sequence(&reg, &task, None, "seq_pol", steps)
            .await
            .unwrap();
        assert!(!outcome.success);
        assert_eq!(outcome.summary["executed_steps"], 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn output_limits_per_child() {
        let dir = std::env::temp_dir().join(format!("treat_lim_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_lim", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t_lim").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        let sandbox = Sandbox::new([&dir]).unwrap();
        let fs = FileSystemTool::new(sandbox).writable().with_read_limit(10);
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(fs));
        std::fs::write(dir.join("big.txt"), "0123456789ABCDEF").unwrap();
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("big.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("big.txt").to_string_lossy()}),
            ),
        ];
        let outcome = execute_bounded_sequence(&reg, &task, None, "seq_lim", steps)
            .await
            .unwrap();
        assert!(outcome.success);
        // each child should be truncated at 10
        let per_step = outcome.summary["per_step"].as_array().unwrap();
        for s in per_step {
            assert_eq!(s["output_bytes"], 10);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handoff_vs_underlying_counts() {
        let dir = std::env::temp_dir().join(format!("treat_cnt_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_cnt", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t_cnt").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        let reg = test_registry(&dir);
        std::fs::write(dir.join("a.txt"), "hi").unwrap();
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"write","path": dir.join("b.txt").to_string_lossy(), "content":"hi"}),
            ),
        ];
        let _ = execute_bounded_sequence(&reg, &task, Some("turn_1".into()), "seq_cnt", steps)
            .await
            .unwrap();
        task.task_completed(crate::experiment::schema::TaskOutcome::Success, None, None)
            .unwrap();
        let evs = read_jsonl(task.path()).unwrap();
        let handoff = evs
            .iter()
            .filter(|e| {
                e.event_type == crate::experiment::schema::EventType::BoundedSequenceCompleted
            })
            .count();
        let underlying = evs
            .iter()
            .filter(|e| e.event_type == crate::experiment::schema::EventType::ToolCallCompleted)
            .count();
        assert_eq!(handoff, 1, "parent counted once");
        assert_eq!(underlying, 2, "children counted as 2");
        // ensure no double count: total handoff+underlying not 3+?
        let m = crate::experiment::analyzer::analyze_events(&evs).unwrap();
        assert_eq!(m.model_visible_handoff_count, 1);
        assert_eq!(m.underlying_tool_operation_count, 2);
        assert_eq!(m.model_visible_tool_call_count, 2); // backward compat
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn argument_policy_denial_stops() {
        let dir = std::env::temp_dir().join(format!("treat_arg_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_arg", "treatment", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t_arg").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        let sandbox = Sandbox::new([&dir]).unwrap();
        let shell = crate::ShellTool::new(vec![crate::shell::AllowedCommand::new("/bin/echo")]); // NoFlags default denies args
        let fs = FileSystemTool::new(sandbox).writable();
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(shell));
        reg.register(Arc::new(fs));
        std::fs::write(dir.join("a.txt"), "hi").unwrap();
        let steps = vec![
            (
                "filesystem".to_string(),
                serde_json::json!({"operation":"read","path": dir.join("a.txt").to_string_lossy()}),
            ),
            (
                "shell".to_string(),
                serde_json::json!({"program": "/bin/echo", "args": ["--bad"]}),
            ),
        ];
        let outcome = execute_bounded_sequence(&reg, &task, None, "seq_arg", steps)
            .await
            .unwrap();
        assert!(!outcome.success);
        assert_eq!(outcome.summary["executed_steps"], 2); // second fails, so 2 executed but success false
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn validation_v1_backward_compat() {
        // Old traces without bounded_sequence should still parse and analyze
        let dir = std::env::temp_dir().join(format!("compat_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exp = ExperimentRecorder::new("exp_compat", "baseline", dir.join("exp")).unwrap();
        let task = exp.task_recorder("t_compat").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        task.agent_turn_started("turn_1").unwrap();
        let outcome = crate::ToolOutcome::success("filesystem", serde_json::json!({}), 5);
        task.tool_call_completed(
            "call_1",
            Some("turn_1".into()),
            "filesystem",
            Some("read".into()),
            &outcome,
            None,
            None,
            None,
        )
        .unwrap();
        task.agent_turn_completed("turn_1", None, None, None, None)
            .unwrap();
        task.task_completed(crate::experiment::schema::TaskOutcome::Success, None, None)
            .unwrap();
        let evs = read_jsonl(task.path()).unwrap();
        let m = crate::experiment::analyzer::analyze_events(&evs).unwrap();
        assert_eq!(m.model_visible_handoff_count, 1);
        assert_eq!(m.underlying_tool_operation_count, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
