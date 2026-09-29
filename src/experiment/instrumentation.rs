#![allow(missing_docs)]
//! Measurement instrumentation — separate from execution semantics.
//!
//! Provides thin wrappers around `ToolRegistry` that emit `tool_call_*` events
//! to a `TaskRecorder` without altering `Ok`/`Err` or `ToolOutcome`.
//! All batch/sequence instrumentation emits **N child events, never N+1** —
//! the wrapper itself is not counted as a tool call.

use serde_json::Value;

#[allow(unused_imports)]
use crate::{ContractedCall, ToolOutcome, ToolRegistry};

use super::recorder::TaskRecorder;

/// Single-call instrumentation — emits started/completed around `registry.execute`.
pub async fn instrument_execute(
    registry: &ToolRegistry,
    recorder: &TaskRecorder,
    turn_id: Option<String>,
    call_id: &str,
    tool: &str,
    args: Value,
) -> anyhow::Result<ToolOutcome> {
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .or_else(|| args.get("program").and_then(Value::as_str))
        .or_else(|| args.get("language").and_then(Value::as_str))
        .map(|s| s.to_string());
    let input_bytes = Some(serde_json::to_string(&args).unwrap_or_default().len());
    let _ = recorder.tool_call_started(
        call_id,
        turn_id.clone(),
        tool,
        operation.clone(),
        input_bytes,
    );
    let started = std::time::Instant::now();
    let res = registry.execute(tool, args).await;
    let elapsed = started.elapsed().as_millis() as u64;
    match res {
        Ok(outcome) => {
            let _ = recorder.tool_call_completed(
                call_id,
                turn_id,
                tool,
                operation,
                &outcome,
                input_bytes,
                None,
                None,
            );
            let _ = elapsed;
            Ok(outcome)
        }
        Err(e) => {
            let mut ev = super::schema::ExperimentEvent::new(
                recorder.experiment_id.clone(),
                recorder.task_id.clone(),
                recorder.variant.clone(),
                super::schema::EventType::ToolCallCompleted,
            );
            ev.call_id = Some(call_id.to_string());
            ev.turn_id = turn_id;
            ev.tool = Some(tool.to_string());
            ev.operation = operation;
            ev.duration_ms = Some(elapsed);
            ev.success = Some(false);
            ev.error_code = Some(
                e.to_string()
                    .split(':')
                    .next()
                    .unwrap_or("error")
                    .trim()
                    .to_string(),
            );
            ev.input_bytes = input_bytes;
            let _ = recorder.append_event(&ev);
            Err(e)
        }
    }
}

/// Batch instrumentation — emits N child events, not N+1.
///
/// The experiment harness has no server-global semaphore, so batch items are
/// accounted against a dedicated per-call semaphore sized to
/// `max_concurrency`: this preserves the harness's historical parallelism
/// without pretending to share the daemon's workload cap.
pub async fn instrument_batch(
    registry: &ToolRegistry,
    recorder: &TaskRecorder,
    turn_id: Option<String>,
    requests: Vec<(String, Value)>,
    max_concurrency: usize,
) -> Vec<anyhow::Result<ToolOutcome>> {
    let turn = turn_id.clone();
    for (idx, (tool, args)) in requests.iter().enumerate() {
        let op = args
            .get("operation")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let ib = Some(serde_json::to_string(args).unwrap_or_default().len());
        let _ = recorder.tool_call_started(format!("call_{idx}"), turn.clone(), tool, op, ib);
    }
    let workload = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrency.clamp(1, 32)));
    // Experiment harness: explicit trusted-local calls, no HTTP admission.
    let contracted: Vec<ContractedCall> = requests
        .iter()
        .map(|(tool, args)| ContractedCall::local(registry, tool, args.clone()))
        .collect();
    let results = registry
        .execute_batch(contracted, max_concurrency, &workload)
        .await;
    for (idx, res) in results.iter().enumerate() {
        let (tool, args) = &requests[idx];
        let op = args
            .get("operation")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let ib = Some(serde_json::to_string(args).unwrap_or_default().len());
        match res {
            Ok(outcome) => {
                let _ = recorder.tool_call_completed(
                    format!("call_{idx}"),
                    turn.clone(),
                    tool,
                    op,
                    outcome,
                    ib,
                    None,
                    None,
                );
            }
            Err(e) => {
                let mut ev = super::schema::ExperimentEvent::new(
                    recorder.experiment_id.clone(),
                    recorder.task_id.clone(),
                    recorder.variant.clone(),
                    super::schema::EventType::ToolCallCompleted,
                );
                ev.call_id = Some(format!("call_{idx}"));
                ev.turn_id = turn.clone();
                ev.tool = Some(tool.clone());
                ev.operation = op;
                ev.duration_ms = Some(0);
                ev.success = Some(false);
                ev.error_code = Some(
                    e.to_string()
                        .split(':')
                        .next()
                        .unwrap_or("error")
                        .trim()
                        .to_string(),
                );
                ev.input_bytes = ib;
                let _ = recorder.append_event(&ev);
            }
        }
    }
    results
}

/// Sequence instrumentation — emits N child events in order.
pub async fn instrument_sequence(
    registry: &ToolRegistry,
    recorder: &TaskRecorder,
    turn_id: Option<String>,
    requests: Vec<(String, Value)>,
    continue_on_error: bool,
) -> Vec<anyhow::Result<ToolOutcome>> {
    let turn = turn_id.clone();
    for (idx, (tool, args)) in requests.iter().enumerate() {
        let op = args
            .get("operation")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let ib = Some(serde_json::to_string(args).unwrap_or_default().len());
        let _ = recorder.tool_call_started(format!("call_s{idx}"), turn.clone(), tool, op, ib);
    }
    // Experiment harness: explicit trusted-local calls, no HTTP admission.
    let contracted: Vec<ContractedCall> = requests
        .iter()
        .map(|(tool, args)| ContractedCall::local(registry, tool, args.clone()))
        .collect();
    let results = registry
        .execute_sequence(contracted, continue_on_error)
        .await;
    for (idx, res) in results.iter().enumerate() {
        let (tool, args) = &requests[idx];
        let op = args
            .get("operation")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let ib = Some(serde_json::to_string(args).unwrap_or_default().len());
        match res {
            Ok(outcome) => {
                let _ = recorder.tool_call_completed(
                    format!("call_s{idx}"),
                    turn.clone(),
                    tool,
                    op,
                    outcome,
                    ib,
                    None,
                    None,
                );
            }
            Err(e) => {
                let mut ev = super::schema::ExperimentEvent::new(
                    recorder.experiment_id.clone(),
                    recorder.task_id.clone(),
                    recorder.variant.clone(),
                    super::schema::EventType::ToolCallCompleted,
                );
                ev.call_id = Some(format!("call_s{idx}"));
                ev.turn_id = turn.clone();
                ev.tool = Some(tool.clone());
                ev.operation = op;
                ev.duration_ms = Some(0);
                ev.success = Some(false);
                ev.error_code = Some(
                    e.to_string()
                        .split(':')
                        .next()
                        .unwrap_or("error")
                        .trim()
                        .to_string(),
                );
                ev.input_bytes = ib;
                let _ = recorder.append_event(&ev);
            }
        }
    }
    results
}

/// `execute_once` instrumentation — emits single child event; `cached` stays null
/// unless caller can supply an explicit hint cleanly.
pub async fn instrument_execute_once(
    registry: &ToolRegistry,
    recorder: &TaskRecorder,
    turn_id: Option<String>,
    key: &str,
    tool: &str,
    args: Value,
) -> anyhow::Result<ToolOutcome> {
    let call_id = format!("once_{key}");
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let input_bytes = Some(serde_json::to_string(&args).unwrap_or_default().len());
    let _ = recorder.tool_call_started(
        &call_id,
        turn_id.clone(),
        tool,
        operation.clone(),
        input_bytes,
    );
    let started = std::time::Instant::now();
    // Experiment harness: explicit trusted-local call, no HTTP admission.
    let res = registry
        .execute_once(key, ContractedCall::local(registry, tool, args))
        .await
        .map(|r| r.outcome);
    let elapsed = started.elapsed().as_millis() as u64;
    match res {
        Ok(outcome) => {
            let _ = recorder.tool_call_completed(
                &call_id,
                turn_id,
                tool,
                operation,
                &outcome,
                input_bytes,
                None,
                None,
            );
            let _ = elapsed;
            Ok(outcome)
        }
        Err(e) => {
            let mut ev = super::schema::ExperimentEvent::new(
                recorder.experiment_id.clone(),
                recorder.task_id.clone(),
                recorder.variant.clone(),
                super::schema::EventType::ToolCallCompleted,
            );
            ev.call_id = Some(call_id);
            ev.turn_id = turn_id;
            ev.tool = Some(tool.to_string());
            ev.operation = operation;
            ev.duration_ms = Some(elapsed);
            ev.success = Some(false);
            ev.error_code = Some(
                e.to_string()
                    .split(':')
                    .next()
                    .unwrap_or("error")
                    .trim()
                    .to_string(),
            );
            ev.input_bytes = input_bytes;
            let _ = recorder.append_event(&ev);
            Err(e)
        }
    }
}
