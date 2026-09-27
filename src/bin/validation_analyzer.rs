//! validation-analyzer — read one or more experiment traces and produce per-task metrics.
//! Usage:
//!   cargo run --bin validation-analyzer -- experiments/exp_123
//!   cargo run --bin validation-analyzer -- experiments/exp_123/tasks/task_1.jsonl --json

use std::path::PathBuf;

use clap::Parser;
use marshall::experiment::analyzer::{analyze_files, discover_traces};

#[derive(Parser, Debug)]
#[command(
    name = "validation-analyzer",
    about = "Analyze validation JSONL traces"
)]
struct Args {
    /// Paths to experiment dirs or .jsonl files
    paths: Vec<PathBuf>,
    /// Emit machine-readable JSON to stdout (in addition to human text to stderr)
    #[arg(long)]
    json: bool,
    /// Output file for JSON (default stdout)
    #[arg(long)]
    out: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.paths.is_empty() {
        eprintln!(
            "usage: validation-analyzer <experiment_dir|.jsonl> [...] [--json] [--out file.json]"
        );
        std::process::exit(2);
    }
    let mut files: Vec<PathBuf> = Vec::new();
    for p in &args.paths {
        if p.is_dir() {
            let mut d = discover_traces(p);
            if d.is_empty() {
                eprintln!("warning: no .jsonl in {}", p.display());
            }
            files.append(&mut d);
        } else {
            files.push(p.clone());
        }
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        anyhow::bail!("no trace files found");
    }

    let metrics = analyze_files(&files)?;
    // Human-readable
    for m in &metrics {
        println!(
            "task {} variant {} — turns {} rt {} calls {} tools {} duration_ms_total {} wall_ms {:?} success {:?} ver {}/{} files {} +{} -{}",
            m.task_id,
            m.variant,
            m.agent_turn_count,
            m.model_round_trip_count,
            m.model_visible_tool_call_count,
            m.unique_tool_count,
            m.tool_execution_duration_ms_total,
            m.task_wall_clock_duration_ms,
            m.task_success,
            m.verification_pass_count,
            m.verification_count,
            m.files_changed_count.unwrap_or(0),
            m.lines_added.unwrap_or(0),
            m.lines_deleted.unwrap_or(0),
        );
        if m.input_tokens.is_some() || m.output_tokens.is_some() {
            println!(
                "  tokens in:{:?} out:{:?} cached:{:?} reasoning:{:?} total_known:{:?}",
                m.input_tokens,
                m.output_tokens,
                m.cached_input_tokens,
                m.reasoning_tokens,
                m.total_known_tokens
            );
        }
        let mut by_tool: Vec<_> = m.tool_calls_by_tool.iter().collect();
        by_tool.sort_by(|a, b| a.0.cmp(b.0));
        if !by_tool.is_empty() {
            println!(
                "  by_tool: {}",
                by_tool
                    .iter()
                    .map(|(k, v)| format!("{k}:{v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
    }

    // Aggregate summary
    let total_turns: usize = metrics.iter().map(|m| m.agent_turn_count).sum();
    let total_calls: usize = metrics
        .iter()
        .map(|m| m.model_visible_tool_call_count)
        .sum();
    let avg_calls = if metrics.is_empty() {
        0.0
    } else {
        total_calls as f64 / metrics.len() as f64
    };
    println!("\n--- aggregate ({} tasks) ---", metrics.len());
    println!(
        "total_turns {total_turns} total_calls {total_calls} avg_calls_per_task {avg_calls:.2}"
    );
    if metrics.iter().any(|m| m.input_tokens.is_some()) {
        let total_in: u64 = metrics.iter().filter_map(|m| m.input_tokens).sum();
        let total_out: u64 = metrics.iter().filter_map(|m| m.output_tokens).sum();
        println!("total_known tokens in {total_in} out {total_out}");
    }

    if args.json {
        let json = serde_json::to_string_pretty(&metrics)?;
        if let Some(out) = args.out {
            std::fs::write(out, json)?;
        } else {
            println!("{json}");
        }
    } else if let Some(out) = args.out {
        let json = serde_json::to_string_pretty(&metrics)?;
        std::fs::write(out, json)?;
    }

    Ok(())
}
