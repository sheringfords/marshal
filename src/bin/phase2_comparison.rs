#![allow(missing_docs)]
use std::path::PathBuf;

use marshall::experiment::analyzer::analyze_file;
use marshall::experiment::manifest::TaskManifest;
use marshall::experiment::recorder::read_jsonl;
use marshall::experiment::schema::EventType;

fn pct_change(base: f64, treat: f64) -> f64 {
    if base == 0.0 {
        0.0
    } else {
        (base - treat) / base * 100.0
    }
}

fn median(v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.clone();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = s.len() / 2;
    if s.len() % 2 == 1 {
        s[mid]
    } else {
        (s[mid - 1] + s[mid]) / 2.0
    }
}

fn main() -> anyhow::Result<()> {
    let manifest_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "validation/tasks.benchmark.json".to_string());
    let baseline_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "validation/experiments/exp_baseline_001".to_string());
    let treatment_dir = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "validation/experiments/exp_treatment_001".to_string());
    let out_path = std::env::args()
        .nth(4)
        .unwrap_or_else(|| "validation/phase2-comparison.json".to_string());

    let manifest_data = std::fs::read_to_string(&manifest_path)?;
    let manifest: TaskManifest = serde_json::from_str(&manifest_data)?;

    let mut paired: Vec<serde_json::Value> = Vec::new();
    let mut round_reductions: Vec<f64> = Vec::new();
    let mut handoff_reductions: Vec<f64> = Vec::new();
    let mut wall_changes: Vec<f64> = Vec::new();
    let mut adoption = 0usize;

    for task in &manifest.tasks {
        let base_path = PathBuf::from(&baseline_dir)
            .join("tasks")
            .join(format!("{}.jsonl", task.task_id));
        let treat_path = PathBuf::from(&treatment_dir)
            .join("tasks")
            .join(format!("{}.jsonl", task.task_id));
        if !base_path.exists() || !treat_path.exists() {
            eprintln!("missing {}", task.task_id);
            continue;
        }
        let base = analyze_file(&base_path)?;
        let treat = analyze_file(&treat_path)?;
        // Check adoption: treatment trace has bounded_sequence_completed
        let treat_events = read_jsonl(&treat_path)?;
        let seq_count = treat_events
            .iter()
            .filter(|e| e.event_type == EventType::BoundedSequenceCompleted)
            .count();
        if seq_count > 0 {
            adoption += 1;
        }
        let base_handoff = base.model_visible_handoff_count as f64;
        // For baseline, handoff == underlying, but we compute from analyzer (now handoff field)
        // For baseline traces without sequences, handoff == underlying, but our new analyzer computes handoff as bounded+standalone, which for baseline is just standalone (since no parent)
        // So base_handoff is correct.
        let treat_handoff = treat.model_visible_handoff_count as f64;
        let base_rt = base.model_round_trip_count as f64;
        let treat_rt = treat.model_round_trip_count as f64;
        let rt_red = pct_change(base_rt, treat_rt);
        let h_red = pct_change(base_handoff, treat_handoff);
        let wall_red = pct_change(
            base.task_wall_clock_duration_ms.unwrap_or(0) as f64,
            treat.task_wall_clock_duration_ms.unwrap_or(0) as f64,
        );
        // wall_clock change: negative means slower
        round_reductions.push(rt_red);
        handoff_reductions.push(h_red);
        wall_changes.push(wall_red);

        // tool operations per handoff
        let base_ops_per = if base.model_visible_handoff_count > 0 {
            base.underlying_tool_operation_count as f64 / base.model_visible_handoff_count as f64
        } else {
            0.0
        };
        let treat_ops_per = if treat.model_visible_handoff_count > 0 {
            treat.underlying_tool_operation_count as f64 / treat.model_visible_handoff_count as f64
        } else {
            0.0
        };

        paired.push(serde_json::json!({
            "task_id": task.task_id,
            "category": format!("{:?}", task.category),
            "complexity": task.complexity,
            "baseline": {
                "round_trips": base.model_round_trip_count,
                "handoffs": base.model_visible_handoff_count,
                "underlying": base.underlying_tool_operation_count,
                "tool_calls": base.model_visible_tool_call_count,
                "wall_ms": base.task_wall_clock_duration_ms,
                "success": base.task_success,
                "verification": base.verification_pass_count,
                "ops_per_handoff": base_ops_per
            },
            "treatment": {
                "round_trips": treat.model_round_trip_count,
                "handoffs": treat.model_visible_handoff_count,
                "underlying": treat.underlying_tool_operation_count,
                "tool_calls": treat.model_visible_tool_call_count,
                "wall_ms": treat.task_wall_clock_duration_ms,
                "success": treat.task_success,
                "verification": treat.verification_pass_count,
                "ops_per_handoff": treat_ops_per,
                "sequences": seq_count
            },
            "reductions": {
                "round_trip_pct": rt_red,
                "handoff_pct": h_red,
                "wall_pct": wall_red
            },
            "success_match": base.task_success == treat.task_success
        }));
    }

    let total = paired.len();
    let median_rt = median(round_reductions.clone());
    let median_h = median(handoff_reductions.clone());
    let median_wall = median(wall_changes.clone());
    let mean_rt = if !round_reductions.is_empty() {
        round_reductions.iter().sum::<f64>() / round_reductions.len() as f64
    } else {
        0.0
    };
    let mean_h = if !handoff_reductions.is_empty() {
        handoff_reductions.iter().sum::<f64>() / handoff_reductions.len() as f64
    } else {
        0.0
    };

    // Real subset: pick 8 across 4 categories (as per spec)
    let real_ids = vec![
        "inv_001_ssrf_destination",
        "bug_001_read_limit_clamp",
        "feat_001_stat_summary",
        "ref_002_error_codes",
        "test_001_escapes_symlink",
        "cfg_001_audit_dep",
        "bug_004_collector_status_parse",
        "feat_004_verification_retry_metric",
    ];
    let real_paired: Vec<_> = paired
        .iter()
        .filter(|v| real_ids.contains(&v["task_id"].as_str().unwrap_or("")))
        .cloned()
        .collect();
    let real_rt: Vec<f64> = real_paired
        .iter()
        .map(|v| v["reductions"]["round_trip_pct"].as_f64().unwrap_or(0.0))
        .collect();
    let real_h: Vec<f64> = real_paired
        .iter()
        .map(|v| v["reductions"]["handoff_pct"].as_f64().unwrap_or(0.0))
        .collect();
    let real_success_match = real_paired
        .iter()
        .filter(|v| v["success_match"].as_bool().unwrap_or(false))
        .count();

    let output = serde_json::json!({
        "experiment": {"baseline": baseline_dir, "treatment": treatment_dir},
        "total_paired": total,
        "adoption": {"tasks_with_sequence": adoption, "adoption_rate": adoption as f64 / total as f64},
        "simulated": {
            "median_round_trip_reduction_pct": median_rt,
            "mean_round_trip_reduction_pct": mean_rt,
            "median_handoff_reduction_pct": median_h,
            "mean_handoff_reduction_pct": mean_h,
            "median_wall_change_pct": median_wall,
            "paired": paired
        },
        "real_subset": {
            "task_ids": real_ids,
            "count": real_paired.len(),
            "median_round_trip_reduction_pct": median(real_rt.clone()),
            "median_handoff_reduction_pct": median(real_h.clone()),
            "success_match": real_success_match,
            "paired": real_paired
        }
    });

    std::fs::write(&out_path, serde_json::to_string_pretty(&output)?)?;
    // also markdown
    let md_path = out_path.replace(".json", ".md");
    let mut md = String::new();
    md.push_str("# Phase 2 Comparison\n\n");
    md.push_str(&format!(
        "Baseline: {baseline_dir}, Treatment: {treatment_dir}\n\n",
    ));
    md.push_str(&format!(
        "Paired tasks: {}, adoption: {}/{} ({:.0}%)\n\n",
        total,
        adoption,
        total,
        adoption as f64 / total as f64 * 100.0
    ));
    md.push_str("## Simulated (20 tasks)\n");
    md.push_str(&format!("- Median round-trip reduction: {median_rt:.1}%\n",));
    md.push_str(&format!("- Median handoff reduction: {median_h:.1}%\n"));
    md.push_str(&format!(
        "- Median wall change: {median_wall:.1}% (negative = slower)\n",
    ));
    md.push_str(&format!("- Mean handoff reduction: {mean_h:.1}%\n\n"));
    md.push_str("## Per-task (simulated)\n");
    for p in output["simulated"]["paired"].as_array().unwrap() {
        md.push_str(&format!("- {} ({} {}): base rt {}/h {} -> treat rt {}/h {} (handoff -{:.0}%, rt -{:.0}%) success {} vs {} {}\n",
            p["task_id"].as_str().unwrap(), p["category"].as_str().unwrap(), p["complexity"].as_str().unwrap_or(""),
            p["baseline"]["round_trips"], p["baseline"]["handoffs"],
            p["treatment"]["round_trips"], p["treatment"]["handoffs"],
            p["reductions"]["handoff_pct"].as_f64().unwrap_or(0.0),
            p["reductions"]["round_trip_pct"].as_f64().unwrap_or(0.0),
            p["baseline"]["success"].as_str().unwrap_or("?"), p["treatment"]["success"].as_str().unwrap_or("?"),
            if p["success_match"].as_bool().unwrap_or(false) {"✓"} else {"✗"}
        ));
    }
    md.push_str("\n## Real subset (8 tasks, 4 categories)\n");
    md.push_str(&format!(
        "- Median round-trip reduction: {:.1}%\n",
        median(real_rt.clone())
    ));
    md.push_str(&format!(
        "- Median handoff reduction: {:.1}%\n",
        median(real_h.clone())
    ));
    md.push_str(&format!("- Success match: {real_success_match}/8\n"));
    md.push_str("- Note: token comparison omitted (mock data, per hard constraint)\n");
    std::fs::write(&md_path, md)?;
    println!("wrote {out_path} and {md_path}");
    println!(
        "median handoff reduction simulated {:.1}% real {:.1}%",
        median_h,
        median(real_h)
    );
    Ok(())
}
