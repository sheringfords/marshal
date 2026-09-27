#![allow(missing_docs)]
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use marshall::experiment::analyzer::{analyze_file, PerTaskMetrics};
#[allow(unused_imports)]
use marshall::experiment::collector::collect_repo_state;
use marshall::experiment::manifest::TaskManifest;
use marshall::experiment::patterns::{
    duration_dominance, mine_bigrams, mine_trigrams, success_after, volume_dominance,
};
use marshall::experiment::recorder::read_jsonl;

fn percentile(mut v: Vec<u64>, p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_unstable();
    let idx = ((p / 100.0) * (v.len() as f64 - 1.0)).round() as usize;
    v[idx] as f64
}
fn median_u64(v: Vec<u64>) -> f64 {
    percentile(v, 50.0)
}
fn mean(v: &[u64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<u64>() as f64 / v.len() as f64
}

fn stats(v: Vec<u64>) -> serde_json::Value {
    let mut sorted = v.clone();
    sorted.sort_unstable();
    let c = v.len();
    let min = sorted.first().cloned().unwrap_or(0);
    let max = sorted.last().cloned().unwrap_or(0);
    json!({
        "count": c,
        "median": median_u64(v.clone()),
        "mean": mean(&v),
        "p25": percentile(v.clone(), 25.0),
        "p75": percentile(v.clone(), 75.0),
        "min": min,
        "max": max
    })
}

use serde_json::json;

fn main() -> anyhow::Result<()> {
    let manifest_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "validation/tasks.benchmark.json".to_string());
    let exp_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "validation/experiments/exp_baseline_001".to_string());
    let out_dir = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "validation".to_string());

    let manifest_data = std::fs::read_to_string(&manifest_path)?;
    let manifest: TaskManifest = serde_json::from_str(&manifest_data)?;
    let exp_path = PathBuf::from(&exp_dir);
    let tasks_dir = exp_path.join("tasks");
    let files: Vec<PathBuf> = std::fs::read_dir(&tasks_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
        .collect();
    println!("found {} traces in {}", files.len(), tasks_dir.display());

    let mut metrics: Vec<PerTaskMetrics> = Vec::new();
    let mut all_events: HashMap<String, Vec<marshall::experiment::schema::ExperimentEvent>> =
        HashMap::new();
    for f in &files {
        let m = analyze_file(f)?;
        metrics.push(m);
        let evs = read_jsonl(f)?;
        let task_id = evs
            .first()
            .map(|e| e.task_id.clone())
            .unwrap_or_else(|| f.file_stem().unwrap().to_string_lossy().to_string());
        all_events.insert(task_id, evs);
    }
    metrics.sort_by(|a, b| a.task_id.cmp(&b.task_id));

    // Build category/complexity maps from manifest
    let mut cat_map: HashMap<String, String> = HashMap::new();
    let mut comp_map: HashMap<String, String> = HashMap::new();
    for t in &manifest.tasks {
        cat_map.insert(
            t.task_id.clone(),
            format!("{:?}", t.category).to_ascii_lowercase(),
        );
        comp_map.insert(t.task_id.clone(), t.complexity.clone());
    }

    // Aggregate stats
    let turns: Vec<u64> = metrics.iter().map(|m| m.agent_turn_count as u64).collect();
    let calls: Vec<u64> = metrics
        .iter()
        .map(|m| m.model_visible_tool_call_count as u64)
        .collect();
    let walls: Vec<u64> = metrics
        .iter()
        .filter_map(|m| m.task_wall_clock_duration_ms)
        .collect();
    let total_valid = metrics.len();
    let success = metrics
        .iter()
        .filter(|m| m.task_success.as_deref() == Some("success"))
        .count();
    let failure = metrics
        .iter()
        .filter(|m| m.task_success.as_deref() == Some("failure"))
        .count();
    let partial = metrics
        .iter()
        .filter(|m| m.task_success.as_deref() == Some("partial"))
        .count();
    let invalid = 0; // no invalid in this corpus
    let ver_total: usize = metrics.iter().map(|m| m.verification_count).sum();
    let ver_pass: usize = metrics.iter().map(|m| m.verification_pass_count).sum();
    let ver_rate = if ver_total > 0 {
        ver_pass as f64 / ver_total as f64
    } else {
        0.0
    };

    let baseline_summary = json!({
        "experiment_id": metrics.first().map(|m| m.experiment_id.clone()).unwrap_or_default(),
        "total_attempted": total_valid,
        "valid": total_valid,
        "successful": success,
        "failed": failure,
        "partial": partial,
        "invalid_runs": invalid,
        "agent_turns": stats(turns.clone()),
        "tool_calls": stats(calls.clone()),
        "wall_clock_ms": stats(walls.clone()),
        "verification_pass_rate": ver_rate,
        "verification_total": ver_total,
        "verification_pass": ver_pass,
        "metrics": metrics,
        "by_category": group_by(&metrics, &cat_map),
        "by_complexity": group_by(&metrics, &comp_map),
        "by_success": group_by_success(&metrics),
        "tool_distribution": tool_dist(&metrics),
    });

    std::fs::write(
        Path::new(&out_dir).join("baseline-summary.json"),
        serde_json::to_string_pretty(&baseline_summary)?,
    )?;
    // markdown
    let mut md = String::new();
    md.push_str("# Baseline Summary\n\n");
    md.push_str(&format!(
        "Experiment: {}\n\n",
        baseline_summary["experiment_id"].as_str().unwrap_or("")
    ));
    md.push_str(&format!("- Total attempted: {total_valid}\n- Valid: {total_valid}\n- Successful: {success}\n- Failed: {failure}\n- Partial: {partial}\n- Invalid: {invalid}\n\n"));
    md.push_str(&format!(
        "## Agent turns: median {:.1}, mean {:.1}, p25 {:.1}, p75 {:.1}, min {}, max {}\n",
        baseline_summary["agent_turns"]["median"]
            .as_f64()
            .unwrap_or(0.0),
        baseline_summary["agent_turns"]["mean"]
            .as_f64()
            .unwrap_or(0.0),
        baseline_summary["agent_turns"]["p25"]
            .as_f64()
            .unwrap_or(0.0),
        baseline_summary["agent_turns"]["p75"]
            .as_f64()
            .unwrap_or(0.0),
        baseline_summary["agent_turns"]["min"].as_u64().unwrap_or(0),
        baseline_summary["agent_turns"]["max"].as_u64().unwrap_or(0)
    ));
    md.push_str(&format!(
        "## Tool calls: median {:.1}, mean {:.1}, min {}, max {}\n",
        baseline_summary["tool_calls"]["median"]
            .as_f64()
            .unwrap_or(0.0),
        baseline_summary["tool_calls"]["mean"]
            .as_f64()
            .unwrap_or(0.0),
        baseline_summary["tool_calls"]["min"].as_u64().unwrap_or(0),
        baseline_summary["tool_calls"]["max"].as_u64().unwrap_or(0)
    ));
    md.push_str(&format!(
        "## Wall clock ms: median {:.1}, mean {:.1}\n",
        baseline_summary["wall_clock_ms"]["median"]
            .as_f64()
            .unwrap_or(0.0),
        baseline_summary["wall_clock_ms"]["mean"]
            .as_f64()
            .unwrap_or(0.0)
    ));
    md.push_str(&format!(
        "## Verification pass rate: {ver_rate:.2} ({ver_pass}/{ver_total})\n\n",
    ));
    md.push_str("### By category\n");
    for (k, v) in baseline_summary["by_category"].as_object().unwrap() {
        md.push_str(&format!(
            "- {}: {} tasks, median turns {:.1}, median calls {:.1}\n",
            k,
            v["count"],
            v["median_turns"].as_f64().unwrap_or(0.0),
            v["median_calls"].as_f64().unwrap_or(0.0)
        ));
    }
    md.push_str("\n### By complexity\n");
    for (k, v) in baseline_summary["by_complexity"].as_object().unwrap() {
        md.push_str(&format!(
            "- {}: {} tasks, median turns {:.1}, median calls {:.1}\n",
            k,
            v["count"],
            v["median_turns"].as_f64().unwrap_or(0.0),
            v["median_calls"].as_f64().unwrap_or(0.0)
        ));
    }
    md.push_str("\n### Tool distribution\n");
    for (k, v) in baseline_summary["tool_distribution"].as_object().unwrap() {
        md.push_str(&format!("- {k}: {v}\n"));
    }
    std::fs::write(Path::new(&out_dir).join("baseline-summary.md"), md)?;

    // Pattern analysis
    let bigrams = mine_bigrams(&all_events);
    let trigrams = mine_trigrams(&all_events);
    let vol = volume_dominance(&all_events);
    let dur = duration_dominance(&all_events);
    let suc = success_after(&all_events);

    let pattern_json = json!({
        "total_tasks": all_events.len(),
        "total_tool_calls": all_events.values().map(|v| v.iter().filter(|e| e.event_type==marshall::experiment::schema::EventType::ToolCallCompleted).count()).sum::<usize>(),
        "top_bigrams": bigrams.iter().take(20).map(|b| json!({"bigram": b.bigram, "count": b.count, "task_coverage": b.task_coverage, "tasks": b.tasks, "median_turns_between": b.median_turns_between})).collect::<Vec<_>>(),
        "top_trigrams": trigrams.iter().take(20).map(|t| json!({"trigram": t.trigram, "count": t.count, "task_coverage": t.task_coverage})).collect::<Vec<_>>(),
        "volume_dominance": vol,
        "duration_dominance": dur,
        "success_after": suc.iter().map(|(k,(s,f))| json!({"op": k, "success": s, "failure": f})).collect::<Vec<_>>(),
    });
    std::fs::write(
        Path::new(&out_dir).join("pattern-analysis.json"),
        serde_json::to_string_pretty(&pattern_json)?,
    )?;

    let mut pmd = String::new();
    pmd.push_str("# Pattern Analysis\n\n");
    pmd.push_str(&format!(
        "Total tasks: {}, total tool calls: {}\n\n",
        pattern_json["total_tasks"], pattern_json["total_tool_calls"]
    ));
    pmd.push_str("## Top 20 adjacent bigrams\n");
    for b in bigrams.iter().take(20) {
        pmd.push_str(&format!(
            "- {}: count {}, tasks {} ({}), median turns between {:.1}\n",
            b.bigram,
            b.count,
            b.task_coverage,
            b.tasks.join(","),
            b.median_turns_between
        ));
    }
    pmd.push_str("\n## Top trigrams\n");
    for t in trigrams.iter().take(10) {
        pmd.push_str(&format!(
            "- {}: count {}, tasks {}\n",
            t.trigram, t.count, t.task_coverage
        ));
    }
    pmd.push_str("\n## Volume dominance\n");
    for (k, v) in &vol {
        pmd.push_str(&format!("- {k}: {v}\n"));
    }
    pmd.push_str("\n## Duration dominance (ms total)\n");
    for (k, v) in &dur {
        pmd.push_str(&format!("- {k}: {v}\n"));
    }
    pmd.push_str("\n## Success after op\n");
    for (k, (s, f)) in &suc {
        pmd.push_str(&format!("- {k}: success {s}, failure {f}\n"));
    }
    std::fs::write(Path::new(&out_dir).join("pattern-analysis.md"), pmd)?;

    println!("wrote baseline-summary and pattern-analysis to {out_dir}");
    Ok(())
}

fn group_by(metrics: &[PerTaskMetrics], map: &HashMap<String, String>) -> serde_json::Value {
    let mut groups: BTreeMap<String, Vec<&PerTaskMetrics>> = BTreeMap::new();
    for m in metrics {
        let key = map
            .get(&m.task_id)
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        groups.entry(key).or_default().push(m);
    }
    let mut out = serde_json::Map::new();
    for (k, vs) in groups {
        let turns: Vec<u64> = vs.iter().map(|m| m.agent_turn_count as u64).collect();
        let calls: Vec<u64> = vs
            .iter()
            .map(|m| m.model_visible_tool_call_count as u64)
            .collect();
        out.insert(k.clone(), json!({"count": vs.len(), "median_turns": median_u64(turns), "median_calls": median_u64(calls), "tasks": vs.iter().map(|m| &m.task_id).collect::<Vec<_>>() }));
    }
    serde_json::Value::Object(out)
}
fn group_by_success(metrics: &[PerTaskMetrics]) -> serde_json::Value {
    let mut groups: BTreeMap<String, Vec<&PerTaskMetrics>> = BTreeMap::new();
    for m in metrics {
        let k = m.task_success.clone().unwrap_or_else(|| "unknown".into());
        groups.entry(k).or_default().push(m);
    }
    let mut out = serde_json::Map::new();
    for (k, vs) in groups {
        out.insert(k.clone(), json!({"count": vs.len()}));
    }
    serde_json::Value::Object(out)
}
fn tool_dist(metrics: &[PerTaskMetrics]) -> serde_json::Value {
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for pm in metrics {
        for (k, v) in &pm.tool_calls_by_tool {
            *m.entry(k.clone()).or_default() += v;
        }
    }
    let mut out = serde_json::Map::new();
    for (k, v) in m {
        out.insert(k, json!(v));
    }
    serde_json::Value::Object(out)
}
