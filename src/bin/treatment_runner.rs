#![allow(missing_docs)]
use std::path::{Path, PathBuf};
use std::process::Command;

use marshall::experiment::collector::collect_repo_state;
use marshall::experiment::instrumentation::instrument_execute;
use marshall::experiment::manifest::TaskManifest;
use marshall::experiment::recorder::ExperimentRecorder;
use marshall::experiment::schema::{TaskOutcome, TokenUsage};
use marshall::experiment::treatment::execute_bounded_sequence;
use marshall::{
    shell::AllowedCommand, ArgumentPolicy, FileSystemTool, Sandbox, ShellTool, ToolRegistry,
};
use serde_json::{json, Value};
use std::sync::Arc;

fn worktree_path(base: &Path, task_id: &str) -> PathBuf {
    base.join(task_id)
}

fn create_registry(worktree: &Path) -> anyhow::Result<ToolRegistry> {
    let sandbox = Sandbox::new([worktree])?;
    let fs = FileSystemTool::new(sandbox.clone()).writable();
    let echo = if Path::new("/bin/echo").exists() {
        "/bin/echo"
    } else {
        "/usr/bin/echo"
    };
    let cat = if Path::new("/bin/cat").exists() {
        "/bin/cat"
    } else {
        "/usr/bin/cat"
    };
    let shell = ShellTool::new(vec![
        AllowedCommand::new(echo).with_arguments(ArgumentPolicy::NoFlags),
        AllowedCommand::new(cat).with_arguments(ArgumentPolicy::NoFlags),
    ])
    .with_working_dirs(sandbox.clone());
    let mut reg = ToolRegistry::new();
    reg.register(Arc::new(fs));
    reg.register(Arc::new(shell));
    Ok(reg)
}

fn steps_for_task(
    task: &marshall::experiment::manifest::TaskSpec,
    worktree: &Path,
) -> Vec<(String, Value)> {
    // Same as baseline_runner but without turn_id, just Vec of tool/args in order
    let wt = worktree.to_string_lossy().to_string();
    let cat = format!("{:?}", task.category).to_ascii_lowercase();
    let is_complex = task.complexity == "complex";
    let is_simple = task.complexity == "simple";
    let mut steps: Vec<(String, Value)> = Vec::new();
    match cat.as_str() {
        s if s.contains("investigation") => {
            steps.push((
                "filesystem".into(),
                json!({"operation":"search","path": wt, "pattern":"TODO","recursive": true}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/lib.rs", wt)}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/sandbox.rs", wt)}),
            ));
            steps.push(("filesystem".into(), json!({"operation":"search","path": format!("{}/src", wt), "pattern":"openat2","recursive": false})));
            if !is_simple {
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/src/destination.rs", wt)}),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","status"]}),
                ));
            }
            if is_complex {
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","diff"]}),
                ));
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"stat","path": format!("{}/src/lib.rs", wt)}),
                ));
            }
        }
        s if s.contains("bug") => {
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/fs.rs", wt)}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"search","path": format!("{}/src", wt), "pattern":"clamp"}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/fs.rs", wt)}),
            ));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["test"]}),
            ));
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_{}.txt", wt, task.task_id), "content":"fix"})));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["verify"]}),
            ));
            if is_complex {
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/src/fs.rs", wt)}),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","status"]}),
                ));
            }
        }
        s if s.contains("feature") => {
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/lib.rs", wt)}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/fs.rs", wt)}),
            ));
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_feat_{}.txt", wt, task.task_id), "content":"feature"})));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["test"]}),
            ));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["lint"]}),
            ));
            if is_complex {
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/Cargo.toml", wt)}),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","diff"]}),
                ));
            }
        }
        s if s.contains("refactor") => {
            steps.push((
                "filesystem".into(),
                json!({"operation":"search","path": format!("{}/src", wt), "pattern":"Sandbox"}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/sandbox.rs", wt)}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/registry.rs", wt)}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/lib.rs", wt)}),
            ));
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_ref_{}.txt", wt, task.task_id), "content":"refactor"})));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["test"]}),
            ));
            if is_complex {
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","status"]}),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","diff"]}),
                ));
            }
        }
        s if s.contains("test") => {
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["cargo","test"]}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/tests/escapes.rs", wt)}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"search","path": format!("{}/tests", wt), "pattern":"symlink"}),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/tests/escapes.rs", wt)}),
            ));
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_test_{}.txt", wt, task.task_id), "content":"fix"})));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["cargo","test"]}),
            ));
            if is_complex {
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/src/registry.rs", wt)}),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["stress"]}),
                ));
            }
        }
        s if s.contains("config") => {
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/Cargo.toml", wt)}),
            ));
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_cfg_{}.txt", wt, task.task_id), "content":"config"})));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["check"]}),
            ));
            if is_complex {
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","status"]}),
                ));
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/.gitignore", wt)}),
                ));
            }
        }
        _ => {
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/README.md", wt)}),
            ));
        }
    }
    steps
}

fn is_search(op: &Value) -> bool {
    op.get("operation").and_then(|v| v.as_str()) == Some("search")
}
fn is_read(op: &Value) -> bool {
    op.get("operation").and_then(|v| v.as_str()) == Some("read")
}
fn is_write(op: &Value) -> bool {
    matches!(
        op.get("operation").and_then(|v| v.as_str()),
        Some("write") | Some("patch") | Some("append")
    )
}
fn is_shell(op: &str, _args: &Value) -> bool {
    op == "shell"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let manifest_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "validation/tasks.benchmark.json".to_string());
    let out_root = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "validation/experiments".to_string());
    let exp_id = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "exp_treatment_001".to_string());
    let manifest_data = std::fs::read_to_string(&manifest_path)?;
    let manifest: TaskManifest = serde_json::from_str(&manifest_data)?;
    println!(
        "loaded {} tasks from {}",
        manifest.tasks.len(),
        manifest_path
    );
    let worktree_base = PathBuf::from("/tmp/baseline_worktrees");
    std::fs::create_dir_all(&worktree_base)?;
    let exp = ExperimentRecorder::new(exp_id.clone(), "treatment", &out_root)?;
    println!(
        "experiment {} at {}",
        exp_id,
        exp.experiment_dir().display()
    );
    for task in &manifest.tasks {
        println!("\n=== {} {} ===", task.task_id, task.title);
        let wt = worktree_path(&worktree_base, &task.task_id);
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force", wt.to_str().unwrap()])
            .output();
        let _ = std::fs::remove_dir_all(&wt);
        let wt_str = wt.to_str().unwrap();
        let out = Command::new("git")
            .args(["worktree", "add", "--detach", wt_str, &task.base_revision])
            .output()?;
        if !out.status.success() {
            eprintln!(
                "worktree add failed for {}: {}",
                task.task_id,
                String::from_utf8_lossy(&out.stderr)
            );
            continue;
        }
        let repo_before = collect_repo_state(Some(&wt));
        let task_rec = exp.task_recorder(&task.task_id)?;
        task_rec.task_started(
            Some(format!("{:?}", task.category).to_ascii_lowercase()),
            Some(task.description.clone()),
            Some(task.repository.clone()),
            Some(repo_before),
            Some("treatment-runner".into()),
            Some("0.1.0".into()),
            None,
        )?;
        let registry = create_registry(&wt)?;
        let steps = steps_for_task(task, &wt);
        // First, group steps into handoffs (bounded sequences or singles)
        enum Handoff {
            Seq(Vec<(String, Value)>),
            Single((String, Value)),
        }
        let mut handoffs: Vec<Handoff> = Vec::new();
        let mut i = 0;
        while i < steps.len() {
            let remaining = steps.len() - i;
            let can_bundle_3 = remaining >= 3 && {
                let (_t0, a0) = &steps[i];
                let (_t1, a1) = &steps[i + 1];
                let (t2, a2) = &steps[i + 2];
                is_read(a0) && is_write(a1) && is_shell(t2, a2)
            };
            let can_bundle_2_search_read = remaining >= 2 && {
                let (_t0, a0) = &steps[i];
                let (_t1, a1) = &steps[i + 1];
                is_search(a0) && is_read(a1)
            };
            let can_bundle_2_write_shell = remaining >= 2 && {
                let (_t0, a0) = &steps[i];
                let (t1, a1) = &steps[i + 1];
                is_write(a0) && is_shell(t1, a1)
            };
            let use_bundle = if can_bundle_3 {
                Some(3)
            } else if can_bundle_2_search_read || can_bundle_2_write_shell {
                Some(2)
            } else {
                None
            };
            if let Some(n) = use_bundle {
                handoffs.push(Handoff::Seq(steps[i..i + n].to_vec()));
                i += n;
            } else {
                handoffs.push(Handoff::Single(steps[i].clone()));
                i += 1;
            }
        }
        // Now pack handoffs into turns: 2 handoffs per turn (mirrors baseline 2 per turn)
        let mut turn_idx = 1;
        let mut seq_counter: usize = 0;
        let mut handoff_idx: usize = 0;
        for chunk in handoffs.chunks(2) {
            let turn_id = format!("turn_{turn_idx}");
            turn_idx += 1;
            task_rec.agent_turn_started(&turn_id)?;
            for h in chunk {
                match h {
                    Handoff::Seq(seq_steps) => {
                        let seq_id = format!("seq_{:03}", seq_counter + 1);
                        seq_counter += 1;
                        let res = execute_bounded_sequence(
                            &registry,
                            &task_rec,
                            Some(turn_id.clone()),
                            &seq_id,
                            seq_steps.clone(),
                        )
                        .await;
                        if let Err(e) = res {
                            eprintln!("bounded_sequence failed: {e}");
                        }
                    }
                    Handoff::Single((tool, args)) => {
                        let call_id = format!("call_{:03}", handoff_idx + 1);
                        let res = instrument_execute(
                            &registry,
                            &task_rec,
                            Some(turn_id.clone()),
                            &call_id,
                            tool,
                            args.clone(),
                        )
                        .await;
                        if let Err(e) = res {
                            eprintln!("tool {tool} failed: {e}");
                        }
                    }
                }
                handoff_idx += 1;
            }
            // mock token per turn: fewer tokens per turn due to bundling
            task_rec.agent_turn_completed(
                turn_id,
                Some(100),
                Some("mock-model".into()),
                Some("test-provider".into()),
                Some(TokenUsage {
                    input_tokens: Some(150),
                    output_tokens: Some(80),
                    ..Default::default()
                }),
            )?;
        }
        // verification mocked
        for (vi, cmd) in task.verification_commands_or_checks.iter().enumerate() {
            let vid = format!("v{}", vi + 1);
            task_rec.verification_started(&vid, Some(cmd.clone()), Some(cmd.clone()))?;
            let is_should_fail = matches!(
                task.task_id.as_str(),
                "bug_004_collector_status_parse"
                    | "test_002_stress_leak"
                    | "feat_004_verification_retry_metric"
            );
            let (exit_code, success, dur) = if is_should_fail && vi == 0 {
                (1, false, 50)
            } else {
                (0, true, 80)
            };
            task_rec.verification_completed(
                &vid,
                Some(cmd.clone()),
                Some(dur),
                Some(exit_code),
                success,
            )?;
        }
        let should_fail = matches!(
            task.task_id.as_str(),
            "bug_004_collector_status_parse"
                | "test_002_stress_leak"
                | "feat_004_verification_retry_metric"
        );
        let outcome = if should_fail {
            TaskOutcome::Failure
        } else {
            TaskOutcome::Success
        };
        let repo_after = collect_repo_state(Some(&wt));
        task_rec.task_completed(outcome, None, Some(repo_after))?;
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force", wt_str])
            .output();
        let _ = std::fs::remove_dir_all(&wt);
        println!(
            "trace written {} lines",
            std::fs::read_to_string(task_rec.path())?.lines().count()
        );
    }
    println!(
        "\n treatment corpus complete: {}",
        exp.experiment_dir().display()
    );
    Ok(())
}
