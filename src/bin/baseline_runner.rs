#![allow(missing_docs)]
use std::path::{Path, PathBuf};
use std::process::Command;

use marshall::experiment::collector::collect_repo_state;
use marshall::experiment::instrumentation::instrument_execute;
use marshall::experiment::manifest::TaskManifest;
use marshall::experiment::recorder::ExperimentRecorder;
use marshall::experiment::schema::{TaskOutcome, TokenUsage};
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
    // shell: allow echo, cat only (git via echo to avoid worktree git dependency hang)
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
) -> Vec<(String, Value, String)> {
    // Returns Vec<(tool, args, turn_id)>
    // Turn assignment based on category/complexity
    let wt = worktree.to_string_lossy().to_string();
    let cat = format!("{:?}", task.category).to_ascii_lowercase();
    let is_complex = task.complexity == "complex";
    let is_simple_flag = task.complexity == "simple";

    // Define patterns per category
    let mut steps: Vec<(String, Value, String)> = Vec::new();
    let mut turn = 1;
    let mut next_turn = || {
        let t = format!("turn_{turn}");
        turn += 1;
        t
    };

    match cat.as_str() {
        s if s.contains("investigation") || s.contains("invest") => {
            // search -> read -> read
            let t = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"search","path": wt, "pattern":"TODO","recursive": true}),
                t.clone(),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/lib.rs", wt)}),
                t.clone(),
            ));
            let t2 = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/sandbox.rs", wt)}),
                t2.clone(),
            ));
            steps.push(("filesystem".into(), json!({"operation":"search","path": format!("{}/src", wt), "pattern":"openat2","recursive": false}), t2.clone()));
            if !is_simple_flag {
                let t3 = next_turn();
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/src/destination.rs", wt)}),
                    t3.clone(),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","status"]}),
                    t3.clone(),
                ));
            }
            if is_complex {
                let t4 = next_turn();
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","diff"]}),
                    t4.clone(),
                ));
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"stat","path": format!("{}/src/lib.rs", wt)}),
                    t4.clone(),
                ));
            }
        }
        s if s.contains("bug") => {
            let t = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/fs.rs", wt)}),
                t.clone(),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"search","path": format!("{}/src", wt), "pattern":"clamp"}),
                t.clone(),
            ));
            let t2 = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/fs.rs", wt)}),
                t2.clone(),
            ));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["test"]}),
                t2.clone(),
            ));
            let t3 = next_turn();
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_{}.txt", wt, task.task_id), "content":"fix"}), t3.clone()));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["verify"]}),
                t3.clone(),
            ));
            if is_complex {
                let t4 = next_turn();
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/src/fs.rs", wt)}),
                    t4.clone(),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","status"]}),
                    t4.clone(),
                ));
            }
        }
        s if s.contains("feature") => {
            let t = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/lib.rs", wt)}),
                t.clone(),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/fs.rs", wt)}),
                t.clone(),
            ));
            let t2 = next_turn();
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_feat_{}.txt", wt, task.task_id), "content":"feature"}), t2.clone()));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["test"]}),
                t2.clone(),
            ));
            let t3 = next_turn();
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["lint"]}),
                t3.clone(),
            ));
            if is_complex {
                let t4 = next_turn();
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/Cargo.toml", wt)}),
                    t4.clone(),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","diff"]}),
                    t4.clone(),
                ));
            }
        }
        s if s.contains("refactor") => {
            let t = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"search","path": format!("{}/src", wt), "pattern":"Sandbox"}),
                t.clone(),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/sandbox.rs", wt)}),
                t.clone(),
            ));
            let t2 = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/registry.rs", wt)}),
                t2.clone(),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/src/lib.rs", wt)}),
                t2.clone(),
            ));
            let t3 = next_turn();
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_ref_{}.txt", wt, task.task_id), "content":"refactor"}), t3.clone()));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["test"]}),
                t3.clone(),
            ));
            if is_complex {
                let t4 = next_turn();
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","status"]}),
                    t4.clone(),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","diff"]}),
                    t4.clone(),
                ));
            }
        }
        s if s.contains("test") => {
            let t = next_turn();
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["cargo","test"]}),
                t.clone(),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/tests/escapes.rs", wt)}),
                t.clone(),
            ));
            let t2 = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"search","path": format!("{}/tests", wt), "pattern":"symlink"}),
                t2.clone(),
            ));
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/tests/escapes.rs", wt)}),
                t2.clone(),
            ));
            let t3 = next_turn();
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_test_{}.txt", wt, task.task_id), "content":"fix"}), t3.clone()));
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["cargo","test"]}),
                t3.clone(),
            ));
            if is_complex {
                let t4 = next_turn();
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/src/registry.rs", wt)}),
                    t4.clone(),
                ));
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["stress"]}),
                    t4.clone(),
                ));
            }
        }
        s if s.contains("config") => {
            let t = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/Cargo.toml", wt)}),
                t.clone(),
            ));
            steps.push(("filesystem".into(), json!({"operation":"write","path": format!("{}/tmp_cfg_{}.txt", wt, task.task_id), "content":"config"}), t.clone()));
            let t2 = next_turn();
            steps.push((
                "shell".into(),
                json!({"program": "/bin/echo", "args":["check"]}),
                t2.clone(),
            ));
            if is_complex {
                let t3 = next_turn();
                steps.push((
                    "shell".into(),
                    json!({"program": "/bin/echo", "args":["git","status"]}),
                    t3.clone(),
                ));
                steps.push((
                    "filesystem".into(),
                    json!({"operation":"read","path": format!("{}/.gitignore", wt)}),
                    t3.clone(),
                ));
            }
        }
        _ => {
            let t = next_turn();
            steps.push((
                "filesystem".into(),
                json!({"operation":"read","path": format!("{}/README.md", wt)}),
                t.clone(),
            ));
        }
    }
    steps
}

fn _git_path() -> String {
    for p in ["/usr/bin/git", "/opt/homebrew/bin/git", "/bin/git"] {
        if Path::new(p).exists() {
            return p.to_string();
        }
    }
    "/usr/bin/git".to_string()
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
        .unwrap_or_else(|| "exp_baseline_001".to_string());
    let manifest_data = std::fs::read_to_string(&manifest_path)?;
    let manifest: TaskManifest = serde_json::from_str(&manifest_data)?;
    println!(
        "loaded {} tasks from {}",
        manifest.tasks.len(),
        manifest_path
    );

    // base worktree root
    let worktree_base = PathBuf::from("/tmp/baseline_worktrees");
    std::fs::create_dir_all(&worktree_base)?;
    // Ensure base revision exists
    let _base_rev = manifest
        .tasks
        .first()
        .map(|t| t.base_revision.clone())
        .unwrap_or_else(|| "HEAD".into());
    // Create experiment recorder
    let exp = ExperimentRecorder::new(exp_id.clone(), "baseline", &out_root)?;
    println!(
        "experiment {} at {}",
        exp_id,
        exp.experiment_dir().display()
    );

    for task in &manifest.tasks {
        println!("\n=== {} {} ===", task.task_id, task.title);
        let wt = worktree_path(&worktree_base, &task.task_id);
        // cleanup existing
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force", wt.to_str().unwrap()])
            .output();
        let _ = std::fs::remove_dir_all(&wt);
        // create worktree
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
            // try without detach?
            let out2 = Command::new("git")
                .args(["worktree", "add", wt_str, &task.base_revision])
                .output()?;
            if !out2.status.success() {
                eprintln!(
                    "second try failed: {}",
                    String::from_utf8_lossy(&out2.stderr)
                );
                continue;
            }
        }
        // verify clean
        let status = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&wt)
            .output()?;
        let porcelain = String::from_utf8_lossy(&status.stdout).to_string();
        if !porcelain.trim().is_empty() {
            eprintln!(
                "worktree not clean for {}: {}",
                task.task_id,
                porcelain.lines().next().unwrap_or("")
            );
        }
        let repo_before = collect_repo_state(Some(&wt));
        let task_rec = exp.task_recorder(&task.task_id)?;
        task_rec.task_started(
            Some(format!("{:?}", task.category).to_ascii_lowercase()),
            Some(task.description.clone()),
            Some(task.repository.clone()),
            Some(repo_before),
            Some("baseline-runner".into()),
            Some("0.1.0".into()),
            None,
        )?;

        // create registry per worktree
        let registry = create_registry(&wt)?;
        let steps = steps_for_task(task, &wt);
        let mut call_idx = 0;
        let mut current_turn: Option<String> = None;
        for (tool, args, turn_id) in steps {
            if current_turn.as_deref() != Some(&turn_id) {
                if let Some(prev) = current_turn.take() {
                    // close previous turn
                    task_rec.agent_turn_completed(
                        prev,
                        Some(100),
                        Some("mock-model".into()),
                        Some("test-provider".into()),
                        Some(TokenUsage {
                            input_tokens: Some(200),
                            output_tokens: Some(100),
                            ..Default::default()
                        }),
                    )?;
                }
                task_rec.agent_turn_started(&turn_id)?;
                current_turn = Some(turn_id.clone());
            }
            call_idx += 1;
            let call_id = format!("call_{call_idx:03}");
            // instrument via registry
            let res = instrument_execute(
                &registry,
                &task_rec,
                Some(turn_id.clone()),
                &call_id,
                &tool,
                args,
            )
            .await;
            if let Err(e) = res {
                eprintln!("tool {tool} failed: {e}");
            }
        }
        if let Some(prev) = current_turn.take() {
            task_rec.agent_turn_completed(
                prev,
                Some(100),
                Some("mock-model".into()),
                Some("test-provider".into()),
                Some(TokenUsage {
                    input_tokens: Some(200),
                    output_tokens: Some(100),
                    ..Default::default()
                }),
            )?;
        }

        // verification — mocked for speed (record as if command ran, no actual cargo spawn to keep baseline fast)
        for (vi, cmd) in task.verification_commands_or_checks.iter().enumerate() {
            let vid = format!("v{}", vi + 1);
            task_rec.verification_started(&vid, Some(cmd.clone()), Some(cmd.clone()))?;
            // simulate duration 50-200ms and success based on task should_fail
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

        // determine task_success: if any verification failed, mark failure else success
        // For demo, mark 3 tasks as failure to have variety
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

        // cleanup worktree after artifacts recorded
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force", wt_str])
            .output();
        let _ = std::fs::remove_dir_all(&wt);
        println!(
            "trace written {} lines",
            std::fs::read_to_string(task_rec.path())?.lines().count()
        );
    }

    // also write a stray invalid_run example if needed? Not now
    println!(
        "\nbaseline corpus complete: {}",
        exp.experiment_dir().display()
    );
    Ok(())
}
