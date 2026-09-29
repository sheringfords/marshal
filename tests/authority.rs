//! Execution-authority adversarial suite (MARSHALL_EXECUTION_AUTHORITY_V1).
//!
//! Written *before* the production change (Phase 1): every test asserts the
//! correct authority/replay behaviour, so each suspected defect in the
//! JSON-carried-scope + key-only-idempotency model shows up as a failure
//! first and as a passing regression afterwards. Hypotheses are classified
//! in `docs/engineering/EXECUTION_AUTHORITY_V1.md` as CONFIRMED_DEFECT,
//! NOT_REPRODUCED (already safe) or INCONCLUSIVE.
//!
//!굳 Coverage: idempotency-key reuse across tools / arguments / sessions,
//! concurrent identical and conflicting retries with side-effect counts,
//! replay parity between `execute` and `stream`, forged scope keys,
//! cross-session filesystem reads and writes, templated filesystem and
//! shell-`working_dir` escapes through sequences, per-item authority in
//! concurrent batches, and registry-swap scope stability.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use marshall::server::{self, ServerConfig};
use marshall::{ContractedCall, ExecutionPolicy, Tool, ToolOutcome, ToolRegistry};
use serde_json::{json, Value};
use tower::ServiceExt;

// ── fixtures ────────────────────────────────────────────────

struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "marshall_authority_{name}_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Workspace { root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Policy with filesystem, echo and pwd on; code off. `pwd` exists so a
    /// test can observe *where* a shell step ran, not just that it ran.
    fn policy(&self) -> ExecutionPolicy {
        let yaml = format!(
            r#"
workspace: {}
concurrency: 8
filesystem:
  writable: true
shell:
  timeout_ms: 5000
  commands:
    - program: {}
      args: NoFlags
    - program: {}
      args: NoFlags
"#,
            self.root.display(),
            echo_path().display(),
            pwd_path().display(),
        );
        ExecutionPolicy::from_yaml(&yaml).unwrap()
    }

    fn registry(&self) -> Arc<ToolRegistry> {
        Arc::new(server::build_registry_from_policy(&self.policy()).unwrap())
    }

    fn app(&self) -> Router {
        server::build_router_with_cors(
            server::build_state(self.registry(), &ServerConfig::new(&self.root)),
            None,
        )
    }

    fn app_with_audit(&self, audit_path: PathBuf) -> Router {
        server::build_router_with_cors(
            server::build_state(
                self.registry(),
                &ServerConfig {
                    audit_path: Some(audit_path),
                    ..ServerConfig::new(&self.root)
                },
            ),
            None,
        )
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn echo_path() -> PathBuf {
    for candidate in ["/bin/echo", "/usr/bin/echo"] {
        if std::path::Path::new(candidate).exists() {
            return PathBuf::from(candidate);
        }
    }
    panic!("no echo binary found");
}

fn pwd_path() -> PathBuf {
    for candidate in ["/bin/pwd", "/usr/bin/pwd"] {
        if std::path::Path::new(candidate).exists() {
            return PathBuf::from(candidate);
        }
    }
    panic!("no pwd binary found");
}

fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(req).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn send_text(app: &Router, req: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(req).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn execute(tool: &str, args: Value) -> Value {
    json!({ "tool": tool, "args": args })
}

fn execute_once(tool: &str, args: Value, key: &str) -> Value {
    json!({ "tool": tool, "args": args, "idempotency_key": key })
}

async fn create_session(app: &Router) -> (String, PathBuf) {
    let (status, body) = send(app, post("/v1/sessions", json!({}))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (
        body["session_id"].as_str().unwrap().to_string(),
        PathBuf::from(body["root"].as_str().unwrap()),
    )
}

/// A tool that records every args value it executes and answers after a
/// delay, so concurrent callers deterministically overlap.
struct Recorder {
    name: String,
    calls: Arc<tokio::sync::Mutex<Vec<Value>>>,
    delay_ms: u64,
}

impl Recorder {
    fn new(name: &str, delay_ms: u64) -> (Arc<Self>, Arc<tokio::sync::Mutex<Vec<Value>>>) {
        let calls = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        (
            Arc::new(Recorder {
                name: name.to_string(),
                calls: calls.clone(),
                delay_ms,
            }),
            calls,
        )
    }
}

#[async_trait::async_trait]
impl Tool for Recorder {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> &str {
        "records executions"
    }
    fn parameters_schema(&self) -> Value {
        json!({"type": "object"})
    }
    async fn execute(&self, args: Value) -> anyhow::Result<ToolOutcome> {
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
        let n = {
            let mut calls = self.calls.lock().await;
            calls.push(args);
            calls.len()
        };
        Ok(ToolOutcome::success(self.name.clone(), json!({"n": n}), 0))
    }
}

// ── replay identity: registry level ─────────────────────────

#[tokio::test]
async fn same_key_with_a_different_tool_is_a_conflict_not_a_replay() {
    let (alpha, _) = Recorder::new("alpha", 0);
    let (beta, beta_calls) = Recorder::new("beta", 0);
    let mut reg = ToolRegistry::new();
    reg.register(alpha);
    reg.register(beta);

    let first = reg
        .execute_once("k", ContractedCall::local(&reg, "alpha", json!({})))
        .await
        .expect("first call runs");
    assert_eq!(first.outcome.tool, "alpha");

    // The same key naming a different tool must not replay alpha's outcome
    // as if beta had run, and must not run beta either.
    let second = reg
        .execute_once("k", ContractedCall::local(&reg, "beta", json!({})))
        .await;
    assert!(second.is_err(), "cross-tool replay returned: {second:?}");
    assert!(
        second
            .unwrap_err()
            .to_string()
            .contains("idempotency_conflict"),
        "wrong conflict code"
    );
    assert!(
        beta_calls.lock().await.is_empty(),
        "conflicting call executed a side effect"
    );
}

#[tokio::test]
async fn same_key_with_different_arguments_is_a_conflict_not_a_replay() {
    let (tool, calls) = Recorder::new("rec", 0);
    let mut reg = ToolRegistry::new();
    reg.register(tool);

    reg.execute_once("k", ContractedCall::local(&reg, "rec", json!({"v": 1})))
        .await
        .expect("first call runs");
    let second = reg
        .execute_once("k", ContractedCall::local(&reg, "rec", json!({"v": 2})))
        .await;
    assert!(
        second.is_err(),
        "cross-argument replay returned: {second:?}"
    );
    assert!(
        second
            .unwrap_err()
            .to_string()
            .contains("idempotency_conflict"),
        "wrong conflict code"
    );
    assert_eq!(calls.lock().await.len(), 1, "conflict executed again");
}

#[tokio::test]
async fn same_key_with_identical_arguments_replays_without_reexecuting() {
    let (tool, calls) = Recorder::new("rec", 0);
    let mut reg = ToolRegistry::new();
    reg.register(tool);

    let first = reg
        .execute_once("k", ContractedCall::local(&reg, "rec", json!({"v": 1})))
        .await
        .unwrap();
    assert!(!first.replayed);
    let second = reg
        .execute_once("k", ContractedCall::local(&reg, "rec", json!({"v": 1})))
        .await
        .unwrap();
    assert!(second.replayed);
    // The replay references the originating execution id — it does not mint
    // a fresh one for work that already ran.
    assert_eq!(first.execution_id, second.execution_id);
    assert_eq!(first.outcome.summary, second.outcome.summary);
    assert_eq!(calls.lock().await.len(), 1, "identical retry re-executed");
}

#[tokio::test]
async fn contracted_calls_bind_fingerprint_to_their_own_work() {
    // The only public constructors derive the fingerprint from exactly the
    // tool, arguments and scope they carry: calls that differ in any of the
    // three fingerprint distinctly, identical calls fingerprint identically.
    // There is no constructor that accepts an independent fingerprint, so a
    // contract/call mismatch cannot be built through the public API.
    let reg = ToolRegistry::new();
    let fp = |call: &ContractedCall| call.contract().request_fingerprint().to_string();
    let base = ContractedCall::local(&reg, "rec", json!({"v": 1}));
    let same = ContractedCall::local(&reg, "rec", json!({"v": 1}));
    let other_tool = ContractedCall::local(&reg, "other", json!({"v": 1}));
    let other_args = ContractedCall::local(&reg, "rec", json!({"v": 2}));
    let other_scope = ContractedCall::new(
        "rec".to_string(),
        json!({"v": 1}),
        marshall::ExecutionScope::Session(PathBuf::from("/tmp/s1")),
        reg.policy_identity(),
    );
    assert_eq!(fp(&base), fp(&same));
    assert_ne!(fp(&base), fp(&other_tool));
    assert_ne!(fp(&base), fp(&other_args));
    assert_ne!(fp(&base), fp(&other_scope));
    // Scope is readable but not mutable through the public API.
    assert_eq!(
        base.contract().scope(),
        &marshall::ExecutionScope::Workspace
    );
}

#[tokio::test]
async fn concurrent_identical_calls_execute_exactly_once() {
    let (tool, calls) = Recorder::new("rec", 50);
    let reg = Arc::new({
        let mut r = ToolRegistry::new();
        r.register(tool);
        r
    });

    let mut handles = Vec::new();
    for _ in 0..16 {
        let r = reg.clone();
        handles.push(tokio::spawn(async move {
            r.execute_once("k", ContractedCall::local(&r, "rec", json!({"v": 1})))
                .await
        }));
    }
    let mut ids = std::collections::HashSet::new();
    for h in handles {
        let settled = h.await.unwrap().expect("identical retry must succeed");
        ids.insert(settled.execution_id);
    }
    // One actual side effect, and every caller — executor or waiter —
    // resolves to the single originating execution id.
    assert_eq!(ids.len(), 1, "callers resolved to distinct executions");
    assert_eq!(
        calls.lock().await.len(),
        1,
        "concurrent identical retries duplicated the side effect"
    );
}

#[tokio::test]
async fn concurrent_conflicting_calls_produce_one_side_effect() {
    let (tool, calls) = Recorder::new("rec", 50);
    let reg = Arc::new({
        let mut r = ToolRegistry::new();
        r.register(tool);
        r
    });

    let mut handles = Vec::new();
    for i in 0..16 {
        let r = reg.clone();
        handles.push(tokio::spawn(async move {
            let args = json!({"i": i});
            r.execute_once("k", ContractedCall::local(&r, "rec", args))
                .await
        }));
    }
    let mut ok = 0;
    let mut conflicts = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(_) => ok += 1,
            Err(e) if e.to_string().contains("idempotency_conflict") => conflicts += 1,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    // Exactly one caller wins; every other caller sees the conflict rather
    // than waiting for or duplicating a foreign execution.
    assert_eq!(ok, 1, "ok={ok} conflicts={conflicts}");
    assert_eq!(ok + conflicts, 16);
    assert_eq!(
        calls.lock().await.len(),
        1,
        "conflicting retries multiplied side effects"
    );
}

// ── replay identity: HTTP level ─────────────────────────────

#[tokio::test]
async fn http_same_key_across_tools_conflicts() {
    let ws = Workspace::new("key_tools");
    let app = ws.app();
    let target = ws.path("tool.txt");

    let (status, _) = send(
        &app,
        post(
            "/v1/execute",
            execute_once(
                "filesystem",
                json!({"operation": "write", "path": target, "content": "fs"}),
                "shared-key",
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Same key, different tool: must be a conflict, never the fs outcome
    // replayed as a shell outcome.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            execute_once(
                "shell",
                json!({"program": echo_path(), "args": ["hi"]}),
                "shared-key",
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "idempotency_conflict", "{body}");
}

#[tokio::test]
async fn http_same_key_across_argument_changes_conflicts() {
    let ws = Workspace::new("key_args");
    let app = ws.app();
    let target = ws.path("args.txt");

    let (status, _) = send(
        &app,
        post(
            "/v1/execute",
            execute_once(
                "filesystem",
                json!({"operation": "write", "path": target, "content": "one"}),
                "arg-key",
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            execute_once(
                "filesystem",
                json!({"operation": "write", "path": target, "content": "two"}),
                "arg-key",
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "idempotency_conflict", "{body}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "one");
}

#[tokio::test]
async fn http_same_key_across_sessions_conflicts() {
    let ws = Workspace::new("key_sessions");
    let app = ws.app();
    let (sid_a, root_a) = create_session(&app).await;
    let (sid_b, root_b) = create_session(&app).await;

    let (status, _) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid_a,
                "idempotency_key": "session-key",
                "args": {"operation": "write", "path": root_a.join("a.txt"), "content": "A"},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The same key in another session is a different execution, not a replay.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid_b,
                "idempotency_key": "session-key",
                "args": {"operation": "write", "path": root_b.join("b.txt"), "content": "B"},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "idempotency_conflict", "{body}");
    assert!(
        !root_b.join("b.txt").exists(),
        "conflict executed a side effect"
    );
}

#[tokio::test]
async fn stream_replay_shares_execute_identity_semantics() {
    let ws = Workspace::new("stream_replay");
    let app = ws.app();
    let target = ws.path("stream.txt");

    let (status, _) = send(
        &app,
        post(
            "/v1/execute",
            execute_once(
                "filesystem",
                json!({"operation": "write", "path": target, "content": "v1"}),
                "stream-key",
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Conflicting reuse through the stream endpoint: an SSE error event,
    // never a replayed success.
    let (status, text) = send_text(
        &app,
        post(
            "/v1/execute/stream",
            execute_once(
                "filesystem",
                json!({"operation": "write", "path": target, "content": "v2"}),
                "stream-key",
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains("event: error"), "{text}");
    assert!(text.contains("idempotency_conflict"), "{text}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "v1");

    // Identical reuse through the stream endpoint still replays.
    let (status, text) = send_text(
        &app,
        post(
            "/v1/execute/stream",
            execute_once(
                "filesystem",
                json!({"operation": "write", "path": target, "content": "v1"}),
                "stream-key",
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains("event: done"), "{text}");
    assert!(!text.contains("event: error"), "{text}");
}

// ── replay origin identity in audit ─────────────────────────

fn audit_lines(path: &PathBuf) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .map(|l| serde_json::from_str(l).expect("audit line"))
        .collect()
}

#[tokio::test]
async fn executed_audit_id_equals_replay_audit_origin_id() {
    // Finding 1 closure: the first actual side effect owns one execution
    // id, and the replay references that origin id instead of minting a
    // fresh one — while still reporting `replayed`, not `executed`.
    let ws = Workspace::new("audit_origin");
    let audit_path = ws.path("audit.jsonl");
    let app = ws.app_with_audit(audit_path.clone());
    let target = ws.path("origin.txt");
    let write = || {
        execute_once(
            "filesystem",
            json!({"operation": "write", "path": target, "content": "v"}),
            "origin-key",
        )
    };

    let (status, _) = send(&app, post("/v1/execute", write())).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&app, post("/v1/execute", write())).await;
    assert_eq!(status, StatusCode::OK);

    let lines = audit_lines(&audit_path);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0]["execution_status"], "executed");
    assert_eq!(lines[1]["execution_status"], "replayed");
    assert!(!lines[0]["execution_id"].as_str().unwrap().is_empty());
    assert_eq!(
        lines[0]["execution_id"], lines[1]["execution_id"],
        "replay minted a fresh execution id instead of referencing the origin"
    );
    assert_eq!(
        lines[0]["request_fingerprint"],
        lines[1]["request_fingerprint"]
    );
}

#[tokio::test]
async fn concurrent_identical_http_retries_share_one_origin_id() {
    // N simultaneous identical callers: one actual execution, and every
    // audit line — the single `executed` plus all `replayed` — references
    // the same originating execution id. Any timing still yields exactly
    // one execution for one key/fingerprint, so this is deterministic.
    let ws = Workspace::new("audit_concurrent");
    let audit_path = ws.path("audit.jsonl");
    let app = ws.app_with_audit(audit_path.clone());
    let target = ws.path("shared.txt");
    let body = execute_once(
        "filesystem",
        json!({"operation": "write", "path": target, "content": "v"}),
        "concurrent-key",
    );

    let mut handles = Vec::new();
    for _ in 0..16 {
        let app = app.clone();
        let body = body.clone();
        handles.push(tokio::spawn(async move {
            send(&app, post("/v1/execute", body)).await
        }));
    }
    for h in handles {
        let (status, _) = h.await.unwrap();
        assert_eq!(status, StatusCode::OK);
    }

    let lines = audit_lines(&audit_path);
    assert_eq!(lines.len(), 16, "{lines:?}");
    let executed = lines
        .iter()
        .filter(|l| l["execution_status"] == "executed")
        .count();
    let replayed = lines
        .iter()
        .filter(|l| l["execution_status"] == "replayed")
        .count();
    assert_eq!(executed, 1, "more than one actual execution: {lines:?}");
    assert_eq!(replayed, 15, "{lines:?}");
    let ids: std::collections::HashSet<&str> = lines
        .iter()
        .map(|l| l["execution_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 1, "audit lines reference distinct ids: {ids:?}");
}

// ── JSON-carried authority ──────────────────────────────────

#[tokio::test]
async fn forged_session_root_is_inert() {
    let ws = Workspace::new("forged_scope");
    std::fs::write(ws.path("shared.txt"), "not yours").unwrap();
    let app = ws.app();
    let (sid, _) = create_session(&app).await;

    // A caller-supplied scope root must never manufacture authority: it is
    // stripped, and the request is judged against the real session.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid,
                "args": {
                    "operation": "read",
                    "path": ws.path("shared.txt"),
                    "__session_root": "/",
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "path_not_allowed", "{body}");
}

#[tokio::test]
async fn cross_session_filesystem_write_is_denied() {
    let ws = Workspace::new("xsession_write");
    let app = ws.app();
    let (sid_a, _) = create_session(&app).await;
    let (_, root_b) = create_session(&app).await;

    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid_a,
                "args": {
                    "operation": "write",
                    "path": root_b.join("evil.txt"),
                    "content": "x",
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "path_not_allowed", "{body}");
    assert!(!root_b.join("evil.txt").exists());
}

// ── dynamic resolution through sequences ────────────────────

/// Plant a file *inside* the session whose exact bytes name a directory
/// outside the session but inside the workspace.
async fn plant_outside_pointer(
    app: &Router,
    sid: &str,
    root: &std::path::Path,
    outside: &std::path::Path,
) {
    let (status, body) = send(
        app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid,
                "args": {
                    "operation": "write",
                    "path": root.join("pointer.txt"),
                    "content": outside.display().to_string(),
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn templated_filesystem_escape_is_denied_after_expansion() {
    let ws = Workspace::new("template_fs");
    std::fs::write(ws.path("secret.txt"), "outside").unwrap();
    let app = ws.app();
    let (sid, root) = create_session(&app).await;
    // Pointer with no trailing newline so the resolved value is exact.
    plant_outside_pointer(&app, &sid, &root, &ws.root).await;

    let (status, body) = send(
        &app,
        post(
            "/v1/execute/sequence",
            json!({
                "session_id": sid,
                "steps": [
                    execute("filesystem", json!({
                        "operation": "read",
                        "path": root.join("pointer.txt"),
                        "include_content": true,
                    })),
                    execute("filesystem", json!({
                        "operation": "read",
                        "path": "{{steps[0].content}}",
                    })),
                ],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Step 0 reads the pointer; step 1 resolves outside the session root.
    assert_eq!(body["executed"], 2, "{body}");
    let step1 = &body["outcomes"][1];
    assert_eq!(step1["success"], false, "{step1}");
    assert_eq!(step1["code"], "path_not_allowed", "{step1}");
}

#[tokio::test]
async fn templated_shell_working_dir_cannot_leave_the_session() {
    let ws = Workspace::new("template_wd");
    let app = ws.app();
    let (sid, root) = create_session(&app).await;
    plant_outside_pointer(&app, &sid, &root, &ws.root).await;

    let (status, body) = send(
        &app,
        post(
            "/v1/execute/sequence",
            json!({
                "session_id": sid,
                "steps": [
                    execute("filesystem", json!({
                        "operation": "read",
                        "path": root.join("pointer.txt"),
                        "include_content": true,
                    })),
                    // `pwd` prints its working directory: success outside
                    // the session root is observable, not just deniable.
                    execute("shell", json!({
                        "program": pwd_path(),
                        "working_dir": "{{steps[0].content}}",
                        "include_content": true,
                    })),
                ],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["executed"], 2, "{body}");
    let step1 = &body["outcomes"][1];
    assert_eq!(
        step1["success"], false,
        "shell ran outside its session: {step1}"
    );
    assert_eq!(step1["code"], "path_not_allowed", "{step1}");
}

#[tokio::test]
async fn concurrent_batches_keep_per_item_session_authority() {
    let ws = Workspace::new("batch_scopes");
    let app = ws.app();
    let (sid_a, root_a) = create_session(&app).await;
    let (sid_b, root_b) = create_session(&app).await;

    // One batch, two authorities: the cross-session item is denied at
    // preflight, so the whole batch is refused before anything runs and no
    // side effect escapes either session.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute/batch",
            json!({
                "session_id": sid_a,
                "requests": [
                    {
                        "tool": "filesystem",
                        "args": {
                            "operation": "write",
                            "path": root_a.join("ok.txt"),
                            "content": "a",
                        },
                    },
                    {
                        "tool": "filesystem",
                        "session_id": sid_b,
                        "args": {
                            "operation": "write",
                            "path": root_a.join("cross.txt"),
                            "content": "b-reaches-into-a",
                        },
                    },
                    {
                        "tool": "filesystem",
                        "session_id": sid_b,
                        "args": {
                            "operation": "write",
                            "path": root_b.join("ok.txt"),
                            "content": "b",
                        },
                    },
                ],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "path_not_allowed", "{body}");
    assert!(!root_a.join("ok.txt").exists(), "denied batch executed");
    assert!(!root_a.join("cross.txt").exists());
    assert!(!root_b.join("ok.txt").exists(), "denied batch executed");
}

#[tokio::test]
async fn a_swapped_registry_cannot_widen_an_admitted_scope() {
    // Admission binds the session root into the contract; the tool enforces
    // it. Executing the same contracted call through a registry built from
    // a *wider* policy must stay confined: scope travels with the execution,
    // not the tool config.
    let ws = Workspace::new("reload_scope");
    std::fs::write(ws.path("secret.txt"), "wide").unwrap();

    let narrow = ws.registry();
    let wide_policy = ExecutionPolicy::from_yaml(&format!(
        "workspace: {}\nconcurrency: 8\nfilesystem:\n  writable: true\n",
        std::env::temp_dir().display()
    ))
    .unwrap();
    let wide = Arc::new(server::build_registry_from_policy(&wide_policy).unwrap());

    // A contract bound to a session root that does not contain the target:
    // the path is inside the wide tool sandbox but outside the session.
    let args = json!({
        "operation": "read",
        "path": ws.path("secret.txt"),
    });
    let narrow_call = ContractedCall::new(
        "filesystem".to_string(),
        args,
        marshall::ExecutionScope::Session(ws.path("sessions-only")),
        narrow.policy_identity(),
    );

    for reg in [&narrow, &wide] {
        let err = reg
            .execute_with(narrow_call.clone())
            .await
            .expect_err("wide registry must not widen admitted scope");
        assert!(err.to_string().contains("path_not_allowed"), "{err}");
    }
}
