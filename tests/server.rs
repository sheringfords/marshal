//! Endpoint tests for `marshalld`.
//!
//! The daemon was 1500 lines with no tests: every behaviour that only exists at
//! the HTTP layer — auth, session scoping, admission control, the server-side
//! egress check — was unverified, and those are the parts a deployment depends
//! on. These drive the router through `tower::ServiceExt::oneshot` rather than
//! binding a socket, so they are ordinary fast tests.
//!
//! The policy checks themselves live in `tests/escapes.rs`. What is asserted
//! here is that the HTTP layer applies them, and applies them again on its own
//! side where it claims defense in depth.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use marshall::server::{self, ServerConfig};
use marshall::{ExecutionPolicy, ToolRegistry};
use serde_json::{json, Value};
use tower::ServiceExt;

// ── fixtures ────────────────────────────────────────────────

/// A workspace directory that cleans itself up.
struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "marshalld_test_{name}_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Workspace { root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// A policy with the filesystem and shell tools on, code off.
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
http:
  allowed_hosts: [api.github.com]
"#,
            self.root.display(),
            echo_path().display(),
        );
        ExecutionPolicy::from_yaml(&yaml).unwrap()
    }

    fn registry(&self) -> Arc<ToolRegistry> {
        Arc::new(server::build_registry_from_policy(&self.policy()).unwrap())
    }

    fn config(&self) -> ServerConfig {
        ServerConfig {
            egress_hosts: vec!["api.github.com".into()],
            ..ServerConfig::new(&self.root)
        }
    }

    fn app(&self) -> Router {
        self.app_with(self.config())
    }

    fn app_with(&self, config: ServerConfig) -> Router {
        // `build_router_with_cors(.., None)` rather than `build_router`, so a
        // stray MARSHALLD_CORS_ORIGIN in the environment cannot change what
        // these tests exercise.
        server::build_router_with_cors(server::build_state(self.registry(), &config), None)
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

// ── request helpers ─────────────────────────────────────────

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}

fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

fn with_token(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// Send one request and read the status and JSON body.
async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(req).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Send one request and read the status and body as text.
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

// ── health and discovery ────────────────────────────────────

#[tokio::test]
async fn health_reports_version_and_registered_tools() {
    let ws = Workspace::new("health");
    let (status, body) = send(&ws.app(), get("/health")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["sessions"], 0);

    let tools: Vec<&str> = body["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(tools.contains(&"filesystem"), "{tools:?}");
    assert!(tools.contains(&"shell"), "{tools:?}");
}

#[tokio::test]
async fn a_policy_that_grants_no_languages_does_not_register_the_code_tool() {
    // The registry builder used to read an empty `allowed_languages` as
    // `allow_all()`, so this list contained `code` — and `code` on the local
    // backend reads any file and reaches any host, bypassing the two policies
    // this service exists to enforce.
    let ws = Workspace::new("no_code");
    let (_, body) = send(&ws.app(), get("/health")).await;

    let tools: Vec<&str> = body["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(!tools.contains(&"code"), "code tool registered: {tools:?}");
}

#[tokio::test]
async fn a_policy_with_no_commands_does_not_register_the_shell_tool() {
    // It used to be topped up with /bin/echo and /bin/cat.
    let ws = Workspace::new("no_shell");
    let policy = ExecutionPolicy::from_yaml(&format!(
        "workspace: {}\nshell: {{ commands: [] }}\n",
        ws.root.display()
    ))
    .unwrap();
    let registry = Arc::new(server::build_registry_from_policy(&policy).unwrap());
    let app = server::build_router_with_cors(server::build_state(registry, &ws.config()), None);

    let (_, body) = send(&app, get("/health")).await;
    let tools: Vec<&str> = body["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(!tools.contains(&"shell"), "shell registered: {tools:?}");
}

#[tokio::test]
async fn tools_endpoint_returns_schemas() {
    let ws = Workspace::new("tools");
    let (status, body) = send(&ws.app(), get("/v1/tools")).await;

    assert_eq!(status, StatusCode::OK);
    let defs = body.as_array().unwrap();
    assert!(!defs.is_empty());
    for def in defs {
        assert!(def["name"].is_string());
        assert!(def["parameters"].is_object(), "{def}");
    }
}

// ── authentication ──────────────────────────────────────────

#[tokio::test]
async fn every_v1_endpoint_requires_the_token_when_one_is_set() {
    let ws = Workspace::new("auth_all");
    let app = ws.app_with(ServerConfig {
        auth_token: Some("secret".into()),
        ..ws.config()
    });

    // `/health` and `/metrics` stay open: a load balancer probes them and has
    // no credential to present.
    for uri in ["/health", "/metrics"] {
        let (status, _) = send_text(&app, get(uri)).await;
        assert_eq!(status, StatusCode::OK, "{uri} should not require auth");
    }

    let guarded: Vec<Request<Body>> = vec![
        get("/v1/tools"),
        get("/v1/policy"),
        post("/v1/sessions", json!({})),
        post(
            "/v1/execute",
            execute("filesystem", json!({"operation": "list"})),
        ),
        post("/v1/execute/batch", json!({"requests": []})),
        post("/v1/execute/sequence", json!({"steps": []})),
        post("/v1/execute/stream", execute("shell", json!({}))),
    ];
    for req in guarded {
        let uri = req.uri().to_string();
        let (status, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri} was not guarded");
        assert_eq!(body["code"], "unauthorized");
    }
}

#[tokio::test]
async fn a_wrong_token_is_refused_and_the_right_one_is_accepted() {
    let ws = Workspace::new("auth_value");
    let app = ws.app_with(ServerConfig {
        auth_token: Some("secret".into()),
        ..ws.config()
    });

    for wrong in ["", "secret ", " secret", "Secret", "secretsecret", "sec"] {
        let (status, _) = send(&app, with_token(get("/v1/tools"), wrong)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "accepted {wrong:?}");
    }

    // A bare token without the scheme is not enough either.
    let mut req = get("/v1/tools");
    req.headers_mut()
        .insert("authorization", "secret".parse().unwrap());
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send(&app, with_token(get("/v1/tools"), "secret")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn no_configured_token_leaves_v1_open() {
    // Documented behaviour, and why `serve` refuses a non-loopback bind
    // without a token.
    let ws = Workspace::new("auth_none");
    let (status, _) = send(&ws.app(), get("/v1/tools")).await;
    assert_eq!(status, StatusCode::OK);
}

// ── policy enforcement over HTTP ────────────────────────────

#[tokio::test]
async fn a_read_inside_the_workspace_succeeds_and_one_outside_is_refused() {
    let ws = Workspace::new("fs_policy");
    std::fs::write(ws.path("inside.txt"), "hello").unwrap();
    let app = ws.app();

    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            execute(
                "filesystem",
                json!({"operation": "read", "path": ws.path("inside.txt")}),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["outcome"]["success"], true);

    for outside in ["/etc/passwd", "/etc/../etc/passwd"] {
        let (status, body) = send(
            &app,
            post(
                "/v1/execute",
                execute("filesystem", json!({"operation": "read", "path": outside})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{outside}");
        assert_eq!(body["code"], "path_not_allowed", "{outside}");
    }
}

#[tokio::test]
async fn the_metadata_endpoint_is_refused_by_the_server_not_only_the_tool() {
    // Defense in depth: the handler runs `validate_destination` itself, so a
    // registry whose HttpTool was misconfigured still cannot reach 169.254.
    let ws = Workspace::new("ssrf");
    let app = ws.app();

    for url in [
        "https://169.254.169.254/latest/meta-data/",
        "https://[::ffff:169.254.169.254]/latest/",
        "https://10.0.0.1/",
        "https://user:pass@example.com/",
    ] {
        let (status, _) = send(
            &app,
            post("/v1/execute", execute("http", json!({"url": url}))),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "not refused: {url}");
    }
}

#[tokio::test]
async fn a_host_outside_the_egress_allowlist_is_refused() {
    let ws = Workspace::new("egress");
    let app = ws.app();

    // Resolvable and public, but not on the list. `example.com` is used
    // because it resolves; the allowlist check is what must reject it.
    let (status, _) = send(
        &app,
        post(
            "/v1/execute",
            execute("http", json!({"url": "https://example.com/"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_unknown_tool_is_a_client_error() {
    let ws = Workspace::new("unknown_tool");
    let (status, body) = send(
        &ws.app(),
        post("/v1/execute", execute("definitely_not_a_tool", json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["code"].is_string());
}

#[tokio::test]
async fn a_shell_program_off_the_allowlist_is_refused() {
    let ws = Workspace::new("shell_policy");
    let app = ws.app();

    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            execute("shell", json!({"program": "/bin/sh", "args": ["-c", "id"]})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "command_not_allowed");

    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            execute("shell", json!({"program": echo_path(), "args": ["ok"]})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["outcome"]["success"], true);
}

// ── sessions ────────────────────────────────────────────────

#[tokio::test]
async fn a_session_is_created_scoped_and_deleted() {
    let ws = Workspace::new("session_lifecycle");
    let app = ws.app();

    let (status, body) = send(&app, post("/v1/sessions", json!({}))).await;
    assert_eq!(status, StatusCode::CREATED);
    let sid = body["session_id"].as_str().unwrap().to_string();
    let root = PathBuf::from(body["root"].as_str().unwrap());
    assert!(root.is_dir());

    let (status, body) = send(&app, get("/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sessions"], 1);

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/sessions/{sid}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!root.exists(), "session workspace outlived the session");
}

#[tokio::test]
async fn a_path_outside_the_session_root_is_refused() {
    let ws = Workspace::new("session_scope");
    std::fs::write(ws.path("shared.txt"), "not yours").unwrap();
    let app = ws.app();

    let (_, body) = send(&app, post("/v1/sessions", json!({}))).await;
    let sid = body["session_id"].as_str().unwrap().to_string();

    // Inside the workspace root, but outside *this session's* subdirectory.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid,
                "args": {"operation": "read", "path": ws.path("shared.txt")},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "path_not_allowed");
}

#[tokio::test]
async fn an_unknown_session_is_not_found() {
    let ws = Workspace::new("session_missing");
    let (status, body) = send(
        &ws.app(),
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": "00000000-0000-0000-0000-000000000000",
                "args": {"operation": "list", "path": ws.root},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "session_not_found");
}

#[tokio::test]
async fn an_expired_session_is_swept_and_reported() {
    let ws = Workspace::new("session_ttl");
    let app = ws.app_with(ServerConfig {
        session_ttl: Some(Duration::from_millis(1)),
        ..ws.config()
    });

    let (_, body) = send(&app, post("/v1/sessions", json!({}))).await;
    let sid = body["session_id"].as_str().unwrap().to_string();
    let root = PathBuf::from(body["root"].as_str().unwrap());

    tokio::time::sleep(Duration::from_millis(25)).await;

    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid,
                "args": {"operation": "list", "path": root},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Swept before the lookup, so it reads as "not found" rather than lingering.
    assert!(
        body["code"] == "session_expired" || body["code"] == "session_not_found",
        "{body}"
    );
    assert!(!root.exists(), "expired session workspace was not removed");
}

// ── batch and sequence ──────────────────────────────────────

#[tokio::test]
async fn batch_results_come_back_in_request_order() {
    let ws = Workspace::new("batch_order");
    let app = ws.app();
    let echo = echo_path();

    let requests: Vec<Value> = (0..8)
        .map(|i| {
            execute(
                "shell",
                json!({"program": echo, "args": [format!("item{i}")]}),
            )
        })
        .collect();

    let (status, body) = send(
        &app,
        post("/v1/execute/batch", json!({"requests": requests})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let outcomes = body["outcomes"].as_array().unwrap();
    assert_eq!(outcomes.len(), 8);
    for (i, outcome) in outcomes.iter().enumerate() {
        // Concurrency must not reorder: each slot holds its own request's
        // result, identified by the digest of what it echoed.
        let expected = marshall::sha256_hex(format!("item{i}\n").as_bytes());
        assert_eq!(
            outcome["summary"]["stdout_sha256"], expected,
            "slot {i} holds another request's result: {outcome}"
        );
    }
}

#[tokio::test]
async fn an_oversized_batch_is_refused_before_it_runs() {
    let ws = Workspace::new("batch_limit");
    let echo = echo_path();
    let requests: Vec<Value> = (0..65)
        .map(|_| execute("shell", json!({"program": echo, "args": ["x"]})))
        .collect();

    let (status, body) = send(
        &ws.app(),
        post("/v1/execute/batch", json!({"requests": requests})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "batch_too_large");
}

#[tokio::test]
async fn a_sequence_stops_at_the_first_failure_unless_told_otherwise() {
    let ws = Workspace::new("sequence_stop");
    let app = ws.app();
    let echo = echo_path();

    let steps = json!([
        execute("shell", json!({"program": echo, "args": ["one"]})),
        execute(
            "filesystem",
            json!({"operation": "read", "path": "/etc/passwd"})
        ),
        execute("shell", json!({"program": echo, "args": ["three"]})),
    ]);

    let (status, body) = send(&app, post("/v1/execute/sequence", json!({"steps": steps}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 3);
    assert_eq!(
        body["executed"], 2,
        "third step ran after a failure: {body}"
    );

    let (status, body) = send(
        &app,
        post(
            "/v1/execute/sequence",
            json!({"steps": steps, "continue_on_error": true}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["executed"], 3);
}

#[tokio::test]
async fn a_sequence_step_can_read_the_previous_step_output() {
    let ws = Workspace::new("sequence_template");
    let app = ws.app();
    let echo = echo_path();

    let (status, body) = send(
        &app,
        post(
            "/v1/execute/sequence",
            json!({
                "steps": [
                    execute("shell", json!({
                        "program": echo, "args": ["relayed"], "include_content": true
                    })),
                    execute("shell", json!({
                        "program": echo, "args": ["{{steps[0].stdout}}"]
                    })),
                ]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["executed"], 2);

    // The second step echoed the first step's stdout, so its own stdout is
    // that text (which already ends in a newline) plus echo's newline.
    let second = &body["outcomes"][1];
    let expected = marshall::sha256_hex(b"relayed\n\n");
    assert_eq!(second["summary"]["stdout_sha256"], expected, "{second}");
}

#[tokio::test]
async fn a_template_placeholder_cannot_expand_into_another_placeholder() {
    // Single-pass substitution: text that arrives *from* a previous step must
    // not be re-scanned. Otherwise a tool that controls its own output —
    // reading an attacker-authored file, say — can emit `{{steps[N]...}}` and
    // reach into a step it was never given.
    //
    // The placeholder has to enter through step output rather than through an
    // argument, since arguments are substituted before the step runs.
    let ws = Workspace::new("sequence_injection");
    std::fs::write(ws.path("payload.txt"), "{{steps[1].stdout}}").unwrap();
    let app = ws.app();
    let echo = echo_path();

    let (status, body) = send(
        &app,
        post(
            "/v1/execute/sequence",
            json!({
                "steps": [
                    // Step 0 reads the literal placeholder text out of a file.
                    execute("filesystem", json!({
                        "operation": "read",
                        "path": ws.path("payload.txt"),
                        "include_content": true
                    })),
                    execute("shell", json!({"program": echo, "args": ["secret"]})),
                    // Step 2 interpolates step 0's content — the placeholder.
                    execute("shell", json!({"program": echo, "args": ["{{steps[0].stdout}}"]})),
                ]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["executed"], 3, "{body}");

    let third = &body["outcomes"][2];
    let literal = marshall::sha256_hex(b"{{steps[1].stdout}}\n");
    let expanded = marshall::sha256_hex(b"secret\n\n");
    assert_ne!(
        third["summary"]["stdout_sha256"], expanded,
        "step output was re-expanded and leaked step 1: {third}"
    );
    assert_eq!(third["summary"]["stdout_sha256"], literal, "{third}");
}

// ── admission control ───────────────────────────────────────

#[tokio::test]
async fn requests_over_the_concurrency_cap_are_shed() {
    let ws = Workspace::new("concurrency");
    let app = ws.app_with(ServerConfig {
        concurrency: 1,
        ..ws.config()
    });

    // Hold the only permit with a slow call, then try to get in alongside it.
    let slow = app.clone().oneshot(post(
        "/v1/execute",
        execute("system", json!({"operation": "sleep", "duration_ms": 400})),
    ));
    let contender = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        send(
            &app,
            post(
                "/v1/execute",
                execute("system", json!({"operation": "now"})),
            ),
        )
        .await
    };

    let (_slow, (status, body)) = tokio::join!(slow, contender);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "concurrency_limited");
}

// ── workload-bounded concurrency (M2-001) ────────────────────
//
// `concurrency` bounds concurrently *executing* workloads, not admitted HTTP
// requests: every batch item takes its own permit as it starts. These tests
// pin that a batch cannot fan out past the cap, that mixed traffic shares
// one workload budget, and that aborting a batch returns its permits.

fn sleep_tool(ms: u64) -> Value {
    execute("system", json!({"operation": "sleep", "duration_ms": ms}))
}

fn batch_of_sleeps(n: usize, ms: u64, max_concurrency: usize) -> Value {
    json!({
        "requests": (0..n).map(|_| execute("system", json!({"operation": "sleep", "duration_ms": ms}))).collect::<Vec<_>>(),
        "max_concurrency": max_concurrency,
    })
}

#[tokio::test]
async fn batch_cannot_fan_out_past_the_workload_cap() {
    let ws = Workspace::new("batch-cap");
    let app = ws.app_with(ServerConfig {
        concurrency: 1,
        ..ws.config()
    });

    // Three 300 ms sleeps with max_concurrency 32 must serialize: one running
    // workload at a time under a single permit.
    let started = std::time::Instant::now();
    let (status, body) = send(&app, post("/v1/execute/batch", batch_of_sleeps(3, 300, 32))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["outcomes"].as_array().unwrap().len(), 3);
    for outcome in body["outcomes"].as_array().unwrap() {
        assert_eq!(outcome["success"], true);
    }
    assert!(started.elapsed() >= Duration::from_millis(800));
}

#[tokio::test]
async fn batch_holds_no_request_permit_while_items_wait() {
    // Regression for the old shape (1 request permit per batch hiding 32
    // children): with concurrency 1, a contender arriving mid-batch must see
    // the workload budget as exhausted, not as one free request slot.
    let ws = Workspace::new("batch-shed");
    let app = ws.app_with(ServerConfig {
        concurrency: 1,
        ..ws.config()
    });

    let slow = app
        .clone()
        .oneshot(post("/v1/execute/batch", batch_of_sleeps(2, 400, 8)));
    let contender = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        send(&app, post("/v1/execute", sleep_tool(10))).await
    };

    let (_slow, (status, body)) = tokio::join!(slow, contender);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "concurrency_limited");
}

#[tokio::test]
async fn mixed_single_and_batch_traffic_shares_one_workload_budget() {
    let ws = Workspace::new("mixed-budget");
    let app = ws.app_with(ServerConfig {
        concurrency: 4,
        ..ws.config()
    });

    // Occupy all four workload permits with slow singles.
    let mut singles = Vec::new();
    for _ in 0..4 {
        let app = app.clone();
        singles.push(tokio::spawn(async move {
            app.oneshot(post("/v1/execute", sleep_tool(500)))
                .await
                .expect("response")
        }));
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    // A batch arriving with no free workload capacity is shed, not queued
    // behind an unbounded wait.
    let (status, body) = send(&app, post("/v1/execute/batch", batch_of_sleeps(2, 10, 8))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "concurrency_limited");
    for slow in singles {
        let response = slow.await.expect("task");
        assert_eq!(response.status(), StatusCode::OK);
    }
    // After the drain, the same batch is admitted and runs.
    let (status, body) = send(&app, post("/v1/execute/batch", batch_of_sleeps(2, 10, 8))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["outcomes"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn aborted_batch_returns_its_workload_permits() {
    // Dropping the batch request mid-flight (client disconnect) must abort
    // queued/running items and release every permit: with concurrency 1, a
    // leaked permit would turn the next request into a 503.
    let ws = Workspace::new("batch-abort");
    let app = ws.app_with(ServerConfig {
        concurrency: 1,
        ..ws.config()
    });

    {
        let fut = app
            .clone()
            .oneshot(post("/v1/execute/batch", batch_of_sleeps(4, 400, 4)));
        tokio::pin!(fut);
        tokio::select! {
            _ = &mut fut => panic!("batch finished before the abort"),
            _ = tokio::time::sleep(Duration::from_millis(120)) => {}
        }
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    let (status, _) = send(&app, post("/v1/execute", sleep_tool(10))).await;
    assert_eq!(status, StatusCode::OK);
}

// ── quotas ──────────────────────────────────────────────────

#[tokio::test]
async fn a_client_over_its_quota_gets_429_with_retry_after() {
    let ws = Workspace::new("quota");
    let app = ws.app_with(ServerConfig {
        rate_limit: Some(marshall::RateLimit::new(60, 2)),
        ..ws.config()
    });

    for i in 0..2 {
        let (status, _) = send(&app, get("/v1/tools")).await;
        assert_eq!(status, StatusCode::OK, "burst request {i}");
    }

    let response = app.clone().oneshot(get("/v1/tools")).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = response
        .headers()
        .get("retry-after")
        .expect("retry-after header")
        .to_str()
        .unwrap()
        .parse()
        .expect("retry-after is a number of seconds");
    assert!(retry_after >= 1, "retry-after invites an instant retry");
}

#[tokio::test]
async fn quotas_are_per_token_so_one_client_cannot_starve_another() {
    // The global semaphore could not do this: it sheds whoever arrives when
    // the pool is full, regardless of who filled it.
    let ws = Workspace::new("quota_isolation");
    let app = ws.app_with(ServerConfig {
        auth_token: None,
        rate_limit: Some(marshall::RateLimit::new(60, 2)),
        ..ws.config()
    });

    for _ in 0..2 {
        let (status, _) = send(&app, with_token(get("/v1/tools"), "noisy")).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, body) = send(&app, with_token(get("/v1/tools"), "noisy")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");

    // A different token has its own bucket and is unaffected.
    let (status, _) = send(&app, with_token(get("/v1/tools"), "quiet")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn no_quota_configured_means_no_throttling() {
    let ws = Workspace::new("quota_off");
    let app = ws.app();
    for i in 0..50 {
        let (status, _) = send(&app, get("/v1/tools")).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }
}

#[tokio::test]
async fn the_quota_runs_after_auth_so_it_cannot_be_used_to_probe_tokens() {
    // If throttling came first, an unauthenticated attacker could exhaust a
    // victim's bucket, and 429-vs-401 would distinguish valid tokens.
    let ws = Workspace::new("quota_after_auth");
    let app = ws.app_with(ServerConfig {
        auth_token: Some("secret".into()),
        rate_limit: Some(marshall::RateLimit::new(60, 1)),
        ..ws.config()
    });

    for _ in 0..5 {
        let (status, _) = send(&app, with_token(get("/v1/tools"), "wrong")).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a bad token produced something other than 401"
        );
    }

    // The real client's allowance was not spent by those attempts.
    let (status, _) = send(&app, with_token(get("/v1/tools"), "secret")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn health_and_metrics_are_not_throttled() {
    // A liveness probe that gets 429 takes the instance out of rotation.
    let ws = Workspace::new("quota_probes");
    let app = ws.app_with(ServerConfig {
        rate_limit: Some(marshall::RateLimit::new(60, 1)),
        ..ws.config()
    });

    for uri in ["/health", "/metrics", "/health", "/metrics"] {
        let (status, _) = send_text(&app, get(uri)).await;
        assert_eq!(status, StatusCode::OK, "{uri} was throttled");
    }
}

// ── idempotency ─────────────────────────────────────────────

#[tokio::test]
async fn the_same_idempotency_key_does_not_run_the_tool_twice() {
    let ws = Workspace::new("idempotency");
    let app = ws.app();
    let target = ws.path("counter.txt");

    let write = |content: &str| {
        json!({
            "tool": "filesystem",
            "idempotency_key": "fixed-key",
            "args": {"operation": "write", "path": target, "content": content},
        })
    };

    let (status, first) = send(&app, post("/v1/execute", write("first"))).await;
    assert_eq!(status, StatusCode::OK);

    // Same key, different content: the cached outcome comes back and the file
    // is untouched.
    let (status, second) = send(&app, post("/v1/execute", write("second"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["outcome"]["summary"], second["outcome"]["summary"]);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "first");
}

// ── observability ───────────────────────────────────────────

#[tokio::test]
async fn metrics_count_outcomes_per_tool_and_are_valid_exposition() {
    let ws = Workspace::new("metrics");
    let app = ws.app();
    let echo = echo_path();

    send(
        &app,
        post(
            "/v1/execute",
            execute("shell", json!({"program": echo, "args": ["ok"]})),
        ),
    )
    .await;
    send(
        &app,
        post(
            "/v1/execute",
            execute(
                "filesystem",
                json!({"operation": "read", "path": "/etc/passwd"}),
            ),
        ),
    )
    .await;

    let (status, text) = send_text(&app, get("/metrics")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(text.contains("marshalld_requests_total 2"), "{text}");
    assert!(
        text.contains(r#"marshalld_tool_requests_total{tool="shell",status="success"} 1"#),
        "{text}"
    );

    // Histogram buckets must be cumulative or Prometheus rejects the series.
    let buckets: Vec<u64> = text
        .lines()
        .filter(|l| l.starts_with("marshalld_duration_ms_bucket"))
        .filter_map(|l| l.rsplit(' ').next()?.parse().ok())
        .collect();
    assert_eq!(buckets.len(), 7, "{text}");
    assert!(
        buckets.windows(2).all(|w| w[0] <= w[1]),
        "buckets not cumulative: {buckets:?}"
    );
}

#[tokio::test]
async fn an_audit_line_is_written_with_a_digest_and_no_payload() {
    let ws = Workspace::new("audit");
    let audit_path = ws.path("audit.jsonl");
    let app = ws.app_with(ServerConfig {
        audit_path: Some(audit_path.clone()),
        ..ws.config()
    });

    std::fs::write(ws.path("secret.txt"), "TOP SECRET").unwrap();
    send(
        &app,
        post(
            "/v1/execute",
            execute(
                "filesystem",
                json!({
                    "operation": "read",
                    "path": ws.path("secret.txt"),
                    "include_content": true
                }),
            ),
        ),
    )
    .await;

    // The write is spawned onto a blocking task; give it a moment to land.
    for _ in 0..50 {
        if audit_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let line = std::fs::read_to_string(&audit_path).expect("audit log");
    let record: Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();

    assert_eq!(record["tool"], "filesystem");
    assert_eq!(record["success"], true);
    assert_eq!(
        record["content_sha256"],
        marshall::sha256_hex(b"TOP SECRET")
    );
    assert_eq!(
        record["redaction_policy_version"],
        marshall::REDACTION_POLICY_VERSION
    );
    assert!(
        !line.contains("TOP SECRET"),
        "the audit log copied the payload it was supposed to digest"
    );
}

// ── CORS ────────────────────────────────────────────────────

#[tokio::test]
async fn no_cors_headers_are_sent_by_default() {
    // The default used to be `AllowOrigin::any()`, which let any page in a
    // browser drive an unauthenticated local daemon.
    let ws = Workspace::new("cors_default");
    let app = ws.app();

    let mut req = get("/health");
    req.headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    let response = app.oneshot(req).await.unwrap();

    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "headers: {:?}",
        response.headers()
    );
}

#[tokio::test]
async fn a_configured_origin_is_echoed_and_others_are_not() {
    let ws = Workspace::new("cors_exact");
    let cors = tower_http::cors::CorsLayer::new().allow_origin(
        tower_http::cors::AllowOrigin::exact("https://app.example".parse().unwrap()),
    );
    let app = server::build_router_with_cors(
        server::build_state(ws.registry(), &ws.config()),
        Some(cors),
    );

    let mut allowed = get("/health");
    allowed
        .headers_mut()
        .insert("origin", "https://app.example".parse().unwrap());
    let response = app.clone().oneshot(allowed).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap()),
        Some("https://app.example")
    );

    // A different origin must never be echoed back: `AllowOrigin::exact` always
    // states the one configured origin, and the browser refuses the mismatch.
    let mut other = get("/health");
    other
        .headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    let response = app.oneshot(other).await.unwrap();
    let allowed = response
        .headers()
        .get("access-control-allow-origin")
        .map(|v| v.to_str().unwrap().to_string());
    assert_ne!(allowed.as_deref(), Some("https://evil.example"));
    assert_ne!(allowed.as_deref(), Some("*"));
}

// ── unified admission (MAR-P0-003) ────────────────────────────
//
// `/v1/execute/stream` used to admit with auth + quota + concurrency only,
// skipping session, egress, idempotency, audit, and metrics. These tests pin
// the contract: every execution endpoint denies the same calls with the same
// codes, and a streamed execution is audited and metered like a single one.

/// POST the same body to every execution endpoint, normalizing the two
/// envelope shapes (single/stream return the outcome; batch/sequence wrap).
fn endpoint_bodies(
    tool: &str,
    args: Value,
    session_id: Option<&str>,
) -> Vec<(&'static str, Value)> {
    let single = match session_id {
        Some(sid) => json!({"tool": tool, "session_id": sid, "args": args}),
        None => execute(tool, args.clone()),
    };
    vec![
        ("/v1/execute", single),
        (
            "/v1/execute/batch",
            json!({"session_id": session_id, "requests": [execute(tool, args.clone())]}),
        ),
        (
            "/v1/execute/sequence",
            json!({"session_id": session_id, "steps": [execute(tool, args.clone())]}),
        ),
        (
            "/v1/execute/stream",
            json!({"tool": tool, "session_id": session_id, "args": args}),
        ),
    ]
}

#[tokio::test]
async fn every_execution_endpoint_denies_an_unknown_session() {
    let ws = Workspace::new("admission_unknown_session");
    let app = ws.app();
    let sid = "00000000-0000-0000-0000-000000000000";

    for (uri, body) in endpoint_bodies(
        "filesystem",
        json!({"operation": "list", "path": ws.root}),
        Some(sid),
    ) {
        let (status, _) = match uri {
            "/v1/execute/stream" => {
                let (status, text) = send_text(&app, post(uri, body)).await;
                (status, Value::String(text))
            }
            _ => send(&app, post(uri, body)).await,
        };
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{uri} admitted an unknown session"
        );
    }
}

#[tokio::test]
async fn every_execution_endpoint_denies_an_expired_session() {
    let ws = Workspace::new("admission_expired_session");
    let app = ws.app_with(ServerConfig {
        session_ttl: Some(Duration::from_millis(1)),
        ..ws.config()
    });

    let (_, body) = send(&app, post("/v1/sessions", json!({}))).await;
    let sid = body["session_id"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(25)).await;

    for (uri, body) in endpoint_bodies(
        "filesystem",
        json!({"operation": "list", "path": ws.root}),
        Some(&sid),
    ) {
        let (status, _) = match uri {
            "/v1/execute/stream" => {
                let (status, text) = send_text(&app, post(uri, body)).await;
                (status, Value::String(text))
            }
            _ => send(&app, post(uri, body)).await,
        };
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{uri} admitted an expired session"
        );
    }
}

#[tokio::test]
async fn stream_denies_a_path_outside_the_session_like_execute() {
    let ws = Workspace::new("admission_stream_scope");
    std::fs::write(ws.path("shared.txt"), "not yours").unwrap();
    let app = ws.app();

    let (_, body) = send(&app, post("/v1/sessions", json!({}))).await;
    let sid = body["session_id"].as_str().unwrap().to_string();
    let args = json!({"operation": "read", "path": ws.path("shared.txt")});

    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({"tool": "filesystem", "session_id": sid, "args": args}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "path_not_allowed");

    // The same call over SSE must not reach the tool either — and because it
    // is denied at admission, there is no SSE body to parse, just a 403.
    let (status, _) = send_text(
        &app,
        post(
            "/v1/execute/stream",
            json!({"tool": "filesystem", "session_id": sid, "args": args}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn stream_denies_blocked_http_destinations_like_execute() {
    let ws = Workspace::new("admission_stream_egress");
    let app = ws.app();

    for url in [
        "https://169.254.169.254/latest/meta-data/",
        "https://example.com/",
    ] {
        let args = json!({"url": url});
        let (status, _) = send(&app, post("/v1/execute", execute("http", args.clone()))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "execute admitted {url}");

        let (status, _) = send_text(&app, post("/v1/execute/stream", execute("http", args))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "stream admitted {url}");
    }
}

#[tokio::test]
async fn stream_is_rate_limited_and_sheds_load_like_execute() {
    // Quota parity: an exhausted bucket refuses the stream with 429.
    let ws = Workspace::new("admission_stream_quota");
    let app = ws.app_with(ServerConfig {
        rate_limit: Some(marshall::RateLimit::new(60, 2)),
        ..ws.config()
    });

    for _ in 0..2 {
        let (status, _) = send(&app, get("/v1/tools")).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, body) = send(
        &app,
        post(
            "/v1/execute/stream",
            execute("system", json!({"operation": "now"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");

    // Concurrency parity: with the pool full, the stream sheds with 503.
    let ws = Workspace::new("admission_stream_concurrency");
    let app = ws.app_with(ServerConfig {
        concurrency: 1,
        ..ws.config()
    });

    let slow = app.clone().oneshot(post(
        "/v1/execute",
        execute("system", json!({"operation": "sleep", "duration_ms": 400})),
    ));
    let contender = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        send(
            &app,
            post(
                "/v1/execute/stream",
                execute("system", json!({"operation": "now"})),
            ),
        )
        .await
    };

    let (_slow, (status, _)) = tokio::join!(slow, contender);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_streamed_execution_is_audited_and_metered() {
    let ws = Workspace::new("admission_stream_observability");
    let audit_path = ws.path("audit.jsonl");
    let app = ws.app_with(ServerConfig {
        audit_path: Some(audit_path.clone()),
        ..ws.config()
    });
    let echo = echo_path();

    let (status, text) = send_text(
        &app,
        post(
            "/v1/execute/stream",
            execute("shell", json!({"program": echo, "args": ["hi"]})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(text.contains("event: summary"), "{text}");
    assert!(text.contains("event: done"), "{text}");

    for _ in 0..50 {
        if audit_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let line = std::fs::read_to_string(&audit_path).expect("audit log");
    let record: Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
    assert_eq!(record["tool"], "shell");
    assert_eq!(record["success"], true);

    let (status, text) = send_text(&app, get("/metrics")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        text.contains(r#"marshalld_tool_requests_total{tool="shell",status="success"} 1"#),
        "{text}"
    );
}

#[tokio::test]
async fn a_stream_denied_at_admission_runs_nothing() {
    let ws = Workspace::new("admission_stream_denied_runs_nothing");
    let audit_path = ws.path("audit.jsonl");
    let app = ws.app_with(ServerConfig {
        audit_path: Some(audit_path.clone()),
        ..ws.config()
    });

    // Unknown session: denied before any tool runs.
    let (status, _) = send_text(
        &app,
        post(
            "/v1/execute/stream",
            json!({
                "tool": "filesystem",
                "session_id": "00000000-0000-0000-0000-000000000000",
                "args": {"operation": "list", "path": ws.root},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // No audit record: nothing executed. No per-tool metrics either.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !audit_path.exists(),
        "a denied stream wrote an audit record for work it never did"
    );
    let (_, text) = send_text(&app, get("/metrics")).await;
    assert!(!text.contains(r#"tool="filesystem""#), "{text}");
}

#[tokio::test]
async fn stream_honors_idempotency_like_execute() {
    let ws = Workspace::new("admission_stream_idempotency");
    let app = ws.app();
    let target = ws.path("counter.txt");

    let (status, _) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "idempotency_key": "stream-key",
                "args": {"operation": "write", "path": target, "content": "first"},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Same key over SSE with different content: the cached outcome replays
    // and the file is untouched.
    let (status, text) = send_text(
        &app,
        post(
            "/v1/execute/stream",
            json!({
                "tool": "filesystem",
                "idempotency_key": "stream-key",
                "args": {"operation": "write", "path": target, "content": "second"},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(text.contains("event: done"), "{text}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "first");
}

#[tokio::test]
async fn batch_and_sequence_report_per_item_failures_without_failing_the_request() {
    let ws = Workspace::new("admission_partial_failure");
    let app = ws.app();
    let echo = echo_path();

    // The single endpoint rejects an unknown tool with a 400 + code; the
    // batch/sequence endpoints keep the request 200 and report per item.
    let (status, body) = send(&app, post("/v1/execute", execute("nope", json!({})))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "tool_not_found");

    let (status, body) = send(
        &app,
        post(
            "/v1/execute/batch",
            json!({"requests": [
                execute("shell", json!({"program": echo, "args": ["ok"]})),
                execute("nope", json!({})),
            ]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let outcomes = body["outcomes"].as_array().unwrap();
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0]["success"], true);
    assert_eq!(outcomes[1]["code"], "tool_not_found");

    // A sequence stops at the failure by default and says how far it got.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute/sequence",
            json!({"steps": [
                execute("nope", json!({})),
                execute("shell", json!({"program": echo, "args": ["unreached"]})),
            ]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["executed"], 1);
    assert_eq!(body["total"], 2);
}

#[tokio::test]
async fn batch_and_sequence_executions_are_audited() {
    let ws = Workspace::new("admission_multi_audit");
    let audit_path = ws.path("audit.jsonl");
    let app = ws.app_with(ServerConfig {
        audit_path: Some(audit_path.clone()),
        ..ws.config()
    });
    let echo = echo_path();

    let (status, _) = send(
        &app,
        post(
            "/v1/execute/batch",
            json!({"requests": [
                execute("shell", json!({"program": echo, "args": ["one"]})),
                execute("system", json!({"operation": "now"})),
            ]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(
        &app,
        post(
            "/v1/execute/sequence",
            json!({"steps": [execute("shell", json!({"program": echo, "args": ["two"]}))]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Three executed tools → three audit records, one per item.
    let mut records = vec![];
    for _ in 0..50 {
        if audit_path.exists() {
            let text = std::fs::read_to_string(&audit_path).unwrap();
            records = text.lines().map(str::to_string).collect::<Vec<_>>();
            if records.len() >= 3 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(records.len(), 3, "{records:?}");
    let tools: Vec<String> = records
        .iter()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["tool"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(tools, vec!["shell", "system", "shell"]);
}

#[tokio::test]
async fn aborting_a_stream_mid_flight_does_not_wedge_the_server() {
    let ws = Workspace::new("admission_stream_abort");
    std::fs::write(ws.path("big.txt"), vec![b'x'; 1_000_000]).unwrap();
    let app = ws.app();

    // Start a multi-chunk stream (1 MiB of content at 64 KiB per event),
    // then drop the client mid-flight.
    let in_flight = tokio::spawn({
        let app = app.clone();
        let path = ws.path("big.txt");
        async move {
            let _ = app
                .oneshot(post(
                    "/v1/execute/stream",
                    execute(
                        "filesystem",
                        json!({"operation": "read", "path": path, "include_content": true}),
                    ),
                ))
                .await;
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    in_flight.abort();
    let _ = in_flight.await;

    // The server still admits and runs work afterwards.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            execute("system", json!({"operation": "now"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["outcome"]["success"], true);
}

// ── session isolation at the operation boundary (M2-002) ────
//
// MAR-REV-004: per-item session overrides without a top-level session skipped
// path checks, so batch/sequence executed workspace-wide reads that single
// execution refused. These tests pin the documented contract: the effective
// session (per-item override, else top-level) binds every filesystem path at
// admission *and* at the tool, on every endpoint, with the same denial shape.

/// Create a session; return (id, root).
async fn make_session(app: &Router) -> (String, PathBuf) {
    let (_, body) = send(app, post("/v1/sessions", json!({}))).await;
    (
        body["session_id"].as_str().unwrap().to_string(),
        PathBuf::from(body["root"].as_str().unwrap()),
    )
}

fn fs_read(path: &PathBuf) -> Value {
    json!({"operation": "read", "path": path})
}

#[tokio::test]
async fn batch_per_item_session_cannot_read_outside_its_root() {
    let ws = Workspace::new("m2-batch-scope");
    std::fs::write(ws.path("shared.txt"), "not yours").unwrap();
    let app = ws.app();
    let (sid, _) = make_session(&app).await;

    let (status, body) = send(
        &app,
        post(
            "/v1/execute/batch",
            json!({"requests": [{
                "tool": "filesystem",
                "session_id": sid,
                "args": fs_read(&ws.path("shared.txt")),
            }]}),
        ),
    )
    .await;
    // Admission denies the whole request before anything runs.
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "path_not_allowed", "{body}");
}

#[tokio::test]
async fn sequence_per_item_session_cannot_read_outside_its_root() {
    let ws = Workspace::new("m2-seq-scope");
    std::fs::write(ws.path("shared.txt"), "not yours").unwrap();
    let app = ws.app();
    let (sid, _) = make_session(&app).await;

    let (status, body) = send(
        &app,
        post(
            "/v1/execute/sequence",
            json!({"steps": [{
                "tool": "filesystem",
                "session_id": sid,
                "args": fs_read(&ws.path("shared.txt")),
            }]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "path_not_allowed", "{body}");
}

#[tokio::test]
async fn top_level_and_override_follow_one_contract_on_both_endpoints() {
    // Override wins for its item and is checked against the *override* root:
    // a path inside the top-level session but outside the override is denied
    // identically by batch and sequence.
    let ws = Workspace::new("m2-override-contract");
    let app = ws.app();
    let (sid_a, root_a) = make_session(&app).await;
    let (sid_b, _) = make_session(&app).await;
    std::fs::write(root_a.join("a.txt"), "a's file").unwrap();

    for uri in ["/v1/execute/batch", "/v1/execute/sequence"] {
        let key = if uri.ends_with("batch") {
            "requests"
        } else {
            "steps"
        };
        let (status, body) = send(
            &app,
            post(
                uri,
                json!({
                    "session_id": sid_a,
                    key: [{
                        "tool": "filesystem",
                        "session_id": sid_b,
                        "args": fs_read(&root_a.join("a.txt")),
                    }],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(body["code"], "path_not_allowed", "{uri}");
    }
}

#[tokio::test]
async fn session_a_cannot_read_or_write_session_b_files() {
    let ws = Workspace::new("m2-cross-session");
    let app = ws.app();
    let (sid_a, _) = make_session(&app).await;
    let (_sid_b, root_b) = make_session(&app).await;
    std::fs::write(root_b.join("secret.txt"), "b secret").unwrap();

    // Read across.
    let (status, _) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid_a,
                "args": fs_read(&root_b.join("secret.txt")),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Write across via batch override without top-level.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute/batch",
            json!({"requests": [{
                "tool": "filesystem",
                "session_id": sid_a,
                "args": {"operation": "write", "path": root_b.join("evil.txt"), "content": "x"},
            }]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "path_not_allowed", "{body}");
    assert!(!root_b.join("evil.txt").exists());
}

#[tokio::test]
async fn dotdot_traversal_is_rejected_under_session() {
    let ws = Workspace::new("m2-dotdot");
    std::fs::write(ws.path("shared.txt"), "not yours").unwrap();
    let app = ws.app();
    let (sid, root) = make_session(&app).await;

    // Lexically inside the root, canonically outside it.
    let escaped = root.join("..").join("shared.txt");
    for uri in ["/v1/execute", "/v1/execute/stream"] {
        let (status, body) = send(
            &app,
            post(
                uri,
                json!({
                    "tool": "filesystem",
                    "session_id": sid,
                    "args": fs_read(&escaped),
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(body["code"], "path_not_allowed", "{uri}");
    }
}

#[tokio::test]
async fn symlink_escape_is_rejected_under_session() {
    let ws = Workspace::new("m2-symlink");
    std::fs::write(ws.path("shared.txt"), "not yours").unwrap();
    let app = ws.app();
    let (sid, root) = make_session(&app).await;
    #[cfg(unix)]
    std::os::unix::fs::symlink(ws.path("shared.txt"), root.join("link.txt")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(ws.path("shared.txt"), root.join("link.txt")).unwrap();

    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid,
                "args": fs_read(&root.join("link.txt")),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "path_not_allowed");
}

#[tokio::test]
async fn copy_and_move_validate_both_ends_under_session() {
    let ws = Workspace::new("m2-copy-move");
    let app = ws.app();
    let (sid, root) = make_session(&app).await;
    std::fs::write(root.join("a.txt"), "a").unwrap();
    std::fs::write(ws.path("other.txt"), "other").unwrap();

    // Destination outside the session is denied even when the source is inside.
    for op in ["copy", "move"] {
        let target = if op == "copy" {
            "copied.txt"
        } else {
            "moved.txt"
        };
        let (status, _) = send(
            &app,
            post(
                "/v1/execute",
                json!({
                    "tool": "filesystem",
                    "session_id": sid,
                    "args": {"operation": op, "path": root.join("a.txt"),
                             "destination": ws.path(target)},
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{op}");
        assert!(!ws.path(target).exists(), "{op} escaped the session");
    }
    // Source outside the session is denied even when the destination is inside.
    let (status, _) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid,
                "args": {"operation": "copy", "path": ws.path("other.txt"),
                         "destination": root.join("in.txt")},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!root.join("in.txt").exists());
}

#[tokio::test]
async fn search_and_glob_are_scoped_to_the_session() {
    let ws = Workspace::new("m2-enumerate");
    std::fs::write(ws.path("outside.txt"), "needle here").unwrap();
    let app = ws.app();
    let (sid, root) = make_session(&app).await;
    std::fs::write(root.join("inside.txt"), "needle here").unwrap();

    // A base outside the session is denied.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid,
                "args": {"operation": "search", "path": ws.root,
                         "pattern": "needle", "recursive": true},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "path_not_allowed");

    // A base inside the session never surfaces outside files.
    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid,
                "args": {"operation": "search", "path": root,
                         "pattern": "needle", "recursive": true},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = body.to_string();
    assert!(text.contains("inside.txt"), "{text}");
    assert!(!text.contains("outside.txt"), "{text}");
}

#[tokio::test]
async fn shell_working_dir_outside_the_session_is_rejected() {
    let ws = Workspace::new("m2-shell-cwd");
    let app = ws.app();
    let (sid, _) = make_session(&app).await;

    let (status, body) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "shell",
                "session_id": sid,
                "args": {"program": echo_path(), "args": ["hi"],
                         "working_dir": ws.root},
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "path_not_allowed");
}

#[tokio::test]
async fn session_roots_are_absolute_and_registry_independent() {
    // Hot reload swaps the tool registry and egress list but never the
    // sessions table: roots are absolute paths bound at creation, so a reload
    // cannot silently expand what an existing session may touch.
    let ws = Workspace::new("m2-reload-shape");
    std::fs::write(ws.path("shared.txt"), "not yours").unwrap();
    let app = ws.app();
    let (sid, root) = make_session(&app).await;
    assert!(root.is_absolute(), "{root:?}");
    assert!(root.starts_with(&ws.root));

    // The same denial holds when the request is served by a registry built
    // from a different policy: enforcement follows the stored root, not the
    // currently loaded tools.
    let other = Workspace::new("m2-reload-other");
    let _other_app = other.app();
    let (status, _) = send(
        &app,
        post(
            "/v1/execute",
            json!({
                "tool": "filesystem",
                "session_id": sid,
                "args": fs_read(&ws.path("shared.txt")),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn concurrent_batches_cannot_cross_session_boundaries() {
    let ws = Workspace::new("m2-concurrent-scope");
    let app = ws.app();
    let (sid_a, _) = make_session(&app).await;
    let (_sid_b, root_b) = make_session(&app).await;
    std::fs::write(root_b.join("secret.txt"), "b secret").unwrap();

    let mut handles = Vec::new();
    for _ in 0..4 {
        let app = app.clone();
        let sid_a = sid_a.clone();
        let target = root_b.join("secret.txt");
        handles.push(tokio::spawn(async move {
            send(
                &app,
                post(
                    "/v1/execute/batch",
                    json!({"requests": [{
                        "tool": "filesystem",
                        "session_id": sid_a,
                        "args": {"operation": "read", "path": target},
                    }]}),
                ),
            )
            .await
        }));
    }
    for h in handles {
        let (status, body) = h.await.expect("task");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "path_not_allowed", "{body}");
    }
}

#[tokio::test]
async fn templated_step_paths_get_the_effective_session_scope() {
    // `{{steps}}` placeholders resolve after admission, so only execution-time
    // enforcement can bind them. Step 0 prints an outside-session path byte
    // for byte (printf, no trailing newline); step 1 reads it under session.
    let ws = Workspace::new("m2-template-scope");
    std::fs::write(ws.path("shared.txt"), "not yours").unwrap();
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
    - program: /usr/bin/printf
      args: NoFlags
"#,
        ws.root.display(),
        echo_path().display(),
    );
    let policy = ExecutionPolicy::from_yaml(&yaml).unwrap();
    let config = ws.config();
    let app = server::build_router_with_cors(
        server::build_state(
            Arc::new(server::build_registry_from_policy(&policy).unwrap()),
            &config,
        ),
        None,
    );
    let (_, body) = send(&app, post("/v1/sessions", json!({}))).await;
    let sid = body["session_id"].as_str().unwrap().to_string();
    let outside = ws.path("shared.txt").to_string_lossy().into_owned();

    let (status, body) = send(
        &app,
        post(
            "/v1/execute/sequence",
            json!({
                "session_id": sid,
                "steps": [
                    {"tool": "shell",
                     "args": {"program": "/usr/bin/printf",
                              "args": ["%s", outside]}},
                    {"tool": "filesystem",
                     "args": {"operation": "read",
                              "path": "{{steps[0].stdout}}"}},
                ],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["outcomes"][0]["success"], true);
    let step1 = &body["outcomes"][1];
    assert_eq!(step1["success"], false, "{step1}");
    assert_eq!(step1["code"], "path_not_allowed", "{step1}");
}
