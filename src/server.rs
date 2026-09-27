//! The `marshalld` HTTP service.
//!
//! A [`ToolRegistry`] behind an HTTP API, so callers in another process or
//! language get the same policy checks the library applies in-process. The
//! binary in `src/bin/marshalld.rs` is a CLI wrapper over [`serve`]; the module
//! lives in the library so the endpoints can be tested without a socket
//! (see `tests/server.rs`, which drives [`build_router`] through `tower`).
//!
//! ```sh
//! marshalld --config marshall.yaml --port 3000
//! curl http://localhost:3000/health
//! ```
//!
//! # Defaults worth knowing
//!
//! Binds loopback, refuses a non-loopback bind without `MARSHALLD_API_TOKEN`,
//! and sends no CORS headers unless `MARSHALLD_CORS_ORIGIN` names an origin.
//! Session workspaces live under [`ServerConfig::workspace_root`] and are swept
//! on a TTL.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{sse::Event, IntoResponse, Response, Sse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

use crate::ratelimit::{RateLimit, RateLimiter};
use crate::{
    destination as dest, EgressPolicy, ExecutionPolicy, FileSystemTool, HttpTool, Sandbox,
    ShellTool, ToolOutcome, ToolRegistry,
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Shared state behind every handler.
///
/// Public so tests can build a router directly; construct it with
/// [`build_state`] rather than by hand.
#[derive(Clone)]
pub struct AppState {
    registry: Arc<tokio::sync::RwLock<Arc<ToolRegistry>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    /// Concurrency cap (pool). `executor.sh` default ~32 per node.
    semaphore: Arc<Semaphore>,
    /// Audit log path (JSONL). If None, logs to tracing only.
    audit_path: Option<PathBuf>,
    /// workspace root for new sessions (tmpfs on Linux).
    workspace_root: PathBuf,
    metrics: Arc<Metrics>,
    audit_lock: Arc<Mutex<()>>,
    /// Egress allowlist from ExecutionPolicy (host file) — server-side enforcement.
    egress_hosts: Arc<Mutex<Vec<String>>>,
    /// Optional bearer token (`MARSHALLD_API_TOKEN`). If set, `/v1/*`
    /// requires `Authorization: Bearer <token>`.
    auth_token: Option<String>,
    /// Session TTL (`MARSHALLD_SESSION_TTL_SECS`, default 3600s).
    session_ttl: Duration,
    /// Per-client quota. `None` disables throttling.
    rate_limiter: Option<Arc<RateLimiter>>,
}

/// Default session TTL: 1h.
fn session_ttl_from_env() -> Duration {
    std::env::var("MARSHALLD_SESSION_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(3600))
}

fn auth_token_from_env() -> Option<String> {
    std::env::var("MARSHALLD_API_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The address to listen on.
///
/// Loopback by default. This used to be `0.0.0.0` unconditionally, so the
/// out-of-the-box daemon — which also does not require a token — was reachable
/// from the whole network, and a tool executor reachable without credentials is
/// a remote shell.
fn bind_addr(port: u16, bind_override: Option<&str>) -> anyhow::Result<SocketAddr> {
    let host = match bind_override {
        Some(h) => h.to_string(),
        None => std::env::var("MARSHALLD_BIND").unwrap_or_else(|_| "127.0.0.1".into()),
    };
    let ip: std::net::IpAddr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid bind address: {host}"))?;
    Ok(SocketAddr::new(ip, port))
}

/// Refuse to serve an unauthenticated executor on a non-loopback address.
///
/// A warning was not enough here: the failure mode is remote code execution,
/// and the warning scrolls past in a container log nobody reads.
fn check_bind_safety(addr: &SocketAddr, auth_token: &Option<String>) -> anyhow::Result<()> {
    if auth_token.is_some() || addr.ip().is_loopback() {
        return Ok(());
    }
    anyhow::bail!(
        "refusing to bind {addr} without authentication: set MARSHALLD_API_TOKEN, \
         or bind loopback (MARSHALLD_BIND=127.0.0.1) for local development"
    )
}

/// 401 response when the bearer token is missing/wrong. `None` = authorized.
fn check_auth(headers: &axum::http::HeaderMap, state: &AppState) -> Option<Response> {
    let expected = state.auth_token.as_ref()?;
    let got = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Constant-shape comparison to avoid leaking prefix length via timing.
    let ok = got.strip_prefix("Bearer ").is_some_and(|tok| {
        tok.len() == expected.len()
            && tok
                .bytes()
                .zip(expected.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    });
    if ok {
        None
    } else {
        Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".into(),
                    code: "unauthorized".into(),
                }),
            )
                .into_response(),
        )
    }
}

/// Identify the caller for quota purposes.
///
/// The bearer token when there is one, digested — bucket keys land in maps that
/// get logged and dumped, and a raw token there is a credential in a crash
/// report. Otherwise the peer address, so an unauthenticated deployment still
/// gets per-source limits. Callers with neither share one bucket, which is the
/// conservative reading of "we cannot tell these apart".
fn client_key(headers: &axum::http::HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(token) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        // 16 hex chars is plenty to separate clients and useless for recovering
        // the token.
        return format!("t:{}", &crate::sha256_hex(token.as_bytes())[..16]);
    }
    match peer {
        Some(addr) => format!("ip:{}", addr.ip()),
        None => "anonymous".to_string(),
    }
}

/// 429 response when the caller is over quota. `None` = within quota.
fn check_rate_limit(
    headers: &axum::http::HeaderMap,
    peer: Option<SocketAddr>,
    state: &AppState,
) -> Option<Response> {
    let limiter = state.rate_limiter.as_ref()?;
    let key = client_key(headers, peer);
    match limiter.check(&key) {
        Ok(()) => None,
        Err(throttled) => {
            warn!(client = %key, "rate limited");
            Some(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("retry-after", throttled.retry_after_secs.to_string())],
                    Json(ErrorResponse {
                        error: "rate limit exceeded".into(),
                        code: "rate_limited".into(),
                    }),
                )
                    .into_response(),
            )
        }
    }
}

#[derive(Debug)]
struct Metrics {
    requests_total: std::sync::atomic::AtomicU64,
    success_total: std::sync::atomic::AtomicU64,
    failure_total: std::sync::atomic::AtomicU64,
    duration_ms_sum: std::sync::atomic::AtomicU64,
    // Histogram buckets: 10, 50, 100, 500, 1000, 5000, +Inf ms
    buckets: [std::sync::atomic::AtomicU64; 7],
    per_tool: std::sync::Mutex<std::collections::HashMap<String, (u64, u64)>>, // tool -> (success, failure)
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests_total: std::sync::atomic::AtomicU64::new(0),
            success_total: std::sync::atomic::AtomicU64::new(0),
            failure_total: std::sync::atomic::AtomicU64::new(0),
            duration_ms_sum: std::sync::atomic::AtomicU64::new(0),
            buckets: [0, 0, 0, 0, 0, 0, 0].map(|_| std::sync::atomic::AtomicU64::new(0)),
            per_tool: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl Metrics {
    fn inc_request(&self) {
        self.requests_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    #[allow(dead_code)]
    fn observe(&self, success: bool, duration_ms: u64) {
        self.observe_with_tool("", success, duration_ms);
    }
    fn observe_with_tool(&self, tool: &str, success: bool, duration_ms: u64) {
        if success {
            self.success_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.failure_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.duration_ms_sum
            .fetch_add(duration_ms, std::sync::atomic::Ordering::Relaxed);
        let idx = match duration_ms {
            0..=10 => 0,
            11..=50 => 1,
            51..=100 => 2,
            101..=500 => 3,
            501..=1000 => 4,
            1001..=5000 => 5,
            _ => 6,
        };
        self.buckets[idx].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !tool.is_empty() {
            if let Ok(mut map) = self.per_tool.lock() {
                let entry = map.entry(tool.to_string()).or_insert((0, 0));
                if success {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
                }
            }
        }
    }
    fn exposition(&self) -> String {
        let r = self
            .requests_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let s = self
            .success_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let f = self
            .failure_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let d = self
            .duration_ms_sum
            .load(std::sync::atomic::Ordering::Relaxed);
        let b: Vec<u64> = self
            .buckets
            .iter()
            .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
            .collect();
        // Prometheus histogram buckets must be cumulative.
        let mut cum = 0u64;
        let mut cb = Vec::with_capacity(7);
        for &v in &b {
            cum += v;
            cb.push(cum);
        }
        let mut out = format!(
            "# HELP marshalld_requests_total Total execute requests\n# TYPE marshalld_requests_total counter\nmarshalld_requests_total {r}\n# HELP marshalld_success_total Successful tool outcomes\n# TYPE marshalld_success_total counter\nmarshalld_success_total {s}\n# HELP marshalld_failure_total Failed tool outcomes\n# TYPE marshalld_failure_total counter\nmarshalld_failure_total {f}\n# HELP marshalld_duration_ms_sum Sum of durations ms\n# TYPE marshalld_duration_ms_sum counter\nmarshalld_duration_ms_sum {d}\n# HELP marshalld_duration_ms_bucket Histogram\n# TYPE marshalld_duration_ms_bucket histogram\nmarshalld_duration_ms_bucket{{le=\"10\"}} {}\nmarshalld_duration_ms_bucket{{le=\"50\"}} {}\nmarshalld_duration_ms_bucket{{le=\"100\"}} {}\nmarshalld_duration_ms_bucket{{le=\"500\"}} {}\nmarshalld_duration_ms_bucket{{le=\"1000\"}} {}\nmarshalld_duration_ms_bucket{{le=\"5000\"}} {}\nmarshalld_duration_ms_bucket{{le=\"+Inf\"}} {}\nmarshalld_duration_ms_count {r}\nmarshalld_duration_ms_sum {d}\n",
            cb[0], cb[1], cb[2], cb[3], cb[4], cb[5], cb[6]
        );
        if let Ok(map) = self.per_tool.lock() {
            if !map.is_empty() {
                out.push_str("# HELP marshalld_tool_requests_total Per-tool requests\n# TYPE marshalld_tool_requests_total counter\n");
                for (tool, (succ, fail)) in map.iter() {
                    out.push_str(&format!("marshalld_tool_requests_total{{tool=\"{tool}\",status=\"success\"}} {succ}\n"));
                    out.push_str(&format!("marshalld_tool_requests_total{{tool=\"{tool}\",status=\"failure\"}} {fail}\n"));
                }
            }
        }
        out
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct Session {
    id: String,
    sandbox: Sandbox,
    root: PathBuf,
    created: Instant,
}

impl Session {
    fn is_expired(&self, ttl: Duration) -> bool {
        self.created.elapsed() > ttl
    }
}

/// Remove expired sessions + their workspace dirs. Returns count removed.
async fn purge_expired_sessions(state: &AppState) -> usize {
    let ttl = state.session_ttl;
    let mut sessions = state.sessions.lock().await;
    let expired: Vec<(String, PathBuf)> = sessions
        .iter()
        .filter(|(_, s)| s.is_expired(ttl))
        .map(|(id, s)| (id.clone(), s.root.clone()))
        .collect();
    let n = expired.len();
    for (id, root) in expired {
        sessions.remove(&id);
        let _ = std::fs::remove_dir_all(&root);
        info!(session_id = %id, "session expired");
    }
    n
}

fn spawn_session_sweeper(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            purge_expired_sessions(&state).await;
        }
    });
}

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ExecuteRequest {
    tool: String,
    args: serde_json::Value,
    /// Optional session id — if omitted, uses default workspace sandbox.
    session_id: Option<String>,
    /// Idempotency key for `execute_once`.
    idempotency_key: Option<String>,
}

#[derive(Serialize)]
struct ExecuteResponse {
    outcome: ToolOutcome,
}

#[derive(Deserialize)]
struct BatchRequest {
    requests: Vec<ExecuteRequest>,
    max_concurrency: Option<usize>,
    /// Optional session to scope all steps (validates paths inside session root)
    session_id: Option<String>,
}

#[derive(Serialize)]
struct BatchResponse {
    outcomes: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct SequenceRequest {
    steps: Vec<ExecuteRequest>,
    continue_on_error: Option<bool>,
    /// Optional session to scope all steps
    session_id: Option<String>,
}

#[derive(Serialize)]
struct SequenceResponse {
    outcomes: Vec<serde_json::Value>,
    executed: usize,
    total: usize,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct CreateSessionRequest {
    /// Optional label for audit.
    label: Option<String>,
}

#[derive(Serialize)]
struct CreateSessionResponse {
    session_id: String,
    root: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    tools: Vec<String>,
    sessions: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let sessions = state.sessions.lock().await.len();
    let registry = state.registry.read().await.clone();
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        tools: registry.tool_names(),
        sessions,
    })
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        state.metrics.exposition(),
    )
}

// `headers` is skipped deliberately: `tracing::instrument` records every
// un-skipped argument with `Debug`, and a `HeaderMap` Debug-prints
// `Authorization: Bearer <token>` in full. Every request was writing the
// caller's credential into the log at INFO.
#[tracing::instrument(skip(state, headers))]
async fn list_tools(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = check_auth(&headers, &state) {
        return resp;
    }
    if let Some(resp) = check_rate_limit(&headers, peer.map(|p| p.0), &state) {
        return resp;
    }
    let registry = state.registry.read().await.clone();
    Json(registry.definitions()).into_response()
}

async fn create_session(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(_req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    if let Some(resp) = check_auth(&headers, &state) {
        return resp;
    }
    if let Some(resp) = check_rate_limit(&headers, peer.map(|p| p.0), &state) {
        return resp;
    }
    let id = uuid::Uuid::new_v4().to_string();
    let root = state.workspace_root.join(&id);
    if let Err(e) = std::fs::create_dir_all(&root) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    let sandbox = match Sandbox::new([&root]) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let session = Session {
        id: id.clone(),
        sandbox: sandbox.clone(),
        root: root.clone(),
        created: Instant::now(),
    };

    // The global registry stays shared: session binding travels with each
    // request instead. Admission checks paths against the session sandbox,
    // the server injects the trusted session root into filesystem args, and
    // the tool enforces it at execution time (M2-002).

    state.sessions.lock().await.insert(id.clone(), session);

    info!(session_id = %id, root = %root.display(), "session created");

    (
        StatusCode::CREATED,
        Json(CreateSessionResponse {
            session_id: id,
            root: root.display().to_string(),
        }),
    )
        .into_response()
}

fn redacted_url(url: &str) -> String {
    dest::host_of(url).unwrap_or_else(|_| "invalid".into())
}

async fn egress_allowed_hosts(state: &AppState) -> Vec<String> {
    let policy_hosts = state.egress_hosts.lock().await.clone();
    if !policy_hosts.is_empty() {
        return policy_hosts;
    }
    std::env::var("MARSHALLD_ALLOWED_HOSTS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect()
}

/// Reserved filesystem arg carrying the trusted effective session root.
///
/// Lifecycle: stripped from every incoming execution request *before*
/// admission (a caller can never forge it), then re-injected from server-side
/// session state *after* admission for `filesystem` items that run under a
/// session. `FileSystemTool` requires every resolved path to stay inside this
/// root at execution time — which also covers `{{steps}}`-templated paths
/// that only resolve after admission, and any future registry caller that
/// skips HTTP admission.
pub const SESSION_SCOPE_KEY: &str = "__session_root";

fn path_not_allowed() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: "path_not_allowed: outside session".into(),
            code: "path_not_allowed".into(),
        }),
    )
        .into_response()
}

/// Remove a caller-supplied scope key, if any. The server is the sole source
/// of session roots; anything the caller sends is untrusted.
fn strip_scope_key(args: &mut serde_json::Value) {
    if let Some(obj) = args.as_object_mut() {
        obj.remove(SESSION_SCOPE_KEY);
    }
}

/// Canonical session-path check for one (`tool`, `args`) pair.
///
/// Every `path`/`destination` string — plus the shell `working_dir` — must
/// resolve inside the session sandbox. Resolution goes through the session's
/// own [`Sandbox`], so `..` segments and symlinks are judged on where they
/// *land*, not on how they are spelled (the previous lexical prefix check
/// admitted `<root>/../shared.txt`). Values containing `{{` are step-output
/// templates that only resolve at execution time; admission skips them and
/// the tool-level scope check enforces the resolved value instead.
fn check_session_path(sess: &Session, tool: &str, args: &serde_json::Value) -> Option<Response> {
    let mut keys = vec!["path", "destination"];
    if tool == "shell" {
        keys.push("working_dir");
    }
    for key in keys {
        let Some(p) = args.get(key).and_then(|v| v.as_str()) else {
            continue;
        };
        if p.contains("{{") {
            continue;
        }
        let denied = sess
            .sandbox
            .resolve_existing(p)
            .or_else(|_| sess.sandbox.resolve_for_create(p))
            .is_err();
        if denied {
            return Some(path_not_allowed());
        }
    }
    None
}

fn inject_session_id(requests: &mut [ExecuteRequest], top_sid: &Option<String>) {
    for r in requests.iter_mut() {
        // Per-step session_id takes precedence; fall back to top-level.
        let sid = r.session_id.as_ref().or(top_sid.as_ref());
        if let Some(sid) = sid {
            if matches!(r.tool.as_str(), "memory" | "todo" | "plan")
                && r.args.get("session_id").is_none()
            {
                if let Some(obj) = r.args.as_object_mut() {
                    obj.insert(
                        "session_id".to_string(),
                        serde_json::Value::String(sid.clone()),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unified admission
//
// Every execution endpoint — single, batch, sequence, stream — admits work
// through these helpers, in the same order: edge (auth, quota) → concurrency
// → session → egress. A denial returns before any tool runs, with the same
// status code and `code` value on every endpoint. For single, sequence and
// stream the concurrency step holds one workload permit for the execution;
// batch instead checks burst capacity up front (503 when none is free) and
// each item takes its own workload permit as it starts, so at most
// `concurrency` tools execute at once no matter how requests are shaped.
//
// What is recorded: a call that executes a tool (success or failure outcome)
// gets one audit record and one metrics observation. A call turned away at
// admission never executed anything, so it gets no audit record; only the
// concurrency shed is metered (it represents load the server refused).
// ---------------------------------------------------------------------------

/// 401/429 edge checks shared by every handler. `None` = admitted.
fn admit_edge(
    headers: &axum::http::HeaderMap,
    peer: Option<SocketAddr>,
    state: &AppState,
) -> Option<Response> {
    if let Some(resp) = check_auth(headers, state) {
        return Some(resp);
    }
    if let Some(resp) = check_rate_limit(headers, peer, state) {
        return Some(resp);
    }
    None
}

/// One concurrency permit per running workload.
///
/// Single, sequence and streaming requests hold exactly one permit while they
/// execute their (single, serial) workload, so each counts 1 against the cap.
/// Batch requests do not take a permit here at all: every batch item acquires
/// its own permit from the same semaphore as it starts executing (see the
/// registry), so the cap bounds concurrently *executing* workloads rather
/// than admitted HTTP requests. Items waiting for a permit hold nothing.
/// The caller meters the shed load to keep `concurrency_limited` visible on
/// every path.
///
/// `Response` is large (axum's body type), so this carries an allow rather
/// than a box: boxing would add indirection to every admitted request to
/// satisfy a lint about the denied ones.
#[allow(clippy::result_large_err)]
fn admit_concurrency(state: &AppState) -> Result<OwnedSemaphorePermit, Response> {
    match state.semaphore.clone().try_acquire_owned() {
        Ok(permit) => Ok(permit),
        Err(_) => {
            state.metrics.observe_with_tool("", false, 0);
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "too many concurrent executions".into(),
                    code: "concurrency_limited".into(),
                }),
            )
                .into_response())
        }
    }
}

fn session_not_found(sid: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: format!("session not found: {sid}"),
            code: "session_not_found".into(),
        }),
    )
        .into_response()
}

fn session_expired(sid: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: format!("session expired: {sid}"),
            code: "session_expired".into(),
        }),
    )
        .into_response()
}

/// Session admission for one (`session_id`, `tool`, `args`) item: purge,
/// lookup, expiry, then the canonical session-root path check. `None` admits
/// the call — including when no session was named, which keeps the
/// default-workspace behaviour of every endpoint.
async fn admit_session(
    state: &AppState,
    session_id: Option<&String>,
    tool: &str,
    args: &serde_json::Value,
) -> Option<Response> {
    let sid = session_id?;
    // Opportunistically drop expired sessions before lookup.
    purge_expired_sessions(state).await;
    let sessions = state.sessions.lock().await;
    match sessions.get(sid) {
        Some(sess) if sess.is_expired(state.session_ttl) => Some(session_expired(sid)),
        Some(sess) => check_session_path(sess, tool, args),
        None => Some(session_not_found(sid)),
    }
}

/// Trusted canonical root for a live session, for tool-level scope binding.
///
/// Returns `None` for expired or unknown sessions (fail closed at injection
/// time, even if the session lapsed between admission and execution).
async fn session_scope_root(state: &AppState, session_id: &str) -> Option<PathBuf> {
    purge_expired_sessions(state).await;
    let sessions = state.sessions.lock().await;
    let sess = sessions.get(session_id)?;
    if sess.is_expired(state.session_ttl) {
        return None;
    }
    sess.sandbox.roots().first().cloned()
}

/// Existence-only session check, for top-level session requirements: the
/// session must name a live session, while per-item paths are scoped to each
/// item's effective session (see `effective_session`).
async fn require_session(state: &AppState, session_id: &str) -> Option<Response> {
    purge_expired_sessions(state).await;
    let sessions = state.sessions.lock().await;
    match sessions.get(session_id) {
        Some(sess) if sess.is_expired(state.session_ttl) => Some(session_expired(session_id)),
        Some(_) => None,
        None => Some(session_not_found(session_id)),
    }
}

fn destination_forbidden(e: impl std::fmt::Display) -> Response {
    let code = e.to_string();
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: code.clone(),
            code,
        }),
    )
        .into_response()
}

fn allowlist_forbidden(code: String) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: code.clone(),
            code,
        }),
    )
        .into_response()
}

/// Egress admission for one (`tool`, `args`) pair: the destination check runs
/// first (it blocks metadata/private addresses regardless of the allowlist),
/// then the configured host allowlist. Non-HTTP tools, and HTTP calls without
/// a `url` string, pass here — the tool validates its own arguments next.
async fn admit_egress(state: &AppState, tool: &str, args: &serde_json::Value) -> Option<Response> {
    if tool != "http" {
        return None;
    }
    let url = match args.get("url").and_then(|v| v.as_str()) {
        Some(url) => url,
        None => return None,
    };
    // Always validate destination (blocks 169.254.169.254, private ranges etc.)
    if let Err(e) = dest::validate_destination(url) {
        warn!(error = %e, url = %redacted_url(url), "egress blocked (destination)");
        return Some(destination_forbidden(e));
    }
    // If allowlist configured via policy file or env, enforce it server-side
    // (not just HttpTool).
    let allowed = egress_allowed_hosts(state).await;
    if !allowed.is_empty() {
        let egress = EgressPolicy::new(allowed);
        if let Err(err) = egress.check(url) {
            warn!(error = %err.code, url = %err.url_redacted, "egress blocked (allowlist)");
            return Some(allowlist_forbidden(err.code));
        }
    }
    None
}

/// Session + egress admission for one item, in the order `execute` applies
/// them. Batch and sequence resolve each item's effective session first and
/// then call the two halves per item; `execute` and `execute_stream` call
/// this directly so a streamed call can never skip what a single call checks.
async fn admit_item(
    state: &AppState,
    session_id: Option<&String>,
    tool: &str,
    args: &serde_json::Value,
) -> Option<Response> {
    if let Some(resp) = admit_session(state, session_id, tool, args).await {
        return Some(resp);
    }
    if let Some(resp) = admit_egress(state, tool, args).await {
        return Some(resp);
    }
    None
}

/// Effective session for one batch/sequence item: a per-item override wins
/// for that item, otherwise the top-level session applies, otherwise the
/// request runs workspace-scoped. The contract is identical on batch and
/// sequence: paths are always checked against the *effective* session.
fn effective_session<'a>(
    top_sid: Option<&'a String>,
    item_sid: Option<&'a String>,
) -> Option<&'a String> {
    item_sid.or(top_sid)
}

/// Bind a filesystem item's args to its effective session root.
///
/// Looks the session up again from server-side state (fail closed when it
/// lapsed) and writes the canonical root under [`SESSION_SCOPE_KEY`], which
/// the tool enforces at execution time. Non-filesystem tools and
/// session-less items are left untouched.
async fn bind_session_scope(
    state: &AppState,
    session_id: Option<&String>,
    tool: &str,
    args: &mut serde_json::Value,
) -> Option<Response> {
    if tool != "filesystem" {
        return None;
    }
    let sid = session_id?;
    match session_scope_root(state, sid).await {
        Some(root) => {
            if let Some(obj) = args.as_object_mut() {
                obj.insert(
                    SESSION_SCOPE_KEY.to_string(),
                    serde_json::Value::String(root.display().to_string()),
                );
            }
            None
        }
        None => Some(session_not_found(sid)),
    }
}

// `headers` skipped: see `list_tools`. It carries the bearer token.
#[tracing::instrument(skip(state, req, headers), fields(tool = %req.tool))]
async fn execute(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(mut req): Json<ExecuteRequest>,
) -> Response {
    if let Some(resp) = admit_edge(&headers, peer.map(|p| p.0), &state) {
        return resp;
    }
    state.metrics.inc_request();
    // Concurrency guard — 503 if at cap (pool).
    let _permit = match admit_concurrency(&state) {
        Ok(permit) => permit,
        Err(resp) => return resp,
    };

    // A caller-supplied scope root is untrusted: drop it before admission.
    strip_scope_key(&mut req.args);
    // Session validation: if session_id given, ensure it exists and paths are inside it.
    // Egress proxy — server-side SSRF enforcement (defense-in-depth).
    if let Some(resp) = admit_item(&state, req.session_id.as_ref(), &req.tool, &req.args).await {
        return resp;
    }
    // Bind filesystem execution to the trusted session root (no-op without
    // a session). The tool enforces this at execution time, after any
    // template resolution admission cannot see.
    if let Some(resp) =
        bind_session_scope(&state, req.session_id.as_ref(), &req.tool, &mut req.args).await
    {
        return resp;
    }

    let started = Instant::now();
    let registry = state.registry.read().await.clone();
    let outcome = if let Some(key) = req.idempotency_key {
        match registry.execute_once(&key, &req.tool, req.args).await {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, tool = %req.tool, "execute_once rejected");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: extract_code(&e.to_string()),
                    }),
                )
                    .into_response();
            }
        }
    } else {
        match registry.execute(&req.tool, req.args).await {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, tool = %req.tool, "execute rejected");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: extract_code(&e.to_string()),
                    }),
                )
                    .into_response();
            }
        }
    };

    // Audit: JSONL with sha256 (P0 redaction intact).
    audit_log(&state, &outcome, started.elapsed().as_millis() as u64).await;

    // Metrics + OTel
    state
        .metrics
        .observe_with_tool(&outcome.tool, outcome.success, outcome.duration_ms);
    info!(
        tool = %outcome.tool,
        success = outcome.success,
        duration_ms = outcome.duration_ms,
        error_code = ?outcome.error_code,
        "tool executed via http"
    );

    (StatusCode::OK, Json(ExecuteResponse { outcome })).into_response()
}

async fn execute_batch(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(mut req): Json<BatchRequest>,
) -> Response {
    if let Some(resp) = admit_edge(&headers, peer.map(|p| p.0), &state) {
        return resp;
    }
    purge_expired_sessions(&state).await;
    // Auto-scope agentic state to top-level session
    inject_session_id(&mut req.requests, &req.session_id);
    // A caller-supplied scope root is untrusted: drop it before admission.
    // The trusted root is bound per item after admission instead.
    for r in &mut req.requests {
        strip_scope_key(&mut r.args);
    }
    // Admission control: limit batch size and concurrency to avoid OOM / fan-out.
    const MAX_BATCH: usize = 64;
    if req.requests.len() > MAX_BATCH {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("batch too large: {} > {MAX_BATCH}", req.requests.len()),
                code: "batch_too_large".into(),
            }),
        )
            .into_response();
    }
    // Workload admission: every batch item acquires its own permit from the
    // global semaphore as it starts executing (see `execute_batch` in the
    // registry), so running workloads — not admitted requests — are what the
    // `concurrency` cap bounds. Holding one request-level permit here while
    // items wait for workload permits would deadlock at `concurrency: 1`
    // (the permit the items need is the one the handler holds), so the
    // handler holds no permit across fan-out. Instead this fail-fast burst
    // gate sheds the request when no workload capacity is currently free;
    // admitted items then queue on the semaphore holding nothing.
    // Queued items hold no permits; each running item holds exactly one.
    let max = req.max_concurrency.unwrap_or(8).clamp(1, 32);
    if state.semaphore.available_permits() == 0 {
        state.metrics.observe_with_tool("", false, 0);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "too many concurrent executions".into(),
                code: "concurrency_limited".into(),
            }),
        )
            .into_response();
    }
    // Session validation per item against its effective session (per-item
    // override wins, else the top-level session), then per-item egress. A
    // top-level session must still exist even for an empty batch: an unknown
    // session is a 404 before any item runs. The helpers hold the sessions
    // lock only for one lookup each, so admission here cannot deadlock
    // against itself.
    let top_sid = req.session_id.clone();
    if let Some(sid) = &top_sid {
        if let Some(resp) = require_session(&state, sid).await {
            return resp;
        }
    }
    for r in &req.requests {
        let effective = effective_session(top_sid.as_ref(), r.session_id.as_ref());
        if let Some(resp) = admit_session(&state, effective, &r.tool, &r.args).await {
            return resp;
        }
        if let Some(resp) = admit_egress(&state, &r.tool, &r.args).await {
            return resp;
        }
    }
    // Bind every filesystem item to its effective session root. A session
    // that lapsed between admission and binding fails closed here.
    for r in &mut req.requests {
        let effective = effective_session(top_sid.as_ref(), r.session_id.as_ref());
        if let Some(resp) = bind_session_scope(&state, effective, &r.tool, &mut r.args).await {
            return resp;
        }
    }
    let inner: Vec<(String, serde_json::Value)> =
        req.requests.into_iter().map(|r| (r.tool, r.args)).collect();
    state.metrics.inc_request();
    let registry = state.registry.read().await.clone();
    // Workload permits come from the shared global semaphore: at most
    // `concurrency` items execute at once across all requests. Dropping this
    // future (client disconnect) aborts queued/running items via the
    // registry's abort-on-drop set; permits release through RAII.
    let results = registry.execute_batch(inner, max, &state.semaphore).await;
    let mut outcomes: Vec<serde_json::Value> = Vec::with_capacity(results.len());
    for r in results {
        match r {
            Ok(o) => {
                // One audit record per executed item, as in `execute`.
                audit_log(&state, &o, o.duration_ms).await;
                let tool = o.tool.clone();
                state
                    .metrics
                    .observe_with_tool(&tool, o.success, o.duration_ms);
                outcomes.push(
                    serde_json::to_value(o).unwrap_or(serde_json::json!({"error":"serialize"})),
                );
            }
            Err(e) => {
                state.metrics.observe_with_tool("", false, 0);
                outcomes.push(serde_json::json!({"error": e.to_string(), "code": extract_code(&e.to_string())}));
            }
        }
    }
    (StatusCode::OK, Json(BatchResponse { outcomes })).into_response()
}

async fn execute_sequence(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(mut req): Json<SequenceRequest>,
) -> Response {
    if let Some(resp) = admit_edge(&headers, peer.map(|p| p.0), &state) {
        return resp;
    }
    purge_expired_sessions(&state).await;
    // Auto-scope agentic state to top-level session
    inject_session_id(&mut req.steps, &req.session_id);
    // A caller-supplied scope root is untrusted: drop it before admission.
    for r in &mut req.steps {
        strip_scope_key(&mut r.args);
    }
    const MAX_STEPS: usize = 32;
    if req.steps.len() > MAX_STEPS {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("sequence too large: {} > {MAX_STEPS}", req.steps.len()),
                code: "sequence_too_large".into(),
            }),
        )
            .into_response();
    }
    let _permit = match admit_concurrency(&state) {
        Ok(permit) => permit,
        Err(resp) => return resp,
    };
    // Session validation mirrors the batch contract: every step is admitted
    // against its effective session (per-step override wins, else the
    // top-level session), and a top-level session must exist even for an
    // empty sequence. Egress is admitted per step afterwards, before anything
    // runs.
    if let Some(sid) = &req.session_id {
        if let Some(resp) = require_session(&state, sid).await {
            return resp;
        }
    }
    let top_sid = req.session_id.clone();
    for r in &req.steps {
        let effective = effective_session(top_sid.as_ref(), r.session_id.as_ref());
        if let Some(resp) = admit_session(&state, effective, &r.tool, &r.args).await {
            return resp;
        }
    }
    // Egress check for each step if http
    for r in &req.steps {
        if let Some(resp) = admit_egress(&state, &r.tool, &r.args).await {
            return resp;
        }
    }
    // Bind every filesystem step to its effective session root, as in batch.
    for r in &mut req.steps {
        let effective = effective_session(top_sid.as_ref(), r.session_id.as_ref());
        if let Some(resp) = bind_session_scope(&state, effective, &r.tool, &mut r.args).await {
            return resp;
        }
    }
    let continue_on_error = req.continue_on_error.unwrap_or(false);
    let total = req.steps.len();
    let inner: Vec<(String, serde_json::Value)> =
        req.steps.into_iter().map(|r| (r.tool, r.args)).collect();
    state.metrics.inc_request();
    let registry = state.registry.read().await.clone();
    let results = registry.execute_sequence(inner, continue_on_error).await;
    let executed = results.len();
    let mut outcomes: Vec<serde_json::Value> = Vec::with_capacity(results.len());
    for r in results {
        match r {
            Ok(o) => {
                // One audit record per executed step, as in `execute`.
                audit_log(&state, &o, o.duration_ms).await;
                let tool = o.tool.clone();
                state
                    .metrics
                    .observe_with_tool(&tool, o.success, o.duration_ms);
                outcomes.push(
                    serde_json::to_value(o).unwrap_or(serde_json::json!({"error":"serialize"})),
                );
            }
            Err(e) => {
                state.metrics.observe_with_tool("", false, 0);
                outcomes.push(serde_json::json!({"error": e.to_string(), "code": extract_code(&e.to_string()), "success": false}));
            }
        }
    }
    (
        StatusCode::OK,
        Json(SequenceResponse {
            outcomes,
            executed,
            total,
        }),
    )
        .into_response()
}

/// SSE streaming — uniform SSE for all tools (shell chunks, others single outcome).
/// Non-shell tools emit `summary` then `done` so SDKs can always parse SSE.
///
/// Admission is identical to [`execute`]: edge, concurrency, session, egress.
/// An `idempotency_key` is honored exactly as in `execute` — the same key on
/// the same call replays the cached success instead of running the tool
/// again. Executed outcomes are audited and metered like `execute`; a call
/// the registry rejects becomes an SSE `error` event, mirroring the 400
/// `execute` would return for the same call.
async fn execute_stream(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(mut req): Json<ExecuteRequest>,
) -> Response {
    if let Some(resp) = admit_edge(&headers, peer.map(|p| p.0), &state) {
        return resp;
    }
    state.metrics.inc_request();
    let _permit = match admit_concurrency(&state) {
        Ok(permit) => permit,
        Err(resp) => return resp,
    };
    // A caller-supplied scope root is untrusted: drop it before admission.
    strip_scope_key(&mut req.args);
    // Same session + egress admission as `execute`: a streamed call can never
    // skip what a single call checks.
    if let Some(resp) = admit_item(&state, req.session_id.as_ref(), &req.tool, &req.args).await {
        return resp;
    }
    // Bind filesystem execution to the trusted session root, as in `execute`.
    if let Some(resp) =
        bind_session_scope(&state, req.session_id.as_ref(), &req.tool, &mut req.args).await
    {
        return resp;
    }

    let started = Instant::now();
    let registry = state.registry.read().await.clone();
    let outcome = if let Some(key) = req.idempotency_key {
        match registry.execute_once(&key, &req.tool, req.args).await {
            Ok(o) => o,
            Err(e) => {
                let err_event = Event::default()
                    .event("error")
                    .data(serde_json::json!({"error": e.to_string()}).to_string());
                let stream = tokio_stream::once(Ok::<_, std::convert::Infallible>(err_event));
                return Sse::new(stream).into_response();
            }
        }
    } else {
        match registry.execute(&req.tool, req.args).await {
            Ok(o) => o,
            Err(e) => {
                let err_event = Event::default()
                    .event("error")
                    .data(serde_json::json!({"error": e.to_string()}).to_string());
                let stream = tokio_stream::once(Ok::<_, std::convert::Infallible>(err_event));
                return Sse::new(stream).into_response();
            }
        }
    };

    // Audit + metrics exactly as `execute`: one record per executed tool.
    audit_log(&state, &outcome, started.elapsed().as_millis() as u64).await;
    state
        .metrics
        .observe_with_tool(&outcome.tool, outcome.success, outcome.duration_ms);

    let (tx, rx) = tokio::sync::mpsc::channel(16);

    // Spawn chunk emission.
    tokio::spawn(async move {
        // Summary event.
        let summary = Event::default()
            .event("summary")
            .data(serde_json::to_string(&outcome.summary).unwrap_or_default());
        let _ = tx.send(Ok::<_, std::convert::Infallible>(summary)).await;

        // Content chunks (cap 64k per SSE event to avoid large frames).
        if let Some(content) = outcome.content {
            for chunk in content.chunks(64 * 1024) {
                let data = serde_json::json!({
                    "bytes": chunk.len(),
                    "sha256": crate::sha256_hex(chunk),
                    "chunk_b64": base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD, chunk
                    ),
                });
                let ev = Event::default().event("chunk").data(data.to_string());
                if tx.send(Ok(ev)).await.is_err() {
                    break;
                }
            }
        }

        let done = Event::default().event("done").data(
            serde_json::json!({
                "success": outcome.success,
                "error_code": outcome.error_code,
                "duration_ms": outcome.duration_ms
            })
            .to_string(),
        );
        let _ = tx.send(Ok(done)).await;
    });

    Sse::new(ReceiverStream::new(rx)).into_response()
}

async fn delete_session(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    if let Some(resp) = check_auth(&headers, &state) {
        return resp;
    }
    if let Some(resp) = check_rate_limit(&headers, peer.map(|p| p.0), &state) {
        return resp;
    }
    let mut sessions = state.sessions.lock().await;
    if let Some(sess) = sessions.remove(&id) {
        let _ = std::fs::remove_dir_all(&sess.root);
        info!(session_id = %id, "session deleted");
        // 204 must not carry a body (RFC 9110 §15.3.5); this used to send `{}`.
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("session not found: {id}"),
                code: "session_not_found".into(),
            }),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_code(msg: &str) -> String {
    // Policy errors are `code` strings like `path_not_allowed` — first token.
    msg.split(':').next().unwrap_or(msg).trim().to_string()
}

async fn audit_log(state: &AppState, outcome: &ToolOutcome, _elapsed: u64) {
    let entry = serde_json::json!({
        "ts": chrono_like_now(),
        "tool": outcome.tool,
        "success": outcome.success,
        "error_code": outcome.error_code,
        "duration_ms": outcome.duration_ms,
        "summary": outcome.summary,
        "content_sha256": outcome.content.as_ref().map(|b| crate::sha256_hex(b)),
        "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
    });
    let line = serde_json::to_string(&entry).unwrap_or_default();
    tracing::info!(audit = %line, "audit");

    if let Some(path) = &state.audit_path {
        let path = path.clone();
        let lock = state.audit_lock.clone();
        let _guard = lock.lock().await;
        let line_clone = line.clone();
        let _ = tokio::task::spawn_blocking(move || {
            use std::io::Write;
            // Rotate if >10MiB: audit.jsonl -> audit.jsonl.1, serialized via audit_lock.
            if let Ok(meta) = std::fs::metadata(&path) {
                if meta.len() > 10 * 1024 * 1024 {
                    let rotated = path.with_extension("jsonl.1");
                    let _ = std::fs::rename(&path, &rotated);
                }
            }
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = writeln!(f, "{line_clone}");
            }
        })
        .await;
    }
}

fn chrono_like_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// A registry from default policy rooted at `workspace`.
pub fn build_registry(workspace: &Path) -> anyhow::Result<ToolRegistry> {
    build_registry_from_policy(&ExecutionPolicy {
        workspace: workspace.to_path_buf(),
        ..Default::default()
    })
}

/// Build a registry from a policy file.
///
/// Every allowlist is read strictly: an empty list means the tool is not
/// registered. See [`crate::policy::CodePolicy`] for why `code` needs a second
/// opt-in beyond naming a language.
pub fn build_registry_from_policy(policy: &ExecutionPolicy) -> anyhow::Result<ToolRegistry> {
    let sandbox = policy.sandbox()?;
    let mut registry = ToolRegistry::new();

    // Filesystem
    let mut fs = FileSystemTool::new(sandbox.clone());
    if policy.filesystem.writable {
        fs = fs.writable();
    }
    fs = fs.with_read_limit(policy.filesystem.read_limit);
    registry.register(std::sync::Arc::new(fs));

    // Shell — strictly from policy. An empty allowlist used to be topped up
    // with `echo`/`cat` "for the demo", which meant a config that granted no
    // commands silently granted two.
    let commands = policy.allowed_commands();
    if commands.is_empty() {
        info!("shell.commands is empty: shell tool not registered");
    } else {
        let mut shell = ShellTool::new(commands)
            .with_working_dirs(sandbox.clone())
            .with_timeout(policy.shell_timeout())
            .with_output_limit(policy.shell.output_limit);
        if let Some(env) = &policy.shell.allowed_env {
            shell = shell.with_allowed_env(env.clone());
        }
        registry.register(std::sync::Arc::new(shell));
    }

    // HTTP + egress proxy (server-side allowlist)
    let egress = EgressPolicy::new(policy.http.allowed_hosts.clone());
    // egress is checked again in `execute` handler for defense-in-depth
    let http = HttpTool::new(policy.http.allowed_hosts.clone())
        .with_timeout(policy.http_timeout())
        .with_body_limit(policy.http.response_body_limit)
        .with_request_body_limit(policy.http.request_body_limit);
    let _ = egress; // kept for middleware use; HttpTool already validates
    registry.register(std::sync::Arc::new(http));

    // Agentic meta-tools — think/memory/todo/plan/reflect (no sandbox, pure planning)
    {
        use crate::{MemoryTool, PlanTool, ReflectTool, ThinkTool, TodoTool};
        registry.register(std::sync::Arc::new(ThinkTool));
        registry.register(std::sync::Arc::new(MemoryTool::new()));
        registry.register(std::sync::Arc::new(TodoTool::new()));
        registry.register(std::sync::Arc::new(PlanTool::new()));
        registry.register(std::sync::Arc::new(ReflectTool));
    }

    // Code execution — registered only when the policy names languages *and*
    // acknowledges that the local backend is unsandboxed (`ExecutionPolicy::
    // validate` enforces the second half). An empty list used to mean
    // `allow_all()`, so the deny-by-default config was the permissive one.
    if policy.code_enabled() {
        use crate::CodeTool;
        let mut code_tool = CodeTool::new()
            .with_sandbox(sandbox.clone())
            .with_timeout(policy.code_timeout())
            .with_output_limit(policy.code.output_limit);
        for lang in policy.code_languages() {
            code_tool = code_tool.allow_language(lang);
        }
        // Inherit env allowlist if specified for shell
        if let Some(env) = &policy.shell.allowed_env {
            code_tool = code_tool.with_allowed_env(env.clone());
        }
        warn!(
            languages = ?policy.code.allowed_languages,
            "code tool enabled on the local backend: snippets are not isolated \
             and bypass filesystem and http policy"
        );
        registry.register(std::sync::Arc::new(code_tool));
    } else {
        info!("code.allowed_languages is empty: code tool not registered");
    }

    // System facts + bounded process control (deny-by-default policy)
    {
        registry.register(std::sync::Arc::new(policy.system_tool()));
    }

    Ok(registry)
}
/// How to run the service.
///
/// Everything the daemon needs that is not already in the [`ToolRegistry`].
/// The registry carries the policy; this carries the deployment.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Where session workspaces are created.
    pub workspace_root: PathBuf,
    /// JSONL audit log. `None` logs through `tracing` only.
    pub audit_path: Option<PathBuf>,
    /// Global cap on concurrently executing workloads (tool executions).
    /// Single, sequence and streaming requests each run one workload per
    /// permit; batch items each take their own permit as they start, so this
    /// bounds running tools across all requests, not admitted HTTP requests.
    pub concurrency: usize,
    /// Listen port.
    pub port: u16,
    /// Listen address. `None` reads `MARSHALLD_BIND`, defaulting to loopback.
    pub bind: Option<String>,
    /// Policy file to watch for hot reload.
    pub config_path: Option<PathBuf>,
    /// Server-side egress allowlist, enforced independently of `HttpTool`.
    pub egress_hosts: Vec<String>,
    /// Bearer token for `/v1/*`. `None` reads `MARSHALLD_API_TOKEN`.
    pub auth_token: Option<String>,
    /// Session lifetime. `None` reads `MARSHALLD_SESSION_TTL_SECS`.
    pub session_ttl: Option<Duration>,
    /// Per-client quota. `None` disables throttling, leaving only the global
    /// concurrency cap — which bounds running workloads to protect the host
    /// but not the other callers' share. Quota is charged per HTTP request,
    /// not per executed item (see `RateLimitPolicy`).
    pub rate_limit: Option<RateLimit>,
}

impl ServerConfig {
    /// Defaults: loopback, port 3000, concurrency 32, no audit file.
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        ServerConfig {
            workspace_root: workspace_root.into(),
            audit_path: None,
            concurrency: 32,
            port: 3000,
            bind: None,
            config_path: None,
            egress_hosts: Vec::new(),
            auth_token: None,
            session_ttl: None,
            rate_limit: None,
        }
    }
}

/// Assemble the shared state a router needs.
///
/// Split out from [`serve`] so tests can build a router without binding a
/// socket. `auth_token` and `session_ttl` fall back to the environment when the
/// config leaves them unset, which is what the CLI relies on.
pub fn build_state(registry: Arc<ToolRegistry>, config: &ServerConfig) -> AppState {
    AppState {
        registry: Arc::new(tokio::sync::RwLock::new(registry)),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        semaphore: Arc::new(Semaphore::new(config.concurrency)),
        audit_path: config.audit_path.clone(),
        workspace_root: config.workspace_root.clone(),
        metrics: Arc::new(Metrics::default()),
        audit_lock: Arc::new(Mutex::new(())),
        egress_hosts: Arc::new(Mutex::new(config.egress_hosts.clone())),
        auth_token: config.auth_token.clone().or_else(auth_token_from_env),
        session_ttl: config.session_ttl.unwrap_or_else(session_ttl_from_env),
        rate_limiter: config
            .rate_limit
            .map(|limit| Arc::new(RateLimiter::new(limit))),
    }
}

/// Bind and serve until the process is stopped.
pub async fn serve(registry: Arc<ToolRegistry>, config: ServerConfig) -> anyhow::Result<()> {
    let mut config = config;
    // Egress hosts default to whatever the watched policy file allows.
    if config.egress_hosts.is_empty() {
        if let Some(cfg) = &config.config_path {
            config.egress_hosts = ExecutionPolicy::from_file(cfg)
                .map(|p| p.http.allowed_hosts)
                .unwrap_or_default();
        }
    }
    let config_path = config.config_path.clone();
    let state = build_state(registry, &config);

    let addr = bind_addr(config.port, config.bind.as_deref())?;
    check_bind_safety(&addr, &state.auth_token)?;
    if state.auth_token.is_none() {
        warn!("MARSHALLD_API_TOKEN not set: /v1/* is unauthenticated (loopback only)");
    }
    spawn_session_sweeper(state.clone());

    // Hot reload: watch config file and swap registry atomically, including egress hosts.
    if let Some(cfg) = config_path.clone() {
        let registry_ref = state.registry.clone();
        let hosts_ref = state.egress_hosts.clone();
        tokio::spawn(async move {
            use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
            let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
            let tx_clone = tx.clone();
            let cfg_clone = cfg.clone();
            let mut watcher: RecommendedWatcher = match RecommendedWatcher::new(
                move |res: notify::Result<notify::Event>| {
                    if let Ok(ev) = res {
                        if ev.kind.is_modify() {
                            let _ = tx_clone.blocking_send(());
                        }
                    }
                },
                NotifyConfig::default(),
            ) {
                Ok(w) => w,
                Err(e) => {
                    warn!(error = %e, "notify watcher failed");
                    return;
                }
            };
            let _ = watcher.watch(&cfg_clone, RecursiveMode::NonRecursive);
            // Keep watcher alive
            let _watcher = watcher;
            while rx.recv().await.is_some() {
                // Debounce
                tokio::time::sleep(Duration::from_millis(300)).await;
                while rx.try_recv().is_ok() {}
                match ExecutionPolicy::from_file(&cfg) {
                    Ok(pol) => match build_registry_from_policy(&pol) {
                        Ok(new_reg) => {
                            *registry_ref.write().await = Arc::new(new_reg);
                            *hosts_ref.lock().await = pol.http.allowed_hosts.clone();
                            info!(config = %cfg.display(), "hot-reloaded marshall.yaml");
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to rebuild registry from reloaded policy")
                        }
                    },
                    Err(e) => warn!(error = %e, config = %cfg.display(), "failed to reload policy"),
                }
            }
        });
    }

    let cors = build_cors()?;
    let app = build_router_with_cors(state, cors);

    info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // `into_make_service_with_connect_info` is what makes the peer address
    // available to handlers; without it every unauthenticated caller shares one
    // rate-limit bucket.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Build the CORS layer, if any.
///
/// Unset means *no* CORS layer: same-origin only. This used to default to
/// `AllowOrigin::any()`, which let any web page in the user's browser drive
/// the executor — and since the browser attaches no bearer token, an
/// unauthenticated daemon on localhost was reachable from any tab.
///
/// An invalid `MARSHALLD_CORS_ORIGIN` is a hard error rather than a silent
/// downgrade to `any()`, which is what it used to do.
fn build_cors() -> anyhow::Result<Option<tower_http::cors::CorsLayer>> {
    let origin = match std::env::var("MARSHALLD_CORS_ORIGIN") {
        Ok(o) if !o.trim().is_empty() => o,
        _ => return Ok(None),
    };
    let value = origin
        .parse::<axum::http::HeaderValue>()
        .map_err(|_| anyhow::anyhow!("MARSHALLD_CORS_ORIGIN is not a valid origin: {origin}"))?;
    Ok(Some(
        tower_http::cors::CorsLayer::new()
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::DELETE,
            ])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
            ])
            .allow_origin(tower_http::cors::AllowOrigin::exact(value)),
    ))
}

/// The full router, with CORS read from the environment.
pub fn build_router(state: AppState) -> Router {
    build_router_with_cors(state, build_cors().unwrap_or(None))
}

/// The router with an explicit CORS layer. Tests use this to pin behaviour
/// that would otherwise depend on `MARSHALLD_CORS_ORIGIN`.
pub fn build_router_with_cors(
    state: AppState,
    cors: Option<tower_http::cors::CorsLayer>,
) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/tools", get(list_tools))
        .route("/v1/sessions", post(create_session))
        .route("/v1/sessions/:id", axum::routing::delete(delete_session))
        .route("/v1/execute", post(execute))
        .route("/v1/execute/batch", post(execute_batch))
        .route("/v1/execute/sequence", post(execute_sequence))
        .route("/v1/execute/stream", post(execute_stream))
        .route("/v1/policy", get(get_policy))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());
    match cors {
        Some(layer) => router.layer(layer),
        None => router,
    }
}

async fn get_policy(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = check_auth(&headers, &state) {
        return resp;
    }
    if let Some(resp) = check_rate_limit(&headers, peer.map(|p| p.0), &state) {
        return resp;
    }
    // Return current marshall.yaml if present, else defaults.
    let path = PathBuf::from("marshall.yaml");
    if path.exists() {
        if let Ok(s) = std::fs::read_to_string(&path) {
            return (StatusCode::OK, s).into_response();
        }
    }
    (
        StatusCode::OK,
        serde_yaml::to_string(&ExecutionPolicy::default()).unwrap_or_default(),
    )
        .into_response()
}
