//! `marshalld` — CLI wrapper over [`marshall::server`].
//!
//! Everything interesting lives in the library so it can be tested without a
//! socket. This file parses arguments, sets up tracing, and hands off to
//! [`marshall::server::serve`].
//!
//! ```sh
//! marshalld --config marshall.yaml --port 3000
//! marshalld --validate-config ./marshall.yaml
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use marshall::server::{self, ServerConfig};
use marshall::{ExecutionPolicy, Limits};
use tracing::info;

const HELP: &str = "\
marshalld -- policy-checked tool execution over HTTP

Usage: marshalld [--port 3000] [--bind 127.0.0.1] [--workspace /tmp/marshalld]
                 [--audit-log audit.jsonl] [--concurrency 32]
                 [--config marshall.yaml] [--validate-config <path>]
                 [--healthcheck]

Env:
  PORT, MARSHALLD_PORT        listen port (default 3000)
  MARSHALLD_BIND              listen address (default 127.0.0.1)
  MARSHALLD_API_TOKEN         bearer token for /v1/*; required for non-loopback binds
  MARSHALLD_CORS_ORIGIN       exact allowed origin; unset means same-origin only
  MARSHALLD_SESSION_TTL_SECS  session lifetime in seconds (default 3600)
  MARSHALLD_ALLOWED_HOSTS     comma-separated egress allowlist
  RUST_LOG, MARSHALLD_JSON_LOGS

Policy: --config marshall.yaml is hot-reloaded via notify. Every allowlist is
deny-by-default: an empty list means the tool is not registered.";

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if std::env::var("MARSHALLD_JSON_LOGS").is_ok() {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
}

/// Parsed command line.
struct Args {
    port: Option<u16>,
    bind: Option<String>,
    workspace: Option<PathBuf>,
    audit_path: Option<PathBuf>,
    concurrency: Option<usize>,
    config_path: Option<PathBuf>,
}

/// Either run the server, or do something and exit.
enum Action {
    Serve(Box<Args>),
    /// Probe a running daemon and exit with its verdict.
    Healthcheck(u16),
    Exit,
}

fn parse_args() -> anyhow::Result<Action> {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        port: None,
        bind: None,
        workspace: None,
        audit_path: None,
        concurrency: None,
        config_path: None,
    };

    while let Some(arg) = args.next() {
        // A flag whose value is missing is a mistake worth reporting: it used
        // to be ignored, so `--config` with a typo'd path silently served the
        // default policy.
        let mut value = || {
            args.next()
                .ok_or_else(|| anyhow::anyhow!("{arg} requires a value"))
        };
        match arg.as_str() {
            "--port" => parsed.port = Some(value()?.parse()?),
            "--bind" => parsed.bind = Some(value()?),
            "--workspace" => parsed.workspace = Some(PathBuf::from(value()?)),
            "--audit-log" => parsed.audit_path = Some(PathBuf::from(value()?)),
            "--concurrency" => parsed.concurrency = Some(value()?.parse()?),
            "--config" | "-c" => parsed.config_path = Some(PathBuf::from(value()?)),
            "--validate-config" => {
                let path = value()?;
                let policy = ExecutionPolicy::from_file(Path::new(&path))?;
                println!("config valid: {path}");
                println!("{policy:#?}");
                return Ok(Action::Exit);
            }
            "--healthcheck" => return Ok(Action::Healthcheck(port_from_env())),
            "--version" | "-V" => {
                println!("marshalld {}", env!("CARGO_PKG_VERSION"));
                return Ok(Action::Exit);
            }
            "--help" | "-h" => {
                println!("{HELP}");
                return Ok(Action::Exit);
            }
            other => anyhow::bail!("unknown argument: {other}\n\n{HELP}"),
        }
    }
    Ok(Action::Serve(Box::new(parsed)))
}

/// Probe a locally running daemon's `/health`.
///
/// Exists so a container `HEALTHCHECK` can test the service rather than just
/// proving the binary starts, without adding curl to the runtime image.
async fn healthcheck(port: u16) -> anyhow::Result<()> {
    let url = format!("http://127.0.0.1:{port}/health");
    let response = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("health probe failed: {e}"))?;
    if !response.status().is_success() {
        anyhow::bail!("health probe returned {}", response.status());
    }
    Ok(())
}

fn port_from_env() -> u16 {
    std::env::var("PORT")
        .or_else(|_| std::env::var("MARSHALLD_PORT"))
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let args = match parse_args()? {
        Action::Serve(args) => *args,
        Action::Healthcheck(port) => return healthcheck(port).await,
        Action::Exit => return Ok(()),
    };

    // Load the policy file named on the command line, or `./marshall.yaml` if
    // it happens to be there. A named config that fails to load is fatal — it
    // used to fall back to defaults with a warning, which quietly served a
    // policy nobody wrote.
    let explicit_config = args.config_path.clone();
    let config_path = explicit_config.clone().or_else(|| {
        let candidate = PathBuf::from("marshall.yaml");
        candidate.exists().then_some(candidate)
    });

    let mut policy = match &config_path {
        Some(path) => {
            let policy = ExecutionPolicy::from_file(path)
                .map_err(|e| anyhow::anyhow!("failed to load policy {}: {e}", path.display()))?;
            info!(config = %path.display(), "loaded policy");
            policy
        }
        None => ExecutionPolicy::default(),
    };

    // Command-line overrides win over the file.
    if let Some(workspace) = args.workspace {
        policy.workspace = workspace;
    }
    if let Some(concurrency) = args.concurrency {
        policy.concurrency = concurrency;
    }
    policy.validate()?;

    std::fs::create_dir_all(&policy.workspace)?;
    Limits::default().apply_rlimits();

    let registry = Arc::new(server::build_registry_from_policy(&policy)?);
    info!(
        workspace = %policy.workspace.display(),
        tools = ?registry.tool_names(),
        concurrency = policy.concurrency,
        "starting marshalld"
    );

    let config = ServerConfig {
        workspace_root: policy.workspace.clone(),
        audit_path: args.audit_path.or(policy.audit_log.clone()),
        concurrency: policy.concurrency,
        port: args.port.unwrap_or_else(port_from_env),
        bind: args.bind,
        config_path,
        egress_hosts: policy.http.allowed_hosts.clone(),
        auth_token: None,
        session_ttl: None,
        rate_limit: policy.rate_limit.limit(),
    };

    server::serve(registry, config).await
}
