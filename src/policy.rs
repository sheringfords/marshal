//! Policy as Code — `marshall.yaml` (Phase 3)
//!
//! ```yaml
//! workspace: /tmp/marshalld
//! concurrency: 32
//! audit_log: ./audit.jsonl
//! filesystem:
//!   writable: true
//! shell:
//!   commands:
//!     - program: /bin/echo
//!       args: NoFlags
//!     - program: /bin/cat
//!       args: { Exact: [["--help"]] }
//!     - program: /usr/bin/git
//!       args: { Exact: [["status"]] }
//! http:
//!   allowed_hosts: [api.github.com]
//!   request_body_limit: 1048576
//!   response_body_limit: 4194304
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{shell::AllowedCommand, ArgumentPolicy, Sandbox};

/// The whole of `marshall.yaml`.
///
/// Every allowlist inside is deny-by-default, and [`ExecutionPolicy::validate`]
/// rejects a file rather than quietly correcting it — a policy that loads with
/// a warning is a policy nobody reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    /// Sandbox root. Session workspaces are created beneath it.
    #[serde(default = "default_workspace")]
    pub workspace: PathBuf,
    /// Global cap on in-flight executions.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// JSONL audit log. Absent logs through `tracing` only.
    pub audit_log: Option<PathBuf>,
    /// Filesystem tool policy.
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    /// Shell tool policy.
    #[serde(default)]
    pub shell: ShellPolicy,
    /// HTTP tool policy.
    #[serde(default)]
    pub http: HttpPolicy,
    /// Code tool policy. Read [`CodePolicy`] before enabling it.
    #[serde(default)]
    pub code: CodePolicy,
    /// System tool policy.
    #[serde(default)]
    pub system: SystemPolicy,
    /// Per-client quota.
    #[serde(default)]
    pub rate_limit: RateLimitPolicy,
}

/// What the filesystem tool may do inside the workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Whether mutating operations are permitted at all.
    #[serde(default = "default_true")]
    pub writable: bool,
    /// Cap on a single read, in bytes. Reads past it report truncation.
    #[serde(default = "default_read_limit")]
    pub read_limit: usize,
}

/// Which binaries the shell tool may run, and with what arguments.
///
/// An empty [`ShellPolicy::commands`] means the tool is not registered. The
/// argument policy is the effective control: most binaries accept options that
/// reach the filesystem or the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellPolicy {
    /// Permitted programs. Empty means the tool is not registered.
    #[serde(default)]
    pub commands: Vec<ShellCommandPolicy>,
    /// Wall-clock limit per call.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Cap on combined stdout and stderr, in bytes.
    #[serde(default = "default_output_limit")]
    pub output_limit: usize,
    /// Environment variables to pass through. Absent clears the environment.
    pub allowed_env: Option<Vec<String>>,
}

/// One permitted program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellCommandPolicy {
    /// Absolute path to the binary. Relative paths are rejected at load time.
    pub program: String,
    /// What arguments it may receive. Defaults to none.
    #[serde(default = "default_arg_policy")]
    pub args: ArgPolicySerde,
}

/// An [`ArgumentPolicy`] as written in YAML.
///
/// Two spellings, because both read naturally: `args: NoFlags` for the
/// variants that carry no data, and a mapping for `Exact`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArgPolicySerde {
    /// A bare variant name: `None`, `NoFlags`, or `Unrestricted`.
    Simple(String),
    /// A mapping, which is how `Exact` carries its argument vectors.
    Detailed(ArgPolicyDetailed),
}

/// The mapping form of [`ArgPolicySerde`].
///
/// Fields are capitalised to match the variant names as they appear in YAML.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgPolicyDetailed {
    /// Permitted argument vectors, matched in full.
    pub Exact: Option<Vec<Vec<String>>>,
    /// Permit positionals but no `-`/`--` options.
    pub NoFlags: Option<bool>,
    /// Permit anything. Read [`crate::shell::ShellTool`] first.
    pub Unrestricted: Option<bool>,
    /// Permit no arguments.
    pub None: Option<bool>,
}

impl ArgPolicySerde {
    /// Convert to the runtime policy. An unrecognised name falls back to
    /// [`ArgumentPolicy::None`], the most restrictive option.
    pub fn into_policy(self) -> ArgumentPolicy {
        match self {
            ArgPolicySerde::Simple(s) => match s.as_str() {
                "None" => ArgumentPolicy::None,
                "NoFlags" => ArgumentPolicy::NoFlags,
                "Unrestricted" => ArgumentPolicy::Unrestricted,
                _ => ArgumentPolicy::None,
            },
            ArgPolicySerde::Detailed(d) => {
                if let Some(v) = d.Exact {
                    return ArgumentPolicy::Exact(v);
                }
                if d.NoFlags == Some(true) {
                    return ArgumentPolicy::NoFlags;
                }
                if d.Unrestricted == Some(true) {
                    return ArgumentPolicy::Unrestricted;
                }
                ArgumentPolicy::None
            }
        }
    }
}

/// Which hosts the HTTP tool may reach.
///
/// The allowlist is checked before DNS, and every resolved address still has to
/// pass [`crate::destination`]. An allowlisted host that redirects or proxies
/// extends trust to wherever it sends clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPolicy {
    /// Permitted hostnames. Wildcards are rejected at load time.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Cap on an outbound request body, in bytes.
    #[serde(default = "default_req_limit")]
    pub request_body_limit: usize,
    /// Cap on a response body, in bytes.
    #[serde(default = "default_resp_limit")]
    pub response_body_limit: usize,
    /// Wall-clock limit per request.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

/// Policy for the `code` tool.
///
/// # Why this one has an extra gate
///
/// `shell` is an allowlist of *binaries*: the policy names what may run.
/// `code` accepts arbitrary source in an allowed language, so on the local
/// backend it is equivalent to `shell` with `ArgumentPolicy::Unrestricted` on
/// an interpreter — a snippet reads any file the daemon can read and reaches
/// any host the daemon can reach, bypassing `filesystem` and `http` policy
/// entirely.
///
/// So enabling a language is not enough. [`CodePolicy::allow_unsandboxed`]
/// must also be set, which is the operator saying in the config file that they
/// know the other policies do not apply here. The isolating `wasm` backend
/// does not need it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodePolicy {
    /// Languages the tool will run. Empty means the tool is not registered.
    #[serde(default)]
    pub allowed_languages: Vec<String>,
    /// Wall-clock limit per snippet.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Cap on combined stdout and stderr, in bytes.
    #[serde(default = "default_output_limit")]
    pub output_limit: usize,
    /// Acknowledge that local-backend code execution has no OS isolation.
    ///
    /// Required to enable [`CodePolicy::allowed_languages`] on the local
    /// backend; without it, a config that lists languages fails to load.
    #[serde(default)]
    pub allow_unsandboxed: bool,
}

/// What the system tool may report and do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPolicy {
    /// Environment variables readable through `env_get`/`env_list`. Values are
    /// returned in `content`; only a digest reaches the summary.
    #[serde(default)]
    pub allowed_env: Vec<String>,
    /// Permit `process_list`. Linux only; elsewhere it reports `not_supported`.
    #[serde(default)]
    pub allow_process_list: bool,
    /// Permit `process_kill`. Not scoped to session children.
    #[serde(default)]
    pub allow_kill: bool,
    /// Upper bound on `sleep`, itself bounded by a hard cap.
    #[serde(default = "default_max_sleep")]
    pub max_sleep_ms: u64,
}

/// Per-client request quota.
///
/// The global `concurrency` cap bounds concurrently executing workloads to
/// protect the host; it does nothing to stop one caller consuming the whole
/// allowance. This is per client — the bearer token when there is one, the
/// peer address otherwise.
///
/// Quota contract: one token is consumed per admitted HTTP request,
/// regardless of how many tool executions a batch or sequence runs. A batch
/// of 64 items costs the same quota as a single execution; size the quota
/// accordingly when batch endpoints are exposed.
///
/// On by default: "no quota" is not a sensible default for a service that
/// executes tools on request. Set `enabled: false` to turn it off.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    /// Whether to enforce quotas at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Sustained rate per client.
    #[serde(default = "default_rate_per_minute")]
    pub per_minute: u32,
    /// How many requests may arrive at once before the sustained rate applies.
    #[serde(default = "default_rate_burst")]
    pub burst: u32,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            per_minute: default_rate_per_minute(),
            burst: default_rate_burst(),
        }
    }
}

impl RateLimitPolicy {
    /// The limit to enforce, or `None` when disabled.
    pub fn limit(&self) -> Option<crate::RateLimit> {
        self.enabled
            .then(|| crate::RateLimit::new(self.per_minute, self.burst))
    }
}

// defaults
fn default_workspace() -> PathBuf {
    PathBuf::from("/tmp/marshalld")
}
fn default_concurrency() -> usize {
    32
}
fn default_true() -> bool {
    true
}
fn default_read_limit() -> usize {
    8 * 1024 * 1024
}
fn default_timeout() -> u64 {
    30_000
}
fn default_output_limit() -> usize {
    1024 * 1024
}
fn default_req_limit() -> usize {
    4 * 1024 * 1024
}
fn default_resp_limit() -> usize {
    4 * 1024 * 1024
}
fn default_arg_policy() -> ArgPolicySerde {
    ArgPolicySerde::Simple("None".into())
}
fn default_max_sleep() -> u64 {
    5_000
}
/// 10 requests per second sustained: comfortably above what an agent loop
/// needs, comfortably below what a retry storm produces.
fn default_rate_per_minute() -> u32 {
    600
}
fn default_rate_burst() -> u32 {
    60
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            workspace: default_workspace(),
            concurrency: default_concurrency(),
            audit_log: None,
            filesystem: FilesystemPolicy::default(),
            shell: ShellPolicy::default(),
            http: HttpPolicy::default(),
            code: CodePolicy::default(),
            system: SystemPolicy::default(),
            rate_limit: RateLimitPolicy::default(),
        }
    }
}
impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            writable: true,
            read_limit: default_read_limit(),
        }
    }
}
impl Default for ShellPolicy {
    fn default() -> Self {
        Self {
            commands: vec![],
            timeout_ms: default_timeout(),
            output_limit: default_output_limit(),
            allowed_env: None,
        }
    }
}
impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: vec![],
            request_body_limit: default_req_limit(),
            response_body_limit: default_resp_limit(),
            timeout_ms: default_timeout(),
        }
    }
}
impl Default for CodePolicy {
    fn default() -> Self {
        Self {
            // Deny by default, like every other allowlist in this crate. The
            // previous default enabled python/bash/javascript, which made an
            // unconfigured daemon strictly more permissive than a configured
            // one.
            allowed_languages: Vec::new(),
            timeout_ms: default_timeout(),
            output_limit: default_output_limit(),
            allow_unsandboxed: false,
        }
    }
}
impl Default for SystemPolicy {
    fn default() -> Self {
        Self {
            allowed_env: vec![],
            allow_process_list: false,
            allow_kill: false,
            max_sleep_ms: default_max_sleep(),
        }
    }
}

impl ExecutionPolicy {
    /// Read and validate a policy file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Self::from_yaml(&s)
    }

    /// Parse and validate YAML.
    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        let p: Self = serde_yaml::from_str(s)?;
        p.validate()?;
        Ok(p)
    }

    /// Reject a policy that is malformed, out of bounds, or dangerously
    /// permissive in a way the operator has not acknowledged.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.concurrency == 0 {
            anyhow::bail!("concurrency must be >0");
        }
        if self.concurrency > 128 {
            anyhow::bail!("concurrency too large: {}", self.concurrency);
        }
        if self.workspace.as_os_str().is_empty() {
            anyhow::bail!("workspace must not be empty");
        }
        if !self.workspace.is_absolute() {
            anyhow::bail!("workspace must be absolute");
        }
        if self.filesystem.read_limit == 0 || self.filesystem.read_limit > 64 * 1024 * 1024 {
            anyhow::bail!("read_limit must be 1..64MiB");
        }
        if self.shell.timeout_ms == 0 || self.shell.timeout_ms > 300_000 {
            anyhow::bail!("shell timeout must be 1..300000ms");
        }
        if self.shell.output_limit == 0 || self.shell.output_limit > 16 * 1024 * 1024 {
            anyhow::bail!("shell output_limit must be 1..16MiB");
        }
        if self.http.timeout_ms == 0 || self.http.timeout_ms > 120_000 {
            anyhow::bail!("http timeout must be 1..120000ms");
        }
        for c in &self.shell.commands {
            if !c.program.starts_with('/') {
                anyhow::bail!("shell program must be absolute: {}", c.program);
            }
            if !Path::new(&c.program).is_absolute() {
                anyhow::bail!("absolute path required: {}", c.program);
            }
            // Reject weak policies for interpreters at load time (fail closed).
            crate::shell::validate_policy_for_program(&c.program, &c.args.clone().into_policy())?;
        }
        // hosts must be lowercased, no wildcards, no whitespace/control
        for h in &self.http.allowed_hosts {
            if h.chars().any(|c| c.is_control() || c.is_whitespace()) {
                anyhow::bail!("host contains control/whitespace: {h}");
            }
            if h.contains('*') {
                anyhow::bail!("wildcard hosts not allowed: {h}");
            }
            if h.len() > 253 {
                anyhow::bail!("host too long: {h}");
            }
        }
        if self.code.timeout_ms == 0 || self.code.timeout_ms > 30_000 {
            anyhow::bail!("code timeout must be 1..30000ms");
        }
        if self.code.output_limit == 0 || self.code.output_limit > 16 * 1024 * 1024 {
            anyhow::bail!("code output_limit must be 1..16MiB");
        }
        for lang in &self.code.allowed_languages {
            if !matches!(
                lang.as_str(),
                "python" | "javascript" | "js" | "bash" | "sh"
            ) {
                anyhow::bail!("unsupported code language: {lang}");
            }
        }
        // Fail closed: listing languages enables arbitrary source execution on
        // the local backend, which bypasses `filesystem` and `http` policy. The
        // operator has to say so explicitly.
        if !self.code.allowed_languages.is_empty() && !self.code.allow_unsandboxed {
            anyhow::bail!(
                "code.allowed_languages is set but code.allow_unsandboxed is false: \
                 local-backend code execution has no OS isolation and bypasses \
                 filesystem and http policy. Set code.allow_unsandboxed: true to \
                 accept this, or remove code.allowed_languages to disable the tool."
            );
        }
        if self.rate_limit.enabled && self.rate_limit.burst == 0 {
            anyhow::bail!("rate_limit.burst must be >0 when rate limiting is enabled");
        }
        if self.rate_limit.per_minute > 1_000_000 {
            anyhow::bail!("rate_limit.per_minute is implausibly large");
        }
        if self.system.max_sleep_ms == 0
            || self.system.max_sleep_ms > crate::system::MAX_SLEEP_MS_HARD_CAP
        {
            anyhow::bail!("system max_sleep_ms must be 1..30000ms");
        }
        for key in &self.system.allowed_env {
            if key.is_empty() || key.len() > crate::system::MAX_ENV_KEY_LEN {
                anyhow::bail!("system allowed_env key too long: {key}");
            }
            if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                anyhow::bail!("system allowed_env key invalid: {key}");
            }
            if key.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
                anyhow::bail!("system allowed_env key invalid: {key}");
            }
        }
        Ok(())
    }

    /// Create the workspace directory and a [`Sandbox`] rooted at it.
    pub fn sandbox(&self) -> anyhow::Result<Sandbox> {
        std::fs::create_dir_all(&self.workspace)?;
        Sandbox::new([&self.workspace]).map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// The shell allowlist as runtime values.
    pub fn allowed_commands(&self) -> Vec<AllowedCommand> {
        self.shell
            .commands
            .iter()
            .map(|c| {
                AllowedCommand::new(c.program.clone()).with_arguments(c.args.clone().into_policy())
            })
            .collect()
    }

    /// [`ShellPolicy::timeout_ms`] as a [`Duration`].
    pub fn shell_timeout(&self) -> Duration {
        Duration::from_millis(self.shell.timeout_ms)
    }
    /// [`HttpPolicy::timeout_ms`] as a [`Duration`].
    pub fn http_timeout(&self) -> Duration {
        Duration::from_millis(self.http.timeout_ms)
    }

    /// [`CodePolicy::timeout_ms`] as a [`Duration`].
    pub fn code_timeout(&self) -> Duration {
        Duration::from_millis(self.code.timeout_ms)
    }

    /// The configured languages as runtime values.
    pub fn code_languages(&self) -> Vec<crate::Language> {
        self.code
            .allowed_languages
            .iter()
            .filter_map(|s| crate::Language::parse(s))
            .collect()
    }

    /// Whether the `code` tool should be registered at all.
    ///
    /// An empty language list means "no code execution", not "all languages".
    /// The registry builder used to read it the other way round.
    pub fn code_enabled(&self) -> bool {
        !self.code_languages().is_empty()
    }

    /// Build a [`crate::SystemTool`] from [`ExecutionPolicy::system`].
    pub fn system_tool(&self) -> crate::SystemTool {
        crate::SystemTool::new()
            .with_allowed_env(self.system.allowed_env.clone())
            .with_process_list(self.system.allow_process_list)
            .with_kill(self.system.allow_kill)
            .with_max_sleep_ms(self.system.max_sleep_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_valid() {
        ExecutionPolicy::default().validate().unwrap();
    }

    #[test]
    fn yaml_roundtrip_minimal() {
        let yaml = r#"
workspace: /tmp/test_exec
concurrency: 8
filesystem:
  writable: true
shell:
  commands:
    - program: /bin/echo
      args: NoFlags
http:
  allowed_hosts: [api.github.com]
"#;
        let p = ExecutionPolicy::from_yaml(yaml).unwrap();
        assert_eq!(p.concurrency, 8);
        assert_eq!(p.http.allowed_hosts, vec!["api.github.com"]);
        assert_eq!(p.shell.commands.len(), 1);
    }

    #[test]
    fn yaml_exact_args() {
        let yaml = r#"
shell:
  commands:
    - program: /usr/bin/git
      args:
        Exact: [["status"], ["log", "--oneline"]]
"#;
        let p = ExecutionPolicy::from_yaml(yaml).unwrap();
        let cmds = p.allowed_commands();
        assert!(matches!(cmds[0].arguments, crate::ArgumentPolicy::Exact(_)));
    }

    #[test]
    fn rejects_relative_program() {
        let yaml = r#"shell: { commands: [{program: echo, args: None}]}"#;
        assert!(ExecutionPolicy::from_yaml(yaml).is_err());
    }

    #[test]
    fn rejects_wildcard_host() {
        let yaml = r#"http: { allowed_hosts: ["*.evil.com"] }"#;
        assert!(ExecutionPolicy::from_yaml(yaml).is_err());
    }

    #[test]
    fn system_policy_parses_and_builds_tool() {
        use crate::Tool;
        let yaml = r#"
system:
  allowed_env: [PATH, TZ]
  allow_process_list: true
  allow_kill: false
  max_sleep_ms: 2000
"#;
        let p = ExecutionPolicy::from_yaml(yaml).unwrap();
        assert_eq!(p.system.allowed_env, vec!["PATH", "TZ"]);
        assert!(p.system.allow_process_list);
        let tool = p.system_tool();
        assert!(tool.parameters_schema().get("properties").is_some());
    }

    #[test]
    fn code_is_denied_by_default() {
        // The default used to enable python/bash/javascript, making an
        // unconfigured daemon more permissive than a configured one.
        let p = ExecutionPolicy::default();
        assert!(p.code.allowed_languages.is_empty());
        assert!(!p.code_enabled());
        assert!(!p.code.allow_unsandboxed);
    }

    #[test]
    fn an_empty_language_list_means_no_languages() {
        // Not "all languages" — which is how the registry builder read it.
        let p = ExecutionPolicy::from_yaml("code: { allowed_languages: [] }").unwrap();
        assert!(p.code_languages().is_empty());
        assert!(!p.code_enabled());
    }

    #[test]
    fn enabling_a_language_requires_acknowledging_it_is_unsandboxed() {
        let yaml = r#"code: { allowed_languages: [python] }"#;
        let err = ExecutionPolicy::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("allow_unsandboxed"), "{err}");

        let yaml = r#"code: { allowed_languages: [python], allow_unsandboxed: true }"#;
        let p = ExecutionPolicy::from_yaml(yaml).unwrap();
        assert!(p.code_enabled());
        assert_eq!(p.code_languages().len(), 1);
    }

    #[test]
    fn rejects_bad_system_policy() {
        let yaml = r#"system: { max_sleep_ms: 99999 }"#;
        assert!(ExecutionPolicy::from_yaml(yaml).is_err());
        let yaml = r#"system: { allowed_env: ["HAS SPACE"] }"#;
        assert!(ExecutionPolicy::from_yaml(yaml).is_err());
        let yaml = r#"system: { allowed_env: ["123BAD"] }"#;
        assert!(ExecutionPolicy::from_yaml(yaml).is_err());
    }
}
