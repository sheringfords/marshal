//! Running an allowlisted binary.
//!
//! Read this before enabling it.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use base64::Engine as _;
use serde_json::{json, Value};
use tracing::debug;

use crate::backend::{ExecRequest, ExecutionBackend, LocalProcessBackend, ResourceLimits};
use crate::sandbox::Sandbox;
use crate::{Tool, ToolOutcome};

/// Default cap on captured stdout/stderr, per stream.
pub const DEFAULT_OUTPUT_LIMIT: usize = 1024 * 1024;

/// Default wall-clock budget for one command.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// What arguments a command may receive.
///
/// This exists because a binary allowlist alone is not a security boundary,
/// and the crate this was extracted from had only a binary allowlist.
#[derive(Debug, Clone)]
pub enum ArgumentPolicy {
    /// No arguments at all. The only policy that is safe by construction.
    None,

    /// Only these exact argument vectors, matched in full.
    ///
    /// The safe way to allow a small number of known invocations.
    Exact(Vec<Vec<String>>),

    /// Any argument, as long as none begins with `-`.
    ///
    /// Blocks the common option-injection shapes — `--exec`, `-o ProxyCommand`,
    /// `--upload-file` — while still permitting positional arguments like a
    /// filename. Not a guarantee: a binary that treats a bare positional as a
    /// script name is still fully exploitable.
    NoFlags,

    /// Anything at all.
    ///
    /// Equivalent to granting whatever the binary can do. `git` reaches
    /// arbitrary execution through `--exec-path`; `find` through `-exec`;
    /// `tar` through `--to-command`. Choose this only when the binary is
    /// trusted with everything the parent process can do.
    Unrestricted,
}

impl ArgumentPolicy {
    fn permits(&self, args: &[String]) -> bool {
        match self {
            ArgumentPolicy::None => args.is_empty(),
            ArgumentPolicy::Exact(allowed) => allowed.iter().any(|candidate| candidate == args),
            ArgumentPolicy::NoFlags => !args.iter().any(|a| a.starts_with('-')),
            ArgumentPolicy::Unrestricted => true,
        }
    }
}

/// Binary names that treat a bare positional as code/script and therefore
/// must never use `NoFlags`/`Unrestricted`. Use `Exact` vectors instead.
pub const INTERPRETER_BINARIES: &[&str] = &[
    "sh", "bash", "dash", "zsh", "fish", "python", "python3", "node", "nodejs", "deno", "bun",
    "perl", "ruby", "php", "lua", "awk", "gawk",
];

/// Whether `program` is a known interpreter by file name.
pub fn is_interpreter_program(program: &str) -> bool {
    let base = program.rsplit('/').next().unwrap_or(program);
    // Allow versioned names like `python3.11`.
    let stem = base.split('.').next().unwrap_or(base);
    INTERPRETER_BINARIES.contains(&base)
        || INTERPRETER_BINARIES.contains(&stem)
        || base.starts_with("python")
}

/// Reject `NoFlags`/`Unrestricted` for interpreters. Returns `Err` with a
/// stable code string (`noflags_for_interpreter` / `unrestricted_for_interpreter`).
pub fn validate_policy_for_program(program: &str, policy: &ArgumentPolicy) -> anyhow::Result<()> {
    if is_interpreter_program(program) {
        match policy {
            ArgumentPolicy::NoFlags => anyhow::bail!("noflags_for_interpreter: {program}"),
            ArgumentPolicy::Unrestricted => {
                anyhow::bail!("unrestricted_for_interpreter: {program}")
            }
            _ => {}
        }
    }
    Ok(())
}

/// One permitted command.
#[derive(Debug, Clone)]
pub struct AllowedCommand {
    /// Absolute path to the executable.
    ///
    /// Absolute on purpose: resolving through `PATH` means whoever controls
    /// the environment chooses which binary runs.
    pub program: PathBuf,
    /// What arguments it may be given.
    pub arguments: ArgumentPolicy,
}

impl AllowedCommand {
    /// Permit `program` with no arguments.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        AllowedCommand {
            program: program.into(),
            arguments: ArgumentPolicy::None,
        }
    }

    /// Set the argument policy.
    pub fn with_arguments(mut self, policy: ArgumentPolicy) -> Self {
        self.arguments = policy;
        self
    }
}

/// Runs allowlisted binaries with a bounded runtime and bounded output.
///
/// # This is not a sandbox
///
/// The allowlist decides *which binary* runs. It does not decide what that
/// binary does, and for most binaries the arguments decide that entirely:
///
/// ```text
/// allow: /usr/bin/find      →  find / -exec sh -c '…' \;
/// allow: /usr/bin/git       →  git --exec-path=/tmp/evil status
/// allow: /usr/bin/tar       →  tar --to-command=/tmp/evil -xf …
/// ```
///
/// Every one of those is a whitelisted binary reaching arbitrary execution
/// through its own documented options. [`ArgumentPolicy`] is the control that
/// matters, and it defaults to [`ArgumentPolicy::None`].
///
/// There is no shell. Commands are executed directly, so shell metacharacters
/// in an argument are inert — `;`, `|`, `$(…)` are passed through as literal
/// text.
pub struct ShellTool {
    commands: Vec<AllowedCommand>,
    working_dirs: Option<Sandbox>,
    timeout: Duration,
    output_limit: usize,
    allowed_env: Option<Vec<String>>,
    extra_env: Vec<(String, String)>,
    backend: Arc<dyn ExecutionBackend>,
    stdin_limit: usize,
    cpu_time: Option<Duration>,
    memory_bytes: Option<u64>,
}

impl ShellTool {
    /// A shell tool permitting exactly these commands.
    ///
    /// An empty list denies everything, which is the correct behaviour for an
    /// unconfigured tool.
    pub fn new(commands: Vec<AllowedCommand>) -> Self {
        ShellTool {
            commands,
            working_dirs: None,
            timeout: DEFAULT_TIMEOUT,
            output_limit: DEFAULT_OUTPUT_LIMIT,
            allowed_env: None,
            extra_env: Vec::new(),
            backend: Arc::new(LocalProcessBackend),
            stdin_limit: 1024 * 1024,
            cpu_time: None,
            memory_bytes: None,
        }
    }

    /// Permit `working_dir` arguments inside this sandbox.
    ///
    /// Without it, `working_dir` is rejected and commands inherit the parent's
    /// directory.
    pub fn with_working_dirs(mut self, sandbox: Sandbox) -> Self {
        self.working_dirs = Some(sandbox);
        self
    }

    /// Set the wall-clock budget. The process is killed when it elapses.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the per-stream capture limit.
    pub fn with_output_limit(mut self, bytes: usize) -> Self {
        self.output_limit = bytes;
        self
    }

    /// Set stdin limit.
    pub fn with_stdin_limit(mut self, bytes: usize) -> Self {
        self.stdin_limit = bytes;
        self
    }

    /// Allow only these env vars to be inherited from the parent.
    ///
    /// If not set, the child inherits no environment (`env_clear`). This
    /// prevents `LD_PRELOAD`, `GIT_SSH_COMMAND`, `PYTHONPATH` etc. from
    /// bypassing `ArgumentPolicy`.
    pub fn with_allowed_env<I, S>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_env = Some(vars.into_iter().map(Into::into).collect());
        self
    }

    /// Inject an explicit env var into the child.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_env.push((key.into(), value.into()));
        self
    }

    /// Override the execution backend (e.g. `WasmBackend`, `ContainerBackend`).
    pub fn with_backend(mut self, backend: Arc<dyn ExecutionBackend>) -> Self {
        self.backend = backend;
        self
    }

    /// Set CPU time limit (enforced by Wasm/Container backends; advisory for local).
    pub fn with_cpu_time(mut self, cpu: Duration) -> Self {
        self.cpu_time = Some(cpu);
        self
    }

    /// Set memory limit in bytes (enforced by Wasm/Container backends).
    pub fn with_memory_limit(mut self, bytes: u64) -> Self {
        self.memory_bytes = Some(bytes);
        self
    }

    /// Streaming execution — returns chunks instead of buffering all output.
    /// Shape matches what `executor.sh` SSE needs; `LocalProcessBackend` currently
    /// buffers then chunks.
    pub async fn execute_streaming(&self, args: Value) -> Result<crate::backend::StreamingOutput> {
        let started = Instant::now();
        let (program, arguments, working_dir, stdin) = self.parse(&args)?;
        let env = self.build_env();
        let req = ExecRequest {
            program,
            args: arguments,
            working_dir,
            env,
            stdin,
            limits: ResourceLimits {
                timeout: self.timeout,
                output_limit: self.output_limit,
                cpu_time: self.cpu_time,
                memory_bytes: self.memory_bytes,
            },
        };
        let _ = started;
        self.backend.execute_streaming(req).await
    }

    fn lookup(&self, program: &str) -> Option<&AllowedCommand> {
        self.commands
            .iter()
            .find(|candidate| candidate.program.as_os_str() == program)
    }

    pub(crate) fn build_env(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();
        if let Some(allowed) = &self.allowed_env {
            for key in allowed {
                if let Ok(val) = std::env::var(key) {
                    env.insert(key.clone(), val);
                }
            }
        }
        for (k, v) in &self.extra_env {
            env.insert(k.clone(), v.clone());
        }
        env
    }

    #[allow(clippy::type_complexity)]
    fn parse(
        &self,
        args: &Value,
    ) -> Result<(PathBuf, Vec<String>, Option<PathBuf>, Option<Vec<u8>>)> {
        let program = args
            .get("program")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'program'"))?;

        let arguments: Vec<String> = match args.get("args") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow::anyhow!("'args' must be an array of strings"))
                })
                .collect::<Result<_>>()?,
            Some(_) => bail!("'args' must be an array of strings"),
        };

        let allowed = self
            .lookup(program)
            .ok_or_else(|| anyhow::anyhow!("command_not_allowed"))?;

        if !allowed.arguments.permits(&arguments) {
            bail!("arguments_not_allowed");
        }
        // Harden `NoFlags` heuristic: interpreters treat a bare positional as
        // code, so `NoFlags`/`Unrestricted` is never safe for them.
        validate_policy_for_program(program, &allowed.arguments)?;

        let working_dir = match args.get("working_dir").and_then(Value::as_str) {
            None => None,
            Some(dir) => {
                let sandbox = self
                    .working_dirs
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("working_dir_not_allowed"))?;
                Some(
                    sandbox
                        .resolve_existing(dir)
                        .map_err(|_| anyhow::anyhow!("working_dir_not_allowed"))?,
                )
            }
        };
        // stdin handling — capped to stdin_limit, supports utf8 or base64
        if args.get("stdin").is_some() && args.get("stdin_base64").is_some() {
            bail!("provide only one of stdin or stdin_base64");
        }
        let stdin = if let Some(s) = args.get("stdin").and_then(Value::as_str) {
            if s.len() > self.stdin_limit {
                bail!("stdin_too_large");
            }
            Some(s.as_bytes().to_vec())
        } else if let Some(b64) = args.get("stdin_base64").and_then(Value::as_str) {
            // Pre-check raw length to avoid OOM on huge base64 before decode
            if b64.len() > self.stdin_limit * 4 / 3 + 1024 {
                bail!("stdin_too_large");
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|_| anyhow::anyhow!("invalid_base64"))?;
            if bytes.len() > self.stdin_limit {
                bail!("stdin_too_large");
            }
            Some(bytes)
        } else if args.get("stdin").is_some() || args.get("stdin_base64").is_some() {
            bail!("stdin must be string");
        } else {
            None
        };

        Ok((allowed.program.clone(), arguments, working_dir, stdin))
    }

    /// Parse under a typed session scope: everything `parse` checks, plus
    /// the resolved `working_dir` — evaluated *after* any sequence template
    /// expansion, at the actual execution boundary — must stay inside the
    /// session root. Both values are canonical, so the check is
    /// component-wise. `None` scope is the explicit trusted-local path.
    #[allow(clippy::type_complexity)]
    fn parse_with(
        &self,
        scope: Option<&std::path::PathBuf>,
        args: &Value,
    ) -> Result<(PathBuf, Vec<String>, Option<PathBuf>, Option<Vec<u8>>)> {
        let (program, arguments, working_dir, stdin) = self.parse(args)?;
        if let (Some(root), Some(dir)) = (scope, working_dir.as_ref()) {
            if !dir.starts_with(root) {
                anyhow::bail!("path_not_allowed");
            }
        }
        Ok((program, arguments, working_dir, stdin))
    }
}

#[async_trait::async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn description(&self) -> &str {
        "Run an allowlisted binary (echo/cat/git, plus configured). Enforced by ArgumentPolicy (None/NoFlags/Exact). No shell — metachars inert. Use for git status, cat files via shell, or other allowlisted binaries. Prefer code tool for python/bash snippets."
    }

    fn parameters_schema(&self) -> Value {
        let names: Vec<String> = self
            .commands
            .iter()
            .map(|c| c.program.display().to_string())
            .collect();
        json!({
            "type": "object",
            "properties": {
                "program": {
                    "type": "string",
                    "description": "Absolute path to allowlisted executable. Must be in allowlist or command_not_allowed. Example: /bin/echo, /bin/cat, /usr/bin/git",
                    "enum": names
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Arguments obeying ArgumentPolicy. NoFlags blocks -flags, Exact only allows listed vectors. Example: [\"hello\"] for echo, [\"status\"] for git."
                },
                "working_dir": {
                    "type": "string",
                    "description": "Sandboxed working dir. Must be inside sandbox via Sandbox::resolve_existing. Omit to inherit parent."
                },
                "stdin": { "type": "string", "description": "UTF-8 stdin piped (max 1MiB). Use for cat << stdin." },
                "stdin_base64": { "type": "string", "description": "Base64 stdin bytes (binary). Pre-checked raw len to avoid OOM." }
            },
            "required": ["program"],
            "examples": [
                {"program":"/bin/echo","args":["hello"]},
                {"program":"/usr/bin/git","args":["status"],"working_dir":"/tmp/marshalld/abc"}
            ]
        })
    }

    async fn validate(&self, args: &Value) -> Result<()> {
        self.parse(args).map(|_| ())
    }

    async fn validate_with(&self, ctx: &crate::ExecutionContract, args: &Value) -> Result<()> {
        self.parse_with(ctx.session_root(), args).map(|_| ())
    }

    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        self.execute_inner(None, args).await
    }

    async fn execute_with(
        &self,
        ctx: &crate::ExecutionContract,
        args: Value,
    ) -> Result<ToolOutcome> {
        self.execute_inner(ctx.session_root(), args).await
    }
}

impl ShellTool {
    /// Shared execution body: `None` scope is the explicit trusted-local
    /// path (tool sandbox bounds only); a session scope additionally
    /// confines the resolved `working_dir` at execution time.
    async fn execute_inner(
        &self,
        scope: Option<&std::path::PathBuf>,
        args: Value,
    ) -> Result<ToolOutcome> {
        let started = Instant::now();
        let (program, arguments, working_dir, stdin) = self.parse_with(scope, &args)?;

        debug!(
            program = %program.display(),
            argc = arguments.len(),
            backend = %self.backend.name(),
            "shell exec"
        );

        let env = self.build_env();
        let req = ExecRequest {
            program: program.clone(),
            args: arguments,
            working_dir,
            env,
            stdin,
            limits: ResourceLimits {
                timeout: self.timeout,
                output_limit: self.output_limit,
                cpu_time: self.cpu_time,
                memory_bytes: self.memory_bytes,
            },
        };

        let out = match self.backend.execute(req).await {
            Ok(o) => o,
            Err(e) if e.to_string().contains("spawn_failed") => {
                return Ok(ToolOutcome::failure(
                    "shell",
                    "spawn_failed",
                    elapsed(started),
                ))
            }
            Err(e) => {
                // Backend-specific error (e.g. wasm not enabled) surfaces as policy error
                anyhow::bail!(e)
            }
        };

        if out.timed_out {
            return Ok(ToolOutcome::failure("shell", "timed_out", elapsed(started))
                .with_metadata("timeout_ms", self.timeout.as_millis().to_string()));
        }

        let summary = json!({
            "exit_code": out.exit_code,
            "stdout_bytes": out.stdout.len(),
            "stdout_sha256": crate::sha256_hex(&out.stdout),
            "stdout_truncated": out.stdout_truncated,
            "stderr_bytes": out.stderr.len(),
            "stderr_sha256": crate::sha256_hex(&out.stderr),
            "stderr_truncated": out.stderr_truncated,
            "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
            "backend": self.backend.name(),
        });

        let outcome = if out.exit_code == Some(0) {
            ToolOutcome::success("shell", summary, elapsed(started))
        } else {
            let mut failed = ToolOutcome::failure("shell", "nonzero_exit", elapsed(started));
            failed.summary = summary;
            failed
        };

        Ok(outcome
            .with_content(out.stdout)
            .with_metadata(
                "exit_code",
                out.exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into()),
            )
            .with_metadata("program", program.display().to_string()))
    }
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

/// Names of the commands an allowlist permits, for diagnostics.
pub fn allowed_names(commands: &[AllowedCommand]) -> HashSet<String> {
    commands
        .iter()
        .map(|c| c.program.display().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_path() -> &'static str {
        if std::path::Path::new("/bin/echo").exists() {
            "/bin/echo"
        } else {
            "/usr/bin/echo"
        }
    }

    fn tool_allowing(policy: ArgumentPolicy) -> ShellTool {
        ShellTool::new(vec![AllowedCommand::new(echo_path()).with_arguments(policy)])
    }

    #[tokio::test]
    async fn an_empty_allowlist_denies_everything() {
        let tool = ShellTool::new(vec![]);
        let err = tool
            .validate(&json!({"program": echo_path()}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("command_not_allowed"));
    }

    #[tokio::test]
    async fn a_non_allowlisted_program_is_denied() {
        let tool = tool_allowing(ArgumentPolicy::None);
        let err = tool
            .validate(&json!({"program": "/bin/rm"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("command_not_allowed"));
    }

    #[tokio::test]
    async fn a_relative_program_name_does_not_match_an_absolute_allowlist() {
        // PATH resolution is the point: `echo` must not satisfy `/bin/echo`,
        // or whoever controls PATH chooses the binary.
        let tool = tool_allowing(ArgumentPolicy::None);
        assert!(tool.validate(&json!({"program": "echo"})).await.is_err());
    }

    #[tokio::test]
    async fn the_default_argument_policy_rejects_arguments() {
        let tool = tool_allowing(ArgumentPolicy::None);
        let err = tool
            .validate(&json!({"program": echo_path(), "args": ["hello"]}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("arguments_not_allowed"));
    }

    #[tokio::test]
    async fn no_flags_blocks_option_injection_but_allows_positionals() {
        let tool = tool_allowing(ArgumentPolicy::NoFlags);
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["hello"]}))
            .await
            .is_ok());
        // The shape that turns a whitelisted binary into arbitrary execution.
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["--exec-path=/tmp/evil"]}))
            .await
            .is_err());
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["-exec"]}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn exact_matches_the_whole_vector() {
        let tool = tool_allowing(ArgumentPolicy::Exact(vec![vec!["status".into()]]));
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["status"]}))
            .await
            .is_ok());
        // A permitted prefix must not admit extra arguments.
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["status", "--porcelain"]}))
            .await
            .is_err());
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": []}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_command_runs_and_reports_its_output() {
        let tool = tool_allowing(ArgumentPolicy::NoFlags);
        let outcome = tool
            .execute(json!({"program": echo_path(), "args": ["hello"]}))
            .await
            .unwrap();

        assert!(outcome.success);
        assert_eq!(outcome.summary["exit_code"], json!(0));
        assert_eq!(
            String::from_utf8_lossy(outcome.content.as_ref().unwrap()).trim(),
            "hello"
        );
    }

    #[tokio::test]
    async fn shell_metacharacters_are_inert() {
        // No shell is involved, so this must be echoed literally rather than
        // interpreted as a command separator.
        let tool = tool_allowing(ArgumentPolicy::NoFlags);
        let outcome = tool
            .execute(json!({"program": echo_path(), "args": ["a; touch /tmp/exectool_pwned"]}))
            .await
            .unwrap();

        let out = String::from_utf8_lossy(outcome.content.as_ref().unwrap()).to_string();
        assert!(
            out.contains("touch"),
            "argument was not passed literally: {out}"
        );
        assert!(!std::path::Path::new("/tmp/exectool_pwned").exists());
    }

    #[tokio::test]
    async fn output_is_capped_and_truncation_is_reported() {
        let yes = ["/bin/cat", "/usr/bin/cat"]
            .iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(cat) = yes else { return };

        let big = std::env::temp_dir().join(format!("exectool_big_{}.txt", std::process::id()));
        std::fs::write(&big, vec![b'x'; 100_000]).unwrap();

        let tool = ShellTool::new(vec![
            AllowedCommand::new(*cat).with_arguments(ArgumentPolicy::NoFlags)
        ])
        .with_output_limit(1024);

        let outcome = tool
            .execute(json!({"program": cat, "args": [big.to_string_lossy()]}))
            .await
            .unwrap();

        assert_eq!(outcome.content.as_ref().unwrap().len(), 1024);
        assert_eq!(outcome.summary["stdout_truncated"], json!(true));
        let _ = std::fs::remove_file(&big);
    }

    #[tokio::test]
    async fn a_working_dir_is_rejected_without_a_sandbox() {
        let tool = tool_allowing(ArgumentPolicy::None);
        let err = tool
            .validate(&json!({"program": echo_path(), "working_dir": "/tmp"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("working_dir_not_allowed"));
    }

    #[tokio::test]
    async fn a_working_dir_outside_the_sandbox_is_rejected() {
        let base = std::env::temp_dir().join(format!("exectool_wd_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("safe")).unwrap();
        // The sibling-prefix escape, applied to working_dir.
        std::fs::create_dir_all(base.join("safe_evil")).unwrap();

        let tool = tool_allowing(ArgumentPolicy::None)
            .with_working_dirs(Sandbox::new([base.join("safe")]).unwrap());

        assert!(tool
            .validate(
                &json!({"program": echo_path(), "working_dir": base.join("safe").to_string_lossy()})
            )
            .await
            .is_ok());
        assert!(tool
            .validate(&json!({"program": echo_path(), "working_dir": base.join("safe_evil").to_string_lossy()}))
            .await
            .is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_contract_session_root_confines_the_resolved_working_dir() {
        // The tool sandbox admits the whole base, but the contract narrows
        // to the session subdirectory — including values that only resolve
        // after template expansion, since the check runs on the resolved
        // directory at the execution boundary.
        let base = std::env::temp_dir().join(format!("exectool_wd_ctx_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("session")).unwrap();
        let session_root = base.join("session").canonicalize().unwrap();

        let tool =
            tool_allowing(ArgumentPolicy::None).with_working_dirs(Sandbox::new([&base]).unwrap());
        let ctx = crate::ExecutionContract::admit(
            crate::ExecutionScope::Session(session_root.clone()),
            "shell",
            &json!({}),
            crate::ADHOC_POLICY_IDENTITY.to_string(),
        );
        let run = |dir: &std::path::Path| json!({"program": echo_path(), "working_dir": dir.to_string_lossy()});
        // Inside the session: allowed.
        assert!(tool.validate_with(&ctx, &run(&session_root)).await.is_ok());
        // Inside the tool sandbox but outside the session: denied with the
        // same stable code admission uses.
        let err = tool.validate_with(&ctx, &run(&base)).await.unwrap_err();
        assert_eq!(err.to_string(), "path_not_allowed");
        // And the denial holds at execution time, not just validation.
        let err = tool.execute_with(&ctx, run(&base)).await.unwrap_err();
        assert_eq!(err.to_string(), "path_not_allowed");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_slow_command_times_out_and_the_child_does_not_survive() {
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(sleep) = sleep else { return };

        let tool = ShellTool::new(vec![
            AllowedCommand::new(*sleep).with_arguments(ArgumentPolicy::NoFlags)
        ])
        .with_timeout(Duration::from_millis(150));

        let started = Instant::now();
        let outcome = tool
            .execute(json!({"program": sleep, "args": ["30"]}))
            .await
            .unwrap();

        assert!(!outcome.success);
        assert_eq!(outcome.error_code.as_deref(), Some("timed_out"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_a_failed_outcome_not_an_error() {
        let f = ["/usr/bin/false", "/bin/false"]
            .iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(f) = f else { return };

        let tool = ShellTool::new(vec![AllowedCommand::new(*f)]);
        let outcome = tool.execute(json!({"program": f})).await.unwrap();

        assert!(!outcome.success);
        assert_eq!(outcome.error_code.as_deref(), Some("nonzero_exit"));
        assert_ne!(outcome.summary["exit_code"], json!(0));
    }

    #[tokio::test]
    async fn non_string_arguments_are_rejected() {
        let tool = tool_allowing(ArgumentPolicy::Unrestricted);
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": [1, 2]}))
            .await
            .is_err());
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": "not an array"}))
            .await
            .is_err());
    }

    #[test]
    fn argument_policies_behave_as_documented() {
        let none = ArgumentPolicy::None;
        assert!(none.permits(&[]));
        assert!(!none.permits(&["x".into()]));

        let unrestricted = ArgumentPolicy::Unrestricted;
        assert!(unrestricted.permits(&["--anything".into()]));

        let no_flags = ArgumentPolicy::NoFlags;
        assert!(no_flags.permits(&["file.txt".into()]));
        assert!(!no_flags.permits(&["-r".into()]));
    }
}
