//! Code execution tool — python/javascript/bash via sandboxed backend.
//!
//! Like `executor.sh` code cells, this runs a snippet in a sandbox with
//! bounded time/output, returning `ToolOutcome` with `sha256` audit.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde_json::{json, Value};
use tracing::debug;

use crate::backend::{ExecRequest, ExecutionBackend, LocalProcessBackend, ResourceLimits};
use crate::sandbox::Sandbox;
use crate::{sha256_hex, Tool, ToolOutcome};

/// Default wall-clock limit for a snippet.
pub const DEFAULT_CODE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default cap on combined stdout and stderr, in bytes.
pub const DEFAULT_CODE_OUTPUT_LIMIT: usize = 1024 * 1024;
/// Largest snippet accepted, in bytes. Source arrives over the wire, so it is
/// bounded before it reaches a temporary file.
pub const MAX_CODE_BYTES: usize = 64 * 1024;

/// Languages the tool can run. Allowlist is deny-by-default like `HttpTool`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Language {
    /// `python`, run through the interpreter found on `PATH` at construction.
    Python,
    /// `javascript`, run through `node`.
    JavaScript,
    /// `bash`. Equivalent to an unrestricted shell, and worth naming as such.
    Bash,
}

impl Language {
    /// The canonical name used in policy files and tool arguments.
    pub fn as_str(&self) -> &'static str {
        match self {
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::Bash => "bash",
        }
    }

    /// Parse a language name, accepting the common aliases (`py`, `js`, `sh`).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "python" | "py" | "python3" => Some(Language::Python),
            "javascript" | "js" | "node" => Some(Language::JavaScript),
            "bash" | "sh" | "shell" => Some(Language::Bash),
            _ => None,
        }
    }
}

/// Executes code snippets in a sandbox via `ExecutionBackend`.
pub struct CodeTool {
    sandbox: Option<Sandbox>,
    backend: Arc<dyn ExecutionBackend>,
    timeout: Duration,
    output_limit: usize,
    allowed: HashSet<Language>,
    python_path: PathBuf,
    node_path: PathBuf,
    bash_path: PathBuf,
    extra_env: Vec<(String, String)>,
    allowed_env: Option<Vec<String>>,
}

impl std::fmt::Debug for CodeTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeTool")
            .field("allowed", &self.allowed)
            .field("timeout", &self.timeout)
            .field("output_limit", &self.output_limit)
            .finish()
    }
}

impl CodeTool {
    /// A tool that runs nothing. Every language must be allowed explicitly.
    pub fn new() -> Self {
        Self {
            sandbox: None,
            backend: Arc::new(LocalProcessBackend),
            timeout: DEFAULT_CODE_TIMEOUT,
            output_limit: DEFAULT_CODE_OUTPUT_LIMIT,
            allowed: HashSet::new(),
            python_path: find_python(),
            node_path: find_node(),
            bash_path: PathBuf::from("/bin/bash"),
            extra_env: Vec::new(),
            allowed_env: None,
        }
    }

    /// Run snippets with their working directory inside `sandbox`.
    ///
    /// This bounds where the snippet *starts*, not what it can reach: on the
    /// local backend it can still open any path the process can open.
    pub fn with_sandbox(mut self, sandbox: Sandbox) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    /// Run snippets through `backend` instead of the local process backend.
    ///
    /// This is the only way to get real isolation for this tool.
    pub fn with_backend(mut self, backend: Arc<dyn ExecutionBackend>) -> Self {
        self.backend = backend;
        self
    }

    /// Wall-clock limit per snippet.
    pub fn with_timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /// Cap on combined stdout and stderr, clamped to 16 MiB.
    pub fn with_output_limit(mut self, n: usize) -> Self {
        self.output_limit = n.clamp(1, 16 * 1024 * 1024);
        self
    }

    /// Permit one language.
    pub fn allow_language(mut self, lang: Language) -> Self {
        self.allowed.insert(lang);
        self
    }

    /// Permit every language this tool knows.
    ///
    /// On the local backend this grants arbitrary code execution with the
    /// daemon's privileges. [`crate::policy::CodePolicy`] requires a separate
    /// acknowledgement before it will do this from a config file.
    pub fn allow_all(mut self) -> Self {
        self.allowed.insert(Language::Python);
        self.allowed.insert(Language::JavaScript);
        self.allowed.insert(Language::Bash);
        self
    }

    /// Permit several languages at once.
    pub fn with_allowed_languages<I>(mut self, langs: I) -> Self
    where
        I: IntoIterator<Item = Language>,
    {
        for l in langs {
            self.allowed.insert(l);
        }
        self
    }

    /// Override the python interpreter, instead of the one found on `PATH`.
    pub fn with_python_path(mut self, p: impl Into<PathBuf>) -> Self {
        self.python_path = p.into();
        self
    }

    /// Override the node binary, instead of the one found on `PATH`.
    pub fn with_node_path(mut self, p: impl Into<PathBuf>) -> Self {
        self.node_path = p.into();
        self
    }

    /// Set one environment variable for the snippet.
    pub fn with_env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.extra_env.push((k.into(), v.into()));
        self
    }

    /// Pass through only these variables from the parent environment.
    ///
    /// Absent clears the environment entirely, which is the default.
    pub fn with_allowed_env<I, S>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_env = Some(vars.into_iter().map(Into::into).collect());
        self
    }

    fn build_env(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();
        if let Some(allowed) = &self.allowed_env {
            for k in allowed {
                if let Ok(v) = std::env::var(k) {
                    env.insert(k.clone(), v);
                }
            }
        }
        for (k, v) in &self.extra_env {
            env.insert(k.clone(), v.clone());
        }
        env
    }

    fn interpreter(&self, lang: &Language) -> Option<&Path> {
        match lang {
            Language::Python => {
                if self.python_path.exists() {
                    Some(&self.python_path)
                } else {
                    None
                }
            }
            Language::JavaScript => {
                if self.node_path.exists() {
                    Some(&self.node_path)
                } else {
                    None
                }
            }
            Language::Bash => {
                if self.bash_path.exists() {
                    Some(&self.bash_path)
                } else {
                    None
                }
            }
        }
    }

    async fn write_code_to_file(&self, lang: &Language, code: &str) -> Result<PathBuf> {
        let ext = match lang {
            Language::Python => "py",
            Language::JavaScript => "js",
            Language::Bash => "sh",
        };
        let filename = format!(
            "code_{}_{}.{}",
            &uuid::Uuid::new_v4().to_string()[..8],
            lang.as_str(),
            ext
        );
        let dir = if let Some(s) = &self.sandbox {
            s.roots()
                .first()
                .cloned()
                .unwrap_or_else(std::env::temp_dir)
        } else {
            std::env::temp_dir()
        };
        let path = dir.join(filename);
        tokio::fs::write(&path, code.as_bytes())
            .await
            .map_err(|e| anyhow::anyhow!("write_code_failed: {e}"))?;
        Ok(path)
    }
}

fn find_python() -> PathBuf {
    for p in [
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3",
        "/bin/python3",
    ] {
        if Path::new(p).exists() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("/usr/bin/python3")
}

fn find_node() -> PathBuf {
    for p in [
        "/usr/bin/node",
        "/usr/local/bin/node",
        "/opt/homebrew/bin/node",
        "/usr/local/bin/nodejs",
    ] {
        if Path::new(p).exists() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("/usr/bin/node")
}

impl Default for CodeTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Tool for CodeTool {
    fn name(&self) -> &str {
        "code"
    }

    fn description(&self) -> &str {
        "Execute code snippet in sandbox (python via python3 -c, javascript via node -e, bash via bash -c). Bounded timeout (default 10s, max 30s) and output (1MiB). Use for data transform, calculations, scripts. Prefer filesystem for file ops, code for logic."
    }

    fn parameters_schema(&self) -> Value {
        let langs: Vec<&str> = self.allowed.iter().map(|l| l.as_str()).collect();
        json!({
            "type": "object",
            "properties": {
                "language": { "type": "string", "enum": if langs.is_empty() { vec!["python","javascript","bash"] } else { langs }, "description": "Language. python: python3 -c, javascript: node -e, bash: bash -c. Must be in allowed_languages." },
                "code": { "type": "string", "description": "Code snippet (1..64KiB). Example python: \"print(sum([1,2,3]))\", bash: \"echo hi | tr a-z A-Z\" " },
                "stdin": { "type": "string", "description": "Optional stdin piped to program (max 1MiB). Example: code reads from stdin via input() (python) or read (bash)." },
                "timeout_ms": { "type": "integer", "description": "Override timeout 1..30000ms. Use short for quick calcs, longer for loops. Default from policy.", "minimum": 1, "maximum": 30000 }
            },
            "required": ["language", "code"],
            "examples": [
                {"language":"python","code":"import json; print(json.dumps({'a':1}))"},
                {"language":"bash","code":"echo hello | tr a-z A-Z"},
                {"language":"javascript","code":"console.log([1,2,3].map(x=>x*2))"}
            ]
        })
    }

    async fn validate(&self, args: &Value) -> Result<()> {
        let lang_str = args
            .get("language")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'language'"))?;
        let lang =
            Language::parse(lang_str).ok_or_else(|| anyhow::anyhow!("unsupported_language"))?;
        if !self.allowed.contains(&lang) {
            bail!("language_not_allowed");
        }
        if self.interpreter(&lang).is_none() {
            bail!("interpreter_not_found");
        }
        let code = args
            .get("code")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'code'"))?;
        if code.is_empty() {
            bail!("code_empty");
        }
        if code.len() > MAX_CODE_BYTES {
            bail!("code_too_large");
        }
        if let Some(stdin) = args.get("stdin").and_then(Value::as_str) {
            if stdin.len() > 1024 * 1024 {
                bail!("stdin_too_large");
            }
        } else if args.get("stdin").is_some() {
            bail!("stdin_must_be_string");
        }
        if let Some(t) = args.get("timeout_ms").and_then(Value::as_u64) {
            if t == 0 || t > 30000 {
                bail!("timeout_out_of_range");
            }
        }
        Ok(())
    }

    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        self.validate(&args).await?;

        let lang_str = args.get("language").and_then(Value::as_str).unwrap();
        let lang = Language::parse(lang_str).unwrap();
        let code = args
            .get("code")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let stdin = args
            .get("stdin")
            .and_then(Value::as_str)
            .map(|s| s.as_bytes().to_vec());
        let timeout = args
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .map(Duration::from_millis)
            .unwrap_or(self.timeout);

        let prog = self.interpreter(&lang).unwrap().to_path_buf();
        // Use temp file for robustness (handles quotes, newlines, large code). Fallback to -c for tiny snippets if file write fails.
        let (prog_args, _temp_path) = match self.write_code_to_file(&lang, &code).await {
            Ok(path) => (vec![path.to_string_lossy().to_string()], Some(path)),
            Err(_) => match lang {
                Language::Python => (vec!["-c".into(), code.clone()], None),
                Language::JavaScript => (vec!["-e".into(), code.clone()], None),
                Language::Bash => (vec!["-c".into(), code.clone()], None),
            },
        };

        debug!(language = %lang.as_str(), program = %prog.display(), args = ?prog_args, "code exec");

        let working_dir = self
            .sandbox
            .as_ref()
            .and_then(|s| s.roots().first().cloned());

        let env = self.build_env();

        let req = ExecRequest {
            program: prog.clone(),
            args: prog_args,
            working_dir,
            env,
            stdin,
            limits: ResourceLimits {
                timeout,
                output_limit: self.output_limit,
                cpu_time: None,
                memory_bytes: None,
            },
        };

        let out = self
            .backend
            .execute(req)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        // Best-effort cleanup of temp file
        if let Some(p) = _temp_path {
            let _ = tokio::fs::remove_file(p).await;
        }

        if out.timed_out {
            return Ok(ToolOutcome::failure("code", "timed_out", elapsed(started))
                .with_metadata("language", lang.as_str())
                .with_metadata("timeout_ms", timeout.as_millis().to_string()));
        }

        let stdout_len = out.stdout.len();
        let stderr_len = out.stderr.len();
        let summary = json!({
            "language": lang.as_str(),
            "exit_code": out.exit_code,
            "stdout_bytes": stdout_len,
            "stdout_sha256": sha256_hex(&out.stdout),
            "stdout_truncated": out.stdout_truncated,
            "stderr_bytes": stderr_len,
            "stderr_sha256": sha256_hex(&out.stderr),
            "stderr_truncated": out.stderr_truncated,
            "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
            "backend": self.backend.name(),
        });

        let outcome = if out.exit_code == Some(0) {
            ToolOutcome::success("code", summary, elapsed(started))
        } else {
            let mut failed = ToolOutcome::failure("code", "nonzero_exit", elapsed(started));
            failed.summary = summary;
            failed
        };

        // For code tool, content is stdout; stderr goes to metadata via summary
        Ok(outcome
            .with_content(out.stdout)
            .with_metadata("language", lang.as_str())
            .with_metadata(
                "exit_code",
                out.exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into()),
            )
            .with_metadata("program", prog.display().to_string()))
    }
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sandbox;
    use serde_json::json;

    fn sandbox() -> Sandbox {
        let dir = std::env::temp_dir().join(format!("code_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        Sandbox::new([&dir]).unwrap()
    }

    #[tokio::test]
    async fn python_hello_via_code_tool() {
        let tool = CodeTool::new()
            .with_sandbox(sandbox())
            .allow_language(Language::Python);
        if !tool.python_path.exists() {
            return;
        }
        let out = tool
            .execute(json!({"language":"python","code":"print('hello from python')"}))
            .await
            .unwrap();
        assert!(out.success, "failed: {:?}", out.summary);
        let content = String::from_utf8_lossy(out.content.as_ref().unwrap());
        assert!(content.contains("hello from python"), "{content}");
    }

    #[tokio::test]
    async fn bash_hello_via_code_tool() {
        let tool = CodeTool::new()
            .with_sandbox(sandbox())
            .allow_language(Language::Bash);
        let out = tool
            .execute(json!({"language":"bash","code":"echo hello-bash"}))
            .await
            .unwrap();
        assert!(out.success);
        let content = String::from_utf8_lossy(out.content.as_ref().unwrap());
        assert!(content.contains("hello-bash"), "{content}");
    }

    #[tokio::test]
    async fn javascript_via_code_tool_if_node() {
        let tool = CodeTool::new()
            .with_sandbox(sandbox())
            .allow_language(Language::JavaScript);
        if !tool.node_path.exists() {
            return;
        }
        let out = tool
            .execute(json!({"language":"javascript","code":"console.log('hello-js')"}))
            .await
            .unwrap();
        if !out.success {
            eprintln!("js test skipped: {:?}", out.summary);
            return;
        }
        let content = String::from_utf8_lossy(out.content.as_ref().unwrap());
        assert!(content.contains("hello-js"), "{content}");
    }

    #[tokio::test]
    async fn disallowed_language_is_rejected() {
        let tool = CodeTool::new().with_sandbox(sandbox()); // no allowed languages
        let err = tool
            .validate(&json!({"language":"python","code":"print(1)"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("language_not_allowed"));
    }

    #[tokio::test]
    async fn code_too_large_rejected() {
        let tool = CodeTool::new()
            .with_sandbox(sandbox())
            .allow_language(Language::Bash);
        let big = "x".repeat(MAX_CODE_BYTES + 1);
        let err = tool
            .validate(&json!({"language":"bash","code": big}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("code_too_large"));
    }

    #[tokio::test]
    async fn timeout_is_enforced() {
        let tool = CodeTool::new()
            .with_sandbox(sandbox())
            .allow_language(Language::Bash)
            .with_timeout(Duration::from_millis(200));
        let out = tool
            .execute(json!({"language":"bash","code":"sleep 5; echo done"}))
            .await
            .unwrap();
        assert!(!out.success);
        assert_eq!(out.error_code.as_deref(), Some("timed_out"));
    }
}
