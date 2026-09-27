#![allow(missing_docs)]
//! Execution backend abstraction — Phase 1 isolation layer.
//!
//! `ShellTool` previously spawned `tokio::process::Command` directly.
//! That couples policy (which binary) to mechanism (how it runs). To become
//! an `executor.sh` class runtime we need:
//!
//! ```text
//! ToolRegistry -> ShellTool (policy) -> ExecutionBackend (mechanism)
//!                                    ├─ LocalProcessBackend (dev, current)
//!                                    ├─ WasmBackend (wasmtime fuel/memory)
//!                                    └─ ContainerBackend (fail-closed placeholder;
//!                                       no isolation runtime is wired yet)
//! ```
//!
//! This module provides the trait and the `LocalProcessBackend` implementation.
//! `WasmBackend` runs wasm modules behind the `wasm` feature flag (wasmtime
//! with fuel, memory, and epoch-timeout enforcement, and a two-function WASI
//! subset) — without the feature the type exists but returns `unsupported`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
#[cfg(feature = "wasm")]
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
#[allow(unused_imports)]
use std::os::unix::process::CommandExt;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[cfg(feature = "wasm")]
use std::sync::Mutex;
#[cfg(feature = "wasm")]
use wasmtime::{Caller, Config, Engine, Linker, Module, Store};

use crate::{sha256_hex, ToolOutcome};

/// Limits applied to a single execution.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Wall-clock timeout. Child is killed on expiry (`kill_on_drop`).
    pub timeout: Duration,
    /// Per-stream capture cap (`stdout`/`stderr`).
    pub output_limit: usize,
    /// Optional CPU time limit (enforced by backend, e.g. wasmtime fuel or cgroup).
    pub cpu_time: Option<Duration>,
    /// Optional memory limit in bytes (backend-enforced).
    pub memory_bytes: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            output_limit: 1024 * 1024,
            cpu_time: None,
            memory_bytes: None,
        }
    }
}

/// What to run.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// Absolute path to binary or wasm module.
    pub program: PathBuf,
    /// Arguments (already validated by `ArgumentPolicy`).
    pub args: Vec<String>,
    /// Working directory, already resolved inside `Sandbox`.
    pub working_dir: Option<PathBuf>,
    /// Environment. Empty means `env_clear` (P0.1).
    pub env: HashMap<String, String>,
    /// Optional stdin bytes (capped by `ShellTool::stdin_limit`).
    pub stdin: Option<Vec<u8>>,
    /// Resource limits.
    pub limits: ResourceLimits,
}

/// What ran.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// Exit code, `None` if terminated by signal.
    pub exit_code: Option<i32>,
    /// Captured stdout (capped).
    pub stdout: Vec<u8>,
    /// Captured stderr (capped).
    pub stderr: Vec<u8>,
    /// Whether stdout was truncated at `output_limit`.
    pub stdout_truncated: bool,
    /// Whether stderr was truncated.
    pub stderr_truncated: bool,
    /// Whether the execution timed out.
    pub timed_out: bool,
}

/// Backend that actually runs the request.
///
/// `LocalProcessBackend` is the current behaviour. `WasmBackend` enforces
/// fuel/memory/epoch limits on wasm modules; `ContainerBackend` is a
/// fail-closed placeholder until a real isolation runtime is integrated.
#[async_trait::async_trait]
pub trait ExecutionBackend: Send + Sync + std::fmt::Debug {
    /// Human name for metrics/tracing (`local`, `wasm`, `container`).
    fn name(&self) -> &str;

    /// Execute `req` and return `ExecOutput`. Backend must enforce `limits.timeout`
    /// and `limits.output_limit` and kill the child on timeout.
    async fn execute(&self, req: ExecRequest) -> anyhow::Result<ExecOutput>;

    /// Streaming variant — default impl buffers then yields one chunk per stream.
    /// Backends that support true streaming (e.g. container) should override.
    async fn execute_streaming(&self, req: ExecRequest) -> anyhow::Result<StreamingOutput> {
        let out = self.execute(req).await?;
        Ok(StreamingOutput::buffered(out))
    }
}

/// Handle for streaming output. For P1 we expose a simple buffered impl that
/// satisfies the `Stream<Item=Bytes>` shape `executor.sh` needs without requiring
/// `async-stream` dep yet. Phase 2 will wire `tokio::sync::mpsc` + `axum` SSE.
#[derive(Debug)]
pub struct StreamingOutput {
    /// Buffered output (Phase 1). Phase 2 will make this a `Receiver<Chunk>`.
    pub buffered: Option<ExecOutput>,
    /// Chunks yielded so far (for testing).
    pub chunks: Vec<StreamChunk>,
}

/// One chunk of streaming output.
#[derive(Debug, Clone)]
pub struct StreamChunk {
    /// `stdout` or `stderr`.
    pub stream: StreamKind,
    /// Bytes in this chunk.
    pub bytes: Vec<u8>,
    /// SHA256 of chunk (for verifiable audit).
    pub sha256: String,
}

/// Which stream a chunk belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Stdout,
    Stderr,
}

impl StreamingOutput {
    /// Create a buffered streaming output (one chunk per stream).
    pub fn buffered(out: ExecOutput) -> Self {
        let mut chunks = Vec::new();
        if !out.stdout.is_empty() {
            chunks.push(StreamChunk {
                stream: StreamKind::Stdout,
                sha256: sha256_hex(&out.stdout),
                bytes: out.stdout.clone(),
            });
        }
        if !out.stderr.is_empty() {
            chunks.push(StreamChunk {
                stream: StreamKind::Stderr,
                sha256: sha256_hex(&out.stderr),
                bytes: out.stderr.clone(),
            });
        }
        Self {
            buffered: Some(out),
            chunks,
        }
    }
}

// ---------------------------------------------------------------------------
// LocalProcessBackend — current behaviour extracted from `shell.rs`
// ---------------------------------------------------------------------------

/// Runs the binary as a child process with `env_clear`, `kill_on_drop`, capped I/O.
#[derive(Debug, Default, Clone)]
pub struct LocalProcessBackend;

#[async_trait::async_trait]
impl ExecutionBackend for LocalProcessBackend {
    fn name(&self) -> &str {
        "local"
    }

    async fn execute(&self, req: ExecRequest) -> anyhow::Result<ExecOutput> {
        let mut cmd = Command::new(&req.program);
        cmd.args(&req.args)
            .stdin(if req.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear();
        for (k, v) in &req.env {
            cmd.env(k, v);
        }
        if let Some(dir) = &req.working_dir {
            cmd.current_dir(dir);
        }
        // Per-child resource limits via pre_exec (Unix only) — closes gap where Limits::apply_rlimits was server-wide
        #[cfg(unix)]
        {
            let cpu = req.limits.cpu_time;
            let mem = req.limits.memory_bytes;
            // SAFETY: pre_exec runs after fork but before exec, must not allocate or use async
            unsafe {
                cmd.pre_exec(move || {
                    if let Some(d) = cpu {
                        let secs = d.as_secs();
                        // Use rustix to set RLIMIT_CPU in child
                        let limit = rustix::process::Rlimit {
                            current: Some(secs),
                            maximum: Some(secs.saturating_add(1)),
                        };
                        let _ = rustix::process::setrlimit(rustix::process::Resource::Cpu, limit);
                    }
                    if let Some(bytes) = mem {
                        let limit = rustix::process::Rlimit {
                            current: Some(bytes),
                            maximum: Some(bytes),
                        };
                        // RLIMIT_AS for address space
                        let _ = rustix::process::setrlimit(rustix::process::Resource::As, limit);
                    }
                    Ok(())
                });
            }
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(program = %req.program.display(), error = %e, "spawn failed");
                return Err(anyhow::anyhow!("spawn_failed: {e}"));
            }
        };
        // Feed stdin if provided
        if let Some(stdin_bytes) = req.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                let _ = stdin.write_all(&stdin_bytes).await;
                // stdin dropped here closes pipe
            }
        }
        let mut stdout = child.stdout.take().expect("stdout piped");
        let mut stderr = child.stderr.take().expect("stderr piped");
        let limit = req.limits.output_limit;
        let timeout = req.limits.timeout;

        let collect = async {
            let (out, err) = tokio::join!(
                read_capped(&mut stdout, limit),
                read_capped(&mut stderr, limit)
            );
            let status = child.wait().await?;
            std::io::Result::Ok((status, out?, err?))
        };

        match tokio::time::timeout(timeout, collect).await {
            Err(_) => Ok(ExecOutput {
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                timed_out: true,
            }),
            Ok(Err(e)) => Err(anyhow::anyhow!("io_error: {e}")),
            Ok(Ok((status, (out, out_trunc), (err, err_trunc)))) => Ok(ExecOutput {
                exit_code: status.code(),
                stdout: out,
                stderr: err,
                stdout_truncated: out_trunc,
                stderr_truncated: err_trunc,
                timed_out: false,
            }),
        }
    }
}

async fn read_capped<R>(reader: &mut R, limit: usize) -> std::io::Result<(Vec<u8>, bool)>
where
    R: AsyncReadExt + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() < limit {
            let room = limit - buf.len();
            buf.extend_from_slice(&chunk[..n.min(room)]);
            if n > room {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok((buf, truncated))
}

impl ExecOutput {
    /// Convert to `ToolOutcome` (`shell` shape) without leaking paths.
    pub fn into_outcome(self, started_ms: u64) -> ToolOutcome {
        if self.timed_out {
            return ToolOutcome::failure("shell", "timed_out", started_ms);
        }
        let summary = serde_json::json!({
            "exit_code": self.exit_code,
            "stdout_bytes": self.stdout.len(),
            "stdout_sha256": sha256_hex(&self.stdout),
            "stdout_truncated": self.stdout_truncated,
            "stderr_bytes": self.stderr.len(),
            "stderr_sha256": sha256_hex(&self.stderr),
            "stderr_truncated": self.stderr_truncated,
            "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
        });
        let outcome = if self.exit_code == Some(0) {
            ToolOutcome::success("shell", summary, started_ms)
        } else {
            let mut failed = ToolOutcome::failure("shell", "nonzero_exit", started_ms);
            failed.summary = summary;
            failed
        };
        outcome.with_content(self.stdout.clone()).with_metadata(
            "exit_code",
            self.exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into()),
        )
    }
}

// ---------------------------------------------------------------------------
// WasmBackend — scaffolded, real impl behind `wasm` feature (wasmtime)
// ---------------------------------------------------------------------------

/// WASM execution backend: runs a WebAssembly module file with wasmtime.
///
/// The guest gets a deliberately minimal `wasi_snapshot_preview1` subset —
/// `fd_write` (fd 1/2 only, into the capped stdout/stderr buffers) and
/// `proc_exit` — and nothing else: no filesystem, no network, no clocks, no
/// args/environ, no other WASI interface. A module importing anything beyond
/// those two functions fails to link. Entry point is `_start`, falling back
/// to `run`/`_run`.
///
/// Limits: `fuel` (or `limits.cpu_time` converted at 10_000 fuel/ms) bounds
/// instructions, `memory_limit` (or `limits.memory_bytes`, unbounded when
/// neither is set) caps linear memory via a `ResourceLimiter`, and
/// `limits.timeout` is enforced by epoch interruption. Fuel/epoch exhaustion
/// reports `timed_out: true` with no exit code, matching the local backend's
/// timeout shape. Without the `wasm` feature this always returns
/// `unsupported` — fail-closed, never silent.
///
/// Motorcycle-shed honesty: this is language-agnostic at the wasm level
/// (anything that compiles to a freestanding wasm module using only those
/// two imports runs), but it is not a Python/JS runtime — there is no
/// interpreter embedded. Execution is synchronous on the calling task.
#[derive(Debug, Default, Clone)]
pub struct WasmBackend {
    /// Fuel limit (wasmtime) — maps to `ResourceLimits.cpu_time`.
    pub fuel: Option<u64>,
    /// Memory limit in bytes.
    pub memory_limit: Option<u64>,
}

#[async_trait::async_trait]
impl ExecutionBackend for WasmBackend {
    fn name(&self) -> &str {
        "wasm"
    }

    async fn execute(&self, req: ExecRequest) -> anyhow::Result<ExecOutput> {
        #[cfg(feature = "wasm")]
        {
            return execute_wasm(req, self.fuel, self.memory_limit).await;
        }
        #[cfg(not(feature = "wasm"))]
        {
            let _ = req;
            anyhow::bail!(
                "wasm backend not enabled: rebuild with --features wasm (requires wasmtime)"
            )
        }
    }
}

#[cfg(feature = "wasm")]
async fn execute_wasm(
    req: ExecRequest,
    fuel: Option<u64>,
    memory_limit: Option<u64>,
) -> anyhow::Result<ExecOutput> {
    let wasm_bytes = tokio::fs::read(&req.program)
        .await
        .map_err(|e| anyhow::anyhow!("wasm read failed: {e}"))?;
    let effective_fuel =
        fuel.or_else(|| req.limits.cpu_time.map(|d| d.as_millis() as u64 * 10_000));
    let effective_mem = memory_limit.or(req.limits.memory_bytes);

    let mut config = Config::new();
    config.consume_fuel(effective_fuel.is_some());
    config.epoch_interruption(true);
    config.async_support(false);
    let engine = Engine::new(&config).map_err(|e| anyhow::anyhow!("engine: {e}"))?;

    let module = Module::new(&engine, &wasm_bytes).map_err(|e| anyhow::anyhow!("module: {e}"))?;

    struct StoreData {
        stdout: Arc<Mutex<Vec<u8>>>,
        stderr: Arc<Mutex<Vec<u8>>>,
        output_limit: usize,
        limiter: MemoryLimiter,
    }

    let stdout_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    let stdout_clone = stdout_buf.clone();
    let stderr_clone = stderr_buf.clone();
    let output_limit = req.limits.output_limit;
    let mem_limit = effective_mem.unwrap_or(u64::MAX);

    let mut store = Store::new(
        &engine,
        StoreData {
            stdout: stdout_clone,
            stderr: stderr_clone,
            output_limit,
            limiter: MemoryLimiter { limit: mem_limit },
        },
    );

    if let Some(f) = effective_fuel {
        store
            .set_fuel(f)
            .map_err(|e| anyhow::anyhow!("fuel: {e}"))?;
    }

    // Memory limiter
    store.limiter(|data| &mut data.limiter as &mut dyn wasmtime::ResourceLimiter);

    // Wall-clock timeout via epoch interruption. The call itself is
    // synchronous and may never return on its own, so it runs on a blocking
    // thread while this task watches the clock: on timeout the epoch is
    // incremented, which traps the module promptly, and the blocking thread
    // unwinds with that trap. (A `tokio::spawn` timer alone is not enough:
    // on a single-threaded runtime it would never run while the guest
    // spins, hanging the caller instead of timing it out.)
    let timeout = req.limits.timeout;
    let engine_clone = engine.clone();
    store.set_epoch_deadline(1);

    let mut linker = Linker::new(&engine);

    // Minimal WASI preview1 host functions for the hello test
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_write",
            move |mut caller: Caller<StoreData>,
                  fd: i32,
                  iovs: i32,
                  iovs_len: i32,
                  nwritten: i32| {
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| anyhow::anyhow!("no memory"))?;
                let data = memory.data(&caller);
                let mut total_written = 0usize;
                for i in 0..iovs_len {
                    let iovs_ptr = iovs as usize + (i as usize * 8);
                    if iovs_ptr + 8 > data.len() {
                        return Err(anyhow::anyhow!("iovs out of bounds"));
                    }
                    let ptr = u32::from_le_bytes(data[iovs_ptr..iovs_ptr + 4].try_into().unwrap())
                        as usize;
                    let len =
                        u32::from_le_bytes(data[iovs_ptr + 4..iovs_ptr + 8].try_into().unwrap())
                            as usize;
                    if ptr + len > data.len() {
                        return Err(anyhow::anyhow!("iovs data out of bounds"));
                    }
                    let bytes = &data[ptr..ptr + len];
                    let output_limit = caller.data().output_limit;
                    let buf = if fd == 1 {
                        &caller.data().stdout
                    } else if fd == 2 {
                        &caller.data().stderr
                    } else {
                        continue;
                    };
                    let mut guard = buf.lock().unwrap();
                    let remaining = output_limit.saturating_sub(guard.len());
                    let to_write = remaining.min(bytes.len());
                    guard.extend_from_slice(&bytes[..to_write]);
                    total_written += to_write;
                }
                // Write nwritten to memory
                let mem_mut = memory.data_mut(&mut caller);
                if nwritten as usize + 4 <= mem_mut.len() {
                    mem_mut[nwritten as usize..nwritten as usize + 4]
                        .copy_from_slice(&(total_written as u32).to_le_bytes());
                }
                Ok(0)
            },
        )
        .map_err(|e| anyhow::anyhow!("link fd_write: {e}"))?;

    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "proc_exit",
            |code: i32| -> anyhow::Result<()> { anyhow::bail!("wasi_exit:{code}") },
        )
        .map_err(|e| anyhow::anyhow!("link proc_exit: {e}"))?;

    // Also handle fd_close, fd_seek etc as no-ops for minimal WASI if needed, but hello only uses fd_write and proc_exit.

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| anyhow::anyhow!("instantiate: {e}"))?;

    let start = instance
        .get_func(&mut store, "_start")
        .or_else(|| instance.get_func(&mut store, "run"))
        .or_else(|| instance.get_func(&mut store, "_run"))
        .ok_or_else(|| anyhow::anyhow!("wasm module has no _start/run export"))?;

    let result = {
        let mut call = tokio::task::spawn_blocking(move || start.call(&mut store, &[], &mut []));
        tokio::select! {
            joined = &mut call => {
                joined.map_err(|e| anyhow::anyhow!("wasm join: {e}"))?
            }
            _ = tokio::time::sleep(timeout) => {
                engine_clone.increment_epoch();
                // The epoch trap stops the module; wait for it to unwind.
                call.await.map_err(|e| anyhow::anyhow!("wasm join: {e}"))?
            }
        }
    };

    // wasmtime wraps host-function failures (including our `proc_exit`
    // sentinel) in a trap error, so every match below walks the whole error
    // chain instead of only the top-level message.
    fn chain_text(e: &anyhow::Error) -> String {
        e.chain()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    let exit_code = match result {
        Ok(_) => Some(0),
        Err(e) => {
            let chained = chain_text(&e);
            let lower = chained.to_ascii_lowercase();
            let limit_exhausted = lower.contains("fuel")
                || lower.contains("epoch")
                || lower.contains("deadline")
                || lower.contains("interrupt");
            if let Some(code) = e.chain().find_map(|c| {
                c.to_string()
                    .split("wasi_exit:")
                    .nth(1)
                    .and_then(|s| s.trim().parse::<i32>().ok())
            }) {
                Some(code)
            } else if limit_exhausted {
                let stdout = stdout_buf.lock().unwrap().clone();
                let stderr = stderr_buf.lock().unwrap().clone();
                let (out, out_trunc) = truncate_bytes(stdout, output_limit);
                let (err, err_trunc) = truncate_bytes(stderr, output_limit);
                return Ok(ExecOutput {
                    exit_code: None,
                    stdout: out,
                    stderr: if err.is_empty() {
                        format!("fuel or epoch exhausted: {e:#}").into_bytes()
                    } else {
                        err
                    },
                    stdout_truncated: out_trunc,
                    stderr_truncated: err_trunc,
                    timed_out: true,
                });
            } else {
                // A real guest trap (or link-time surprise at call time):
                // keep any guest stderr, otherwise say what trapped so the
                // caller is not left with a bare exit code.
                let trap_note = format!("wasm trap: {e:#}");
                let mut err_bytes = stderr_buf.lock().unwrap().clone();
                if err_bytes.is_empty() {
                    err_bytes = trap_note.into_bytes();
                }
                let stdout = stdout_buf.lock().unwrap().clone();
                let (out, out_trunc) = truncate_bytes(stdout, output_limit);
                let (err, err_trunc) = truncate_bytes(err_bytes, output_limit);
                return Ok(ExecOutput {
                    exit_code: Some(1),
                    stdout: out,
                    stderr: err,
                    stdout_truncated: out_trunc,
                    stderr_truncated: err_trunc,
                    timed_out: false,
                });
            }
        }
    };

    let stdout = stdout_buf.lock().unwrap().clone();
    let stderr = stderr_buf.lock().unwrap().clone();
    let (out, out_trunc) = truncate_bytes(stdout, output_limit);
    let (err, err_trunc) = truncate_bytes(stderr, output_limit);

    Ok(ExecOutput {
        exit_code,
        stdout: out,
        stderr: err,
        stdout_truncated: out_trunc,
        stderr_truncated: err_trunc,
        timed_out: false,
    })
}
#[cfg(feature = "wasm")]
struct MemoryLimiter {
    limit: u64,
}
#[cfg(feature = "wasm")]
impl wasmtime::ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _max: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok((desired as u64) <= self.limit)
    }
    fn table_growing(
        &mut self,
        _current: u32,
        desired: u32,
        _max: Option<u32>,
    ) -> anyhow::Result<bool> {
        // Cap tables similarly to prevent DoS via huge tables
        Ok((desired as u64) <= 10_000)
    }
}
#[cfg(feature = "wasm")]
fn truncate_bytes(mut v: Vec<u8>, limit: usize) -> (Vec<u8>, bool) {
    if v.len() > limit {
        v.truncate(limit);
        (v, true)
    } else {
        (v, false)
    }
}

// ---------------------------------------------------------------------------
// ContainerBackend — fail-closed placeholder (MAR-P0-002)
// ---------------------------------------------------------------------------

/// Container/microVM backend: currently a fail-closed placeholder.
///
/// History: this type used to delegate to a `watchdog` crate behind the
/// `container` feature, falling back to [`LocalProcessBackend`] with a
/// warning when KVM was unavailable. That wiring was removed because the
/// dependency it assumed does not exist — the pinned `watchdog` revision
/// exposes a cgroup-supervisor API (`Supervisor`, `Bounds`), not the
/// Firecracker `Pool`/`Config`/`ExecRequest` API the code called, so the
/// feature never compiled, and the fallback silently ran isolated-labeled
/// work without isolation.
///
/// Until a real, published isolation integration lands, `execute` refuses
/// every request with an `isolation_unavailable` error instead of running
/// it anywhere. The builder fields are kept so call sites and policy shapes
/// survive the eventual integration. `name()` still reports `"container"`,
/// and because nothing ever executes under it, the identity is honest: no
/// outcome is ever attributed to isolation that did not happen.
#[derive(Debug, Clone, Default)]
pub struct ContainerBackend {
    /// Image or microVM kernel path (e.g. "alpine:3.19" or "/path/to/vmlinux").
    pub image: Option<String>,
    /// Kernel path for Firecracker (if None, uses watchdog default).
    pub kernel: Option<PathBuf>,
    /// Rootfs path for Firecracker.
    pub rootfs: Option<PathBuf>,
    /// Vsock path for Firecracker communication.
    pub vsock: Option<PathBuf>,
}

impl ContainerBackend {
    /// Create with an image/kernel.
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: Some(image.into()),
            ..Default::default()
        }
    }

    /// Set kernel path.
    pub fn with_kernel(mut self, path: impl Into<PathBuf>) -> Self {
        self.kernel = Some(path.into());
        self
    }

    /// Set rootfs path.
    pub fn with_rootfs(mut self, path: impl Into<PathBuf>) -> Self {
        self.rootfs = Some(path.into());
        self
    }

    #[cfg(target_os = "linux")]
    fn is_kvm_available() -> bool {
        std::path::Path::new("/dev/kvm").exists()
    }

    #[cfg(not(target_os = "linux"))]
    fn is_kvm_available() -> bool {
        false
    }
}

#[async_trait::async_trait]
impl ExecutionBackend for ContainerBackend {
    fn name(&self) -> &str {
        "container"
    }

    async fn execute(&self, req: ExecRequest) -> anyhow::Result<ExecOutput> {
        let _ = req;
        // Fail closed. An earlier revision fell back to LocalProcessBackend
        // here with a warning; a warning is not a control, and the response
        // still claimed the `container` backend. Refusing is the only honest
        // behaviour until a real isolation integration exists.
        if Self::is_kvm_available() {
            anyhow::bail!(
                "isolation_unavailable: container backend has no isolation integration \
                 (kvm present but no runtime wired); refusing to execute"
            )
        } else {
            anyhow::bail!(
                "isolation_unavailable: container backend requires Linux KVM and an \
                 isolation runtime; refusing to execute (no local fallback)"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn local_backend_runs_echo() {
        let echo = if std::path::Path::new("/bin/echo").exists() {
            "/bin/echo"
        } else {
            "/usr/bin/echo"
        };
        let backend = LocalProcessBackend;
        let out = backend
            .execute(ExecRequest {
                program: echo.into(),
                args: vec!["hello".into()],
                working_dir: None,
                env: HashMap::new(),
                stdin: None,
                limits: ResourceLimits {
                    timeout: Duration::from_secs(2),
                    output_limit: 1024 * 1024,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("hello"));
        assert!(!out.timed_out);
    }

    #[tokio::test]
    async fn local_backend_times_out() {
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap();
        let backend = LocalProcessBackend;
        let out = backend
            .execute(ExecRequest {
                program: (*sleep).into(),
                args: vec!["30".into()],
                working_dir: None,
                env: HashMap::new(),
                stdin: None,
                limits: ResourceLimits {
                    timeout: Duration::from_millis(150),
                    output_limit: 1024,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert!(out.timed_out);
    }

    #[tokio::test]
    #[cfg(not(feature = "wasm"))]
    async fn wasm_backend_without_feature_is_unsupported() {
        let backend = WasmBackend::default();
        let err = backend
            .execute(ExecRequest {
                program: "/tmp/fake.wasm".into(),
                args: vec![],
                working_dir: None,
                env: HashMap::new(),
                stdin: None,
                limits: ResourceLimits::default(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("wasm backend not enabled"));
    }

    #[tokio::test]
    async fn container_backend_refuses_rather_than_falling_back() {
        // MAR-P0-002: requesting the container backend must never silently
        // run the workload locally. It refuses on every platform — including
        // Linux with KVM, where there is still no runtime wired.
        let backend = ContainerBackend::new("alpine:3.19")
            .with_kernel("/tmp/vmlinux")
            .with_rootfs("/tmp/alpine.ext4");
        assert_eq!(backend.image.as_deref(), Some("alpine:3.19"));
        assert_eq!(
            backend.kernel.as_deref(),
            Some(std::path::Path::new("/tmp/vmlinux"))
        );
        assert_eq!(backend.name(), "container");
        let echo = if std::path::Path::new("/bin/echo").exists() {
            "/bin/echo"
        } else {
            "/usr/bin/echo"
        };
        let err = backend
            .execute(ExecRequest {
                program: echo.into(),
                args: vec!["hello".into()],
                working_dir: None,
                env: HashMap::new(),
                stdin: None,
                limits: ResourceLimits {
                    timeout: Duration::from_secs(2),
                    output_limit: 1024 * 1024,
                    ..Default::default()
                },
            })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("isolation_unavailable"),
            "container backend did not fail closed: {err}"
        );
    }

    #[tokio::test]
    async fn shell_tool_on_the_container_backend_reports_unavailable() {
        // End to end through `ShellTool`: no process spawns, and the caller
        // learns the backend — not a tool failure — is unavailable.
        use crate::shell::AllowedCommand;
        use crate::{ArgumentPolicy, ShellTool, Tool};
        let echo = if std::path::Path::new("/bin/echo").exists() {
            "/bin/echo"
        } else {
            "/usr/bin/echo"
        };
        let tool = ShellTool::new(vec![
            AllowedCommand::new(echo).with_arguments(ArgumentPolicy::NoFlags)
        ])
        .with_backend(std::sync::Arc::new(ContainerBackend::default()));
        let err = tool
            .execute(serde_json::json!({"program": echo, "args": ["hi"]}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("isolation_unavailable"),
            "shell did not surface the backend refusal: {err}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn wasm_backend_runs_hello() {
        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
            (memory 1)
            (export "memory" (memory 0))
            (data (i32.const 8) "hello wasm\n")
            (func $_start (export "_start")
                (i32.store (i32.const 0) (i32.const 8))
                (i32.store (i32.const 4) (i32.const 11))
                (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 20)))
                (call $proc_exit (i32.const 0))
            )
        )"#;
        let wasm = wat::parse_str(wat).unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "wasm_hello_{}_{}.wasm",
            std::process::id(),
            uuid_simple()
        ));
        std::fs::write(&tmp, &wasm).unwrap();
        let backend = WasmBackend {
            fuel: Some(1_000_000),
            memory_limit: Some(16 * 1024 * 1024),
        };
        let out = backend
            .execute(ExecRequest {
                program: tmp.clone(),
                args: vec![],
                working_dir: None,
                env: HashMap::new(),
                stdin: None,
                limits: ResourceLimits {
                    timeout: std::time::Duration::from_secs(2),
                    output_limit: 1024 * 1024,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(out.exit_code, Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("hello wasm"));
        assert!(!out.timed_out);
    }

    #[cfg(feature = "wasm")]
    fn uuid_simple() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!(
            "{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Write `wat` to a unique temp file and return its path. The caller
    /// removes the file; a leak on panic is acceptable in tests.
    #[cfg(feature = "wasm")]
    fn write_wasm_module(name: &str, wat: &str) -> std::path::PathBuf {
        let wasm = wat::parse_str(wat).unwrap();
        let tmp = std::env::temp_dir().join(format!("wasm_{name}_{}.wasm", uuid_simple()));
        std::fs::write(&tmp, &wasm).unwrap();
        tmp
    }

    #[cfg(feature = "wasm")]
    fn wasm_request(program: std::path::PathBuf, timeout: Duration) -> ExecRequest {
        ExecRequest {
            program,
            args: vec![],
            working_dir: None,
            env: HashMap::new(),
            stdin: None,
            limits: ResourceLimits {
                timeout,
                output_limit: 1024 * 1024,
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn wasm_fuel_exhaustion_is_reported_as_timeout() {
        // An infinite loop with almost no fuel must trap on fuel, which the
        // backend reports as a timeout (killed by limits, no exit code).
        let wat = r#"(module
            (func $_start (export "_start")
                (loop $spin (br $spin))
            )
        )"#;
        let tmp = write_wasm_module("fuel", wat);
        let backend = WasmBackend {
            fuel: Some(100),
            memory_limit: Some(16 * 1024 * 1024),
        };
        let out = backend
            .execute(wasm_request(tmp.clone(), Duration::from_secs(10)))
            .await
            .unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert!(out.timed_out, "fuel exhaustion was not reported: {out:?}");
        assert_eq!(out.exit_code, None);
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn wasm_wall_clock_timeout_fires_without_fuel() {
        // Generous fuel but a short wall-clock deadline: the epoch
        // interruption must still stop the module and report a timeout.
        let wat = r#"(module
            (func $_start (export "_start")
                (loop $spin (br $spin))
            )
        )"#;
        let tmp = write_wasm_module("epoch", wat);
        let backend = WasmBackend {
            fuel: None,
            memory_limit: Some(16 * 1024 * 1024),
        };
        let out = backend
            .execute(wasm_request(tmp.clone(), Duration::from_millis(300)))
            .await
            .unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert!(out.timed_out, "epoch timeout was not reported: {out:?}");
        assert_eq!(out.exit_code, None);
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn wasm_memory_limit_is_enforced() {
        // One page of memory, then a grow far past the 64 KiB limit. A
        // refused grow returns -1 rather than trapping, so the module turns
        // that into an `unreachable` trap — the point is the grow must not
        // succeed and `_start` must not exit 0.
        let wat = r#"(module
            (memory 1)
            (export "memory" (memory 0))
            (func $_start (export "_start")
                (if (i32.eq (memory.grow (i32.const 100)) (i32.const -1))
                    (then (unreachable))
                )
            )
        )"#;
        let tmp = write_wasm_module("memory", wat);
        let backend = WasmBackend {
            fuel: Some(1_000_000),
            memory_limit: Some(64 * 1024),
        };
        let out = backend
            .execute(wasm_request(tmp.clone(), Duration::from_secs(5)))
            .await
            .unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_ne!(
            out.exit_code,
            Some(0),
            "memory growth past the limit succeeded: {out:?}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn wasm_module_without_an_entry_point_is_a_structured_error() {
        let wat = r#"(module (memory 1) (export "memory" (memory 0)))"#;
        let tmp = write_wasm_module("noentry", wat);
        let backend = WasmBackend::default();
        let err = backend
            .execute(wasm_request(tmp.clone(), Duration::from_secs(5)))
            .await
            .unwrap_err();
        let _ = std::fs::remove_file(&tmp);
        assert!(
            err.to_string().contains("no _start"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn wasm_guest_has_no_filesystem_imports() {
        // The backend exposes only `fd_write` and `proc_exit`: a module
        // importing anything else (here `path_open`) must fail to link.
        // That is the whole filesystem preopen story — there is nothing to
        // preopen because no filesystem interface exists.
        let wat = r#"(module
            (import "wasi_snapshot_preview1" "path_open"
                (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
            (memory 1)
            (export "memory" (memory 0))
            (func $_start (export "_start")
                (drop (call $path_open
                    (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                    (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 0)))
            )
        )"#;
        let tmp = write_wasm_module("nofs", wat);
        let backend = WasmBackend::default();
        let err = backend
            .execute(wasm_request(tmp.clone(), Duration::from_secs(5)))
            .await
            .unwrap_err();
        let _ = std::fs::remove_file(&tmp);
        let msg = err.to_string();
        assert!(
            msg.contains("path_open") || msg.contains("unknown import"),
            "filesystem import was not refused at link time: {msg}"
        );
    }
}
