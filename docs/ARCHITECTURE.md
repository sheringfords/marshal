# Architecture — marshall → executor.sh

## Firecracker vs gVisor — Decision (Phase 3)

**Recommendation: Hybrid — Firecracker for `shell`, WASM for `code`.**

| Criterion | Firecracker (microVM) | gVisor (runsc) | WASM (wasmtime) |
|---|---|---|
| Isolate | VM boundary, strong | Syscall filter, medium | Language boundary, strong but limited |
| Cold start | ~150ms (snapshot < 50ms) | ~80ms | ~5ms |
| Memory | ~50MiB per VM | ~20MiB | ~2MiB |
| Syscall | Full | Filtered (~300) | No (WASI only) |
| Binary | Any Linux ELF | Any, but ptrace overhead | Only WASM |
| Ops | Need KVM, host kernel | No KVM, but seccomp ptrace cost | No extra |
| Team cost | High (image, snapshot, vsock) | Medium (runsc + cgroup) | Low |

**Why hybrid:** `ShellTool` must run arbitrary ELF (`/bin/git`, `/usr/bin/python`) — needs VM. `Code` (`python/js`) can compile to WASM via `wasm32-wasi` and run cheaper with fuel/memory limits. `backend::WasmBackend` provides fuel.

**`ContainerBackend` — watchdog wiring REMOVED (MAR-P0-002):**

The `container` feature and the `watchdog` dependency are gone. The assumed
Firecracker API (`watchdog::Pool`/`Config`/`ExecRequest`) never existed at
the pinned revision — that crate is a cgroup supervisor, not a microVM
runtime — so the feature never compiled, and the "fallback to local
execution with a warning" ran `container`-labeled work without isolation.
`ContainerBackend` is now a fail-closed placeholder: `execute` refuses with
`isolation_unavailable` on every platform, and `name()` reporting
`"container"` is honest because nothing ever executes under it. The way back
is an `ExecutionBackend` implementation against a real, published isolation
runtime (E2B or Firecracker-as-a-service per the roadmap), not a revival of
the removed wiring.

## Current Layers (P3.5 + P4)

```
Agent → JS/Python SDK → marshalld (axum 0.7)
                         ├─ Policy (marshall.yaml → ExecutionPolicy, hot-reload notify, --validate-config, code allowed_languages)
                         ├─ Egress (EgressPolicy::check + destination::validate_destination, server-side 403, batch/sequence enforced)
                         ├─ Registry (ToolRegistry, semaphore 32, execute_once dedup, execute_batch concurrent cap 64, execute_sequence ordered + templating {{steps[0].stdout}} single-pass)
                         │   ├─ FileSystemTool (Sandbox openat2 BENEATH on Linux, 12 ops: read/write/list/mkdir/delete/stat/copy/move/append/search/glob/patch, streaming read)
                         │   ├─ ShellTool → ExecutionBackend (stdin/stdin_base64 capped, cpu_time/memory_bytes → ResourceLimits)
                         │   │   ├─ LocalProcessBackend (env_clear, kill_on_drop, capped, piped stdin, ResourceLimits timeout/output_limit)
                         │   │   ├─ WasmBackend (wasmtime 22, fuel/memory, two-function WASI subset, epoch timeout)
                         │   │   └─ ContainerBackend (fail-closed placeholder: refuses with isolation_unavailable)
                         │   ├─ CodeTool → ExecutionBackend (python/javascript/bash via temp file code_<uuid>.py, sandbox working_dir, timeout 10s, output 1MiB, 64KiB cap, stdin piped)
                         │   └─ HttpTool (allowlist before DNS, pinned addrs, no redirect, headers allowlist, streaming bytes_stream body cap, CRLF check)
                         └─ Observability (tracing instrument, Prometheus /metrics histogram 7 buckets + per-tool counters, audit JSONL sha256 rotation 10MiB, Limits RLIMIT via rustix, Cors restricted GET/POST/DELETE)
```
