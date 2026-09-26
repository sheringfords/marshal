# 02 — Execution Architecture

## Request flow

```
Agent → JS/Python SDK (no policy, no auth header)
  → marshalld (axum 0.7) routes src/server.rs:1542-1559
    → check_auth (bearer, constant-shape) :124-156
    → check_rate_limit (per-client token bucket) :182-206
    → semaphore try_acquire_owned (503 on exhaustion) :608,771,951,1094
    → session + egress pre-checks (execute/batch/sequence ONLY)
    → ToolRegistry::execute / execute_batch / execute_sequence / execute_once
      → tool.validate(args) then tool.execute(args) (dual validation intentional, registry.rs:142-143)
        → ShellTool/CodeTool → ExecutionBackend (Local | Wasm | Container)
```

- SDKs are thin JSON clients: `sdk/js/index.js:37-107`, `sdk/python/marshall_sdk.py:32-98`. Neither sends `Authorization` (MAR-P1-004).
- `ShellTool::validate:414-416` → `parse:291-367`; `execute:418-493` re-parses (`:420`) then builds `ExecRequest:430-442` → `backend.execute`.
- `CodeTool::validate:320-356`; `execute:358-464` re-validates (`:360`), writes `code_<uuid>.py` tempfile (`:381-388`), delegates to backend (`:413-417`), best-effort cleanup (`:420-422`).
- `LocalProcessBackend:176-278`: `env_clear` + `kill_on_drop` (`:191-192`), Unix `pre_exec` RLIMIT_CPU/AS (`:199-227`), `read_capped` (`:280-303`), `tokio::time::timeout` (`:258-266`).

## Endpoints

| Route | Handler | Pre-checks |
|---|---|---|
| `GET /health`, `GET /metrics` | `:435-452` | none (intentional; metrics leaks per-tool counts) |
| `POST /v1/execute` | `:594-738` | auth, quota, semaphore, session purge+lookup+path check, destination+egress, idempotency, audit, metrics |
| `POST /v1/execute/batch` | `:740-923` | same set (per-step session/egress loops `:800-894`) |
| `POST /v1/execute/sequence` | `:925-1078` | same set (`:967-1042`) |
| `POST /v1/execute/stream` | `:1082-1161` | **auth + quota + semaphore only** — MAR-P0-003 |
| `POST /v1/sessions`, `DELETE /v1/sessions/:id` | `:487-510,:1163-1191` | blocking `std::fs` inside async handlers |
| `GET /v1/policy` | `:1561-1584` | reads hardcoded CWD `marshall.yaml` (`:1573`), not the served config path; returns defaults if missing |

Router: `src/server.rs:1542-1559`. CORS: none unless `MARSHALLD_CORS_ORIGIN` exact match (`:1508-1529`). Bind: loopback default, non-loopback refused without token (`:98-121`).

## Batch / sequence / idempotency / SSE

- **Batch** (`registry.rs:203-243`): rejects >64, `clamp(1,32)` concurrency, `tokio::spawn` per item, results re-ordered to input order. Server holds **1** semaphore permit for up to 32-way fan-out — noted in code as blow-up (`server.rs:767-784`).
- **Sequence** (`registry.rs:254-290`): cap 32, single-pass templating (32 placeholders, fields `stdout|content|output|summary|success|error_code|tool|duration_ms`), stops on first failure unless `continue_on_error`. Server default `unwrap_or(false)` (`server.rs:1043`) contradicts the registry doc comment claiming default true (`registry.rs:252-253`).
- **Idempotency** (`registry.rs:164-196`): `Mutex<HashMap>`, TTL 300 s, cap 1024, success-only caching, double-checked insert. Key is a bare caller string — not namespaced by tool/args. Batch/sequence strip `session_id`+`idempotency_key` when mapping (`server.rs:899-900,1045-1046`).
- **SSE** (`server.rs:1082-1161`): buffered, not streaming (comment `:1108-1109` admits it) — full `registry.execute`, then `summary`, 64 KiB `chunk{bytes,sha256,chunk_b64}`, `done`, `error` events. `ShellTool::execute_streaming` (`shell.rs:248-267`) delegates to `backend.execute_streaming` whose default is buffer-and-split (`backend.rs:107-110`).

## Concurrency, cancellation, timeout, cleanup

- `ServerConfig.concurrency` default 32 (`server.rs:1377`), policy range 1–128 (`policy.rs:399-404`). All four execution handlers fail fast with 503 `concurrency_limited`.
- No cancel endpoint, no `tower::Timeout`, no graceful shutdown (`axum::serve(...).await` without signal handling, `:1413-1497`). Client disconnect drops the handler future; buffered SSE cannot preempt work.
- Timeouts: `ResourceLimits` default 30 s (`backend.rs:35-45`); shell default 30 s, code 10 s; policy clamps shell 1–300 s, HTTP 1–120 s, code 1–30 s. On expiry partial output is discarded and `timed_out` returned. CPU/memory limits are Unix-`pre_exec`/WASM-only; elsewhere advisory.
- Code tempfiles leak on crash/kill; session workspaces orphan on restart (no rehydration); audit `Mutex` held across `spawn_blocking` write + 10 MiB single-generation rotation (`:1219-1238`).
- Hot-reload swaps `registry` (`RwLock`) and `egress_hosts` (`Mutex`) separately (`:1468-1469`) — in-flight handlers finish on the old policy (correct), but registry/hosts can skew mid-request.

## Duplicated / inconsistent enforcement

1. Stream endpoint skips the whole pre-check pipeline (P0). 2. Egress checked in `HttpTool`, plus server pre-checks in three handlers, with per-step vs top-level inconsistencies between batch and sequence. 3. `check_session_path` covers only `path`/`destination` keys. 4. Error codes: `ToolError` covers a subset; live codes (`timed_out`, `language_not_allowed`, …) travel as `anyhow!` strings re-split by `extract_code` (`server.rs:1197-1200`) — fragile, undocumented. 5. `session_expired` only on single-execute; batch/sequence rely on purge-then-`contains_key` (`session_not_found`).
