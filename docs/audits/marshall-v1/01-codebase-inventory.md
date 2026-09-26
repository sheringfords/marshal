# 01 — Codebase Inventory

Baseline: `fb350018c22d5ea7b88c17dfaed20df95174cfec` · branch `hardening/production-readiness` (clean) · audit branch `audit/marshall-execution-runtime-v1`.

## Layout

| Path | Contents |
|---|---|
| `src/` | 18 modules (~11.4k LOC incl. experiment bins); lib root `src/lib.rs:1-255` |
| `src/bin/marshalld.rs` | CLI: serve / `--validate-config` / `--healthcheck` (`:69-115`) |
| `src/experiment/` | Research harness, feature-gated `experiment`, excluded from published crate (`Cargo.toml:12-20,36`) |
| `src/bin/{baseline_runner,treatment_runner,validation_analyzer,generate_reports,phase2_comparison,mcp_*}.rs` | Experiment runners; `mcp_bounded_sequence` builds without the feature |
| `tests/` | `escapes.rs` (14 attack cases), `server.rs` (32 endpoint tests), `stress.rs` (10k idempotency bound), `validation.rs` (17, feature-gated) |
| `sdk/js/` | `index.js` + `package.json` (`marshall-sdk@0.1.0`, self-described "scaffold") |
| `sdk/python/` | `marshall_sdk.py` + `pyproject.toml` (broken `readme` path — see §6) |
| `examples/agent_tools.rs` | Runnable quick-start (1 allowed read + 1 shell, 4 refusals) |
| `fuzz/fuzz_destination.rs` | Destination parser fuzz driver, wired as `bin fuzz_destination` (`Cargo.toml:81-83`) |
| `validation/` | Research artifacts (summaries, traces, experiment JSON) — not shipped |
| `docs/` | `ARCHITECTURE.md` (partly stale — cites `branch = "main"` watchdog at `Cargo.toml:37` claim vs pinned rev at `Cargo.toml:59`), `DEPLOYMENT.md` |
| `.github/workflows/ci.yml` | test (ubuntu+macos), MSRV 1.88, docs, supply-chain (audit+deny blocking), container image probe |
| `marshall.yaml` | Shipped strict-default policy; loads clean (`--validate-config` PASS) |
| `Dockerfile`, `deny.toml`, `verify_change.yaml`, `audit.jsonl` | Deployment + supply-chain + stray local audit log (excluded from package) |

## Module map (tools, backends, cross-cutting)

| Module | Role | Policy hook |
|---|---|---|
| `sandbox.rs` | Path containment (`openat2` Linux / `canonicalize` elsewhere) | `Sandbox::new`, `resolve_existing/for_create` |
| `destination.rs` | SSRF-grade URL/host/IP validation | `validate_destination` |
| `egress.rs` | Server-side host allowlist re-check | `EgressPolicy::check` |
| `fs.rs` | 12 filesystem ops + caps | `writable`, `read_limit` |
| `shell.rs` | Binary allowlist + `ArgumentPolicy` | `AllowedCommand`, interpreter guard `:69-96` |
| `http.rs` | Pinned, redirectless HTTP client | allowlist-before-DNS, body caps |
| `code.rs` | python/js/bash via tempfile or `-c` | `allowed_languages`, 64 KiB cap, `allow_unsandboxed` gate in `policy.rs:462-469` |
| `system.rs` | now/sleep/env/hash/info/process_list/process_kill | `SystemPolicy` gates |
| `agent.rs` | think/memory/todo/plan/reflect (session-scoped, in-memory) | per-tool caps (256 keys, 64 todos, 32 plans) |
| `backend.rs` | `LocalProcessBackend` (default) / `WasmBackend` / `ContainerBackend` | `ResourceLimits{timeout,output_limit,cpu_time,memory_bytes}` |
| `registry.rs` | Dispatch, batch/sequence/templating, idempotency cache | caps 64/32/32, TTL 300 s, 1024 entries |
| `server.rs` | axum service: auth, quotas, sessions, audit, metrics, hot-reload | 11 routes (`:1542-1559`) |
| `policy.rs` | YAML loader + `validate` (fail-closed) | concurrency 1–128, timeout/clamp bounds |
| `ratelimit.rs` | Per-client token buckets | 10k buckets, 600 s idle evict |
| `limits.rs` | `RLIMIT` guard (deliberately not pids/nofile server-wide `:37-43`) | — |
| `redaction.rs` | `REDACTION_POLICY_VERSION`, header/env allowlists | — |
| `error.rs` | `ToolError` codes (fs/shell/http/generic; many live codes fall through to `Other`) | — |

## API surface (`marshalld`)

`GET /health`, `GET /metrics` (unauthenticated by design) · `GET /v1/tools`, `GET /v1/policy`, `POST /v1/sessions`, `DELETE /v1/sessions/:id`, `POST /v1/execute`, `POST /v1/execute/batch`, `POST /v1/execute/sequence`, `POST /v1/execute/stream` (`src/server.rs:1542-1559`).

## Tests and CI

- 248 tests claimed in `ROADMAP.md:11` ("131 lib (166 w/ experiment), 14 escapes, 32 server, 17 validation, 1 stress"). Reproduced: 131 lib + 1 doc + 14 escapes + 32 server + 1 stress + 17 validation = 196 observed on this checkout (166-lib experiment count not re-run; `cargo test --all-targets` single-shot exceeded 300 s here).
- CI checks fmt, clippy, lib/doc/escapes/server/stress/validation, example run, `--validate-config`, MSRV, docs, audit/deny, and a container open-executor probe. **CI never exercises `--features wasm` or `--features container`** — the two isolation backends ship untested, and `wasm` is broken (MAR-P0-001).
- `RUSTSEC-2026-0258` fixed per roadmap; `cargo audit`/`deny` blocking in CI (not re-run here — network-restricted env; recorded as NOT_VERIFIED in evidence log).

## Incomplete / risky items

1. `wasm` feature does not compile (P0). 2. `container` feature unbuildable by third parties (P0). 3. `docs/ARCHITECTURE.md:21` describes watchdog wiring that no longer matches `Cargo.toml:59` (branch→pinned rev). 4. `sdk/python/pyproject.toml` references nonexistent `README.md`. 5. `validation/` and `audit.jsonl` excluded from package — good; `audit.jsonl` present in repo root is a stray local artifact. 6. No tags/releases; `cargo add marshall` (README) cannot work until crates.io publish. 7. `origin` still points at `wiramahendra/execution-tool` while `Cargo.toml:8` advertises `rapture-fx/Marshall` (roadmap §4 notes it; still true).
