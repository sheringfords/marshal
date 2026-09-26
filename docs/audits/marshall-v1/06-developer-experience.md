# 06 — Developer Experience

## Quick-start reproduction

- `cargo run --example agent_tools`: PASS — output matches README (1 allowed read + 1 shell, then 4 refusals with the documented codes).
- README minimal snippet (`README.md:52-61`): valid API usage but uses `?` with no `Result` wrapper — copy-paste fails to compile. `src/lib.rs:6-17` shows the correct wrapper.
- README fuller example (`:65-90`): all APIs exist — but `CodeTool::allow_all()` (`:88`) bypasses the server-side `allow_unsandboxed` gate, and the example never mentions it. A reader who copies it gets a config-load error with no pointer back.
- README curl `:222-224` (`code`/`python`) fails against the stock `marshall.yaml` (`allowed_languages: []`) with `language_not_allowed` — the first copy-paste server command contradicts the shipped policy.
- Install: `cargo add marshall` (`:47`) assumes crates.io; the crate is unpublished (no tags/releases). Working paths (`git clone + cargo build`, Docker) are correct.

## SDKs: transport OK, auth missing (MAR-P1-004)

| Capability | JS `sdk/js/index.js` | Python `sdk/python/marshall_sdk.py` |
|---|---|---|
| execute / batch / sequence / stream / createSession | present | present (batch always sends `max_concurrency: 8`) |
| `Authorization: Bearer` | **absent — no token option** | **absent — no token param** |
| `DELETE /v1/sessions/:id`, `GET /v1/policy` | absent | absent |
| Error shape | `{code, status}` attached | collapsed to `RuntimeError("code: error")`; batch/sequence/stream discard the `{error, code}` body via bare `raise_for_status()` |
| Stream shape | yields `{event, data}` | yields `(event, data)` tuples — undocumented asymmetry |

Against any token-protected deployment both SDKs get `401` with no recourse. README snippets also use an undefined `SID`, the JS import path (`'./index.js'`) is wrong for the published package name, and `sdk/README.md:24` / `:13` contain a wrong Python import and an unpromised workspace layout.

## Structured errors

Good core (`ToolOutcome.error_code`, `ToolError::code()`, audit carries codes not payloads). Gap: `src/error.rs` models only fs/shell/http/generic codes; live codes (`timed_out`, `language_not_allowed`, `code_too_large`, `redirect_refused`, `http_status`, `noflags_for_interpreter`) travel as `anyhow!` strings recovered by `extract_code` string-splitting (`src/server.rs:1197-1200`). No published code registry exists. Smallest integration for an existing coding agent: `POST /v1/execute` + `ToolOutcome{success, summary, content, error_code, duration_ms}` is sufficient and stable; batch/sequence templating and SSE are optional extras.

## Packaging

- JS: `package.json` v0.1.0 vs crate v0.2.0, "scaffold" header, no `exports`/`files`/`repository` — unpublishable as-is.
- Python: `pyproject.toml` `readme = "README.md"` points at a nonexistent file (only `sdk/README.md` exists) so builds fail; phantom `httpx` dependency (only `requests` imported); `requires-python >= 3.9` fine; no install docs anywhere.

## Undocumented limits (functional, source-only)

`code` 64 KiB source / 1 MiB stdin / 1–30 s timeout clamp / 16 MiB output clamp (`src/code.rs:25,124,344,350-354`); shell interpreter hard-stop list (`src/shell.rs:69-96`); fs 1000-result + 1 MiB search caps (`src/fs.rs:97,502`); agent-tool TTL/LRU/item caps (`src/agent.rs`); `max_sleep_ms` reject-vs-clamp semantics. Fix priority: SDK auth → packaging → README snippet correctness → error-code registry → limits documentation.
