# Evidence — commands and results

Baseline SHA: `fb350018c22d5ea7b88c17dfaed20df95174cfec` (recorded in `evidence/baseline-sha.txt`)
Start branch: `hardening/production-readiness`, clean tree (`git status --porcelain=v1 -b` showed only the branch line).
Remotes: `origin https://github.com/wiramahendra/execution-tool.git`, `rapture-fx https://github.com/rapture-fx/Marshall.git`.
Platform: Darwin 22.6.0 x86_64 · rustc/cargo 1.90.0 · default features · no KVM.

## Validation commands

```
cargo fmt --check                                     → PASS (exit 0)
cargo clippy --all-targets -- -D warnings             → PASS (Finished dev profile, exit 0)
cargo test --lib                                      → 131 passed, 0 failed
cargo test --doc                                      → 1 passed
cargo test --test escapes                             → 14 passed
cargo test --test server                              → 32 passed
cargo test --test stress                              → 1 passed (6.48 s)
cargo test --features experiment --test validation    → 17 passed
cargo run --example agent_tools                       → PASS (allowed read+shell, 4 refusals w/ documented codes)
./target/debug/marshalld --validate-config ./marshall.yaml → PASS ("config valid", full policy debug print)
cargo test --all-targets (single shot)                → TIMED OUT at 300 s (suites pass individually)
cargo check --features wasm                           → FAIL, 13 errors (E0412/E0425/E0433, src/backend.rs:380-441)
cargo check --features container                      → FAIL, 3 errors (E0422/E0432, src/backend.rs:722,752,758; watchdog API drift at pinned rev ae5ea2f)
cargo audit / cargo deny                              → NOT_VERIFIED (network-restricted env; blocking in CI per ci.yml:82-93)
```

Note: fresh `cargo run --bin marshalld` exceeded 60 s on cold compile in this environment; the prebuilt `target/debug/marshalld` validated the config instantly. `cargo check --features container` DID fetch the watchdog git rev (network allowed) and failed at API usage, not fetch.

## Benchmark (debug build, local backends, 2026-09-26)

Harness: temporary `examples/__bench_tmp.rs` (ToolRegistry direct; created, run, deleted; no tree trace).

```
cold_fs_read: 1.65645ms success=true
warm_fs_read_n=200 mean_us=1708.5 p50_us=666.0 p95_us=6301.0 p99_us=18383.0 min_us=333.0 max_us=22944.0
warm_shell_echo_n=50 mean_us=8851.6 p50_us=7756.0 p95_us=15231.0 p99_us=25399.0 max_us=25399.0
throughput_32_parallel_shell: 57.474777ms
timeout_req_ms=300 actual_ms=305 success=false error_code=Some("timed_out")
```

Caveats: debug binary, macOS spawn-dominated shell numbers, fs mean skewed by warmup (use p50), no release/Linux/HTTP/SSE-soak/WASM/container numbers (features unbuildable).

## Reproduction pointers (all confirmed in source)

- MAR-P0-001: `cargo check --features wasm` — errors listed above.
- MAR-P0-002: `cargo check --features container` — errors listed above; fallback code `src/backend.rs:686-707`, name `src/backend.rs:679`.
- MAR-P0-003: diff pre-checks `src/server.rs:594-704` vs `src/server.rs:1082-1111`.
- MAR-P1-002: `src/fs.rs:316,348,389-481,628-704` + `src/sandbox.rs:242-274`.
- MAR-P1-003: `src/backend.rs:191,258-266`; test `src/shell.rs:693-713` covers direct child only.
- MAR-P1-004: `sdk/js/index.js` (no `Authorization`), `sdk/python/marshall_sdk.py` (no token param) vs `src/server.rs:124-156`.
- MAR-P1-005: `src/server.rs:548-571` (+ batch/sequence asymmetries `:800-867,:967-1010`).
- MAR-P1-006: `src/registry.rs:164-196`; dropped keys `src/server.rs:899-900,1045-1046`; stale-key behavior `tests/server.rs:831-853`.
- Sequence-default doc contradiction: `src/registry.rs:252-253` vs `src/server.rs:1043`.
- `GET /v1/policy` wrong path: `src/server.rs:1573`.
