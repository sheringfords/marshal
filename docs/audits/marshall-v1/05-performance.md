# 05 — Performance

Environment: MacBook Pro x86_64, macOS 22.6.0, rustc 1.90.0, **debug** build, default features, local backends only (no KVM; wasm/container unbuildable). Method: throwaway `examples/__bench_tmp.rs` (created, run, deleted — no trace in tree) driving `ToolRegistry` directly: 1 cold read, 200 warm reads, 50 warm `/bin/echo`, 32 parallel shells, 1 timeout probe. Raw output preserved in `evidence/commands-and-results.md`.

## Results

| Metric | Value |
|---|---|
| Cold filesystem read (20 B file) | 1.66 ms |
| Warm filesystem read (n=200) | mean 1.71 ms · p50 0.67 ms · p95 6.30 ms · p99 18.38 ms · min 0.33 ms · max 22.94 ms |
| Warm shell `/bin/echo` (n=50) | mean 8.85 ms · p50 7.76 ms · p95 15.23 ms · p99/max 25.40 ms |
| 32 parallel shells wall time | 57.5 ms (~560 exec/s) |
| Timeout accuracy (300 ms vs `/bin/sleep 10`) | 305 ms observed, `timed_out` code |

## Interpretation

- Shell latency is dominated by macOS `spawn` (~8 ms); the policy layer adds sub-millisecond overhead on top (fs p50 0.67 ms includes `canonicalize` + capped read).
- The fs p50/mean skew (0.67 vs 1.71 ms) is warmup/allocator noise in the first dozen samples of a debug binary — report p50 as the steady-state figure, not the mean.
- Throughput (~560 small execs/s) is adequate for a policy gateway; the 503 shedding point (32 in-flight) was not load-tested here — that is a soak-test item for the plan.
- Timeout accuracy (+5 ms on 300 ms) is good.

## Not measured (stated explicitly, not implied)

- No release-build numbers, no Linux/`openat2` numbers, no HTTP-tool latency (would need a local allowlisted server), no SSE overhead split (endpoint is buffered — streaming overhead is ~0 by construction), no memory-growth soak, no WASM/container numbers (features do not compile). Simulated isolation results are not reported anywhere in this audit.
- `tests/stress.rs` (10k idempotent execs, ~6.5 s, cache bound holds) is the closest thing to a soak test in-tree.
