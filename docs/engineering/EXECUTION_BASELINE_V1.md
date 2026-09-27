# Execution Baseline V1

Release `marshalld` (this branch), loopback, `curl` per request, 10× warm-up
(3× where noted), macOS 4-CPU host. `bench_exec.sh` in repo root reproduces
the first four rows; `/tmp` scripts used for the rest are described below.

## Latency (ms)

| workload | n | p50 | p95 | p99 | mean | stdev |
|----------|---|-----|-----|-----|------|-------|
| single echo | 100 | 18.27 | 21.80 | 23.13 | 18.01 | 2.39 |
| fs read (4 B) | 100 | 15.56 | 23.99 | 34.25 | 16.42 | 3.12 |
| fs write | 50 | 16.58 | 22.86 | 23.02 | 16.96 | 2.47 |
| batch 8×echo, mc=8 | 30 | 16.75 | 20.88 | 21.18 | 17.13 | 1.67 |
| session-scoped read | 50 | 23.85 | 65.54 | 146.33 | 30.17 | 22.01 |
| batch 32×echo, mc=32 | 15 | 85.67 | 166.37 | 166.37 | 94.52 | 26.45 |

## Footprint

Idle daemon: RSS ≈ 3.7 MB, 8 threads. No FD growth observed across the runs
(FD accounting is covered by the Linux-only `fd_count_is_stable` test).

## Reading the numbers

- The ~15 ms floor is the measurement harness (process-spawned `curl` +
  TCP + JSON), not the server. Treat rows as relative, not absolute.
- Batch fan-out works: 8 echoes cost the same as 1; 32 cost ~5× one —
  sublinear, consistent with the M2-001 workload cap.
- Session scoping adds noise-level overhead on p50 (+~8 ms, inside harness
  variance); the p99 tail (146 ms) is warm-up/cache noise on a shared
  desktop, reported honestly rather than trimmed.
- Filesystem cache effects were NOT separated (all reads page-cache hot);
  cold-cache numbers are future work, not a decision input.

## Bottlenecks (measured, in order)

1. Per-request HTTP/JSON plumbing dominates every row. In-server work is a
   small fraction; micro-optimizing tool internals will not move these
   numbers — reducing round trips (batch/sequence) does.
2. Inside the server, every filesystem op pays two canonical resolutions
   (validate + execute) plus a root bind (2 opens). This is the D4
   consolidation candidate in the RFC: bind-first classification would halve
   path syscalls per op. Not yet worth doing on latency grounds alone.
3. Nothing here justifies allocator, pooling, or async-runtime work: the
   daemon idles at megabytes with single-digit threads and sub-100 ms
   batch tails on a laptop.

## Variance and limits

Single shared desktop machine; no isolation, no pinning; `curl`-spawn
jitter included. No pre-M2 comparison build was retained, so no speedup
claim is made — the baseline stands alone for future slices to regress
against.
