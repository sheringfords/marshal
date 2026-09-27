# WASM Trust V1 (draft — migration in progress)

## Contract (verified against implementation)

`WasmBackend` executes a freestanding WASM module file with exactly two host
imports (`fd_write` on fds 1/2 into capped buffers, `proc_exit`) and entry
`_start`/`run`/`_run`. No filesystem, network, clocks, args, or environ;
anything else fails at link time (test-pinned). Fuel bounds instructions,
`ResourceLimiter` bounds memory, epoch interruption bounds wall-clock;
fuel/epoch exhaustion reports `timed_out` with no exit code. Traps report
`exit_code: Some(1)`; `proc_exit(n)` reports `Some(n)`. Without `--features
wasm` every call fails closed (`unsupported`).

## Retain vs remove

- Production wiring: NONE. The daemon builds only `LocalProcessBackend`;
  `WasmBackend` is constructed solely in tests and exposed via the
  `ShellTool::with_backend` API for programmatic use. No policy, config, or
  HTTP path selects it.
- Use case that justifies retention: an in-process sandbox for untrusted
  compute (guest can't touch host fs/net even if admitted), usable by
  embedders through the public API — provided its own sandbox (the wasmtime
  compiler) is sound. The two critical advisories (below) strike exactly
  that property, which is why the version migration — not removal — is the
  primary path.
- Removal case: zero production callers + compiler CVEs + heavy dependency
  (320 crates in the wasm closure, Cranelift build minutes). If the
  migration proves infeasible or the use case is rejected, retirement means
  deleting the `wasm` feature, `WasmBackend`, and its tests — a small,
  mechanical PR. No removal without explicit approval (this mission).

## Version selection

Committed advisories require: most fixed in `>=36.0.7`, `RUSTSEC-2026-0269`
needs `>=36.0.14`, `RUSTSEC-2026-0222` needs `>=36.0.13`, `RUSTSEC-2025-0118`
covered by `>=36.0.3,<37`. Selected **wasmtime 36.0.16** (max 36.x):
satisfies every patched range, `rust_version = 1.86.0` (preserves MSRV
1.88), smallest maintained line that clears all findings (24.x leaves the
two critical compiler escapes unfixed). Migration diff: one `table_growing`
signature (`u32` → `usize`); all other APIs (`Config`, `Engine`, `Linker::
func_wrap`, `Caller`, fuel, epoch) unchanged.

## Cancellation fix found by testing

The new cancellation test hung the harness: dropping the execute future left
the guest spinning forever on its detached blocking thread (no fuel, no epoch
bump on that path) — 30 CPU-minutes burned before it was killed. Fix:
`EpochBumpOnDrop` guard bumps the per-call engine epoch unless the call
completed, so an abandoned guest traps instead of spinning. The engine is
fresh per call with a single store, so nothing else observes the bump. This
was a pre-existing leak (old MAR-REV-008 class), not a 36 regression.

## Performance (release, fixed hello module, 30 reps, shared desktop)

| backend | p50 | p95 | mean | binary | max RSS |
|---------|-----|-----|------|--------|---------|
| wasmtime 22.0.1 | 9–20 ms | 31–40 ms | 12–20 ms | 10.8 MB | 6.8 MB |
| wasmtime 36.0.16 | 1.0–3.5 ms | 2–20 ms | 1.1–6.3 ms | 16.9 MB | 7.5 MB |

Each iteration builds a fresh `Engine` + compiles the module, so these are
end-to-end numbers dominated by Cranelift compile time. Ranges across runs
(machine load); no steady-state caching configured. Deps: 320 → 317 unique
crates with `wasm`. No performance claim beyond: the migration does not
regress execution, at the cost of +6 MB binary.
