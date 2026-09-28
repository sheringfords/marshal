# Dependency Security Baseline (2026-09-27, lockfile as committed on PR #12)

Toolchain note: `cargo audit` 0.22.2 against the committed `Cargo.lock`;
`cargo deny` 0.20.2. CI runs both without `--features`, which matters
(see §4).

## 1. Full advisory inventory (committed lockfile)

### Fixed in this mission

| ID | Crate/version | Severity | Reachability | Resolution |
|----|---------------|----------|--------------|------------|
| RUSTSEC-2026-0285 | rustls 0.23.43 → **0.23.45** | medium 5.3 (TLS 1.3 handshake across encryption levels) | Reachable: reqwest TLS for the allowlisted `http` tool + `marshalld --healthcheck` client | `cargo update -p rustls --precise 0.23.45` (compatible patch bump; matrix re-run green) |

### Remaining vulnerabilities (18, all wasmtime 22.0.1, optional `wasm` feature)

| ID | Title | Severity |
|----|-------|----------|
| RUSTSEC-2026-0096 | Miscompiled guest heap access enables sandbox escape on aarch64 Cranelift | 9.0 critical |
| RUSTSEC-2026-0095 | Winch backend sandbox-escaping memory access | 9.0 critical |
| RUSTSEC-2026-0269 | Filesystem sandbox escape on trailing-slash paths/symlinks | 8.8 high |
| RUSTSEC-2026-0020 | Guest-controlled resource exhaustion in WASI | 6.9 medium |
| RUSTSEC-2026-0021 | Panic on excessive `wasi:http/types.fields` | 6.9 medium |
| RUSTSEC-2026-0093 | Heap OOB read, component UTF-16 transcoding | 6.9 medium |
| RUSTSEC-2026-0087 | Segfault / out-of-sandbox load, `f64x2.splat` x86-64 | 4.1 medium |
| RUSTSEC-2026-0092 | Panic transcoding misaligned component UTF-16 | 5.9 medium |
| RUSTSEC-2026-0089 | Host panic, Winch `table.fill` | 5.9 medium |
| RUSTSEC-2026-0085 | Panic lifting `flags` component value | 5.6 medium |
| RUSTSEC-2026-0094 | Improperly masked `table.grow` return, Winch | 6.1 medium |
| RUSTSEC-2026-0091 | OOB write/crash transcoding component strings | 6.1 medium |
| RUSTSEC-2026-0086 | Host data leakage, 64-bit tables + Winch | 2.3 low |
| RUSTSEC-2026-0088 | Data leakage between pooling-allocator instances | 2.3 low |
| RUSTSEC-2026-0222 | Type-index confusion between engines | 3.8 low |
| RUSTSEC-2025-0118 | Unsound shared-linear-memory API | 1.8 low |
| RUSTSEC-2025-0046 | Host panic, `fd_renumber` WASIp1 | 3.3 low |
| RUSTSEC-2024-0438 | Windows device filenames not sandboxed | n/a (Windows-only) |

### Remaining warnings (4, allowed — see §3 for why allowed ≠ clean)

| ID | Crate | Kind |
|----|-------|------|
| RUSTSEC-2025-0057 | fxhash 0.2.1 | unmaintained |
| RUSTSEC-2024-0436 | paste 1.0.15 | unmaintained |
| RUSTSEC-2024-0442 | wasmtime-jit-debug 22.0.1 | unsound |
| (yanked) | chacha20 0.10.1 | yanked |

## 2. Reachability (what Marshall actually exposes)

`src/backend.rs` builds `wasmtime::Config` with fuel + epoch interruption,
`async_support(false)`, default (Cranelift) compiler, then links exactly two
host functions (`fd_write`, `proc_exit`) — no component model, no WASI
filesystem/preopens, no threads/shared memory, no pooling-allocator
configuration, no WASI-http. Consequences per advisory class:

- **Directly in the threat model**: RUSTSEC-2026-0096 (aarch64 Cranelift
  miscompile — guests run on deployers' CPUs, including Apple Silicon),
  RUSTSEC-2026-0087 (`f64x2.splat` x86-64 — any guest can contain it).
  A malicious guest on affected hosts can escape the WASM sandbox into the
  daemon process. This is not mitigated by fuel/memory limits.
- **Latent, not currently reachable**: Winch-backend items (backend never
  selects Winch), component-model transcoding (no components accepted),
  `wasi:http` (no such import), pooling allocator (never configured),
  `fd_renumber` (no such import), Windows filenames (non-Windows targets).
  Unreachable ≠ clean: any of these becomes reachable if the backend's
  import surface widens.
- **Transitive warnings**: fxhash/paste/chacha20/jit-debug arrive via the
  wasmtime/reqwest subtrees (exact paths: `cargo tree -i` at lock time);
  none is called by Marshall code directly. Yanked chacha20 cannot be
  re-resolved fresh, but the committed lock pins it reproducibly.

Fix paths per advisory: minimum `>=24.0.x` (several), most `>=36.0.7` —
i.e. a **major** Wasmtime upgrade (22 → 24+), with API migration
(`Config`, linker, fuel APIs all moved across those majors). Explicitly
out of scope for this recovery slice.

## 3. Why `cargo deny` is green while `cargo audit` fails

Verified by experiment, not by reading docs: deny's advisory check examines
the **default-feature resolve** (debug log: ~20 crates `filtered`, including
the entire `wasmparser`→wasmtime subtree). `cargo audit` scans the whole
lockfile, including optional dependencies. CI runs both without
`--features`, so wasm-gated advisories fail audit and are invisible to deny.
Neither tool is misconfigured; they answer different questions. Operational
rule: **deny-green is not vulnerability-clean** — the audit gate is
authoritative for vulnerabilities, deny for bans/licenses/sources.

## 4. Decisions

- Applied: rustls `0.23.43 → 0.23.45` (compatible; full matrix green).
- Applied (WASM_TRUST_V1): wasmtime `22.0.1 → 36.0.16` — clears all 18
  committed advisories (`cargo audit` exit 0 locally). MSRV 1.88
  preserved (wasmtime 36 rust-version 1.86). Migration diff: one trait
  signature + one cancellation guard; adversarial suite extended and green
  on both platforms.
- Residual warnings at the time (eliminated by the PR #14 supply-chain
  closure entry below; the `r-efi` path suspected here was also wrong —
  `r-efi 6.0.0` is a leaf with no `chacha20` edge; the real lock path was
  `reqwest --(optional http3, not enabled)--> quinn → quinn-proto → rand`):
  `fxhash` (unmaintained) via `fxprof-processed-profile` ← wasmtime
  (profiler never enabled); `chacha20` (yanked) via `r-efi` ← `getrandom`
  (UEFI-target fallback, unreachable on Linux/macOS). Neither is referenced
  by Marshall code; neither is removable compatibly. No suppression added.
- Not suppressed: no `ignore` entries added to `deny.toml`, no audit
  exclusions.
- Applied (PR #14 supply-chain closure): wasmtime `36.0.16` moved from
  default features to `default-features = false` with
  `cranelift,runtime,std,wat`; the `config.async_support(false)` call was
  removed from `src/backend.rs` (synchronous execution is the default with
  the `async` feature off, so the setter was a no-op). `cargo audit --deny
  warnings` exits 0 on the committed lock (343 → 304 entries, pure removal
  plus one compatible bump): `fxprof-processed-profile` + `fxhash` and 37
  other wasmtime-default-only crates (profiling, parallel-compilation,
  component-model, winch, cache/zstd, demangle stacks) left the graph, and
  `chacha20 0.10.1` (yanked) → `0.10.2` via narrow
  `cargo update -p chacha20 --precise 0.10.2`. MSRV 1.88 and the
  WasmBackend adversarial suite remain green (10 lib tests plus a
  throwaway 4096→64-byte stdout/stderr caps probe, removed after use).
- Restriction lifted for `wasm` subject to the remaining notes below; the
  `ContainerBackend` fail-closed posture is unchanged.
