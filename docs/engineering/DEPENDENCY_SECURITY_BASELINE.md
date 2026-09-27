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
- Not applied: Wasmtime 22 → 24+ major upgrade — separate, explicitly scoped
  follow-up (API migration + WASI re-verification + adversarial re-testing).
  Until then the `wasm` feature carries 2 critical + 1 high advisories, two
  of which are in reachable guest-compiler paths.
- Not suppressed: no `ignore` entries added to `deny.toml`, no audit
  exclusions; the supply-chain gate stays red and is reported as such.
- Restriction in force: do not present the WASM backend as a hardened
  isolation boundary until the upgrade lands; local-only deployments are
  unaffected (no wasmtime in the default graph).
