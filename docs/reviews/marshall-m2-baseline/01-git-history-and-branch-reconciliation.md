# Git History and Branch Reconciliation

All SHAs reverified by fetch on 2026-09-27 (this mission). Previously recorded SHAs were treated as historical until rechecked; all confirmed.

## Current SHAs (authoritative: `origin` = wiramahendra/execution-tool, mirrored by rapture-fx/Marshall)

| Ref | SHA | Note |
|-----|-----|------|
| `origin/main` | `eee20cf982562959b4da489cb5f5e6f190e2dabd` | Matches known state. Merge PR #7. |
| `origin/hardening/production-readiness` | `32d0aae86cbe0560490b2402e44991ba82c61865` | Matches known state. Merge PR #4. |
| Previous audit baseline `fb35001` | `fb350018c22d5ea7b88c17dfaed20df95174cfec` | Superseded; preserved as history. |
| Previous integration `b56c082` | `b56c082a894cdec2594cfcd2ee48e88c8df20196` | Byte-identical implementation to current main (see below). |
| Review commit `29bb371` | present locally only (`review/marshall-integration-v1`) | Not on any remote; preserved (Phase 2). |
| Local `main` / `hardening` tracking branches | `2b9778c` / `fb35001` | Stale; not updated (no history rewrite needed — `origin/*` refs are current). |

## Confirmed PR merge history (all merged, none open for #1–#5)

- PR #1 (audit docs `4ea85d7`): merged via `ea857ee` (present in both main and hardening histories).
- PR #2 (admission `06e4449` + `4ed71f4`): merged into `verify/marshall-integration` (`b56c082` lineage), then into main via PR #6 (`fc33b14`, `2b9778c` + `b56c082`); also into hardening via `f444c33`.
- PR #3 (WASM `305e718`): same path via `ae575cd`; also `f120f53` on hardening line.
- PR #4 (container): true change `3b3d8c3` in all lines. Remote `refs/pull/4/head` = `6c069d5` (merge-polluted tip containing all other PRs); the pollution was contained to the feature branch — both main and hardening merged the correct content.
- PR #5 (SDK `6c61765`): via `b56c082` lineage + direct `e994a7c` on main/hardening lines.
- PR #6 (`verify/marshall-integration` → main): `fc33b14`. PR #7 (`hardening/production-readiness` → main): `eee20cf` (current main tip).

## Integration comparison (`b56c082` vs current tips)

- `b56c082..origin/main`: +12 files, +491 lines — exactly the PR #1 audit docs. Zero implementation delta.
- `b56c082..origin/hardening`: identical +12 audit docs. Zero implementation delta.
- `origin/main` vs `origin/hardening`: **empty diff — trees identical**.
- Byte-verified (`shasum -a 256`): `src/server.rs`, `src/backend.rs`, `src/policy.rs`, `src/shell.rs`, `src/registry.rs`, `src/limits.rs`, `tests/server.rs`, `sdk/js/index.js`, `sdk/python/marshall_sdk.py`, `Cargo.toml`, `deny.toml` identical between `b56c082` and `origin/main`.
- Merge commits `fc33b14`, `eee20cf`, `32d0aae` introduce no code beyond their parents (audit docs + already-reviewed changes only). No unexpected conflict resolutions, no dropped code, no unreviewed changes.

## Commit graph (simplified)

```
eee20cf (origin/main, PR #7: hardening -> main)
├── fc33b14 (PR #6: verify/marshall-integration -> main)
│   ├── 2b9778c (old main)
│   └── b56c082 (integration: 06e4449, 4ed71f4, 305e718, 3b3d8c3, 6c61765)
├── ea857ee (PR #1: audit docs 4ea85d7)
32d0aae (origin/hardening, PR #4 incl. polluted tip 6c069d5 — content correct)
```

Merge-base of `origin/main` and `origin/hardening`: `ea857ee`.

## Reconciliation plan and authoritative baseline

No content divergence exists, so no code reconciliation is required and none is performed (no merges, no production changes per mission rules):

- **Authoritative M2 baseline: `origin/main` = `eee20cf982562959b4da489cb5f5e6f190e2dabd`.** Rationale: default branch, contains all merged hardening + audit docs, content-identical to hardening.
- New M2 branches must be cut from `eee20cf`.
- The `hardening/production-readiness` branch is redundant (identical tree); recommend leaving it untouched until M2 lands, then fast-forwarding or retiring it — a maintainer decision, not taken here.
- Local stale tracking branches (`main`@`2b9778c`, `hardening`@`fb35001`) deliberately left alone; all verification used `origin/*` SHAs and a detached worktree at `eee20cf`.
