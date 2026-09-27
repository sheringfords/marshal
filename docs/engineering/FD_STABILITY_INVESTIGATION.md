# FD Stability Investigation

## Symptom

One Linux CI run of `fd_count_is_stable_across_failures` reported growth
16 → 29 descriptors; the rerun passed. The test counts `/proc/self/fd`
entries process-wide before/after 400 failing reads plus a cancelled batch,
asserting growth ≤ 8.

## Analysis

The bound assumes the only fd churn in the process comes from the workload.
That assumption is false under `cargo test`: the toctou binary runs 5 tests
across threads (separate Tokio runtimes per test), each runtime lazily
creating epoll/eventfd/signal-pipe descriptors, plus blocking-pool churn
from the concurrent swap-race tests doing 1500 rapid syscalls each. Any of
these landing between the two snapshots exceeds the +8 bound with no leak
in our code. Additionally, the cancelled batch's blocking tasks may not
have closed at `yield_now` time under load.

Our implementation holds every descriptor in `OwnedFd` RAII guards
(`BoundDir`, opened files, `Dir` dups); cancellation drops the owning
future, which drops the guards. No path retains fds past its owner.

## Fix (this mission)

The test now re-executes this same binary in a child process
(`MARSHALL_FD_CHILD=1`) and measures there: identical workload (400 failing
reads + cancelled batch, warmup, 100 ms quiesce), same +8 bound, plus
`FD_TARGETS_AFTER` capture for classification. Zero sibling interference is
possible in the child; leak-detection power is unchanged (any real leak
persists in the child's table at count time).

## Evidence

- 10 consecutive child-isolated runs on Linux x86-64: all pass
  (`RUN1..RUN10:0`, 6/6 tests each — the child test plus the 5 existing
  toctou tests).
- fd-target captures show only runtime steady-state descriptors
  (epoll/eventfd/pipes) plus fixture dirs — no growth attributable to
  `BoundDir`/opened files.
- Classification: **test interference, not a production leak.** No
  production fix required; no threshold raised, no sleep added to mask it
  (the 100 ms quiesce lets already-cancelled blocking tasks close, and is
  documented as such, not as synchronization with the race).

## Residual note

`/proc`-based counting remains Linux-only; macOS has no equivalent test
(documented gap, unchanged).
