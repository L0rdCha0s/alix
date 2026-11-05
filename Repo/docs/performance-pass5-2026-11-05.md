# Scheduler phase costs and stack-debug configuration, 5 November 2026

This continues the [GUI publication pass](performance-pass4-2026-11-05.md).
Evidence and source snapshots are under `build/perf/pass5-20261105`. Native runs
use eight CPUs and disposable data/firmware through the existing QEMU launcher.

## Measure switch phases with live endpoints

`--scheduler-costs` adds a second checkpoint to the existing native debugger
workflow. At handoff readiness it enables CPU-local phase counters. At the first
completed sample it disables them and captures both live endpoint records, plus
priorities, affinity and CPU/queue state. It retains the same native TID checks
as the existing scheduler snapshot. Default runtime profiling remains off.

The per-thread counters measure scheduler-lock acquisition wait, queue choice,
switch preparation, finish bookkeeping, deferred cleanup, validation, FPU state,
address-space work, FS/GS/TSS updates and kernel-stack permission repair. All TSC
intervals stay on one CPU with IRQs disabled, and updates use owned kernel thread
records. No caller stack or temporary pointer crosses an async handoff.

Values are diagnostic TSC ticks, not calibrated nanoseconds. Profiling adds
work and the paused report cannot be used as a quantitative baseline. Some
subphases are included in preparation or finishing totals; their sums are not
independent wall-clock time. Completed intervals are captured before join can
reclaim either endpoint. Disabling capture also drops unfinished diagnostic
intervals rather than including debugger-stop time.

The initial CLI profile showed preparation around 39,365 and 49,637 TSC units
per switch for the two endpoints. Selection was about 1,452–1,812 units and
finish bookkeeping 1,209–1,369. A more detailed breakdown ruled out FPU and
register updates as the dominant section. With the actual compiled protection
mode equal to 3, stack permission walks accounted for 47,980,000 / 67,001,000
and 65,257,000 / 84,172,000 preparation TSC units: approximately 72% and 78%.
Each endpoint walked the incoming stack on every observed switch.

## Requested configuration: disable kernel stack-debug enforcement

The user explicitly requested turning off the stack guards and related checks.
The normal build now sets these switches to zero in `include/build_features.h`:

- Stack write watching and its logs.
- Stack-page guard protection.
- Saved-context hash guards.
- Kernel stack canary checks and canary-region initialization.
- Bootstrap stack scans, scan logs and scheduler stack dumps.

The disabled configuration exposed an existing conditional-compilation error:
a general stack-range predicate was defined only inside the write-watch build.
That small bounds helper is now available in either configuration. Optional
static diagnostic helpers are marked appropriately so the disabled build has
no new unused-code warnings. Thread construction also leaves context guarding
disabled when the feature is compiled off.

This changes kernel debug enforcement. The reserved stack margin and allocation
layout are retained, so no linker/user address-layout migration was required.
Ordinary VM permissions and scheduler lifetime/ownership gates remain separate.

A permission-cache prototype explored before the request was removed from the
source. Its early global proof was insufficient for a migrating CPU's possible
read-only TLB entry; the next version tracked destination CPUs, but disabling
the guards made the cache unnecessary. Prototype measurements are marked
superseded and are not used for final claims. No cache state or invalidation
hooks remain in the current kernel.

## Verify the actual build and measure the change

The preprocessor output in `effective-stack-flags.txt` confirms all eight selected
switches equal zero. `canary-disabled.asm` confirms the compiled kernel canary
check returns immediately without scanning. A fresh guest reports stack
protection mode 0, and the first completed handoff sample records zero stack
permission walks. Preparation drops to about 7,573–7,706 diagnostic TSC units per
switch in that profile. These counters confirm which work was disabled, rather
than providing a physical CPU timing claim.

Matched uncaptured handoffs use seven requested 500 ms rounds and CPUs 0/1:

| Workload | Guards enabled | Guards disabled |
| --- | ---: | ---: |
| CLI median round trip | 212.856 us | 124.007 us |
| GUI median round trip | 550.660 us | 188.111 us |

Observed sample ranges with a tick margin are separate in both comparisons.
CLI median cost fell 41.7% and GUI cost 65.8%. These are deliberate changes to
the requested debug configuration, not optimizations retaining equivalent guard
enforcement. Before/after JSON, raw batches, image/evaluator hashes and host
conditions are in `handoff-{cli,gui}-{before,guards-off}/`; comparison output is
`{cli,gui}-guards-comparison.txt`. These are QEMU results, not physical hardware
performance or scanout measurements.

## Current validation

Existing native blocking synchronization, pthread ABI/lifetimes, stack/TLS address
reuse, anonymous VM/JIT, protected-copy races and write/none/execute hardware
fault checks passed. The real compositor passed framebuffer pixel checks,
128 presents, repeated resize/control ownership and raw keyboard checks on eight
CPUs. Host scheduler-handoff, current-context, futex and optional stack-watch
race contracts also passed. The latter exercises its explicitly enabled host
model, not guard enforcement in the current disabled guest build.

Fresh CLI and GUI runs each completed all 75 default cases with zero failures.
CLI skipped optional DNS; GUI skipped DNS and multithreaded fork. The GUI's
951 load frame intervals had p95 20 ms and maximum 50 ms, with zero dropped
events and no GUI error. Guest configuration readback and build/evaluator
fingerprints were checked. These are 10 ms-clock observations.

The disabled build required no persistent data changes. Final `make`, Python
parsing and whitespace checks passed. Optional scheduler-cost profiling remains
disabled outside explicit debugger runs. Existing native logs/receipts are
copied to `native-check-evidence/`; `verified-runs.json` separates retained
measurements from superseded permission-cache prototypes. Physical hardware and
scanout latency remain outside this evidence.
