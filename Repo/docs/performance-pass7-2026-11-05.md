# Descriptor capture performance, 5 November 2026

This continues the [unaligned-copy pass](performance-pass6-2026-11-05.md).
Kernel stack-debug guards remain disabled. All native runs use disposable
firmware/data and the existing eight-CPU QEMU launcher.

## Unnecessary work in vector readiness calls

Every poll/select preparation previously called `fd_table_pin` separately for
every nonnegative entry. Each call reacquired the same table lock and adjusted
the current thread's atomic preemption depth, then acquired one description
reference. A 128-entry call paid for 128 table lock/unlock pairs before any
readiness callbacks ran. This is unnecessary: captured entries already live in
one protected, heap-owned set and the vector is limited to 256 entries.

The original performance cases repeat a pipe descriptor. Two new default cases
also poll 128 distinct live local endpoints, idle or with one byte queued per
endpoint. Their 64 socket pairs are prepared before timing; final returned masks
are validated individually, and all endpoints are closed during cleanup. The
inventory now has 81 default cases. The opt-in
`poll_idle_local_repeated_128` supplies a matching local-backend alias control.
The existing pipe cases retain their original timed operations and gain final
mask validation outside timing. No separate harness was added.

Two baseline CLI boots reproduced 98–107 us costs for distinct endpoints, so
the observation was not limited to duplicate integer descriptors.

## Capture the vector under one table lock

`fd_table_pin_many` captures the bounded vector while holding the table lock
once. Every valid entry still gets its own reference, including duplicates.
Invalid/negative slots produce null outputs. Reference overflow preserves earlier
owners for ordinary set cleanup and leaves later outputs null. Closed tables
are checked before inspecting entries because shutdown drains them outside the
lock. No allocation, release/finalizer or readiness callback runs under this lock.

Poll/select use this common capture, then perform the same readiness callbacks
and per-entry event masking. Captured descriptions survive concurrent close and
integer reuse until normal retirement releases them. Caller preparation remains
preemption-protected and all waiting state stays heap-owned. No stack pointer is
passed to another thread. The vector now observes one table state during capture;
concurrent-close behavior still requires application synchronization.

Saved disassembly shows one lock's preemption-disable/enable pair in the vector
capture and one call from poll preparation, instead of a call inside its entry
loop. Other single-descriptor users keep the existing `fd_table_pin` path.

## Measurements

Each focused IPC run uses seven requested 200 ms rounds. There are two fresh
CLI boots before and after, plus a matched GUI pair. These are per-boot p50
batch-average microseconds per operation; ranges describe two CLI boot medians,
not confidence intervals:

| Workload | CLI before | CLI after | GUI before | GUI after |
| --- | ---: | ---: | ---: | ---: |
| Idle pipe, one entry | 10.070–12.207 | 9.765–10.986 | 10.681 | 11.596 |
| Idle pipe, 32 repeated entries | 31.738–32.958 | 21.362–24.414 | 31.738 | 23.803 |
| Idle pipe, 128 repeated entries | 97.656–107.421 | 56.152–61.035 | 102.539 | 63.476 |
| Ready pipe, 32 repeated entries | 31.738–32.958 | 21.972–23.193 | 32.958 | 23.193 |
| Idle local, 128 distinct endpoints | 97.656–107.421 | 63.476–65.917 | 102.539 | 63.476 |
| Ready local, 128 distinct endpoints | 97.656 | 61.035–63.476 | 97.656 | 61.035 |

Distinct idle costs fall about 33–41% in CLI and 38% in GUI; distinct ready
medians fall about 35–38%. Idle distinct-endpoint descriptive ranges expanded
by one advertised tick per operation are separate in all three comparisons.
The ready distinct GUI ranges overlap because of a slower tail sample, despite
the lower median. Do not interpret the medians as individual-call percentiles.

Host load differs between boots, and unchanged CLI pipe/socket-pair controls
also vary. Those changes are not attributed to this patch. GUI controls provide
a useful cross-check: the 64-byte local round trip is 48.828 us both times, the
one-entry poll is slightly slower, while large-vector polling improves. The
focused GUI retains a 20 ms p95 frame interval, maximum 30 ms after versus 40 ms
before, with no dropped events or GUI error. This does not prove a UI latency
improvement. The clock advances in 10 ms ticks; these are QEMU measurements,
not physical-machine or scanout evidence.

## Validation and evidence

Existing descriptor-table ownership, deferred retirement and poll/select host
contracts pass, including allocation failure, event masks, 64-bit deadlines and
20,000 concurrent snapshots. Existing native poll and select fixtures pass on
eight CPUs: timeouts, close/reuse, signal interruption, killed-waiter cleanup,
protected output copies and 16 KiB TCP data/EOF. Their saved packet captures were
inspected with tcpdump; summaries retain the real connections and FIN delivery.

Fresh full CLI and GUI runs each complete all 81 default cases with zero
failures. CLI skips optional DNS; GUI skips DNS and multithreaded fork. The full
GUI retains 1,048 load frame intervals with p95 20 ms and maximum 40 ms, zero
dropped events and no GUI error.

Evidence is under `build/perf/pass7-20261105`: `ipc-{before,after}{,-2}`,
`ipc-gui-{before,after}`, their comparison text, `full-{cli,gui}`, source snapshots,
`pass7.patch`, disassembly and native logs/receipts/packet captures in
`native-check-evidence/`. Every timing run has identical app/evaluator
fingerprints and stable build/evaluator inputs during measurement. The kernel implements the candidate and the loader relinks; both before/after
fingerprints are retained. Persistent data images are not modified.

The actual performance dashboard was captured and inspected in
`gui-alias-visual/dashboard.png`. The opt-in local-alias case passed, one real
keyboard probe was delivered, both requested CSV exports succeeded, and no
events were dropped. Its debugger pause excludes this run from timing
comparisons. This is rendering/control evidence, not compositor or input-to-photon
latency.

Final default `make`, Python parsing, source-drift checks and whitespace checks
pass. The known trampoline GNU-stack linker warning remains from relinking.
`verified-runs.json` lists the current reports and native check receipts;
`source-sha256.json` fingerprints the implementation and evaluators. The compiled
kernel canary check still returns immediately and the scheduler protection-mode
word remains zero. No stack guard or permission-cache prototype is enabled.
