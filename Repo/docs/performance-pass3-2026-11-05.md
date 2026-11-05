# Filesystem and admission performance investigation, 5 November 2026

This continues the [first kernel pass](performance-pass-2026-11-05.md) and
[thread, comparison and TCP pass](performance-pass2-2026-11-05.md). All results
below are native eight-CPU QEMU measurements. Each run uses the existing launcher
with disposable firmware/data, checked guest arguments and build-image receipts.
No persistent user disk was changed. Sources and raw evidence are retained under
`build/perf/pass3-20261105`.

## Separate application checking from file API work

New opt-in cases compare warm 4/60/64 KiB preads. The `*_api` cases check the
last returned array after measurement; `cached_read_60k_checked` validates each
operation. All pread calls and completed bytes, including warmup/calibration, are
reported. These are memory-backed `/tmp` files, not cold-cache or raw-device
measurements. Existing checked workloads retain their validation.

Before this pass's fixes, median 4 KiB API reads were 78.125 us, 60 KiB API reads
87.890 us, and 64 KiB API reads 166.015 us. Every observed pread completed through
the existing resident inline path. A 60 KiB checked read measured 156.250 us;
that difference includes application checking and must not be called storage
latency. The 64 KiB case needed two preads per operation: the 64 KiB registered
request limit also contains its operation header. This boundary remains intact;
changing the bound was not needed to remove the larger delay found below.

Reports are `cached_read_{4k_api,60k_api,64k_api,60k_checked}-before/`.

## Immutable directory entries were taking worker round trips

A directory handle already owns an immutable heap snapshot, but every next-entry
or EOF request went through a protected storage worker. A new checked
`directory_scan_128` evaluation creates 128 children, validates every name once,
validates dot/parent and nonzero identities, and counts real readdir calls. It
cleans up only its unique temporary directory. The original small scan remains
a default case; the larger scan is opt-in.

The registered request can now execute directory-next synchronously after one
successful try of the existing cursor ownership gate. The inline and worker
paths share the same bounded record validation/copy helper. Cursor contention
falls back without advancing or copying. Snapshot construction and rewind
refresh remain protected worker operations. Checked copyout and deferred cleanup
retain their existing ownership and failure behavior.

| Scan | Before | After inline-next |
| --- | ---: | ---: |
| Three entries including dot/parent | 1.171875 ms | 0.312500 ms |
| 128 children plus dot/parent | 35.000 ms | 10.312500 ms |

The larger baseline recorded 7,336 next requests and no inline completions.
The after run recorded 29,344 next requests, all inline, and only 224 worker
submissions for snapshot opens. Counts include calibration and differ because
the faster run completes more scans. Before/after reports are
`directory_scan{,_128}-{before,after}/`; adjacent comparison text retains raw
observed ranges. Existing native eight-CPU shared-cursor acceptance and host
snapshot/cursor/retirement sanitizer checks passed, including exact-once names,
rewind refresh, malformed records and EOF preserving output.

## Full admission queues imposed a timer tick

The remaining resident-read ceiling came from syscall restart. A full I/O queue
returned the internal admission-retry marker after preparation released its
owners. Syscall return then called `process_sleep_ms(1)`. The standard 100 Hz
clock rounds that to one 10 ms tick even if cleanup frees slots immediately.

The 4 KiB diagnostic recorded exactly 192 retries and 192 wait ticks over
24,576 submitted preads: one full tick for every 128 requests. This accounted
for most of the observed cost. Inline directory scans hit the same admission
limit despite no longer waiting for a storage executor.

Both storage and event admission now snapshot a cleanup-progress sequence before
attempting allocation. On full user admission, only that value is retained in
the caller's heap-owned thread record. Preparation unwinds all request/descriptor
owners before syscall return waits. Cleanup advances the sequence after draining
and wakes the static cleanup queue. Sequence checking and queue insertion use
the scheduler lock to avoid a missed wake; terminal callers are not set running
again. The existing one-tick fallback remains for progress without notification.
The original syscall is restarted and captures its inputs afresh. Queue sizes,
request bounds and protected destructor execution remain intact.

| Diagnostic, five 200 ms rounds | Timer retry | Progress wake |
| --- | ---: | ---: |
| Warm 4 KiB API read, median | 80.566 us | 18.717 us |
| Observed range with tick margin | 75.684–83.008 us | 17.090–21.159 us |
| 128-child directory scan, median | 10.000 ms | 3.125 ms |
| Observed range with tick margin | 9.688–10.938 ms | 2.891–3.750 ms |

The optimized read run had 65,536 total preads and 512 admission retries, but
only 23 aggregate wait ticks. The optimized directory run had 576 retries and
23 wait ticks. These totals include warmup/calibration, while result operation
counts cover measured rounds. Reports are `*-admission-{before,after}/` and
`admission-{read,directory}-comparison.txt`. Overall, the larger directory scan
changed from 35 ms before both fixes to about 3.125 ms afterward.

The pipe control had no admission retries in its baseline. Its first medians
varied from 63.477 to 75.684 us with overlapping observed ranges; a longer
seven-round, 1000 ms repeat measured 68.359 us. No pipe improvement is attributed
to this change. The separate `filesystem-{baseline,after}/` reports retain the
matched full filesystem-group evaluation.

## Concurrency and ownership validation

The opt-in `pread_parallel_n` diagnostic shares one retained file across N
CPU-pinned readers, with an independently heap-owned output buffer per worker.
Setup, teardown and final payload checks are outside measurement. Every worker
must complete reads and its last array must match the source. Per-round minimum
and maximum worker counts are saved in serial and JSON `fairness` rows.

Eight-reader and 32-reader native runs passed five rounds each. Across their
rounds, the minimum worker progress was respectively at least 1,664 and 320
reads; no caller remained stuck on an admission wake. The GUI pressure run also
passed with real keyboard input, CSV export and no dropped events. Its debugger
capture is visual/input evidence and is excluded from quantitative timing
comparisons. Evidence is `pread-pressure-{8,32,gui}/`.

Existing request-owner, storage-service and multiplexed-event host contracts
passed. Native I/O service lifecycle checks passed three killed-caller cases,
independent cleanup, late outputs and shutdown, followed by TLS. Native VFS
checks passed a caller killed while blocked on the real tree lock, readlink and
a fresh successful request. Native shared directory cursor checks passed again.
These preserve the existing cancellation evidence; they are not physical disk
failure or power-loss tests. The optional boot fixtures restored the ordinary
kernel and verified their hooks were absent.

## Correct the duration of handoff measurements

The original condition case always ran 64 round trips, regardless of the
requested duration. Its CLI samples were often one 10 ms tick. It now repeats
until the requested duration and at least five advertised clock ticks have
elapsed. The two endpoints stay on CPUs 0 and 1, and all shared state remains
heap-owned. Parallel cases retain their four-times-duration window but now also
honor the five-tick floor in quick mode.

The application publishes separate condition/parallel protocol identifiers.
The runner rejects short successful samples and comparisons mixing the old and
new affected protocols. It also checks that every completed parallel round has
a worker-progress record. Old results retain their original protocol and are
not silently interpreted as the new measurement.

Seven 200 ms samples completed 6,334 CLI round trips and 1,007 GUI round trips.
Their medians were 214.362 us and 1,503.759 us respectively. The GUI slowdown is
still present with adequate sample duration. It remains an investigation target:
inspect active endpoint priorities, CPU placement and scheduler wake behavior
before changing synchronization policy. These GUI/CLI observations are different
load conditions and are not a before/after kernel improvement claim.

## Final checkpoint

Two fresh default CLI and GUI runs each completed all 75 cases with no failures.
CLI skipped only optional DNS; GUI skipped DNS and multithreaded fork. Both had
exact argument readback and no build changes during measurement. The latest
uncaptured GUI recorded 987 load frame intervals, p95 20 ms, maximum 50 ms and
zero event drops; the earlier repeat had maximum 40 ms. All successful samples
met the new floor of at least 50 ms on the current 100 Hz kernel. Reports are
`final-{cli,gui}{,-repeat}/`.

The current runner also passed a fresh 32-reader evaluation and retained all
three worker-progress records (`fairness-parser-current/`). A real comparison
against the old same-configuration handoff report rejected the protocol mismatch;
see `handoff-protocol-rejection.txt`. Native descriptor stream checks passed
aliases, nonblocking behavior, atomic pipe writes, append and shared offsets.
Existing native logs and image receipts are copied to `native-check-evidence/`.

The final matched filesystem-group run measured checked cached 64 KiB reads at
146.484 us versus 234.375 us, and checked random 4 KiB preads at 19.531 us versus
78.125 us. Their observed ranges are separate. Other small differences with
overlapping ranges are not attributed to the fixes. See
`filesystem-comparison.txt` for every workload, including unchanged controls.

`make` and whitespace checks passed. Physical hardware, cold storage,
power-loss durability and complete POSIX conformance remain outside this evidence.
The known broad runtime-archive and extracted service-factory model issues from
the first pass have not been reclassified by these targeted checks.
