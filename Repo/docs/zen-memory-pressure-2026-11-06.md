# Zen memory pressure and retirement diagnostics, 6 November 2026

The browser diagnostics now expose allocation failures, receive-buffer capacity,
resize acknowledgement and process retirement. The native performance GUI and
CLI remain the entry points for platform workloads; the existing Zen runner
exercises the same paths in the actual browser.

## Receive reservations caused the first browser allocation failures

The profile-heavy two-visit workload previously stopped progressing. Failure-only
allocator history records the first requested allocation and caller, plus the
last 16 failures. The captured first six failures were each 5,242,880 bytes at
`tcp_init_rx_buffer` / `net_tcp_socket_connect`, resolved against the exact
`failure-kernel.elf`. Later failures were larger reallocations. This identifies
the first failing subsystem rather than inferring it from total free memory.

Connected TCP sockets previously expanded their receive allocation to the full
5 MiB limit before receiving any payload. They now retain the 64 KiB initial
buffer and grow according to queued data. Recent actual receive traffic also
allows a negotiated scaled window to grow toward its representable limit even
when a fast reader keeps occupancy low. The existing scaling negotiation and
5 MiB queue ceiling remain. Optional growth failure preserves the connection,
actual-window backpressure and the original allocation, with a 100 ms retry
interval. Counters retain current/peak pool capacity and successful/failed growth.
This reduces the initial connected reservation by 98.75%; it does not imply that
large transfers remain in 64 KiB.

Bulk checks used eight CPUs, QEMU TCG/igb, the same empty-volume source, and both
Slirp and the already-running vmnet service. Each run completed eight 1/8 MiB
transfers across `/tmp` and `/root`, checked every file, then shut down and verified
two persistent hashes after a cold remount. All four runs passed: 32 transfers,
eight cold-remount hashes and eight QMP-confirmed guest-originated shutdowns.

| Backend / payload | Before median Saved time | After | Before / after median MiB/s |
| --- | ---: | ---: | ---: |
| Slirp / 1 MiB | 186.7 ms | 187.9 ms | 5.36 / 5.34 |
| Slirp / 8 MiB | 258.6 ms | 256.4 ms | 31.12 / 31.38 |
| vmnet / 1 MiB | 197.3 ms | 187.3 ms | 5.07 / 5.35 |
| vmnet / 8 MiB | 290.6 ms | 282.4 ms | 27.57 / 28.33 |

These small local samples show no material throughput regression; they do not
establish an Internet-throughput improvement. Saved time includes command
submission; packet spans are reported separately. `tcpdump` confirms window
scaling negotiation and an initial effective 65,536-byte receive window on vmnet.
The existing native TCP ownership/cancellation, event-I/O and TLS checks also
passed. Host receive checks retain their assertions and exercise optional growth
failure with their existing static-buffer fixtures.

Raw results are in `test-out/network-tcp-release-{user,vmnet-shared}-{before,after}-20261106/`.
The bulk baseline kernel SHA-256 is
`47c43a0ba9e0d78363b13a74e9801183f0a93455c1c16e4058653c4c66644b8f`;
the TCP candidate is
`7dd7660ec02d653ce10af84689a3ee650942b47d45dc1cb6e6be806ad1066ad5`.

## Resize and close now have separate observations

`--geometry-check --shutdown-check` checks the native window's exact client
size, surface generation and byte count after shrinking, then waits for the
existing DOM response marker to relocate into the smaller window. The surface
and page-marker intervals are host upper bounds; the surface check includes
GDB pauses and neither metric measures physical scanout or complete text reflow.
The marker is anchored at the page edge, so a stale cropped frame cannot pass.

The runner also records close injection and the interval to process retirement,
requires exit status zero, waits for the Terminal launch job to retire, then
captures post-close heap and scheduler counters before shutting down. Failure
snapshots include thread exit/lifetime flags, process state/lifetime and per-CPU
incoming/outgoing handoff identities. A captured kernel fatal is surfaced in
`result.json`, separately from the original timeout. Allocator profiles now also
retain the first/last failed realloc's outer caller and prior allocation size.
All allocator history is failure-only and requires no stack unwinding or target
function calls. GDB resolves recorded callers to symbols/source lines against
the booted ELF. The runner snapshots both GDB scripts and retains `kernel.elf`
in the result folder so subsequent workspace rebuilds cannot invalidate capture
symbols.

The `tcp-final-profiled` run passed two page visits, six trusted native input
probes, all content diagnostics and exact resize checks, with zero allocator
failures. Its close timeout was a scheduler halt: CPU 6 was in
`fatal("terminal thread resumed after context switch")`. The browser window had
closed. This is independent of the earlier receive-allocation failures.

The scheduler's run-current shortcuts checked the RUNNING enum without checking
thread exit or owning-process termination. They could therefore return from a
terminal handoff instead of switching off that stack. Scheduling now rejects
terminal current threads before those shortcuts, clears pending wake/preemption,
and retains CPU/stack ownership until the ordinary assembly handoff. Queue
eligibility also rejects exited threads and terminal processes. Exceptional
handoff/rejection counters make this path observable. The guard does not depend
on the disabled stack-debug features.

A baseline repetition (`close-repro`) passed, confirming that the halt is
intermittent rather than a consistently missed close click. An intermediate
scheduler candidate also completed the already-installed heavy-volume workload
(`scheduler-installed-profiled`), but that volume still recorded nine allocation
failures before geometry and 63 by post-close; this is not a memory-health pass.
The original close race was not forced in these repetitions: both exceptional
scheduler counters were zero. The change closes the observed eligibility hole;
a successful repetition alone does not prove an intermittent race eliminated.

The final ordinary kernel (`632bb3bad237ed4bb61dd0d3ee21740a7a0c6347e8351274645c9106d53e59ba`)
passed the existing eight-CPU process spawn/wait acceptance, including eight
waiters, orphan retirement and a killed waiter. Existing handoff, locking,
process-I/O, TCP ownership and receive host checks passed. The process-I/O model
needed missing admission fields/timer/sleep stubs restored; assertions were not
weakened and no new test harness was added. The heap also compiles with allocation
tracing disabled.

The installed-browser control volume passed two page visits, six trusted input
probes, both sets of 11 content diagnostics, exact resize and clean close/shutdown
on the final kernel (`scheduler-controlled-final`). No progress sampling was
used. Its final heap had 467,838,048 bytes free, 467,223,312 bytes in the largest
block and zero failed allocations; post-close also recorded zero failures.
Resize surface observation took 171.8 ms and page-marker observation 1,274.2 ms,
both upper bounds with the stated debugger/polling limitations. Process retirement
was observed within 6,650.5 ms of close injection. These are separate observations,
not a speedup comparison with the heavier source.

## A separate file-cache limit remains

The final diagnostic-runner confirmation (`final-control-shutdown`) passed one
visit, three trusted inputs, all 11 content diagnostics, exact resize and clean
retirement on the same final kernel. It also retained the QMP event with
`guest=true, reason=guest-shutdown`. This closes a diagnostic bug observed in
`final-pressure-attribution`: poweroff between Enter key-down and key-up had
surfaced as JSON decoding of an empty QMP read. The runner now treats QMP EOF
explicitly, retains asynchronous events and requires guest-originated shutdown
plus runner status zero. That earlier result remains a failed shutdown-gate run,
although its page/resize/retirement stages passed with zero allocation failures.
Intermediate profiled captures are exploratory; final confirmations use frozen
GDB scripts and a retained matching kernel ELF.

The source-heavy volume eagerly caches unrelated files and saved browser
profiles. Its resident cache remains a major part of the fixed kernel heap.
The `scheduler-after-profiled` install failed before browser launch: a small
`libxul.so` size increase triggered a 222,498,016-byte realloc request while the
archive and old library cache were still resident. The extraction returned a
failure status and the runner correctly rejected the run. This is not a browser
runtime or scheduler acceptance pass. The final diagnostics reproduced the install failure again in
`final-guest-shutdown`, retaining the matching kernel ELF and resolving the outer
caller to `vfs_write_at_internal`, inlined `ensure_capacity_locked`, at
`src/kernel/vfs.c:884`. Its previous allocation was 205,720,800 bytes and the
failed request was 222,498,016 bytes. No lazy file loading or cache eviction is
implemented by this change. The already-installed private checkpoint separates
runtime validation from this installer/cache-pressure problem.

A repeat on the installed heavy checkpoint (`scheduler-final-unprofiled`) also
completed both visits, six inputs and content diagnostics, but failed during
geometry: Zen raised signal 11. Before geometry, only 4,141,552 heap bytes were
free and the largest free block was 1,763,456 bytes. Failure history then recorded
VFS growth from 8,390,656 to 16,781,312 bytes and a failed 5,038,080-byte ATK surface
allocation. The outer realloc caller points into `ensure_capacity_locked` /
`vfs_write_at_internal`. There were no scheduler terminal-counter hits in this
failure. The runner now reports a vanished browser window and its observed wait
status explicitly instead of an empty-window `max()` error. This is a remaining
memory-pressure failure, not a clean runtime acceptance result.

The next storage change must load file payloads on demand while keeping namespace
metadata resident. Storage waits must occur outside the namespace/data spinlocks,
with owned references and backing extent/version checks; mapping preparation and
copy-on-write writeback must keep their existing cancellation and publication
contracts. Merely using a cleaner volume does not fix eager caching on the saved
profile-heavy volume.

Evidence is under `build/perf/zen-file-cache-20261106/`, including the allocation
failure run, failed close, baseline repetition, matching preserved kernel ELFs,
packet sample, build/check logs and `evidence.json`. All OS runs use private disk
clones and fresh profiles; source image metadata is checked before and after.
The original `data.img` and saved profiles are preserved. These are QEMU results;
physical-machine behavior remains unverified. All eight kernel stack-debug
flags remain zero by request.

The subsequent [lazy-cache pass](zen-lazy-cache-performance-2026-11-06.md)
implements demand loading and verifies the previously failing heavy-volume
browser/install workloads, unloaded-file rename, independent remounts and full
preservation of prior files and profiles.
