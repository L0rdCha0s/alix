# Native performance lab

`perf.elf` is a native Alix application built with the shared libc, pthreads,
process-owned descriptors, VM syscalls, network stack and ATK renderer. Running
it without arguments opens the GUI. The same workloads run with `--cli`.
Normal `make` builds `build/user/perf.elf`, `build/bin/perf` and includes the
runtime ELF in `user-elfs.zip` / the existing `dl.sh` installer.

## Running on Alix

After installing the current runtime package:

```text
/usr/bin/perf.elf
/usr/bin/perf.elf --cli --quick
/usr/bin/perf.elf --group threading --threads 8
/usr/bin/perf.elf --cli --group vm --rounds 7 --duration 100
```

The GUI has Start, Stop, a workload-group selector, Export CSV, Probe and result
paging controls. `Space` starts/stops, `P` exercises keyboard dispatch, `E`
exports, and `J`/`K` page the result table. Stop requests cooperative cancellation;
network steps have timeouts and thread state is joined before freeing it. The
UI thread alone owns widgets and pixel buffers. Workload callbacks and all
cross-thread synchronization records are heap-owned.

Export writes `/tmp/perf-results-PID.csv`. It contains workload results followed
by tagged `PERF_UI` rows. GUI records also go to serial; CLI records go to stdout
and can be redirected. Failures retain their native errno and partial completed
sample counts. `SKIP` means an optional endpoint was not supplied; `STOP` means
user cancellation. A stop does not become a performance failure.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--gui` / `--cli` | GUI | Select presentation |
| `--autorun --exit-when-done` | off | Bounded unattended GUI run |
| `--quick` | off | Three rounds, 10 ms requested batch duration |
| `--rounds N` | 5 | 1–15 measured rounds |
| `--duration MS` | 30 | 10–1000 ms requested batch duration |
| `--threads N` | min(online CPUs, 8) | 1–32 workers; oversubscription uses twice N |
| `--group NAME` | all | Select one group below |
| `--case NAME` | all | Run one named workload; diagnostic cases below are opt-in |
| `--workdir PATH` | `/tmp` | Existing directory for unique temporary workload files |
| `--net IPv4 --port N` | absent | TCP and UDP echo endpoint |
| `--dns-host NAME` | absent | Opt-in resolver workload |
| `--ui-present dashboard/static/bottom` | dashboard | Draw normally, hold a static bitmap, or change its final pixel on each upload |
| `--present-batch N` | 1 | 1–128 uploads per UI observation; N > 1 requires GUI static/bottom mode |

Filesystem workloads create and remove their own `perf-XXXXXX` directory and
1 MiB file. `/tmp` exercises the memory-backed VFS; use a directory on the mounted
AlixFS volume to measure persistent writes and `fsync`. Cache reads deliberately
measure warm data. These are not raw-device or cold-cache storage benchmarks.
The opt-in `--case socket_burst_128` opens 128 unconnected TCP descriptors and reports their receive-buffer heap reservation. It is excluded from the default suite.

Additional opt-in evaluations are `memory_copy_guard_pages` (memcpy/memmove
return values, all 8x8 pointer alignments, lengths 0–257/4095/4096, overlap gaps
1–33, read-only source, protected page edges and destination canaries),
`memcmp_guard_pages` (all pointer alignments, unsigned ordering and protected
page ends), `thread_identity_lifecycle` (new
thread identity across CPU migration) and `fork_thread_identity` (CLI-only
identity validation in fork-child callbacks). `tcp_vector_stream_1m` alternates
sendmsg/writev with recvmsg scatter copies and validates every echoed byte. It
requires the same echo endpoint as the scalar stream case. The default inventory
has 79 cases.

Opt-in filesystem evaluations include `directory_scan_128` (validate every name
once), `cached_read_4k_api`, `cached_read_60k_api`, `cached_read_64k_api` and
`cached_read_60k_checked`. API cases validate the last array after timing; the
checked case validates every operation. Their detail rows count actual pread
calls/bytes including warmup and calibration. `pread_parallel_n` shares a file
across N pinned readers, requires every worker to progress and verifies final
buffers outside timing. Per-round worker ranges are retained in JSON `fairness`.

`condition_pingpong_2_3` is an opt-in handoff on CPUs 2/3; the default case keeps
CPUs 0/1 so compositor interference remains observable. The alternate requires
four online CPUs and restores the benchmark coordinator to CPU 0 afterward.
`PERF_HANDOFF_IDS` and JSON `handoff_ids` retain the actual native endpoint IDs.
The QEMU driver accepts `--scheduler-profile` for either handoff case. It captures
active priorities, affinity, run queues and current CPU occupants before timing,
validates endpoint identities, and excludes the paused run from comparisons.
`--scheduler-costs` instead uses two debugger checkpoints: it arms optional
CPU-local scheduler counters when both endpoints are ready, then captures the
first completed sample while both remain alive. JSON `scheduler_snapshot.costs`
contains lock wait, selection, preparation, FP, MMU, register, stack and cleanup
counts/TSC sums per thread. Some phases are inclusive; do not sum them as disjoint
wall time. These are diagnostic TSC units, not calibrated nanoseconds, and the
mode adds overhead and excludes its report from timing comparisons. Profiling
is disabled by default. Current kernel stack-debug enforcement is disabled by
request; its configuration and measurements are in the fifth pass.

Kernel profiles also retain futex retry/reuse and wake-to-resume tick totals plus
framebuffer publication byte/tick counters. Framebuffer counters cover the whole
boot, including setup; periodic frame timing can bias coarse tick sums.

The default suite has a bounded working set and does not deliberately exhaust
RAM, force swap, modify existing files or flood a network.

## Workloads

| Group | Paths exercised |
| --- | --- |
| `syscall` | PID query, monotonic and process CPU clocks, 256-byte entropy |
| `memory` | malloc/free at 64 B, 4 KiB, 1 MiB; calloc; realloc preserving data; fragmented allocation churn; aligned/unaligned memcpy, memset, forward/backward one-byte and backward 16-byte overlapping memmove, aligned/unaligned/early/late memcmp |
| `vm` | Map/touch/unmap, sparse reservation, protection changes, discard plus 16 real demand-zero faults per operation |
| `threading` | Futex mismatch and empty wake, normal/recursive/error-checking mutexes, read/write locks, pthread/raw identity queries, TLS, create/join, cross-CPU condition handoff, shared atomics, contended mutex and allocator |
| `scheduling` | Yield alone, 1/10 ms sleeps, CPU work at 1/N/2N workers, yields sharing one CPU and spread across CPUs; worker progress ranges |
| `process` | Self-spawn and wait, single-threaded fork/exit/wait (CLI only) |
| `ipc` | Nonblocking pipe and local socket-pair transfers at 64 B/4 KiB, readiness scans at 1/32/128 entries |
| `filesystem` | stat, open/close, dup, directory enumeration, create/unlink, warm sequential and random reads, overwrite, write/fsync, private file mappings |
| `network` | Socket lifecycle, TCP connect/close, small echo, serialized 64 KiB echo, pipelined 1 MiB echo, UDP at 64/1200 B, optional resolver |
| GUI | Continuous native widget drawing and full-surface presentation, frame intervals, scheduled wake delay, real mouse/key queue delay, input-to-present return, queue overflow count |

Copy throughput cases verify the final complete payload after timing. Move
cases perform one move per operation and verify the final array against the
original data and the actual number of warmup/calibration/measured moves. The
guarded copy case is correctness-only; its elapsed time includes validation and
should not be treated as copy throughput. These user VM guards are separate
from the disabled kernel stack-debug guards.

The poll-size workloads repeat a live descriptor to isolate vector-scan cost
without measuring descriptor creation. Pipe/socket-pair transfers write and
read in one thread: their results measure syscall/copy/readiness cost. The
condition handoff measures blocking wakeups between threads. The CPU workers
perform 128 dependent arithmetic steps per reported work unit. N-worker costs
are elapsed time divided by the sum of worker operations, so throughput and
single-worker latency are different quantities.

Spawn loads the actual benchmark ELF into a fresh address space and waits for a
minimal `--child` exit. It includes loading the full static runtime. GUI fork is
explicitly skipped because the GUI already has multiple threads. No unsupported
API is counted as a successful zero-cost operation.

## Network endpoint

On the host:

```sh
python3 tools/perf.py serve --port 7777
```

On a QEMU user-network guest:

```text
/usr/bin/perf.elf --net 10.0.2.2 --port 7777
```

For a physical machine, pass the host's reachable IPv4 address. TCP and UDP use
the same port; both must be reachable. Echo payloads are checked byte for byte.
The stream case sends and receives concurrently using nonblocking I/O to avoid
application-imposed round trips. The serialized echo case intentionally waits
for each 1 KiB chunk. DNS uses the system resolver and its current cache; it is
not a cold-DNS or public-internet latency test.

## Isolated QEMU runs and comparison

```sh
make
python3 tools/perf.py run --quick --output build/perf/before
python3 tools/perf.py run --quick --output build/perf/after
python3 tools/perf.py compare build/perf/before/report.json build/perf/after/report.json
python3 tools/perf.py run --gui --quick --output build/perf/gui
python3 tools/perf.py run --gui --quick --capture --output build/perf/visual
```

`make perf-qemu` runs the GUI suite; `make perf-cli-qemu` runs the CLI suite.

The driver reuses the existing `run_native_elf` launcher and `run-via-agent.sh`.
It serves the stripped ELF from the runtime package and boots the current kernel and loader in an eight-CPU QEMU guest with disposable
data and firmware variables, supplies local TCP/UDP echo servers, downloads the
actual app, waits for its exit, and saves serial output, image hashes, JSON and
CSV. It does not touch `data.img`. Run sequentially with the same host load,
QEMU acceleration/CPU/RAM and CLI or GUI mode. Compare several runs; one quick
run is a diagnostic, not a stable ranking.

`--capture` uses the existing native debugger checkpoint to capture the actual
compositor and inject physical keyboard probes. That pause contaminates timing;
these runs establish rendering/input proof. The comparison command rejects
captured reports. Use uncaptured runs for quantitative baselines.

`PERF_RESULT` fields are group, name, status, sample count, workers, operations,
bytes, total elapsed ns, batch-average p50/p95/max ns per operation, user/system
CPU microseconds, minor/major faults and error. `PERF_SAMPLE` preserves each raw
batch duration and operation count. `PERF_FAIRNESS` preserves the minimum and
maximum worker progress per round. The JSON report retains raw batches, host UTC/load observations and observed
sample ranges expanded by one advertised tick per operation. Those ranges are
descriptive and are not confidence intervals. The runner verifies the guest's
echoed arguments and rejects configuration mismatches or build changes during
measurement. New reports also fingerprint the evaluation driver and launcher,
reject edits during a run, and compare recorded evaluator fingerprints.
Comparisons check presentation mode, upload count and dimensions.

`PERF_UI` fields are phase, metric, count, mean/p50/p95/max ns.
`PERF_UI_WORKLOAD` has the same fields with the workload name replacing phase.
With the default upload count these are individual UI observations. In explicit
batched mode the present metric is named `present_batch_average`; its value is
total batch duration divided by uploads. `PERF_UI_PRESENT_BATCH` retains phase,
sequence, upload count and total elapsed ns. These batches intentionally block
the event loop; their frame/input delays are not ordinary responsiveness results.
Per-workload assignment follows the workload observed by the UI loop; transitions are not
kernel tracing boundaries. The host JSON keeps both aggregate and workload UI
metrics. `--case NAME` also selects a single workload in the QEMU driver;
`--pcap` saves network packets for tcpdump. `--kernel-profile` takes an existing
debugger checkpoint after a single case for kernel counters, including submitted
TCP capture/reservation versus executor-completed bytes. Named TCP counters are
retained in `kernel_counters`; they include calibration/warmup and count read
PEEK before user copyout. See the continued report for their exact scope. Its pause affects
GUI observations, so those GUI reports are excluded from comparisons. Exported guest CSV includes the aggregate UI rows.

## Measurement boundaries

The present Alix clock advances in 10 ms ticks on the standard 100 Hz kernel.
Reported nanosecond units are conversions, not nanosecond clock accuracy. Batch
measurement continues for at least five clock ticks, even in quick mode, to
avoid reporting zero-cost operations when a calibration sample straddles a
tick. GUI `0` means below the clock's resolution. CPU accounting is also sampled
at timer granularity and, in GUI mode, includes both UI and benchmark threads.
Condition round trips now run to the requested duration and at least five
clock ticks. Parallel workloads retain their four-times-duration window with
the same minimum tick floor. Their explicit protocol identifiers prevent
comparisons against the older fixed-64 handoff and shorter quick parallel runs.
The runner checks successful sample durations and progress-record completeness.
Percentiles over three or five batch averages are descriptive, not statistical
confidence intervals. GUI histogram values at 2000 ms are a saturated lower
bound; exact maxima remain available.

The GUI runs a continuously redrawn dashboard at a requested 16 ms cadence.
“Idle” means no benchmark workload; it still includes this renderer and the
normal desktop. Full-surface present deliberately measures a real upload. Input
queue delay starts when the kernel enqueues the window event, after device
routing. Coalesced moves/resizes retain the oldest queued timestamp. The timed
poll also reports cumulative queue overflows. Input-to-present return ends when
the upload syscall returns: neither this metric nor the present-call metric
proves compositor completion, scanout or input-to-photon latency. Opening the
GUI changes system load; compare GUI runs against GUI runs.

This initial suite covers the core paths listed above. Audio DMA, GPU engines,
USB/disk driver throughput, physical-device latency, cold boot, swap-pressure
replacement and every workload-specific subsystem need separate representative
experiments. QEMU measurements do not establish physical-hardware performance.

## First observed bottleneck

The first full GUI run exhausted TCP allocations after descriptor churn:
`socket_create_close` failed with `ENOMEM`, followed by all TCP connect/echo
cases. Source inspection found that `fd-cleanup` drained only 64 objects then
slept for a timer tick regardless of pending work. Closed objects retained their
resources in that backlog; an unopened TCP socket then allocated a 5 MiB
receive buffer.

The cleanup worker now yields after a full batch and immediately drains another
bounded batch. It sleeps when the queue no longer fills a batch. A full GUI
rerun then completed every enabled workload without allocation failures. This
change retains the existing persistent-worker ownership and deferred-close
contract. A subsequent [performance investigation](performance-pass-2026-11-05.md) reduced unopened socket reservations and fixed deferred receive and scheduler wake delays.
The original captured run is visual/debug evidence, not a timing baseline.

Follow-up results for the 75-case suite are in
[the thread/memory/TCP investigation](performance-pass2-2026-11-05.md) and
[the filesystem/admission investigation](performance-pass3-2026-11-05.md), followed
by [GUI scheduling and publication](performance-pass4-2026-11-05.md) and
[scheduler phase measurements and guard configuration](performance-pass5-2026-11-05.md).
The current 79-case inventory adds the
[unaligned copy investigation](performance-pass6-2026-11-05.md).

## Initial validation recorded on 5 November 2026

- Two fresh eight-CPU CLI boots each completed all 64 cases: 63 OK and the
  optional DNS case skipped, with zero failures. Reports are
  `build/perf/baseline-cli-{1,2}/report.json`; their comparison is
  `build/perf/cli-comparison.txt`.
- The uncaptured packaged GUI run completed 64 cases: 62 OK, with DNS and GUI
  fork skipped, zero failures and zero event drops. Its 2,306 load-phase frame
  observations had p95 20 ms and maximum 170 ms; present-call p95 was 10 ms.
  The longest observed frame intervals occurred around readiness-vector and
  VM workloads, which need longer focused runs before attributing a cause.
  See `build/perf/baseline-gui/report.json` for aggregate and per-workload data.
- The packaged GUI also completed the full suite with an actual compositor
  capture, a real keyboard probe and successful CSV exports. Visual evidence is
  `build/perf/final-gui-visual/dashboard.png`. That captured report is excluded
  from timing comparisons. The separate `build/perf/gui-controls/report.json`
  records actual Probe/Export/Stop input, cooperative cancellation and clean exit.
- Native 1 ms sleeps measured 10 ms in both CLI runs. Pipelined 1 MiB TCP echo
  measured approximately 0.156 MiB/s in both runs. The current transport retains
  one MSS of outstanding payload, a concrete next investigation target; these
  figures include QEMU and the local host echo service.
- `make`, existing window-control contracts, keyboard-event contracts and
  deferred-FD-retirement contracts passed. No new unit-test harness was added.
- Two broader checks remain red: `kernel_service_factory_test.py` lacks a
  `timer_ticks` declaration in its extracted host model, and the runtime-archive
  symbol comparison rejects strip's changed symbol types for
  `__alix_static_tls_start/end` (also present in the existing ATK demo). The perf
  ELF's entry point, program headers and loaded bytes are identical before and
  after stripping; the exact ZIP payload matches the runtime file, and that
  stripped app passed the native GUI runs. This is not a claim that the broad
  runtime-archive gate is green.
