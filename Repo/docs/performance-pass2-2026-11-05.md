# Continued performance investigation, 5 November 2026

The prior pass and its six verified kernel fixes are retained in
[the first report](performance-pass-2026-11-05.md). This continuation uses fresh
native eight-CPU QEMU runs and the same protected data/firmware workflow.
Before-source snapshots, measurements and receipts are under
`build/perf/pass2-20261105`.

## Thread identity and mutex cost

The current suite reports an approximately 2.4 us uncontended pthread mutex
pair, compared with about 0.22 us for an uncontended read lock. Source review
found that `pthread_mutex_lock` and `pthread_mutex_unlock` each call
`pthread_self`, which queries the kernel every time. The next diagnostics add
raw and pthread identity-query costs, recursive/error-checking mutexes, write
locks, migration identity checks and a fork-child callback identity check.
Those checks use native self-info as an independent identity source. The raw
low-level thread-ID syscall remains available for applications which manage
raw TLS themselves.

**Cause and change:** Each mutex pair paid two native identity syscalls, including
one while holding the mutex. `pthread_self` now lazily retains the immutable
native TID in a thread-local, lock-free atomic slot. The raw `sys_thread_self`
interface remains a syscall and gains no TLS dependency. The libc fork-child
boundary invalidates the copied pthread cache before application child callbacks.
Libc-only links use a weak optional hook. The existing host pthread scheduler
model was adjusted to save/restore the added TLS slot when it switches simulated
threads; no new host framework was introduced.

**Matched five-round threading results:**

| Workload | Before | After |
| --- | ---: | ---: |
| Uncontended normal mutex pair | 3.051 us | 0.114 us |
| Recursive mutex pair | 2.899 us | 0.114 us |
| Error-checking mutex pair | 3.051 us | 0.114 us |
| pthread identity query | 1.449 us | 0.047 us |
| Raw native identity query | 1.373 us | 1.373 us |
| Uncontended write lock | 2.899 us | 0.171 us |
| Eight-worker short mutex section | 28.599 us | 0.391 us |

The raw query is an unchanged control. The biggest contention benefit comes from
shortening the lock-holder's path rather than changing futex policy. Read-lock
and allocator observations varied between these runs and are not attributed to
the identity optimization. Reports and raw batches are in `threading-before/`,
`threading-after/` and `threading-comparison.txt`.

Native diagnostics passed before and after across new thread creation, all eight
CPU affinities and fork-child callback execution, comparing pthread identity to
native self-info. Existing eight-CPU pthread lifecycle, initial-thread exit,
raw TLS, compiler TLS and blocking synchronization checks all passed. The existing
host publication/refcount/ownership/deadline contract also passed.

## Memory comparison and frame-upload diagnostics

The kernel's `memcmp` compares one byte at a time. User libc has an aligned word
path but falls back to byte comparisons when pointer alignments differ. Real
window presentation copies and compares the complete surface before deciding
whether to publish it. The new evaluations cover equal/differing, aligned and
unaligned arrays, all 8x8 pointer alignments and protected page ends.

The GUI now supports static-frame and bottom-pixel upload experiments. Static
mode holds the client image unchanged; bottom mode changes the final pixel before
every present. A configurable upload batch records raw operation counts and total
time to exceed the 10 ms clock quantum. These batches intentionally block the
client event loop and are separate from ordinary UI-responsiveness measurements.
The ordinary dashboard remains at one present per loop.

The runner also records host start/end load and timestamps, rejects measurements
whose build artifacts changed during the run, checks record completeness and
GUI error/cancellation status, and retains batch statistics with an observed
range expanded by one advertised clock tick. Range overlap is descriptive, not
a statistical significance or confidence claim.

**Comparison implementation:** Kernel and user `memcmp` now use one shared
bounded scalar helper in `include/libc_compare.h`. It checks an early mismatch
cheaply, compares equal blocks in 32-byte groups with packed aliasable words,
and resolves a differing block bytewise in unsigned lexical order. Wide reads
are issued only while the remaining count covers them. No vector registers are
used in the compiled kernel function; its disassembly is retained in
`kernel-memcmp-disassembly.txt`.

The native `memcmp_guard_pages` evaluation passed before and after. It covers
zero through 257 bytes and a full page, all 8x8 alignment pairs where applicable,
equality, self-comparison, first/middle/last mismatches, reverse ordering,
high-bit unsigned differences and arrays ending at PROT_NONE boundaries.
This exercises the shared source used by both libc wrappers. Existing actual
kernel window publication is measured separately below.

| User comparison workload | Before | After |
| --- | ---: | ---: |
| Equal 4 KiB | 11.596 us | 4.272 us |
| Equal 1 MiB | 468.750 us | 390.625 us |
| Differently aligned 4 KiB | 86.669 us | 4.425 us |
| Differently aligned 1 MiB | 3,125.000 us | 390.625 us |
| First-byte difference | 0.114 us | 0.076 us |
| Last-byte difference, 4 KiB | 12.207 us | 4.882 us |

The matched memory runs are `memory-baseline/` and `memory-after/`; raw batches,
clock margins and host-load observations remain in their reports. These are
TCG measurements and do not establish physical memory bandwidth. Checks within
existing I/O cases also use `memcmp`; any cost reduction in those checked cases
must not be mislabelled as a raw storage improvement.

**Real frame-upload evaluation:** The test window is 1000x720 pixels, with 64
forced uploads per timed batch and a sleeping background workload. Both kernel
frame comparison and upload/publication are exercised. Batched uploads are an
explicit throughput experiment and intentionally delay the client's event loop;
their frame/input intervals are not ordinary responsiveness baselines.

| Present experiment | Before mean/call | After mean/call |
| --- | ---: | ---: |
| Identical frames | 9.545 ms | 2.061 ms |
| Final pixel changes on every upload | 10.170 ms | 1.631 ms |

The static after run includes 3,328 measured load-phase uploads; bottom changes
include 4,096. Baselines include 704 uploads each. Reports are
`present-static-before/`, `present-static-after-repeat/`,
`present-bottom-before/`, and `present-bottom-after/`. Each raw upload batch
retains its operation count and elapsed time.

## Evaluation correctness: verify what the guest actually received

The first static after run requested 1000 ms but echoed 100 ms in guest metadata.
The existing timed HMP keyboard taps could merge repeated characters while
virtual time lagged the host. That run is explicitly invalidated and excluded;
its raw evidence is preserved in `present-static-after/`.

The existing launcher now uses its explicit press/release command-typing path.
The runner verifies echoed mode, selectors, rounds, duration, threads, workdir,
network endpoint and presentation settings against the requested configuration,
and checks a zero process exit status. Numeric arguments are validated before
launch. A retrospective audit found exactly one configuration mismatch among
the complete reports from these two passes: the excluded static run. The audit
and a demonstrated comparison rejection are saved as
`argument-readback-audit.json` and `mismatched-argument-rejection.txt`.

## Final checks after the comparison change

Fresh CLI and ordinary dashboard runs each recorded all 75 default cases. CLI
completed 74 and skipped optional DNS; GUI completed 73 and skipped DNS and
multithreaded fork. Both had zero failures and exact configuration readback.
The GUI recorded 1,058 load frame intervals with p95 20 ms and maximum 40 ms,
zero event drops and no GUI error. These were ordinary single-upload frames.

The existing native compositor checks verified both actual window surfaces,
128 presents and repeated resize/control operations on eight CPUs. Native C11
libc, math, complex and threads passed in both legacy and owned-descriptor
runtimes, including quick-exit lifecycle. Native raw TLS and pthread ABI/lifetime
checks passed. Evidence is `default-{cli,gui}/` and the adjacent
`window-controls.log`, `c11-runtime.log`, `raw-tls-final.log`, `pthread-final.log`.
Physical hardware and scanout remain outside this evidence.

## TCP request capture versus accepted transport bytes

The stream benchmark submits the entire remaining array on each nonblocking
send and receive. The owned-I/O boundary previously reserved and zeroed up to
64 KiB minus its header on every call and copied that prefix on sends. The TCP
executor then accepted at most the negotiated segment size, currently no more
than 1,460 bytes. Read requests reserved the same large array even when only
one segment was queued, or when the read returned EAGAIN.

New monotonic counters record submitted native TCP request counts, payload
reservation/capture bytes, complete request-buffer bytes, executor-completed
payload bytes and nonblocking EAGAIN completions. `--kernel-profile` retains
named counter values in JSON and raw debugger output. Read-completed bytes
include PEEK and precede user copyout; these counters are transport-step data,
not physical wire bytes or successful application copyout. Reservations count
submitted requests, excluding preparation failures. The single-case profiles
include warmup and calibration in addition to the reported measured samples.

**Confirmed waste:** In the first matched profile, the executor accepted 7 MiB
in each direction, but write requests captured 304.433 MiB and read requests
reserved 304.728 MiB. Both runs completed exactly 5,033 write calls; packet
captures retained the same 5,026 full 1,460-byte outbound data segments in the
stream case, plus seven tails. Transport segmentation was unchanged.

**Underlying change:** `io_tcp_capture_limit` bounds large writes to the
negotiated MSS and large reads to a snapshot of queued bytes. Empty reads reserve
one segment so positive requests still wait or return EAGAIN. This is a buffer
sizing hint; the executor rechecks connection state, ownership, readiness,
errors and actual write capacity. It never turns backpressure into a zero-byte
success. Requests up to 256 bytes retain their existing bounded capture and
avoid an extra TCP-lock snapshot. Scalar read/write/send/recv, writev and
sendmsg/recvmsg share this sizing rule; UDP and local stream policies retain
their own limits. All retained state stays in registered heap requests.

The initial matched after profile captured exactly 7 MiB for writes and reserved
8.184 MiB for reads, including empty-read storage. Its 1 MiB echo median changed
from 130 ms to 100 ms. These short samples have coarse clock margins; the longer
controlled comparison below is the stronger timing evidence.

**Longer controlled comparison:** The same final application and counter
instrumentation ran with seven requested 1000 ms rounds. The reference disabled
only the new sizing hint; the optimized helper was restored and `make` rerun
before the after run. Guest configuration readback and build-image receipts
matched their requested inputs, with no build changes during either run.

| Metric | Reference | Optimized |
| --- | ---: | ---: |
| Median 1 MiB pipelined echo | 126.875 ms | 101.250 ms |
| Observed range with tick margin | 123.750–148.750 ms | 95.000–112.500 ms |
| Measured echo operations | 80 | 112 |
| System CPU per measured operation | 127.000 ms | 101.071 ms |
| Write-capture bytes / executor write bytes | 43.490 | 1.000 |
| Read-storage bytes / executor read bytes | 43.534 | 1.195 |

The median reduction is 20.2%. Observed ranges are descriptive, not confidence
intervals; QEMU and recorded host conditions remain part of the result.
`tcp-long-{before,after}/`, `tcp-long-comparison.txt` and
`tcp-capture-summary.json` preserve the full evidence. The separate matched
network group captures are `network-capture-{before,after}/`; tcpdump text and
`network-packet-analysis.json` retain packet inspection. No TCP RST was seen in
either capture. Group totals include download/setup traffic and different
calibrated operation counts, so their aggregate packet totals are not a speed
comparison. Small TCP echo and unrelated cases had overlapping observed ranges.

**Native behavior checks:** The opt-in `tcp_vector_stream_1m` diagnostic alternates
sendmsg and writev while receiving through two scatter vectors. Their boundaries
split payloads at 733 and 17 bytes to cross captured prefixes and exercise aligned
metadata trailers. It verified all echoed bytes over 2,517 sendmsg, 2,516 writev
and 5,036 recvmsg calls, including warmup/calibration. Existing eight-CPU native
scalar socket and Rust Socket2 checks passed, covering blocking/nonblocking,
PEEK, aliases, EOF, failed copies, endpoint queries and real gather/scatter.
Existing writev and native poll/TCP/cancellation checks also passed.

Existing host request ownership/copy-fault models and TCP ownership sanitizer
checks passed. Their dependency stubs now include the sizing hint; the writev
model also needed its missing local-socket predicate stub to match the existing
production dependency. No new host framework was added. Logs are
`{socket,socket2,writev,poll}-after-capture.log`, `tcp-vector-native/` and the
adjacent `*_contract_test.log` files.

## Final application and UI checkpoint

After the TCP change, `final-tcp-cli/` and `final-tcp-gui/` again completed all
75 default cases with zero failures and exact argument readback. CLI skipped
only optional DNS; GUI skipped DNS and multithreaded fork. The uncaptured GUI
recorded 988 load-phase frame intervals with p95 20 ms and maximum 40 ms, zero
dropped events, no GUI error and successful CSV export. The largest frame
interval occurred during the oversubscribed CPU workload. These are 10 ms-clock
observations, not physical scanout measurements.

`final-tcp-visual/` captured the real compositor during vector network load,
received the actual keyboard probe, exported twice and exited cleanly with no
event drops. The app checked the entire echoed payload over 23,012 sendmsg,
23,012 writev and 46,075 recvmsg calls including warmup/calibration. Its debugger
pause excludes it from quantitative timing comparisons. The actual image is
`final-tcp-visual/dashboard.png`. `fork-identity-final/` also passed the native
fork-child callback identity diagnostic using the final runtime and kernel.
Copies of existing native check logs and receipts are retained under
`native-check-evidence/` to avoid depending on later overwritten test outputs.
