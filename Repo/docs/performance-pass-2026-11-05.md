# Performance investigation, 5 November 2026

This pass uses the native performance application in fresh eight-CPU QEMU
boots, with disposable data/firmware and the existing `run-via-agent.sh`
launcher. Source snapshots and benchmark receipts are retained under
`build/perf/pass-20261105`. Results establish behavior in this QEMU environment.
Each change is measured before proceeding to the next one. Existing dirty work
and persistent disk images are preserved.

## 1. TCP receives waited for a timer tick after deferred interrupts

**Observation:** The focused 1 MiB TCP echo took 5.38 seconds at the median
(`tcp-before-profile/report.json`). `tcpdump` showed the host ACKing a guest
segment in roughly 20–60 microseconds and returning echoed bytes promptly, but
many guest receive/next-send steps paused for 6–10 ms. The kernel checkpoint
counted 6,191 deferred NIC interrupts, 7,846 packets drained by polling and
2,616 timer-driven deferred receive polls. The post-measurement breakpoint does
not pause any timed batch.

**Cause:** `igb_on_irq` acknowledges the receive interrupt. If it interrupted a
thread holding a generic preemption guard, dispatch is deferred to avoid
entering TCP/scheduler code under that guard. The only recovery point was the
next safe 100 Hz timer tick. Short nonblocking socket syscalls repeatedly hit
that case, adding an entire tick to many exchanges.

**Change:** Check the pending flag at the unlocked syscall-return boundary and
drain a bounded receive batch there, with interrupts enabled. The driver's
existing RX lock and descriptor budget retain serialization. The timer and
missed-interrupt watchdog remain fallbacks. `/proc/sys/net/igb_stats` now exposes
`syscall_return_polls` as well.

**Result:** The identical captured/profiled workload completed at a 0.20-second
median, about 27x faster; three measured transfers totaled 0.69 seconds versus
16.23 seconds. Every echoed byte matched. Timer-driven deferred polls fell from
2,616 to zero. Raw packets and checkpoint counters are in `tcp-before-profile/`
and `tcp-after-rx/`. This fixes deferred receive latency without changing TCP's
retransmission or send-window policy.

Existing network-download and production TCP ownership contracts passed.
Further native network/SMP validation is recorded below as the pass continues.

## 2. Zero-timeout poll used the asynchronous request lifecycle

**Observation:** A longer GUI `poll_idle_128` run measured 97.656 us per call at
the median. Every immediate scan captured a poll set, allocated a service
request, registered it under the scheduler lock, completed it inline, then
entered wait/result/retirement transitions to collect an already available
answer. This needlessly put global scheduler and request queues on the hot path.

**Change:** A zero-timeout poll now scans its heap-owned, pinned descriptor set
inside the existing bounded preparation guard and copies the answer directly.
It preserves duplicate-FD counting, checked copies, descriptor ownership and
pending-signal EINTR behavior. Calls that may wait retain the registered request
path. The readiness scan is shared with that existing path.

**Result:** The same seven-round GUI workload dropped to 78.125 us per call
(20% lower). Existing production poll/select contracts passed masks, deadlines,
OOM, ownership and 20,000 concurrent snapshots. The GUI still stalled for up to
420 ms, so this change was not treated as the complete UI fix. Reports are
`poll-before/` and `poll-after/`.

## 3. Protected syscalls could postpone UI sleep wakeups for seconds

**Observation:** The longer polling workload exposed a 1,500 ms maximum GUI
frame gap. Temporary kernel profiling recorded no heap or process-memory lock
wait reaching even one 10 ms tick, ruling out long waits on those locks in that
run. The tick handler nevertheless returned before global sleep/alarm wakeups
whenever the BSP was inside a preparation guard. A tight syscall loop could be
inside such a guard on almost every IRQ0, so time advanced while a GUI thread's
expired sleep remained queued.

**Change:** BSP timer interrupts mark deferred wake work when they cannot enter
the scheduler safely. The unlocked, interrupt-enabled syscall-return boundary
now performs pending sleep/alarm wakeups. It also processes deferred TLB
completion notifications. No scheduler operation is moved inside a generic lock,
no timer ticks are fabricated, and CPU accounting is not charged twice.
The temporary heap/memory lock instrumentation was removed after diagnosis.

**Result:** The same seven-round, 300 ms polling case produced 207 load-phase
frames with 20 ms p95 and 30 ms maximum gaps, versus 14 frames and a 1,500 ms
maximum before the changes. The worker cost rose slightly from the intermediate
poll-only optimization because the UI could now run throughout the workload.
The relevant report is `poll-after-wakes/report.json`.

The faster startup also exposed a completion-detection defect in the existing
QEMU launcher: a prompt containing partially typed command text could count as
command completion, while a completed prompt followed by a kernel diagnostic
could fail to count. Its existing prompt check now distinguishes those cases.
The successful rerun verified the actual app after this launcher correction.

## 4. Ready pipe transfers made an unnecessary event-executor trip

**Observation:** A 64-byte pipe round trip took 468.750 us at the median across
seven measured rounds. Local socket operations already tried a bounded step in
the caller, but pipe reads/writes always entered the event executor even when a
write had room or a read already had bytes available.

**Change:** Try the existing pipe ring operation inline while its registered
request and preparation guard protect ownership. If that bounded step cannot
complete, submit the same request to the existing readiness executor. Ring
capacity, PIPE_BUF atomicity, EOF, EPIPE/SIGPIPE, checked copies and cancellation
retain their existing implementation.

**Result:** The identical workload measured 68.359 us at the median, about 6.9x
faster, with all payload checks passing. Reports are `pipe-before/` and
`pipe-after/`. Existing production pipe contracts passed wrap, atomic writes,
EOF/EPIPE, pair rollback and allocation failures.

## 5. Unopened TCP sockets each reserved a full 5 MiB receive buffer

**Observation:** The opt-in `socket_burst_128` case opened 128 ordinary TCP
descriptors without connecting and read their actual receive capacity through
SO_RCVBUF. Each reserved 5,242,880 bytes, or 640 MiB across the batch, despite
having no peer and no incoming traffic.

**Change:** Unopened sockets now reserve 64 KiB. Connect grows the buffer to the
existing 5 MiB capacity before route/SYN/window advertisement. Connected receive
policy, backpressure, retransmission and advertised windows retain their normal
capacity. An unsuccessful expansion leaves the small buffer owned and freed by
the existing error/close path.

**Result:** The same native 128-socket case reported 65,536 bytes per socket,
8 MiB total: an 80x reduction in reserved receive-buffer heap space. This makes
632 MiB available for other allocations within the already reserved kernel heap;
it does not return that physical heap reservation to PMM. The burst's 40 ms
median lifecycle cost was unchanged, so this is a capacity improvement, not a
claimed latency gain. Reports are `socket-memory-before/` and
`socket-memory-after/`. The stress case is opt-in and does not change the default
64-case suite.

## Common-path cost and the remaining VM outlier

The deferred-work hooks now check inactive flags before CPU/guard queries. A
seven-round 300 ms `getpid` workload measured 1.792 us median before that fast
path and 1.602 us afterward (`return-hook-before/`, `return-hook-after/`). Small
microbenchmark changes at this scale remain subject to clock quantization and
host variation; the purpose is to avoid making ordinary syscalls pay repeated
SMP guard checks when there is no deferred work.

A full GUI run recorded a single 110 ms interval around discard/refault. The
longer uncaptured isolated case then recorded 162 load-phase frames, 20 ms p95
and 30 ms maximum (`vm-before/report.json`). A separate post-measurement kernel
profile counted 751 ordinary VM serialization waits and 1,179 TLB waits. This
confirms that the VM path coordinates with concurrent callers, but does not
attribute the unreproduced 110 ms outlier to an incorrect barrier. VM transaction
serialization, pager exclusion and TLB-retirement correctness barriers are
retained. Captured GUI profiling reports are excluded from timing comparisons.

The standard 100 Hz clock still rounds a 1 ms sleep up to about 10 ms. That is
the configured timer resolution, not an incorrect zero-cost or precision claim.
This pass does not increase the interrupt rate, busy-wait to imitate finer
sleep resolution, or change TCP congestion/retransmission policy.

## 6. Ordinary syscalls unnecessarily waited behind VM transaction retirement

**Observation:** A second full GUI sequence reproduced a 170 ms interval in the
discard/refault phase, with a 50 ms protection-phase interval. The isolated
longer case was better, so a single isolated run did not establish the cause.
The VM profile counted 751 serial waits. At syscall entry, every caller used
`vm_lock_ready`, so clocks, input polling and presentation could repeatedly park
behind another thread's VM journal even when touching unrelated mappings.

**Cause:** Pager exclusion and VM-transaction serialization had been combined
in the entry gate. Only pager exclusion is needed for ordinary syscall entry.
The mapping tree is published under `memory_lock`, every safe-copy chunk is
resolved and copied under that lock, and removed backing remains journal-owned
until TLB acknowledgement. Existing already-entered syscalls already rely on
these rules when another thread starts a VM transaction.

**Change:** Entry now waits for an in-flight pager operation and registers its
anti-eviction pin under `memory_lock`, without waiting for unrelated VM journals.
VM mutations, page-fault handlers and swapped-page restoration retain their
existing transaction gates. Retirement acknowledgement, COW-copy barriers and
checked copying remain in place.

**Result:** Repeating the full GUI sequence produced 20 ms maximum intervals in
both protection and discard/refault phases, 20 ms p95 overall and 40 ms maximum
overall (`vm-entry-full-gui/report.json`), with all 64 cases accounted for and
zero failures. Native transaction and delayed-ack/OOM/reclamation contracts
passed before the run. The final native copy/mapping/protection verification
and repeat results are recorded below.

The benchmark's worker-used option text was also moved to heap-owned storage;
GUI workers no longer read strings retained on the creator's argv stack. A fresh
packaged-GUI run with a real probe key and CSV export passed after that change.

## Final verification

- Repeated complete CLI and GUI suites account for all 64 standard cases with
  zero failures. CLI skips only optional DNS; GUI also skips single-threaded
  fork. Final receipts are `complete-cli/report.json` and
  `complete-gui/report.json`. The final GUI recorded 868 load-phase frames,
  20 ms p95 and 50 ms maximum. Its discard/refault phase had 20 ms maximum.
  The prior full run after the VM entry fix had 40 ms maximum overall.
- The focused polling repeat recorded 210 load-phase frames with 20 ms p95 and
  20 ms maximum (`poll-repeat/report.json`). This independently repeats the
  fix for the earlier 1,500 ms stall.
- Post-change VM profiling counted zero serial entry waits versus 751 before.
  The profile still counted 950 TLB waits for the VM mutations themselves;
  the correctness barrier was retained, not bypassed.
- A captured packaged-GUI run received a real keyboard probe and successfully
  exported while discard/refault was active. Four input observations were
  tagged to that workload; no window events were dropped. This is input and
  renderer proof, not an uncaptured timing baseline (`vm-input-final/`).
- Existing native eight-CPU socket, poll, sleep, pipe/SIGPIPE, VM/JIT,
  protected-copy race, demand-zero/protection-fault and mapped-file/remount
  checks passed. Host transaction, delayed-ack/OOM/reclamation, poll/select,
  pipe, network-download and TCP ownership checks passed. No new unit-test
  framework was added; the existing launcher and native workloads were used.
- Connected TCP workloads read SO_RCVBUF back as 5,242,880 bytes after connect,
  confirming expansion from the unopened 64 KiB reservation.
- `tcp-packet-analysis.json` records a median large-send gap reduction from
  9,289 us to 196 us, p95 from 11,641 us to 668 us, and gaps above 5 ms from
  2,611 to 8. Neither capture repeated a large-payload start sequence.
- `summary.json` indexes the run outcomes, kernel/loader/app hashes, GUI metrics
  and log hashes. Before-source snapshots, raw serial logs, packet captures and
  debugger receipts remain alongside it. `complete-*-comparison.txt` retains
  comparison with the original suite baselines.

The final standard CLI stream median was 130 ms per 1 MiB echo; the matched
captured pair for the isolated receive fix was 5,380 ms versus 200 ms. These
are different experimental runs and are kept separate. Small syscall deltas and
rare stress-load intervals remain sensitive to host/TCG scheduling and the
10 ms clock. Physical-device, scanout and deliberate swap-pressure performance
have not been established by this pass. The previously documented broad
runtime-archive TLS-symbol and service-factory host-model blockers are outside
these targeted passes and are not represented as green.
