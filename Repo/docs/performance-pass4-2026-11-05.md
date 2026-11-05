# GUI handoff and framebuffer publication, 5 November 2026

This continues the [filesystem/admission pass](performance-pass3-2026-11-05.md).
Native eight-CPU QEMU measurements, source snapshots, debugger captures and build
receipts are retained under `build/perf/pass4-20261105`. All guest disks and
firmware variables were disposable. The default handoff still uses CPUs 0/1.

## Establish which threads are delayed

The new `--scheduler-profile` captures a checkpoint after both handoff endpoints
are alive. The debugger reads the real kernel thread registry, native priorities,
affinity, queue membership, CPU occupants and switch counts. The app records its
actual endpoint TIDs in `PERF_HANDOFF_IDS`. The runner verifies that those TIDs
belong to the captured process and are pinned to the expected CPUs. Snapshot
runs are excluded from quantitative comparisons.

Both endpoints had normal priority in CLI and GUI mode. The GUI main thread had
the expected foreground boost; the compositor ran at UI priority. The alternate
opt-in `condition_pingpong_2_3` moves the same protocol to CPUs 2/3, restores the
coordinator afterward, and leaves the default inventory at 75 cases.

Initial diagnostic profiles measured approximately 0.221 ms for CLI 0/1,
2.143 ms for GUI 0/1, 0.320 ms for GUI 2/3 and 0.204 ms for CLI 2/3. These
profiles localize the delay rather than establish an optimization claim.
The GUI 0/1 run recorded 1,365 memory-lock retries for 1,886 futex registrations;
the 2/3 run had six retries for 12,885 registrations. Source and snapshot data
identify CPU 1 as the reserved compositor CPU. The alternate pair diagnoses that
interference; it does not replace the default workload.

## Avoid throwing away a completed futex word read

When the nonblocking memory-lock probe failed, the old futex slow path released
the global scheduler lock, obtained a checked scalar read, discarded it, and
repeated the original lock probe. Page-by-page GUI uploads could repeatedly win
that second acquisition. The retry still had to close the wake-before-register
race, so simply reusing the old value would be incorrect.

The process now owns a scheduler-locked futex wake sequence. The slow path
snapshots it before releasing scheduler ownership and reading the word. Once it
reacquires the scheduler lock, an unchanged sequence validates reuse; a crossing
wake forces fresh validation. Every valid wake increments the sequence, even
when it finds no waiter. The live caller retains only a value and sequence,
never a physical alias. Death, failed reads and signals retain their checks.
The normal uncontended path remains the same.

The existing host futex fixture now injects a wake during its existing slow-read
boundary case and verifies that generation invalidation causes a retry. Its
fault, changed-value, death, signal, timeout, isolation and list-collision cases
passed. No new test framework was introduced.

The next GUI profile recorded six memory retries: five completed reads reused
and one invalidated by a crossing wake. Despite removing those repeated probes,
uncaptured GUI medians changed only from 1.485 to 1.442 ms with overlapping
observed ranges. No independent throughput gain is attributed to this change.
The larger handoff delay remained and was investigated separately.

## Locate the remaining wake delay

Futex wake publication now stamps the thread's native timer tick. Successful
wait completion records count, accumulated ticks and maximum by resume CPU.
These are deliberately coarse counters; individual waits are often below the
10 ms quantum and no nanosecond accuracy is implied. The futex counters
are cumulative across the guest boot, including setup. This single workload
dominates their registration counts, but unrelated setup activity remains in
the totals.

The CLI 0/1 profile recorded 60 wake-to-resume ticks on CPU 0 and 32 on CPU 1,
over roughly 9,750 resumes each. The GUI 0/1 profile recorded 46 ticks on CPU 0
and 149 on CPU 1, over roughly 930 resumes each; CPU 1 reached four ticks for
one wake. The 2/3 GUI profile stayed within one tick per resume. Together with
the CPU placement snapshots, this directed attention to compositor work on
CPU 1 rather than inherited worker priority.

## Remove a libc call for every framebuffer word

`fb_memcpy_wc` copied each eight-byte source word into a stack temporary with
`memcpy`, then stored it to the volatile framebuffer. The kernel uses
`-fno-builtin`; disassembly confirmed an actual function call for every word in
three inlined publication loops. Large frames therefore paid hundreds of
thousands of calls while the render lock suppressed preemption.

The wide-copy path now uses packed aliasable scalar loads and aligned volatile
64-bit stores, with four words per iteration. Its remaining eight-byte and byte
tails are bounded by the requested count. Destination alignment, GOP color-mask
conversion, cursor publication, page flips and fences retain their paths.
Disassembly contains no memcpy call in the publication loop and no vector
registers. Before/after assembly is saved as `framebuffer-copy-{before,after}.asm`.

The primary matched comparison uses uncaptured GUI runs with seven requested
500 ms rounds and the same native app and CPU pair:

| Metric | Before copy change | After |
| --- | ---: | ---: |
| Median condition round trip | 1.256281 ms | 0.499001 ms |
| Observed range with tick margin | 1.144165–1.841155 ms | 0.477583–0.684564 ms |
| Measured round trips | 2,624 | 6,716 |
| Measured elapsed time | 3.52 s | 3.50 s |

The median reduction is 60.3%, approximately 2.5x faster. These observed ranges
are descriptive, not confidence intervals. `framebuffer-gui-{before,after}/`
and `framebuffer-handoff-comparison.txt` retain the raw batches and host/load
observations. An after CLI control measured 0.213 ms and the 2/3 GUI control
0.318 ms. Some GUI overhead therefore remains on the default pair.

The separate whole-boot profiles recorded 578 publication calls / 1.346 GB /
494 clock ticks before, and 842 calls / 2.160 GB / 25 ticks afterward. Those
counters include terminal setup and other windows, not just the handoff phase.
Periodic rendering can phase-lock to the timer, so the short-copy tick totals
must not be converted into precise bandwidth or per-frame latency claims. The
uncaptured handoff comparison is the stronger quantitative evidence.

## Evaluation issues found while verifying

The existing hardware contract initially failed its boot-heap assertion. Its
fixture assumed a fixed 512 MiB reservation, whereas the unchanged committed
kernel reserves one quarter of usable RAM, capped at the configured maximum.
The 1.5 GiB fixture therefore expects 384 MiB and its 512 MiB fixture 128 MiB.
Only fixture expectations changed. GOP validation/color and storage checks
passed before that failure; the corrected complete hardware contract passed.

A final visual attempt then ended during GUI-terminal installation, before the
performance app ran. The launcher could sample serial output after an empty
redraw prompt but before the rest of its typed command arrived. Its prompt-only
predicate declared completion and checked the download result too soon.
Download preparation now requires the exact saved byte count/path and a prompt
following that evidence. Directory creation likewise waits for execution
evidence; configured setup checks wait for their expected output before accepting
the following prompt. This changes no guest command, process count or workload.
The failed `final-visual/` report is retained as incomplete. Boundary replay is
saved in `launcher-boundary-replay.txt`; it is not a valid benchmark result.

## Final checks and remaining work

Native compositor acceptance passed all three actual framebuffer pixel probes,
128 presents, repeated resizing, control ownership and raw keyboard handling on
eight CPUs. Native blocking synchronization, pthread ABI/lifetimes, anonymous VM
and JIT, protected-copy races and write/none/execute hardware faults passed.
The complete corrected hardware host contract and futex/condition boundary
contract passed. Logs and image receipts are copied to `native-check-evidence/`.

Fresh CLI and GUI runs completed all 75 default cases with zero failures. CLI
skipped optional DNS; GUI skipped DNS and multithreaded fork. The uncaptured GUI
recorded 978 load frame intervals, p95 20 ms, maximum 50 ms, no GUI error and zero
event drops. Those remain 10 ms-clock observations, not physical scanout proof.
`final-visual-repeat/` passed real compositor capture, keyboard Probe and two
CSV exports using the corrected launcher. `final-stop-controls/` passed Probe,
Export and cooperative Stop during the running timed handoff, cleanly joined its
worker and exited with no GUI error or dropped events. These paused runs are
visual/control evidence, not timing baselines.

The 2/3 scheduler capture passed native owner/TID/affinity validation, and a
fresh CLI snapshot passed with the final runner. New reports retain hashes of
the driver and launcher, reject edits during a run, and reject comparisons of
reports with different recorded evaluation sources. The primary framebuffer
comparison above used the same earlier successful launcher for both runs; its
failed later setup attempt never supplied a performance result.

`make`, Python parsing and whitespace checks passed. The remaining default-pair
GUI handoff cost is roughly 0.50 ms versus a 0.21 ms CLI control, so further CPU 0
wake/dispatch investigation remains useful. The alternate 2/3 GUI control remains
about 0.32 ms. This pass establishes QEMU component/application evidence; physical
hardware, scanout latency and complete subsystem performance remain unverified.
