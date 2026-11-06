# Zen runtime freshness and live-stall diagnostics, 6 November 2026

## Finding and change

The native performance app already used the TLS-cached pthread identity getter,
but the linked Zen executable still jumped directly into `sys_thread_self` on
every `pthread_self` call. The installed browser was using an earlier statically
linked runtime. Rebuilding the OS alone had not refreshed those executable
consumers. Disassembly of the preserved executable confirms the raw syscall
path; the rebuilt executable loads its cached identity from TLS.

The actual Gecko build has now completed and all native consumers were packaged
with the current runtime. `zen-package` now depends on the Gecko build check.
Both Gecko configure and build targets also depend on the DSO startup object;
a clean build directory had exposed its missing prerequisite at shared-library
link time. No upstream targets were disabled to get the build through.

The runtime-refresh bundle was published at `build/ports/zen/zen-browser.zip`, SHA-256
`32e8af734896d3948506bdff275c5c45017ea6873d978fe2b58dac6455e0c4d7`.
It contains 49 files and 26 native ELF images. Packaging checks preserve mapped
code/data/TLS bytes when stripping development symbols. All installed members
were checked inside each test guest. Benchmark autoconfig/actors are not in the
published bundle. The original data image and its saved profiles are unchanged;
`dl-zen.sh` can install the published application bundle with Zen closed.
The current archive is now superseded by the
[validated software-rendering fix](zen-software-rendering-2026-11-06.md), which
preserves this runtime refresh and records the previous archive for rollback.

## Verify removal of unnecessary kernel work

An optional kernel counter now counts actual thread-ID syscall dispatches. It
is disabled by default and performs no counter increment during normal operation.
Its read-mostly gate occupies a separate cache line from the atomic counter.
The browser runner's `--thread-self-counts` arms it after desktop/bundle setup,
then reads and disables it after the scripted browser workload. Such runs are
marked timing-contaminated and are not used for latency comparisons.

The same scripted sequence (two local visits, six trusted inputs, 11 diagnostics
with five samples each) records:

| Bundle | Raw thread-ID syscall dispatches |
| --- | ---: |
| Preserved baseline | 3,682,925 |
| Current runtime | 2,282 |

This is a 99.938% reduction for that instrumented sequence, not a claim that all
syscalls or UI latency improved by that amount. The counter itself adds overhead.
The candidate's live pthread getter bytes match the rebuilt ELF in two observed
processes. The baseline's live probe was unavailable in the selected snapshot;
its installed file hash and mapped-image fingerprint match the preserved ELF.

## Latency results remain mixed

Four unprofiled boots run baseline/candidate/candidate/baseline. Both bundles are
installed and every member hash is verified before timing, so these runs have
warmed asset caches; they are fresh-profile tests, not cold filesystem-cache
measurements. All use the same kernel, evaluator, original disk, eight CPUs,
4 GiB RAM, local pages, input protocol v3 and content diagnostics v2.

| Run | First window, host seconds | First-visit paint samples, guest ms | Repeat-visit paint samples, guest ms |
| --- | ---: | --- | --- |
| Baseline 1 | 10.719 | 790, 4300, 70 | 70, 60, 30 |
| Candidate 1 | 11.660 | 700, 1410, 380 | 100, 60, 60 |
| Candidate 2 | 10.259 | 710, 500, 530 | 70, 110, 60 |
| Baseline 2 | 11.138 | 960, 220, 110 | 110, 70, 70 |

There is no consistent first-window or input-paint latency improvement across
these boots. Renderer sampled CPU totals also overlap. Cold spikes remain an
open issue despite the verified reduction in identity syscall traffic. Do not
subtract guest event-to-paint from host key-to-native-marker time and call the
difference compositor time: they start at different points and include different
queues/reporting overhead. Input delivery and presentation need further timing
boundaries. The standard guest clock advances in 10 ms ticks.

## Additional diagnostics

Content protocol v2 splits the font case into setup, shaping, raster and
readback arrays. One pre-update run measured 160 ms shaping and 20 ms raster,
with readback below clock resolution. These remain raw per-sample observations.

`--stall-profile-ms N --stall-profile-limit N` optionally captures the native
CPUs while a response marker is still absent from a recent framebuffer image.
Each capture retains that pending image, CPU registers/current thread, scheduler
state, module addresses/build IDs and bounded user-stack executable-address
candidates. Candidates are not an unwound stack: Gecko omits frame pointers.
A user location marked `last_syscall_frame` describes the saved caller context.
The sampler performs no target function calls. All debugger pauses are recorded
and the run is excluded from quantitative comparisons.

Supply a matching unstripped executable with `--zen-symbols` when profiling an
older installed bundle. The live samples captured browser main and socket
threads entering syscall 34; libxul's loaded build ID matched the preserved ELF.
A snapshot showing a ready Renderer and idle CPUs is not by itself proof of
prolonged scheduler starvation.

## Acceptance and artifacts

The updated browser passed both local visits, exact actor payload/pixel checks,
all 11 content cases, font raster checks and six trusted input/response-marker
probes in every matched run. A further acceptance boot passed 12 cursor samples,
window drag/bounds, shrink and outside-window pixel checks, browser exit status
0, and clean OS shutdown. Its private shutdown image is retained. The initial
shutdown attempt raced Terminal's launch-job retirement; the harness now waits
for that exact job, clears residual input and uses 120 ms key pacing before
sending shutdown. The corrected acceptance passed. The original failed record
is preserved and is not included among successful runs.

The updated kernel also passed the existing thread-identity/migration diagnostic.
Kernel stack guards/context checks/canaries remain disabled. Default `make`,
Python/GDB-Python parsing, JavaScript syntax and whitespace checks pass.

All evidence is under `build/perf/zen-paint-investigation-20261105`: preserved
baseline bundle and ELF symbols, full successful Gecko build log, runtime-link
fingerprint, before/after assembly, four matched runs, separate counted/profiling
runs, runtime proofs, input CSV, acceptance captures and published-bundle receipt.
The measurements are QEMU evidence, not physical-hardware or scanout proof.
