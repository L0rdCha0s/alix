# Zen playback performance, 6 November 2026

The active requirement is smooth video with no dropped frames and clear audio.
The user confirms that multi-second zero-fps pauses occur even at 480p; this is
the primary reproduction target, with larger formats providing additional load.
Functional playback from the preceding HTML5 media pass is insufficient. This
investigation is active; zero-drop playback at the user's larger video size is
not yet established.

Evidence is under `build/perf/zen-playback-20261106/`. All guests boot private
clones of the same source image. The browser archive remains SHA-256
`06c82d746f491e70ae0699103077648ac8919eeef57955be50e0b72a4f54ddcb`, with
libxul build ID `0312e95f232ab649c486b16a9a43556aff9edb95`. Live debugger runs
are excluded from playback-quality comparisons.

## Measurement

The existing browser evaluator now supports sustained media observations,
500 ms samples of media time and frame counters, opt-in verbose decoder logs,
and independently specified fixture display width. Fixture dimensions and frame
rate come from host ffprobe and are verified against decoded metadata. Generated
35-second VP9/Opus fixtures include 320 by 180 and 1280 by 720 at 30 fps, with a
997 Hz tone. Startup drop totals remain separate from sustained-interval deltas.

Native HDA snapshots before and after playback expose queue occupancy, empty
transitions, reprimes, hardware errors and submitted/played/dropped PCM frames.
These snapshots do not interrupt the measured interval. The unsuccessful first
attempt to read proc files through Gecko's IOUtils is retained in `baseline-320`;
it failed as a diagnostic and supplies no hardware-counter evidence.

For a quiet audio comparison, `steady-audio.wav` contains seconds 2 through 18
of each WAV recording, before post-playback debugger and close operations.
This 16-second tone window cannot hide an underrun as a natural soundtrack pause.
Whole-recording analyses and the original WAVs are also retained.

## Audio I/O handoffs

Every PCM status query and 512-frame write previously traversed the protected
event worker, including immediately available operations. The packet lasts
10.67 ms at 48 kHz; two scheduled request handoffs can consume that budget.
The first native full-redraw control recorded 11 empty/reprime transitions;
the retained-render control recorded 16. The 16-second tone windows contain
241 ms and 483 ms of interior silence respectively. The full control overlapped
a short host kernel build and is not a clean quantitative speed comparison.

`user_file_submit` now attempts the existing bounded audio executor inline.
It retains the registered request, owned descriptor and captured heap data.
Operations needing readiness remain on the existing protected event service;
request completion and cancellation use the existing inline lifecycle.

The first candidate full-redraw run completed 6,560 audio operations inline and
recorded one hardware starvation/reprime. Its 16-second tone window has zero
interior silence, 15,952 expected tone cycles and a maximum sine recurrence
residual of 2.67 PCM units. Whole-recording startup/lifecycle evidence still has
a 111 ms gap, and sustained video still drops frames. The existing native
`audio_owned_test` passes hardware position, aliases, queued close and killed
waiter cleanup on eight CPUs. The process-I/O host lifecycle check also passes.

The existing `audio_stream_contract_test.py` fails a structural assertion which
expects `start_after_copy` inside the old write function; production moved that
logic into `hda_queue_pcm_locked` before this pass. This check is not reported
green. The native ownership check exercises the current production path.

## Rendering and clock experiments

Retained rendering is an evaluation override, not a new default. It does not
reliably improve quality: `inline-retained-320` still has 54 sustained drops and
375 ms of silence in the 16-second tone window. It is not promoted.

The verified live profile finds Renderer execution in full-window
`nsWindow::EndRemoteDrawing` and R8 Gaussian blur. Five captures provide six
verified live libxul PCs. The bounded sample is not a CPU-time distribution.

A separate 1 kHz IRQ experiment preserves the 20 ms normal quantum. It records
zero hardware reprimes and a clean steady tone, but still drops 41 sustained
frames. More significantly, media advances 25.959 seconds while the guest
monotonic clock advances 20.105 seconds at playback rate 1. Increasing interrupt
frequency alone does not fix clock stability. The production source is restored
to 100 Hz; the experimental kernel remains frozen for comparison.

Elapsed time previously counted delivered PIT interrupts. Interrupts masked
during longer kernel operations can be coalesced, causing that clock to lose
time while the audio controller continues consuming samples. The new candidate
uses the ACPI PM free-running counter for monotonic elapsed time and catches up
scheduler ticks after delayed IRQs. Its counter extension is serialized across
CPUs and sampled by timer interrupts, covering 24-bit wrap. Unsupported platforms
retain the PIT fallback. `inline-pm-full-320` validates the actual 24-bit counter
across multiple wraps: media advances 20.411 s against 20.414 s of monotonic
time, with zero hardware empty/reprime transitions and a clean 16-second tone.
Its 58 sustained video drops keep the full objective incomplete.
The hardware register and frequency follow the
[ACPI PM timer specification](https://uefi.org/specs/ACPI/6.5/04_ACPI_Hardware_Specification.html#power-management-timer-pm-tmr).

The combined PM-clock/1 kHz experiment is rejected: it reports 185 total drops,
and this boot fails `/dev/audio` registration, leaving its WAV empty. The browser
falls back to clocked silent playback, so its unmuted state is not audio proof.
The evaluator now requires successful HDA initialization when capturing audio.
The source remains at 100 Hz. Device registration had another SMP race:
separate registrations could close the shared `/dev` mutability window while a
peer was still creating its node. These registration transactions are serialized.

`inline-pm-steal-full-320` successfully enables the optional work-stealing mode
but still has 44 sustained drops and a 115 ms gap in the actual playback capture.
It is not a zero-drop result or an accepted default-policy change. This run
uses the corrected clock, inline audio, and serialized device registration.

The evaluator now starts a separate 48 kHz hardware-output capture immediately
before native Play activation and stops it before post-playback debugging. This
captures startup and sustained output without attributing debugger pauses to
normal playback. Original whole-guest WAV captures are retained too.

## Upload-loop investigation

The verified Renderer PC `libxul+0x450d5f0` lies in the pixel-copy loop of
`nsWindow::EndRemoteDrawing`. Disassembly shows scalar work and a fresh load of
the upload-buffer pointer for every pixel across the entire window. The new
candidate calls Gecko's existing BGRX-to-BGRA opaque swizzle routine, preserving
RGB and forcing alpha to FF as before. It is tracked in the canonical widget
patch with updated source/hash guards. Full build, native pixel references and
playback comparisons are recorded below; the published browser bundle is unchanged.

The isolated upload candidate has libxul build ID
`c11ce7d0cb406eb52acc6a59d3870ecb6027c125`. On the same corrected kernel,
`upload-video-before` records 63 sustained drops and `upload-video-after` 16.
Their playback-only tone recordings still contain gaps. Both exact native
shape references match with zero changed pixels, followed by geometry, clean
exit and shutdown. This candidate is not sufficient for the full goal.

The compiler settings exposed a larger issue: Mozilla's default optimization
selector chooses `-O2` on Linux/Windows and `-O3` on Darwin, but Alix falls through
to `-O` (Clang's `-O1`). The port now requests `--enable-optimize=-O2` explicitly
for the browser. Two complete release builds passed: the first in 31m27s and
the second, after the clock-resolution API update, in 25m32s. The final candidate
has libxul build ID `5dfa37019ccdea672580ae41297a3e3802d7ec0f`; packaging verifies
50 payload files and 26 native ELF images. Runtime acceptance remains pending.

The kernel profile also reaches scalar per-pixel alpha checks in
`video_blit_rgba32_untracked`. An opt-in opaque-prefix path copies eight verified
opaque pixels per group, using packed aliasable 64-bit reads and preserving the
existing scalar path for mixed-alpha pixels, tails and overlapping rows. It
uses no kernel SIMD state. `opaque-corners-before/after` verifies exact native
pixels and lifecycle behavior on the same kernel; its byte counter confirms
634,373,600 bytes used the path. The source default remains off until quiet
playback measurements justify enabling it.

## Coherent clock and timeout contracts

The existing native uptime check exposed a second clock boundary: process age
still used coarse timer ticks after monotonic time gained millisecond precision.
Creation age now records the same elapsed-clock millisecond domain. The repeated
native check then measured a requested 25 ms sleep returning after 22 ms:
`boot_before=1204`, `boot_after=1226`, `first_ns=25000000`, `second_ns=47000000`.
The old relative tick rounding ignored time already spent in the current tick.

The timer now computes absolute, upward-rounded deadlines from the free-running
counter. Kernel sleeps, signal-interruptible sleeps and timed futex waits use
that deadline; generic wait-queue addition saturates instead of wrapping.
Process uptime, normal/interrupted sleep on eight CPUs, pthread/futex lifetimes,
and owned audio channels pass existing native fixtures. Their existing host
contracts pass too. The stat/CPU-clock fixture needs the boot-created VFS test
tree: direct invocation without it fails lstat as expected; the complete existing
acceptance script passes and restores the ordinary kernel. A fresh serialized
relink resolved a brief overlap between two validation builds.

Native syscall 79 reports the actual monotonic-clock resolution. Monotonic and
boot-clock libc queries use it, with the previous CPU-frequency-based path as a
fallback on older kernels. CPU-clock and realtime resolution retain their own
tick-based values. The existing native perf boot-clock case confirms a 1 ms
elapsed-clock resolution and passes its sleep/monotonic checks.

## Freeze diagnostics

Sustained playback emits 500 ms progress samples with separate playhead,
presented/processed/dropped frame counters, actual callback delivery time and
buffered extent. Optional native `mozRequestDebugInfo` snapshots report decoder,
reader, sink and compositor state every two seconds, with bounded query time.
The functional protocol run obtains actual VP9/Opus decoder and queue data.
Its samples have decoded video queued and predominantly compositor-side drops;
this build-overlap run is not a playback-speed comparison.

`--media-freeze-profile-ms` arms only after media input starts and captures live
threads when presentation counters stop or content progress disappears. It is
diagnostic and excluded from quality comparisons. A generated 75-second 480p30
fixture permits a full minute of observation without looping. The quiet release
run uses the user's approximate 686 by 386 display size and preloaded MSE data.

## Live 480p reproduction

The exact video from the screenshot is `https://www.youtube.com/watch?v=XAiR2qKxufQ`,
"Trying to keep my DREAM House from flooding". Native Zen loads that title and
plays an 854 by 480, 29.97 fps AV1 stream through ffvpx, with separate MP4 video
and WebM/Opus audio SourceBuffers. During traced pauses, video remained buffered
well ahead of the playhead and the decoder continued producing frames. Decoder
skip counts were zero; both compositor and late sink drops accumulated.

`release-youtube-trace` captures busy page-thread execution on CPU 0 while
compositor work waits and several other CPUs are idle. Three debugger pauses
perturb its drop totals, so it is diagnostic evidence only. The subsequent
`release-youtube-steal-quiet` enables the existing work-stealing option and uses
no debugger or periodic decoder snapshots during playback. Native moving pixels
and clean exit/shutdown pass, but quality fails: 883 drops out of 2,362 processed
frames by media time 78.62 seconds. One progress interval lasts about 14 seconds
without a frame callback. Work stealing alone is insufficient.

The long local muxed VP9/Opus fixture has a separate reproducible stall at about
one second, with the video reader waiting for data despite the final DOM
buffered extent reaching 75 seconds. The complete downloaded SHA-256 matches
the host fixture. Native source-buffer debug output currently selects the
audio track for both labels on a muxed buffer, so its duplicated sample counts
do not establish video continuity. This stall remains unresolved and is not
treated as proof of the cause of the live YouTube pauses.

An opt-in `--present-diagnostics` flag now measures native window snapshot/map,
opaque pixel conversion and kernel submission times, with dirty-region pixels
and maximum presentation gaps. It emits one aggregate line per 120 presents
and a final partial aggregate at window destruction. Quiet quality runs leave
it off. This will determine whether full-window transfers dominate small video
updates before changing the presentation protocol.

`youtube-present-diagnostics` passes native motion, clean browser exit and guest
shutdown with diagnostic libxul build ID `2501cf8c9c6031a0d40b9d501fec8ef82637279d`.
It still reports 314 drops by media time 33.176 seconds. Across playback batches,
mapping, full-window conversion and kernel submission average approximately
4--8 ms combined per present; maximum presentation gaps reach 1,047 ms. These
transfers do not account for most of the observed delay. Typical steady dirty
regions contain 230,400 pixels versus the 1,179,360-pixel window. Final HDA
counters show no underruns, reprimes, stream errors or dropped PCM frames before
the browser closes. Speech-track silence measurements are not tone-quality
evidence.

Potential return addresses from the page thread at the first prior freeze lead
through incremental GC sweeping and JIT-code poisoning, while the verified live
PC is in libc `memset` with the swept-code poison value. These memory candidates
are not a verified stack unwind or a measurement of GC duration. New opt-in
`--gc-profile-ms` uses SpiderMonkey's native slice profiler; software-renderer
stage timing also uses `--present-diagnostics` to separate rasterization,
composition and commit from gaps between frames. Both remain off in quiet runs.

Renderer stage diagnostics use libxul build ID
`a2899a78d46280568f67f6eb8de317b2aa860352`. `youtube-render-gc-diagnostics`
again fails native motion with 801 drops out of 1,295 frames. Composition alone
has 423--454 ms outliers, while gaps between frames exceed three seconds.

An opt-in idle-placement experiment redirects newly runnable, unpinned threads
to an idle CPU with no queued work, preserving explicit affinity, UI placement
and handoff ownership. Kernel `52a8e10ff5d30aa2558771d10b8ff074776e3bacf38d464a6c6748ab6c8b41fa`
passes the existing scheduler handoff check. In
`youtube-idle-placement-diagnostics`, 95,937 redirects occur, but the run still
has 488 drops out of 999 frames and a 5,554 ms presentation gap, with four audio
reprimes. Native motion and clean shutdown pass. This experiment is not a fix
for the playback requirement; its default remains disabled.

GC profiling initially wrote to the GUI-launched browser's standard-error
stream, outside the serial collector. The evaluator now selects an append-only,
line-buffered file in the private guest and retrieves bounded rows after the
observation, before native-motion validation can fail. Content readback confirms
`JS_GC_PROFILE=100,main`. `youtube-gc-file-control` obtains eight long-slice rows:
the longest collection is 384 ms, with 383 ms in sweeping. A separate page-thread
reporting gap lasts approximately 23 seconds. These GC rows do not explain that
whole gap. The control still has 317 drops out of 1,009 frames and one audio
reprime; motion and shutdown pass. The codec-control option
`--media-disable-av1` is limited to the disposable profile for comparison.

`youtube-vp9-diagnostics` confirms actual 854 by 480 VP9, with no decoder-side
drops, but still has 420 drops out of 1,292 frames. A GC sweep lasts 1,903 ms.
The problem therefore spans more than AV1 decoding. A fresh 1 kHz candidate
with the corrected clock/timeouts and 20 ms normal / 10 ms UI quanta
(`b9fcfef93229843c0d4256672d234eb4c41d125005a8126c18c9cf1742fe7e70`)
still has 482 drops out of 1,440 frames in `youtube-1khz-diagnostics`.
Composition has a 1,926 ms outlier and GC a 1,899 ms sweep. The production
timer is restored to 100 Hz. UI quanta now derive their 10 ms cap from the
timer frequency, preserving the ordinary 100 Hz behavior.

`youtube-render-cpu-host-sample` uses diagnostic libxul build ID
`334a315ebbb4d25c2cc4cd38d0ea5c707bea32d7`. Every recorded 120-frame batch has
120 valid thread CPU-clock samples. Composition consumes substantial CPU time,
for example 3,730 CPU ms out of 4,234 elapsed ms in one batch. Its 35-second Mac
host sample is restricted to the task QEMU PID and is excluded from quality
comparisons. It shows SIMD emulation, translation-block lookup/invalidation and
JIT write-protection calls. No single mechanism is established as the sole
cause. Native motion/shutdown pass; playback quality still fails with 685 drops
out of 1,325 frames. Detailed GC output is now exported in bounded 4 KiB batches;
the first implementation's line-per-request export was unnecessarily slow
after observation. Its late audio counters include that long export interval.

The existing native perf app's `memset_1m` baseline fills 20 GiB in 1.655 seconds.
Disassembly confirms that the native runtime already vectorizes this fill,
correcting the earlier source-level scalar-loop assumption. No libc rewrite is
made on that evidence.

A candidate JIT cleanup change counted the batch's references per executable
pool and avoided rewriting pools whose entire reference count was being
released. Its native build passed, and one batch skipped 3,547,224 bytes beyond
the original single-reference skip, while poisoning 931,352 bytes. The batch
still took 470 ms. `jit-retire-youtube-repeat` failed motion during the first
video, so the second navigation never ran. A quiet default comparison also
fails: control 960 drops out of 1,866 frames; candidate 1,487 out of 1,986 and
static native end captures. These runs do not meet acceptance. The optimization
is reverted; patch 0064 now retains only opt-in retirement-stage diagnostics.
Verbose GC phase output now requires `--gc-detail` because synchronous logging
can perturb playback. Quiet runs use neither GC logging nor render-stage logs.

## Native thread priority

The compiled control NSPR `PR_SetThreadPriority` consists only of clamping and
storing the requested value. It never calls the kernel. Gecko's Renderer setup
explicitly requests high priority, while native snapshots show the Renderer
remaining normal. This is a concrete missing scheduling bridge.

Native syscall 80 now reads/sets background, normal and high base-priority hints
for living user threads in the caller's process. It uses scheduler and process
thread-list locking and the existing queue-safe priority transition; it cannot
assign reserved UI priority or affect another process. The shared libc exposes
`pthread_getpriority_np` / `pthread_setpriority_np`. NSPR applies initial and
later requests under its thread-bookkeeping lock, so initial setup cannot
overwrite a concurrent priority update. Kernel focus overrides remain in effect.

Normal `make`, the existing pthread production contract and scheduler handoff
contract pass. The perf app's new `thread_priority_hints` diagnostic passes
49,152 operations in the existing isolated eight-CPU native runner, including
restoration and invalid-request checks. The existing native pthread lifecycle
fixture also passes. Frozen kernel SHA-256 is
`56b6fbcb9199c96cfdd246005532e4aef4e589a959da4f9b4dbf0876e5d0c33c`.
The actual Gecko/NSPR rebuild passes in 26m48s. Its linked NSPR calls the native
setter and the main executable exports both pthread priority functions. The
candidate has libxul build ID `5bfdee90c1043bbd95e00e397f4db9d5f563a940`.
`youtube-native-priority-quiet` confirms Renderer base and effective priorities
are both `THREAD_PRIORITY_HIGH`, without a focus override. Motion and shutdown
pass, but quality still fails: 1,000 drops out of 2,619 frames by media time
87.339666 seconds, and five hardware reprimes. The priority bridge is functional;
it is not sufficient to meet the playback requirement.

The native audio mixer is a plain pthread and still had normal priority. It now
sets its name to `cubeb-alix` and requests high priority. Alix's compositor thread
also requests high priority, addressing the earlier queued compositor work
behind page execution. That incremental browser build passes without compiler
warnings; libxul build ID is `9877f38690c34b667064d49eb559bdd6a4c4ffd1`.
Native role readback and playback acceptance remain pending.

`youtube-native-pixel-freeze-fixed` confirms high base/effective priorities for
Renderer, Compositor and `cubeb-alix`, with no focus overrides on those threads.
All 42 native pixel probes see a change; no image stays unchanged long enough
to trigger the 1.5-second live-freeze threshold. Frame loss remains: 431 drops
out of 1,333 frames. Native reader statistics report zero decoded-frame drops,
433 compositor drops and 18 sink drops at the later debug query. There are
three audio reprimes. This is a diagnostic result, not quality acceptance.

Native probes now also record all eight CPU register sets through QEMU's monitor,
with a final module/address-space mapping when no live freeze supplied one.
`youtube-native-cpu-samples` captures a true image freeze. Renderer is blocked on
the process-wide `g_heap_lock` (`0x1001d5d20` in that main executable); several
runnable parent-process threads remain queued on busy CPUs while five CPUs are
idle. The snapshot does not establish which thread owns that lock. All 107
sampled user-mode register sets retain the interrupt-enable flag. The CPU-register
query costs a median 12.83 ms and is excluded from quality comparisons.

The matched opt-in work-stealing run avoids a qualifying image-freeze capture,
but still records 796 drops out of 1,723 frames. Work stealing remains disabled
by default. Neither that run nor the default sampling run meets acceptance.
Frequent parent-process samples resolve to SWGL `scale_blit<true>`, with the
sampled instruction in the four-pixel source-over blending loop. Decoder samples
also resolve to dav1d SSSE3 eight-tap prediction loops.

A candidate SWGL fast path copies fully opaque four-pixel chunks directly and
leaves the destination untouched for an entirely zero source chunk. Translucent
chunks and short tails retain the existing math. Assembly verification caught
inactive platform guards in initial builds; those candidates were not treated
as performance evidence. The current implementation tests RGBA alpha byte lanes
directly and has no build-macro dependency. The complete build passes in 25m46s,
with libxul build ID `30f4dda0549e3ef1fb29f943b202067e864d2c84`. The linked
`scale_blit<true>` assembly contains both the opaque and zero-chunk branches.
The first native comparison correctly rejects an older-kernel reference before
comparing pixels. A fresh control uses the current priority-aware kernel and
previous media-priority browser. Against that matched control, the candidate
matches all 204,800 shaped-corner pixels exactly, with zero channel delta, no
browser faults, successful geometry checks and clean browser/OS shutdown.
The first quiet 480p AV1 run does not pass acceptance: 898 drops out of 1,815
frames at 60.537 seconds, two audio reprimes and no changed pixels in the final
native-motion check. The later decoder query reports 463 decoder, 375 sink and
261 compositor drops; these counters are collected at a different time from
the progress sample and are not summed to reproduce it.

A quiet codec control with the same candidate confirms 854 by 480 VP9. It has
274 drops out of 1,795 frames, with two decoder, 75 sink and 197 compositor
drops at the later query. It reaches exactly the buffered end at 60.001 seconds
and readyState 2; its failed final native-motion check therefore also includes
data starvation. There are three audio reprimes. Codec choice changes the
decoding load substantially, but neither run meets the requirement. AV1 remains
enabled in the production defaults. A counter in the existing elapsed-clock
critical section now records hardware clock reads without serial logging; the
existing post-run profiler exports it. Normal `make` passes.

`--media-native-probe-ms` now samples live video pixels independently of the
page thread. With `--media-freeze-profile-ms`, only unchanged native pixels
trigger the live snapshot; the old DOM/progress trigger remains available when
native probes are off. This diagnostic is excluded from quality comparisons.
The first attempt used the video element's pre-play rectangle, which YouTube
placed offscreen (`y=-280`); it failed probe bounds before yielding motion data.
The retry uses the visible player container that the existing stability check
already tracks. End-of-run motion failures are now reported after the kernel
snapshot so failed runs retain base/effective priority evidence.

## Wakeup IPIs and time-slice accounting

Wakeup IPIs enter the same preemption function as timer broadcasts. That
function previously decremented the time slice on every call, including
multiple wakeup IPIs within one hardware tick. It now derives the remaining
slice from elapsed timer ticks since the existing dispatch timestamp. Explicit
signal and wake-pending requests still force a zero slice. This corrects the
accounting without treating interrupt arrival count as elapsed CPU time.

Normal `make`, the existing scheduler handoff check and the eight-CPU native
pthread lifecycle fixture pass. The candidate kernel is
`a0adfb22877d1c501ce858fb779da4d2bc975486596a180258883b4802fec895`.
The matched direct 854 by 480, 30 fps VP9 fixture still drops 155 of 1,854
frames; the previous kernel drops 179 of 1,855. These single runs do not
establish a repeatable speedup or meet acceptance. The fixture uses its default
320 by 180 CSS display size; those dimensions differ from its encoded size.
Both runs have zero audio empty/reprime events. Their exported steady audio
windows, seconds 2 through 18, contain zero silence, 15,952 tone cycles and
maximum recurrence residuals of 3.00 and 3.03 PCM units. Whole recordings also
retain startup/lifecycle gaps, so this is a scoped steady-audio result.

The existing native monotonic-clock performance case passes with 655,360 calls
in 1.341 seconds, averaging 2,006 ns in that single-thread guest workload.
Browser runs perform 1.57 to 2.13 million hardware clock reads across their
whole measured workload. No new clock algorithm has been selected on that
evidence. The post-run profiler also exports the existing per-CPU futex resume
count and elapsed-tick totals. Live stall snapshots now include runnable parent
threads beyond the rendering roles and bounded saved-kernel-stack code
candidates; those candidates are not an unwind or proof of mutex ownership.

## Scalar syscalls and VM pinning

The live `youtube-elapsed-slice-vp9-native-diagnostics` run captures two native
image freezes with readyState 4 and tens of seconds of buffered data ahead.
In one snapshot, six CPUs are waiting on scheduler or process-memory locks.
In the other, Renderer and Compositor wait for events while the content main
thread runs JavaScript promise work and seven CPUs are idle; runnable work is
still queued on that busy CPU. Neither snapshot proves a unique lock owner.
This diagnostic run has 925 drops out of 1,610 frames and seven audio reprimes.
Its debugger pauses and sampling exclude it from quality comparisons.

Every syscall previously entered and left the conservative VM pin, including
scalar clocks and futex wake. Entry and exit each take the process memory lock;
one captured thread is waiting inside `process_vm_syscall_leave`. The explicit
scalar allow-list candidate bypasses that work. Pointer-bearing operations retain the
pin. In the candidate, signal return enters it when pending signals require user-frame access,
before selecting or installing the frame, and the ordinary outer return releases
it. No borrowed pointer or asynchronously shared caller-stack state is added.

Normal `make` and the existing futex check pass. The native signal fixture passes
its eight-CPU asynchronous delivery/register checks, default termination and
forged-frame modes. The existing signal host model is refreshed for current VM
pin, deadline and signal-alias declarations; its 201 checks pass both normally
and with ASan/UBSan, and mapping classification passes. The existing clock
microbenchmark reports mean call costs of 2,006 ns before and 1,121 ns after.
This isolated result does not establish playback quality.

The first quiet live attempt never activates the player: trusted input is not
observed and video remains paused at zero. A physical click retry reaches the
document root rather than the visible control. Bounded start confirmation then
reacquires the control after layout changes, retaining the original frame counts
and trusted-input history. Its second click activates the play control, but
YouTube displays a player error before decoding frames. None of these attempts
supplies playback-performance evidence.

The previous elapsed-slice kernel, with the same browser and start-confirmation
protocol, plays the video and shuts down cleanly. It still reports 284 drops out
of 901 frames at 30.067 media seconds. The scalar VM-pin candidate is therefore
rejected and fully reverted from production source; this comparison does not
establish the exact mechanism of the player error. Its source patch is retained
as `rejected-scalar-vm-pin.patch` alongside kernel `2bab6f8d...` and the logs.
The clock microbenchmark gain is not promoted as a browser improvement.

Failed playback validation now waits for the following decoder/MSE report and
post-run kernel snapshot before failing, preserving diagnostics for startup
errors. It still fails the run and supplies no quality acceptance.

## Empty futex wakes

The denser default-codec native diagnostic records at least 290 of 824 stopped
CPU samples at global scheduler-lock acquisition sites. This is diagnostic
sampling, not a precise CPU-time profile. Across the whole browser workload,
826,294 futex wake calls wake 133,150 waiters, so at least 84 percent of calls
wake nobody. The diagnostic still drops 641 of 1,161 frames and has one audio
reprime; its sampling excludes it from quality comparisons.

A candidate counts possible waiters in each process's existing hash buckets
before the expected-value read. A full waker barrier pairs with that publication;
only a proven-empty bucket bypasses scheduler serialization. Count ownership
stays with the heap-owned thread and is released on every failure, unlink,
timeout and termination path. The initial version moved the wake epoch too
early. The corrected version leaves the epoch increment inside the existing
scheduler-locked path; negative wakes use their separate count/barrier proof.

The existing futex/condition contracts pass, as does the eight-CPU pthread
lifecycle workload. The corrected candidate also passes 6,850 native condition
handoffs over five rounds on CPUs 2 and 3. Its frozen kernel is
`a075572099c8667bdcbafe900d4dc1898fbb9f7e1a5d6e8364f18a21092b6131`.
The earlier `c4165800...` candidate is superseded. Its live run avoids 688,508
scheduler-lock acquisitions but later resets the source and fails playback;
that is not quality acceptance.

The corrected matched locked control (`youtube-futex-ordered-locked`) reaches
60.001 media seconds with 895 drops out of 1,798 frames. At that exact buffered
end it emits `waiting`, readyState 2, with no media error. There are seven audio
reprimes; native end motion and shutdown pass. The corrected fast path avoids
468,243 scheduler-lock acquisitions, but reaches 868 drops out of 1,798 frames
before waiting at 60.001 seconds and clearing the media source. There are three
audio reprimes. It fails playback acceptance. Controls verify the actual kernel
policy rather than assuming it from the command line.

The evaluator now captures media error, abort, emptied, stalled, waiting and
metadata events before a player can clear its decoder. Page/observer freshness
uses the browser's inner-window document identity instead of ordering rounded
wall-clock time origins. Both identities and the original time-origin offset
remain in the evidence. A preceding control timed out before media preparation
and supplies no playback comparison.

## Runnable aging and timing threads

Ready-queue aging previously used the last dispatch time, crediting blocked
time as runnable starvation. The current kernel records a separate enqueue
timestamp. At the production 100 Hz timer rate, its default-policy live run
still drops 940 of 2,238 frames with seven audio reprimes. Enabling optional
work stealing and idle placement yields 510 of 1,852 drops with five reprimes;
the decoder reports zero decoded drops, three sink drops and 508 compositor
drops. These are separate runs, not a controlled estimate of the aging change.

The software-vsync source and shared timer dispatchers were still NORMAL
priority while Renderer, Compositor and cubeb audio already ran HIGH. Patches
0067 and 0068 propagate HIGH through NSPR and nsISupportsPriority respectively.
The actual Gecko build completes, and guest readback verifies HIGH base and
effective priorities without debugger overrides for vsync and all eleven timer
threads. Build ID is `d76f0e6e64f089363da0dd4f7289c8b85b762ef3`.

The quiet live run with that build has 418 drops out of 2,017 frames at 67.252
media seconds and three audio reprimes. AV1 remains 854 by 480 at 29.97 fps;
post-observation decoder statistics report zero decoded drops, 23 sink drops
and 399 compositor drops. Native motion, browser exit and shutdown pass, but
quality does not. An experimental 1 kHz kernel with the same timing-priority
browser has 634 drops out of 2,155 frames and five reprimes. The production
timer remains 100 Hz; a higher IRQ rate is not promoted as a solution.

## Shared allocator free-list scans

The native heap diagnostic reads allocator metadata without executing target
code. In the parent process, a 112-byte allocation would reach its first fitting
block at entry 116 of the old 64--127-byte bin. The corresponding first fits
for 496 and 1,008 bytes are entries 104 and 113. The 128--255-byte bin contains
at least 512 entries of mixed sizes. These are snapshot walk counts, not
measurements of individual allocation latency. Earlier CPU samples land in
`find_free_block`, and a freeze snapshot shows Renderer waiting for the shared
heap mutex. The snapshot does not identify that mutex's owner.

The candidate in shared `user/lib/libc.c` uses exact 16-byte classes through
1 KiB and a two-word occupied-bin bitmap. Small requests no longer traverse
smaller blocks in the same class, and empty classes are skipped directly.
Larger requests retain the existing coarse classes and fit checks. The 48-byte
block header, locking, split/coalesce behavior and public allocator ABI remain
unchanged. No per-application allocator workaround is introduced.

Normal `make` passes. The preserved old binary and rebuilt candidate each pass
all 20 existing memory cases in separate eight-CPU guests. The candidate also
passes five rounds of the existing eight-thread contended allocation case
(3,942,400 operations). The small, lightly fragmented synthetic workload does
not show an improvement: 64-byte allocation/free means are 316 versus 322 ns,
and the 64-allocation fragmentation case means are 20,312 versus 21,289 ns.
These checks validate exercised behavior, not browser performance or complete
allocator conformance. The actual Gecko retry links successfully in 2m02.32s,
with no compiler warnings; its libxul build ID is
`115c75f6c63b9b430f7a4bde182bf091f2c99d01`. The new main executable contains
128 bin heads and the two-word bitmap. Packaging verifies 50 payload files and
26 native ELF images; candidate ZIP SHA-256 is
`9a59c1a837763532759483bb86cc22d0e7e6a547f356ea05818510e2e4847380`.

`youtube-small-bins-quiet` verifies all 93 installed files, plays the same
854-by-480 AV1 stream and records 304 drops out of 1,892 frames at 63.093 media
seconds. Decoder statistics report zero decoded drops, 27 sink drops and 277
compositor drops; buffered data extends to 156.990 seconds. Nine audio reprimes
remain. Native moving pixels, browser exit and shutdown pass; the original
source image is unchanged. This run does not establish a repeatable improvement
over the preceding control and fails the smooth-playback requirement.

The subsequent native diagnostic verifies 128 bin heads in the running parent
and content processes. Parent classes for 96, 112, 240, 496 and 1,008 bytes have
exact-size entries and first fits at entry one. The bounded walk truncates long
lists explicitly. Both heap mutexes are unlocked at this post-observation
snapshot. No 1.5-second native-pixel freeze triggers in this 35-second run;
shorter delays and dropped frames remain. Its 346/1,387 drops and five reprimes
are diagnostic observations, excluded from quiet quality comparisons.

The same run collects 33 all-CPU register samples: 132 of 264 stopped CPU
locations resolve, including inline frames, to `scheduler_lock_acquire`; twelve
resolve to `process_memory_lock` and four to kernel heap locking. This is not a
CPU-time distribution. Kernel free-list snapshots also work: the sampled
240-byte request has first fit 28, while several larger classes require moving
to another class. They do not establish a new kernel allocator bottleneck.
The existing kernel scheduler-stage TSC instrumentation is now available through
`--scheduler-cost`, with per-thread raw counters and confirmed arming. Its nested
stage spans overlap and must not be summed as independent durations. This flag
marks the run diagnostic and disables the counters in the post-run snapshot.

The first stage-cost run confirms armed counters for 336 registered threads.
Its 7,195,565 scheduler-lock acquisitions include startup and must not be
attributed solely to playback. A subsequent run records a second profile just
before native Play, then re-arms the counters. From tick 6,382 to 12,005
(56.23 seconds, including post-observation native verification), surviving
registered threads acquire the scheduler lock 3,651,582 times. The interval
contains 13,460 storage writes through workers, 28,307 reads (28,295 inline),
and 41,553 seeks (all inline). Retired threads are excluded from thread totals.

During that interval, 871,337 futex wakes bypass the lock 315,329 times but still
inspect 827,121 waiter candidates while waking 116,627 waiters. The 64-bucket
process-private table groups unrelated addresses together. The next kernel
candidate uses 1,024 buckets for both the intrusive lists and the existing
empty-wake counts. It retains the same hash, publication ordering, expected-word
checks, ownership and cancellation paths; process metadata grows by 11,520 bytes.
`make`, the existing futex/condition/mutex contracts, eight-CPU pthread lifecycle
and five rounds of native cross-CPU condition handoffs pass. Kernel SHA-256 is
`ac4de000944a007071e84a2b388cae67b7e65bc229db4e793d8ae63f52868109`.
`youtube-futex1024-quiet` verifies the linked 1,024-bucket layout and completes
native motion, browser exit and shutdown. It still has 532 drops out of 2,224
frames at 73.835 media seconds, with four audio reprimes; the later decoder
snapshot reports zero decoded drops, five sink drops and 527 compositor drops.
This does not meet the quality requirement.

Whole-browser counters fall from 2,122,727 candidate checks over 1,637,367 wakes
in the preceding 64-bucket quiet run to 251,832 checks over 1,849,776 wakes.
That is about 1.30 versus 0.14 candidate checks per wake. Actual awakened waiters
are 199,040 and 218,874 respectively. These counts establish reduced collision
work, not a repeatable video-quality improvement. The matched diagnostic now
captures a pre-Play baseline for the larger table as well.

That playback-only diagnostic reduces candidate checks from 827,121 over
871,337 wakes to 123,467 over 822,474 wakes (about 0.95 to 0.15 per wake).
Surviving registered threads record 64,940 versus 60,309 scheduler-lock calls
per second over 56.23- and 53.80-second inclusive intervals. This single pair
shows reduced collision work; it is not a repeatable wall-time speed estimate.
The larger-table diagnostic still drops 339 of 1,410 frames and has eight audio
reprimes, with native motion, exit and shutdown passing.

Matching symbol resolution finds three native samples in the rounded-clip mask
loop inlined into `SwCompositeThread::process_job`, at libxul offset
`0x81504e0`. The Rust routine recomputes a 64-by-64 signed-distance mask for each
affected corner tile. These samples do not establish its total CPU share.
The ELF stores Rust functions in `.ltext.*` sections; disassembling `.text`
alone misses this code.

The superseded timing-priority XUL gzip is now replaced by a 26,438,097-byte
chunk archive in `symbol-delta-archive-20261107/after-timing-priority/`.
Full reconstruction matches raw ELF SHA-256
`319706a9793c1ecb93adccedaa732c41b8717c722b90273cad8baee6ee9305bd`.
The old gzip bitstream is not retained; its complete symbol ELF is preserved.
Keep every reference prefix named by the manifests. They are independent,
read-only APFS clones and do not depend on the live build directory. The
archive README gives exact recovery commands. Source, protected artifacts and
Git state remain unchanged; available space increased from about 304 MB to
877 MB when the verified old gzip was removed.

All eleven superseded XUL gzip archives now use these chunk directories. The
additional ten conversions reduce logical archive size by 2,705,444,415 bytes;
available space reaches about 3.68 GiB. Their complete ELF hashes match before
the gzip inputs are removed. Both nested Git repositories and twelve SDK/Rust
paths are unchanged. Current raw symbols, all browser ZIPs and disk images are
preserved. These recovery manifests replace the old raw/gzip paths.

## Rounded-mask cache candidate

Patch 0069 adds an Alix-only cache to each software-compositor worker context.
Its key contains the complete rounded clip rectangle and radii, tile rectangle
and mask dimensions. It saves the original routine's exact output bytes; misses
still run the unchanged signed-distance formula. Each worker retains at most
64 masks of at most 4,096 bytes, plus bounded metadata. Storage is heap-owned
and mutex-protected, and allocation failure falls back to the computed mask.
No caller stack or source-image pointer is retained.

The evaluator's `--swgl-mask-cache` control supports default, enabled and
disabled modes, with native configuration readback required for explicit
settings. Existing presentation diagnostics report bounded cache statistics.
Before the change, a matching 115-build/ac4-kernel run passes all eight native
corner fixtures, resize/cursor checks, browser exit and shutdown, preserving
its source image. That result is the next candidate's exact pixel reference.
Normal `make` and syntax checks pass. The retry compiles the actual Rust
renderer and bindings, and the native configuration marker is present in the
resulting WebRender archive. Final Gecko linking and runtime acceptance remain
pending.

## Unnecessary build-cache invalidation

The first mask-cache build forces a vendor-wide Rust rebuild because the global
port fingerprint includes every patched `.rs` file. It creates 475 completed
target-cache units plus a failed style output; rustc's retained diagnostic says
`IO failure on output stream: No space left on device`. Only this task's build
process group is interrupted. This is a build-resource failure, not proof of a
cache rendering bug.

Ordinary in-tree path-crate patches can now set `rust_vendor_cache: false`;
Cargo already tracks their source dependencies. Registry/vendor inputs always
remain in the global fingerprint. Patch 0069 opts out, restoring the actual
previously built `22739478c8701fdd` token with the same native std snapshot.
All six existing configure-cache checks pass. The retry compiles 17 Rust crates,
and its Rust portion finishes in 5m49s; the C++ build continues afterward.

An audited cleanup removes only 1,425 target-cache files generated by the failed
`0a31bd406c62aa66` configuration, totaling 2,930,682,345 logical bytes. Ownership
comes from that attempt's compiler flags, fingerprints and creation times.
All files are closed and hash-checked before removal. Old completed target
caches, fingerprint metadata, immutable SDK/std snapshots, current binaries,
images, ZIPs and source remain protected. Available space changes from about
258 MB to 3.19 GB. The audit and compiler diagnostic are retained under
`failed-mask-build-cache-audit/`.

The first link exits unsuccessfully without a detailed linker diagnostic while
available space is close to the output size. The default packager subsequently
reports an explicit ENOSPC during its initial raw-library copy. Superseded
portable and timing-priority symbol snapshots are preserved as gzip archives;
full decompression hashes match before either raw copy is removed. Source,
protected-output and Git-state checks pass. Each archival reduces logical size
by about 1.69 GB and increases observed available space by about 1.7 GB. Current
symbols, SDK/Rust snapshots, disk images and all browser ZIPs are preserved.
The linker failure's exact cause is not established by the successful retry.

## Diagnostic delivery failures

`profile-full-320` stopped during installation because a kernel log split a
printed SHA-1. Removing that interleaved timestamped record recovers the exact
archive hash; this was not evidence of file corruption. The evaluator now removes
only those records and requires both the complete hash and path. Its retry
verified all installed files and completed the live profile.

`inline-steal-full-320` timed out waiting for a serial command marker during
installation, before work stealing was enabled. It provides no work-stealing
performance evidence. Command markers are now logged, and subsequent commands
wait for the completed command's shell prompt. No disk images were removed.

## Remaining acceptance

Require repeated sustained runs with zero reported drops, uninterrupted tone
output, hardware counters consistent with continuous playback, and clock
progress matching the media/hardware timeline. Repeat at 720p and the live
YouTube workload, verify native moving pixels and clean lifecycle behavior,
then retain only improvements supported by those results. Startup drop/gap
counts, larger-resolution behavior and physical-device output remain unproven.
