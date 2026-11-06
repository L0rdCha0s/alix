# Zen software-rendering investigation, 6 November 2026

The later [shader-math investigation](zen-shader-math-performance-2026-11-06.md)
adds offline verification and symbolization of live stall captures, then follows
the remaining shaped-corner work into scalar math and discarded tangent normals.

## Diagnostics that separate input delivery from rendering

The existing real-browser runner now supports `--input-clock-sync`. It brackets
each trusted input with three parent/content/collector clock exchanges before
and after the probe. The smallest round trip at each end gives an interval for
the host-minus-content clock offset, including two guest ticks of margin. Only
overlapping intervals in the same document produce latency estimates. Disjoint
intervals explicitly make attribution unavailable. The raw exchanges are retained.
Native event timestamp and event age at listener entry are also recorded.

This is input protocol `trusted_dom_paint_native_response_v4_clock_bridge`.
Clock exchanges alter setup and scheduling, so the report marks these runs as
timing-contaminated. Use ordinary v3 runs for before/after comparisons. A debugger
pause during a probe also suppresses clock attribution. Neither native marker
observation nor MozAfterPaint measures physical scanout.

The live-stall sampler now reads blocked render-thread contexts through the
kernel's common physical mapping, without switching CR3, modifying page tables,
paging in data, or calling target functions. It retains current CPU registers,
thread states, module ranges, last syscall contexts and futex values where
available. A saved syscall frame can be stale; current user-mode CPU registers
are the authoritative live execution location. Stack code candidates are not
an unwound stack. Sampling limits and missing resident pages remain explicit.

For example, with a prepared private disk containing the current browser:

```sh
python3 ports/zen/benchmark_browser.py \
  --data-image PRIVATE_PREPARED_IMAGE --output build/perf/zen-clock \
  --url local --repeat 2 --native-input --input-samples 3 \
  --diagnostics --diagnostic-samples 5 --input-clock-sync
```

Add `--stall-profile-ms 500 --stall-profile-limit 3` for separate live snapshots,
and `--zen-symbols MATCHING_UNSTRIPPED_ZEN` when the installed executable differs
from the current build. Every run clones its input disk and creates a fresh
profile. The source disk is not booted in place.

## Observed slow path

`build/perf/zen-input-clock-20261106/calibrated/result.json` contains a first-visit
input with a 20 ms native event age, a 0 ms DOM observer delay, 3,010 ms to
MozAfterPaint, and a 3,095 ms host native-marker upper bound. Its overlapping
clock intervals put key-to-listener at 32–92 ms and DOM-to-native observation at
3,002–3,062 ms. This establishes slow work after the DOM update. One other
probe's clock intervals disagreed; no attribution was made for that probe.

Three separate live captures in `build/perf/zen-input-clock-20261106/live-render`
all found the Renderer running. Live PCs resolved to libc's memcpy, SWGL blending
and SWGL linear-gradient drawing. The other render workers were mostly waiting
on futexes. The libxul note page was not resident; symbolization uses the retained
ELF from the previously verified prepared image. Debugger-paused samples are
excluded from quantitative timing comparisons.

The Alix SDK deliberately uses `-fno-builtin`. SWGL's fixed-width, alias-safe
unaligned vector loads/stores and bit casts consequently called external memcpy
inside pixel loops. The captured old blending code includes 4-byte memcpy calls.
Patch 0061 uses explicit `__builtin_memcpy` for those four helpers on Alix, leaving
the SDK flags and other platforms unchanged. The actual rebuilt libxul's
`draw_quad_spans<unsigned int>` drops from 1,873 external memcpy call sites to
zero, and from 360,126 to 235,126 code bytes. These are static call-site/code-size
counts, not measured invocation counts or a claimed latency percentage.

## Controlled redraw-policy evaluation

Alix retains the widget draw target and kernel window surfaces. Patch 0060 allows
controlled evaluation of SWGL's invalidation policy while explicitly forcing
full rendering after first use, resize and resume. The runner can select the
previous full-redraw policy with `--swgl-policy full` or retained policy with
`--swgl-policy retained` in the same binary. It requires matching actual
`ALIX_SWGL_POLICY` serial readback, rather than trusting the requested setting.
The policy diagnostic is opt-in and emits one line when capabilities are read.

Two retained-policy runs produced first-visit paint samples of 370/320/380 ms
and 430/390/130 ms, with repeat samples of 90/90/90 and 80/50/150 ms. Those
results overlap the new full-policy runs. The final patch preserves the existing
full-redraw default; `ALIX_SWGL_FORCE_FULL_REDRAW=0` opts into retained mode and
`1` explicitly selects the default. No broad benefit from changing the default
is established by this small workload.

The retained-policy acceptance run also passed all 12 stationary-cursor samples,
drag/bounds, shrink from 1276 to 976 pixels wide, preserved desktop pixels outside
the resized window, browser exit status 0 and clean OS shutdown. Its private disk
is retained as `intrinsic-retained-2/shutdown.img`.

## Vector-copy comparison

Four ordinary v3 boots ran old/new/new/old, with the previous full-redraw policy
explicitly selected and read back for the new binary. Each uses the same kernel,
evaluator, source image, fresh profile, two visits, six trusted inputs and eleven
content diagnostics with five samples each. Both bundles are installed and every
member hash checked before timing, warming asset caches; these are not cold
filesystem-cache tests. No live sampler, clock exchanges or identity counter is
enabled during these comparisons.

| Run | First window, host s | First-visit paint, guest ms | Repeat paint, guest ms | Renderer sampled ticks |
| --- | ---: | --- | --- | ---: |
| Before 1 | 10.799 | 780, 570, 540 | 60, 30, 60 | 1961 |
| Intrinsics, full 1 | 10.621 | 520, 130, 260 | 110, 70, 80 | 1620 |
| Intrinsics, full 2 | 10.351 | 520, 590, 370 | 60, 60, 50 | 1478 |
| Before 2 | 10.527 | 1170, 330, 690 | 70, 40, 60 | 1448 |

The six first-visit paint samples average 680 ms before and 398 ms after; their
medians are 630 and 445 ms. First-visit native-marker upper bounds average
806 ms before and 652 ms after. Small repeated-visit samples and first-window
times show no consistent benefit, and the sampled Renderer totals overlap.
This is evidence of reduced first-visit paint delay in this bounded workload,
not a general browser speedup or elimination of cold stalls. All four boots
passed every requested content/input/pixel check and left the source unchanged.

Build and raw evidence are under `build/perf/zen-retained-damage-20261106`.
`swgl-codegen.json` and the two assembly files retain the static code comparison;
`measurement-sources.json` and `sources/` preserve the measurement implementation.
Measurements use eight-CPU, 4 GiB QEMU; kernel stack guards and associated stack
debugging remain disabled.

## Build and verification boundaries

The actual Gecko build and native packaging complete successfully. The final
libxul build ID is `f44b5772bdc1077e4e5a87efa0be1be71233f1fc`; its SWGL function
still has zero external memcpy calls. The final package has 49 files and 26 ELF
images. Packaging verifies loaded code/data/TLS bytes before and after stripping.
Normal `make`, Python/GDB-Python parsing, JavaScript syntax and whitespace checks
pass. No new unit-test harness was added.

The existing `tests/zen_patch_test.py` suite fails all nine cases in fixture setup:
the historical native import backup referenced by `.alix-zen-overlay.json` is
missing. It fails before applying or testing these patches. That failure is
retained in `patch-tests.log`; the fixture assertions were not weakened. Checked
patch application/repeat against the actual composed engine tree and the full
Gecko build succeed. This is not a claim that the host patch suite is green.

The benchmark now requests policy diagnostics even for the default setting, so a
supporting browser records its actual default without an override. Older bundles
can omit this readback. The measured four-run comparison predates this logging-only
adjustment; its exact evaluator is preserved in `sources/`.

The exact final bundle passed a further native acceptance boot with both page
visits, all 110 content samples, six trusted input/response-marker probes, all
12 cursor samples, drag, resize, outside-window pixel preservation, browser exit
status 0 and clean OS shutdown. Default-policy readback reports
`redraw_on_invalidation=1` without forcing a selection. The private image is
`final-acceptance/shutdown.img`; all source-image metadata remained unchanged.

The vector-copy package was published at `build/ports/zen/zen-browser.zip`, SHA-256
`0294f426e7e2a6e30f1252e79b481bb51a53786243c5d9842901f58ed13d035f`.
The prior package is preserved at
`build/perf/zen-retained-damage-20261106/baseline-bundle.zip` for rollback.
`published-bundle.json` links exact package and acceptance hashes, and
`final-sources.json` records the final implementation. Disposable benchmark
actors/autoconfig are not in the published package. The original data image
and its saved profiles were not booted or written.
The current archive now includes the
[validated corner-mask optimization](zen-corner-mask-performance-2026-11-06.md),
with this prior package preserved for rollback.
