# Zen shader math investigation, 6 November 2026

Live shaped-corner stalls reached the actual software renderer.
Six live captures found the Renderer running in scalar sign copying,
superellipse distance evaluation, span drawing and shadow-blur texture sampling.
The first candidate removes external scalar bit-operation calls; the combined
candidate also skips normal calculations whose results no SIMD lane uses.
The native comparison separates paint observations, actual framebuffer markers
and functional pixel stability; none is treated as physical scanout timing.
The investigation also exposed first-profile update effects interfering with
native comparisons, leading to explicit chrome-effect tracing and controls.

**Decision:** retain the new diagnostics and packaging improvements, but do not
promote the shader experiment. The controlled native repeats did not establish
an end-to-end gain. The active shader sources/series are restored to the prior
0062 version, and the published browser archive remains unchanged. Candidate
patches, complete changed source files, matching symbols, packages, disassembly
and all measurements remain available under `candidate-patches/` and the other
artifact paths below.

The later [R8 blur investigation](zen-r8-blur-performance-2026-11-06.md) identifies
a separate missing span callback. Its distinct `0063-alix-swgl-r8-blur-span.patch`
does not reinstate the scalar-bit-operation experiment described here.

## Evidence and diagnostic scope

The existing plain-calculator control completed two visits and six trusted
inputs. Its repeated-visit guest paint observations were 40/50/50 ms, while its
first visit included a 430 ms observation. This was a debugger-sampled run:
these values are diagnostic context, not a before/after timing comparison.
Most plain-page captures found the Renderer already blocked. They do not prove
that renderer CPU accounted for all marker-observation delay.

The shaped-corner case found Renderer execution in all six captures. Three live
PCs resolved inside `glsl::texture` / the shadow blur shader; the others were in
`copysignf`, span drawing and the superellipse distance helper. These are sparse
conditional captures, not CPU-time percentages. Eleven live libxul instruction
probes across the plain and corner runs matched the preserved ELF byte-for-byte.
The module build ID was `58b301a0860bcb055588b59048b06cbc1becc25f`.

`tools/perf.py analyze-zen-stalls` now verifies and resolves saved captures:

```sh
python3 tools/perf.py analyze-zen-stalls PATH_TO_RUN \
  --xul-symbols PATH_TO_MATCHING_UNSTRIPPED_LIBXUL \
  --output NEW_SUMMARY_JSON
```

It checks the GNU build ID, executable program-header bounds and captured live
instruction bytes before batching `x86_64-elf-addr2line` lookups. Inline source
frames are retained. Saved syscall/blocked-render contexts are excluded from
live counts. Changing symbol files and existing output files are rejected. The
current corner run resolved seven live libxul PCs in six snapshots: six Renderer
records and one MainThread record. Supplying the newly rebuilt library for those
old captures correctly rejected the different build ID and created no summary.
All symbolization happens offline, outside guest timing.

## Unnecessary scalar calls

The SDK intentionally disables implicit compiler builtins. SWGL's scalar
`abs(float)` and `sign(float)` therefore called external C-ABI math helpers in
pixel paths. The live sign-copy PC resolved into the compiler-builtins provider,
not a hypothetical function inferred from declarations. Callers spill vector
state around those calls.

Patch 0063 uses explicit `__builtin_fabsf` and `__builtin_copysignf` only for Alix.
The existing sign-bit behavior, including signed zero and NaN signs, is retained.
It changes no global compiler or floating-point flags. Preprocessing without
`__ALIX__` produces identical helper tokens for both SSE2 and fallback settings.
The linked scalar candidate's box-shadow distance helper contains only exp2f and
two hypotf calls: both fabsf calls and its copysignf call are gone. Its code shrank
from 1,620 to 1,557 bytes. This is static code/call evidence, not a latency claim.

The scalar-only browser passed two visits, six trusted inputs, content diagnostics,
resize/close/shutdown and the requested corner-pixel comparison. Four captures
were exact; two differed at one pixel by one RGB level. The explicit allowed
channel tolerance was one. Its paint samples were 960/2820/620 and 940/710/490 ms;
these do not establish an isolated latency benefit. That exploratory record is
retained as `scalar-after-1`, not folded into combined-candidate comparisons.

## Discarded tangent-normal work

SWGL translates the shader's varying early-return branch into masked values.
The old generated C++ calculated `compute_superellipse_normals` even when none
of the four pixels used the tangent extension. That executes two scalar hypotf
calls before discarding their results.

The updated 0062 shader patch initializes unused normals to zero and gates their
calculation with an SWGL group vote. Active tangent lanes keep the original
arithmetic and masks. The generated native object has a real `movmskps` / test /
jump around both hypotf calls. The non-SWGL fragment-shader token stream remains
identical. This does not replace the existing curve/distance approximation or
relax precision. The change is consolidated into the existing per-file patch;
checked application and repetition succeed. The earlier patch and temporary
overlay are archived for reproduction.

## Native comparison protocol

The measurement cohort freezes kernel
`092ccd43b25b8569a3aaa94b61a1e3bb8ae1796994f4ad973e9a64b0200300d7`,
eight CPUs, 4 GiB RAM, QEMU TCG/max CPU and the same saved private-volume source.
Every run clones it, creates a fresh profile, installs the selected full browser
bundle, checks package member hashes and uses the same two local-page visits,
six trusted native inputs and shaped-corner scene. No live sampler or clock
calibration runs in quantitative comparisons. Actual full-redraw policy readback
is retained. Native pixel regions are compared with the same explicit one-level
tolerance and raw difference counts. Geometry, clean exit and guest-originated
shutdown are required. These native markers are not physical scanout timings.

The revised matched runs use this command, changing only the selected bundle
and a new output directory; the first original run establishes the reference
and omits the two reference options:

```sh
python3 ports/zen/benchmark_browser.py \
  --data-image build/perf/zen-lazy-cache-20261106/rename-final/shutdown.img \
  --kernel build/perf/zen-ui-followup-20261106/kernel.elf \
  --bundle build/perf/zen-ui-followup-20261106/candidate-combined.zip \
  --output NEW_DIRECTORY --url local --repeat 2 \
  --native-input --input-samples 3 --shaped-corner-check \
  --reference-corners build/perf/zen-ui-followup-20261106/stable-before-1/result.json \
  --corner-channel-tolerance 1 --diagnostics --diagnostic-samples 5 \
  --shutdown-check --geometry-check --startup-effects quiescent
```

Guest paint observations mean the first privileged `MozAfterPaint` after the
trusted key and matching DOM result. They do not identify a compositor transaction
for that mutation. The changing native DOM marker supplies the independent
framebuffer observation, including input delivery, polling and QMP overhead.
Its upper bound should not be subtracted from guest timing without valid clock
calibration. The protocol deliberately keeps these metrics separate.

Raw records, instruction checks, function disassembly, source equivalence,
patch verification and package manifests are in
`build/perf/zen-ui-followup-20261106/`.

## Pixel stability anomaly

The first quantitative sequence used the existing fixed 250 ms functional-capture
wait. `before-1` and both `combined-after` runs completed successfully. Repeating
the identical original bundle in `before-2` failed its pixel comparison after
timing: one capture differed at 37,761 pixels, with a maximum channel delta of
19; the other five matched exactly. This failure is retained, including raw RGB,
a difference image, timings and failure snapshots. It did not reach clean-exit,
geometry or shutdown acceptance and is not reported as a successful run.

| Earlier run | First-visit paint observations (ms) | Repeat-visit observations (ms) | Acceptance |
| --- | --- | --- | --- |
| before-1 | 680 / 720 / 2230 | 880 / 470 / 600 | Passed |
| combined-after-1 | 670 / 780 / 570 | 540 / 690 / 480 | Passed |
| combined-after-2 | 850 / 570 / 670 | 540 / 560 / 490 | Passed |
| before-2 | 860 / 590 / 570 | 540 / 450 / 500 | Failed pixel check; remaining acceptance not reached |

The first original run's 2,230 ms observation makes an apparent mean improvement
misleading. The repeat original run was much closer to the candidate. These
records do not establish a reliable end-to-end speedup.

Apart from one one-level edge pixel, the changed region is a full-width band
across the bottom 59 rows of the fixture. This is consistent with a transient
framebuffer upload, but does not prove its source. The old unconditional wait
could not establish that the captured native region had settled.
The earlier `native-response-0-1.ppm` from that same held phase matched the
reference except for that single edge pixel; its bottom 59 rows were exact.
The later functional capture changed 37,760 pixels in those bottom rows. The
next readiness capture's bottom rows were exact again, despite its intentionally
different corner bend. `original-pixel-instability.json` retains these checks.
This establishes a transient native observation, not the underlying renderer,
compositor or QEMU cause.

The revised stable cohort reproduced the mismatch in `stable-before-2`, this
time on sample 0/2. Two initial observations were followed by a 37,760-pixel
change, then four identical changed observations. The reference check still
failed. This demonstrates that short-term pixel stability alone cannot prove
the intended visual state. That run did not reach geometry/exit/shutdown checks.

Full-frame comparison then showed that the changes extend beyond the fixture,
across browser chrome, with a gradual lightening towards the bottom of the
window. This evidence supersedes the initial upload hypothesis above.

## First-profile update effects

Zen's `ZenUpdates.mjs` calls `playWindowSweepAnimation` whenever the saved
`zen.updates.last-build-id` differs from `Services.appinfo.appBuildID`, including
an empty preference in a fresh profile. It appends `zen-update-animation` and
`zen-update-animation-border` during an idle callback. The first element is a
full-window white gradient; its configured 350 ms animation sweeps vertically.
The first-version notification also appears in the native screenshots. These
are additional visual states in the benchmark, not changes to the CSS fixture.

The existing runner now records insertion/removal and input-time presence of
those exact chrome elements. It reads DOM presence and inline attributes without
forcing a style/layout flush. `--startup-effects default` preserves the ordinary
fresh-profile behavior. `--startup-effects quiescent` seeds only the two saved
Zen version/build-ID preferences to the running application values, before
window startup, in the disposable profile. Readback must match and any observed
update-sweep element fails the quiescent control. This changes no installed
browser code, saved user profile or global animation setting.

References must also use the same startup-effects mode. Quiescent and default
results are separate workloads; earlier sequences remain recorded rather than
being pooled with the new controls.

The native `effects-default` diagnostic confirmed both sweep elements appearing
during page index 0, then being removed 1,260 ms later by guest wall-clock
observations. The profile started with both saved preferences empty and ran the
original browser, build ID `20261106030007`. This establishes overlap with the
workload and additional full-window visual work. The DOM lifetime is not a
measurement of CPU cost or physical display duration, and does not assign all
input delay to the sweep. That diagnostic used an already-installed private
checkpoint without reinstalling assets; its timings are not pooled with the
matched installation cohort.

## Controlled outcome

The final sequence used the quiescent mode, identical evaluator hashes and
the same frozen kernel/source image in original/candidate/candidate/original
order. The host-storage-failed candidate attempt is retained separately; its
successful retry is the second candidate record below.

| Run | First-visit paint observations (ms) | Repeat-visit observations (ms) | Mean native key-to-marker upper bound (ms) |
| --- | --- | --- | ---: |
| quiescent-before-1 | 680 / 570 / 690 | 610 / 720 / 690 | 1043 |
| quiescent-after-1 | 1040 / 640 / 740 | 780 / 520 / 570 | 1296 |
| quiescent-after-2-retry | 610 / 480 / 640 | 590 / 530 / 710 | 794 |
| quiescent-before-2 | 750 / 640 / 820 | 550 / 770 / 560 | 999 |

| Metric, 12 observations per browser | Original | Candidate |
| --- | ---: | ---: |
| Mean guest paint observation (ms) | 670.8 | 654.2 |
| Median guest paint observation (ms) | 685 | 625 |
| Mean native key-to-marker upper bound (ms) | 1020.6 | 1044.7 |
| Median native key-to-marker upper bound (ms) | 918.9 | 829.4 |
| Native upper-bound range (ms) | 719–1667 | 643–2421 |

First-visit mean paint observations were identical at 691.7 ms. Repeat-visit
means were 650.0 versus 616.7 ms, while repeat-visit native means were 857.1
versus 1105.2 ms. The candidate's native mean includes a 2421 ms observation;
it is retained, not trimmed. Two private boots per version and the divergent
native results do not establish a reliable end-to-end speedup or a general
browser regression. Static elimination of calls/discarded work is insufficient
to promote the experiment on these results.

All four accepted runs completed two visits, six trusted native inputs, 22
content diagnostic cases, resize/cursor/drag checks, clean process retirement
and guest-originated shutdown. All 18 reference comparisons were pixel-exact,
including all 12 candidate captures. Each run checked 92 installed member hashes;
same-browser repeats matched, and fonts matched across all four. Recorded source
metadata and evaluator hashes matched, the source image stayed unchanged,
allocation/reallocation failures and fatal page-fault records were zero, and actual SWGL
policy readback remained full redraw. No update-sweep element was observed in
any quiescent run. `quiescent-measurements.json` retains the raw native arrays,
per-visit summaries and validation evidence.

The active 0062 patch again has SHA-256
`3581385a31f5d86b5710b799023bdd292567e1c904a8336fe112fe71414e0c7b`;
0063 is archived outside the active series. Checked application and repetition
verify the restored source. The default ZIP stays
`78cef06dccc5cef51555cb1a801cc40a90fb657af0b142302cbc1fc236bbb4bb`,
with libxul build ID `58b301a0860bcb055588b59048b06cbc1becc25f`.
The unpublished Gecko object tree retains the experimental build
`f38f8d6f545eae63058c7687dbb9ae61b613225e`; normal `zen-package` requires a
Gecko rebuild before packaging the restored sources. No experimental ZIP was
published over the default browser.

Final `make`, Python syntax compilation, JavaScript syntax validation,
`git diff --check`, and restored patch application/repetition passed. The final
kernel SHA-256 equals the frozen kernel used by the native runs. All eight
requested stack-debug flags remain zero. No new unit-test harness was added.

The runner now records `native_corner_stability_v1`: while the guest remains
held on the same input phase, it retains every native RGB observation and waits
for at least four identical samples spanning at least 300 ms. The first
observation still waits 250 ms; the operation has an eight-second bound and fails
if the scene keeps changing. It does not choose frames by reference similarity,
force a Gecko repaint or use an offscreen renderer. Changed-pixel counts and
maximum channel deltas between observations expose transient states. The final
reference comparison keeps the same explicit one-level tolerance.

Settling occurs after the measured native-response observation. It changes the
cadence before later probes, so the earlier and revised cohorts remain separate.
References from a different capture protocol are rejected. Stability across
these observations is evidence of a settled region, not an atomic-display or
tear-free scanout guarantee.

## Host build and storage

The initial scalar candidate completed a full actual Gecko build/link. The first
combined rebuild failed while Rust wrote its static archive because the host
volume filled. The failed code-generation intermediate and this task's duplicate
repack validation output were audited before removal; their manifests and checks
remain. The original native binaries, reference browser and all saved disk images
remain protected.

Three superseded historical debug ELFs were losslessly gzip-archived and verified
by complete original/decompressed SHA-256 hashes before redundant raw copies were
removed. Sidecars record restoration with `gzip -dk`. No source, SDK/stdlib
snapshot, saved volume or raw measurement was removed. The first two archives
reduced logical storage by 3,236,135,744 bytes; the paused-build audit observed
available space increase from 2,744,320,000 to 5,980,160,000 bytes. Later concurrent
build activity makes separate available-space attribution unreliable. A historical
byte-identical symbol file was also retained at its original path using an APFS
clone. The audit records are retained alongside the results. No Time Machine
snapshot was removed.

Browser packaging now uses independent APFS file clones when supported, with
copy2 fallback. Host source symlinks are still materialized; strip writes a new
file before publication, preserving the cloned input. Existing program-load,
TLS and chrome-resource checks remain mandatory. A repack of the existing browser
kept all 49 payload-file records and 26 native load/TLS images identical; only
provenance describing the already-stripped input differs. This avoids copying
multi-GiB debug data twice during staging and does not change guest rendering.

Later comparison runs exhausted the remaining host headroom. With QEMU stopped,
535 completed full-frame PPMs were losslessly gzip-archived, preserving all native
corner reference regions as raw PPM. Complete decompressed SHA-256 checks passed
before the redundant raw copies were unlinked. Their 1,695,629,969 original bytes
became 62,251,463 archive bytes. Available space was observed rising from
623,239,168 to 2,264,539,136 bytes; 40 protected paths, including saved OS disk
images and reference/current binaries, and all three Git status inventories were
unchanged. `framebuffer-archive-audit/` retains metadata, hashes and restoration
instructions; each affected run has a `FRAMEBUFFERS-ARCHIVED.md` sidecar. This
archival ran between cohorts, outside browser timing.

The first `quiescent-after-2` attempt subsequently failed when QMP could not write
a framebuffer screenshot because the host volume filled. Its partial result and
error log are retained; it is excluded from successful comparisons and was
retried under a new directory after restoring headroom. No guest-memory failure
is inferred from this host error.

A second audited archival covered 1,385 older completed full-frame PPMs from the
preceding Zen investigations. Their 5,440,904,179 original bytes became
129,418,116 gzip bytes, each verified by full decompressed SHA-256 before unlink.
Available space was observed rising from 929,906,688 to 6,256,578,560 bytes.
All 262 protected paths, including saved OS disks and raw corner references,
and the three Git status inventories were unchanged. The audit is retained in
`historical-framebuffer-archive-audit/`, with restoration sidecars in affected
run directories. No current SDK, source, browser archive or OS disk was removed.
