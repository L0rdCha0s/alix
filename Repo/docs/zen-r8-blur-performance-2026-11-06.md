# Zen R8 blur investigation, 6 November 2026

Live shader-state capture found R8 shadow blur using the generic four-pixel
shader loop because WebRender's selected `COLOR_TARGET` variant exposes only an
RGBA8 span callback. Patch 0063 exposes the existing R8 span implementation to
that variant. The actual rebuilt browser passed the native comparisons and is
now the default package. Its mean native input-to-pixel observation upper bound
fell by 23.3% in the matched QEMU shadow workload; mean paint observations fell
by 29.5%. These are workload-specific observations, not universal browser speed
or physical-display measurements.

## Evidence

The starting package is SHA-256
`78cef06dccc5cef51555cb1a801cc40a90fb657af0b142302cbc1fc236bbb4bb`,
with libxul build ID `58b301a0860bcb055588b59048b06cbc1becc25f`.
The frozen kernel is
`092ccd43b25b8569a3aaa94b61a1e3bb8ae1796994f4ad973e9a64b0200300d7`.
All boots use private clones; the supplied source disk is not booted in place.
Both diagnostic runs use the quiescent startup mode from the preceding pass.

`live-before` captured six stalls and verified five live libxul PCs against
matching executable bytes. Four Renderer PCs reached blur, rasterization,
packing and sign copying; another was a DOM Worker's CacheIR compilation.
These bounded samples are not CPU-time percentages. Symbolization is offline.

The new `live-state-before` diagnostic captured the selected fragment shader
and its fields. Two Renderer captures were executing the color blur routine:
the current shader pointer equalled live RBX, its R8 callback was null, the
RGBA8 callback was non-null, and the source sampler was `glsl::R8`, 2048 by
2048. Blur support was 8 with duplicate edges, in the vertical direction.
One captured PC was `0x5ee3692`; another was `0x5ee4a15`.

The return address at stack offset 680 was `0x5ffc669`, inside
`draw_quad_spans<unsigned char>`, immediately after its generic fragment call.
The callee's preserved disassembly reserves 632 stack bytes and pushes six
eight-byte registers, placing this return address exactly at that offset.
This validates that single caller relationship; other stack candidates are
still not presented as an unwound stack.

WebRender's `renderer/shade.rs` creates `cs_blur` with `COLOR_TARGET`, and
`renderer/mod.rs` binds that shader for the target's blur passes. The shader's
SWGL section previously exposed `swgl_drawSpanR8` only in the other variant.
The generic R8 rasterizer therefore cannot call its optimized implementation.

## Instrumentation

`tools/perf.py swgl-profile-info` extracts field layouts with GDB from a matching
unstripped ELF, verifies the writable global pointer and executable blur ranges,
and records its GNU build ID and SHA-256. The runner's `--swgl-profile-info`
option passes a captured copy into its existing live sampler. A mismatched live
module ID prevents shader-state reads and fails the diagnostic. No target
functions, page-table changes or page faults are requested by the collector.
Absent resident pages and unavailable state remain explicit.

The native `wrong-build-profile` evaluation supplied a deliberately different
build ID. Its second snapshot found the live Renderer module and returned only
`module_build_id_mismatch`, without shader fields. The runner rejected the
profile, retained the failed run and confirmed its source image unchanged.

Fields are bounded to 128 bytes each within a 4 KiB layout window. General
registers and stack-candidate positions are also retained. The global shader
may describe an earlier primitive when the live PC is outside its recognized
blur routine; the record exposes that distinction. Profiling pauses invalidate
latency comparisons.

## Fix

Patch `0063-alix-swgl-r8-blur-span.patch` gives the color variant an R8 span
callback using the existing Gaussian implementation. Format mismatch still
returns to the generic path. Mirrored-edge inputs retain the generic behavior.
The existing alpha variant, RGBA8 span function and GPU shader bodies remain
unchanged. File-local preprocessor comparisons confirm unchanged GPU vertex,
GPU fragment and SWGL alpha output, with the custom include line omitted equally
for that comparison. This is not a claim of complete shader conformance.

All evidence and build/comparison records are retained under
`build/perf/zen-blur-followup-20261106/`. Quantitative runs use the same source
image, frozen kernel, evaluator, complete bundle installation, fresh profile,
two local-page visits and six trusted native inputs. Pixel comparisons retain
the explicit one-level tolerance from the existing protocol; raw differences
and lifecycle checks are required before promotion.

## Build/storage evidence

The original-browser unsampled baseline passed six trusted inputs, 22 content
diagnostic cases, geometry, clean exit and shutdown. The source image stayed
unchanged. The candidate's generated C++ now registers `draw_span_R8_func`,
retains the duplicate-edge guard, and its native SWGL object contains the new
464-byte callback. These are component checks; full build and guest acceptance
are separate gates.

The full upstream Gecko build/link completed successfully, followed by packaging
49 payload files and 26 native ELF images with the existing load/TLS checks.
The candidate bundle is SHA-256
`5ae3ad0c179d77484889f0bb775081b108b351ba108f1f0aba50c1c49a314ed6`,
with libxul build ID `ad123f1f76881432b5813691a165a827ddc1640c`.

## Native outcome

Four original/candidate/candidate/original runs used matching evaluator hashes,
the same source image and frozen kernel, fresh profiles and full bundle/member
verification. Debugger sampling was excluded from these runs.

| Run | First-visit paint observations (ms) | Repeat-visit observations (ms) |
| --- | --- | --- |
| before-1 | 590 / 510 / 580 | 860 / 630 / 610 |
| after-1 | 500 / 360 / 330 | 370 / 330 / 350 |
| after-2 | 490 / 470 / 500 | 540 / 400 / 370 |
| before-2 | 610 / 510 / 520 | 510 / 630 / 550 |

| Metric, 12 observations per version | Original | Fixed |
| --- | ---: | ---: |
| Mean guest paint observation (ms) | 592.5 | 417.5 |
| Median guest paint observation (ms) | 585 | 385 |
| Mean native key-to-marker upper bound (ms) | 774.2 | 593.7 |
| Median native key-to-marker upper bound (ms) | 736.7 | 539.1 |
| Native upper-bound range (ms) | 599–1055 | 395–1291 |

The candidate's 1291 ms outlier is retained. Tail stalls remain. Repeat-visit
native means were 778.8 versus 504.4 ms. Two boots per version establish the
observed improvement in this scene, not a general speed guarantee.

All four runs passed 24 trusted inputs, 88 content diagnostic cases, 368 installed
member-hash checks, cursor/drag/resize checks, clean process retirement and guest
shutdown. Source images remained unchanged; allocation/reallocation failures and
fatal page-fault records were zero. Actual full-redraw policy remained enabled.
All 12 candidate captures differed at 1155–1169 of 204800 pixels, by at most one
RGB level: 13936 changed pixels across 2457600 compared candidate pixels. The
original repeat's six references were exact. The one-level tolerance was
unchanged. Native screenshot review confirmed intact controls, shapes and shadows.

The separate post-fix diagnostic verified six live instruction probes. Its four
Renderer samples reached rounding, texture sampling and superellipse mask/shadow
math; none of these bounded samples landed in the old generic blur routine.
This is not a CPU-share estimate or proof that generic blur never runs. The plain
page control also passed six inputs, 22 content diagnostic cases, geometry, exit
and shutdown, with paint observations 100/80/60 and 60/50/40 ms. These controls are
kept separate from the shadow comparison.

The tested ZIP was promoted atomically to `build/ports/zen/zen-browser.zip`, with
the old ZIP and directory retained as `zen-browser.before-r8-blur-20261106.zip`
and `zen-browser.before-r8-blur-20261106`. Benchmark instrumentation is absent
from the published ZIP. `published-package.json`, `matched-measurements.json`
and `final-validation.json` record the hashes and checks. `make`, syntax checks
and patch application/repetition passed; the kernel still matches the frozen
native cohort and all eight requested stack-debug flags remain zero.

During the ongoing full build, 463 completed full-frame PPM captures were
losslessly gzip-archived. Their 1,183,587,647 original bytes became 43,676,361
archive bytes, verified by complete decompressed SHA-256 before redundant raw
copies were unlinked. All 298 protected paths, six source hashes and three Git
status inventories were unchanged. Saved OS images, browser binaries and raw
native corner references remain untouched. Audit metadata and restoration
instructions are retained in `framebuffer-archive-audit/` and run sidecars.
Observed free space changed from 6,463,389,696 to 7,610,322,944 bytes while Gecko
was building; that change is not attributed solely to archival. No SDK snapshot
or restore-history snapshot was removed.
