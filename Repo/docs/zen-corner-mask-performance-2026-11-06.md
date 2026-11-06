# Zen shaped-corner mask performance, 6 November 2026

The subsequent [shader-math investigation](zen-shader-math-performance-2026-11-06.md)
evaluates gating unused tangent normals and scalar bit operations. That experiment
was not promoted after native comparisons. Its separate matched cohort retains
both browsers and matching symbols; the measurements below describe this earlier
corner-mask pass.

## Remaining delay and live evidence

The previous SWGL vector-copy fix is present in the starting browser archive
(`0294f426e7e2a6e30f1252e79b481bb51a53786243c5d9842901f58ed13d035f`).
A fresh-profile run without reinstalling/warming browser assets still observed
a first-visit 2,280 ms paint delay and 2,580 ms native-marker upper bound. Its
clock intervals disagreed, so no host/guest stage attribution was made for that
probe. First-use font shaping was only 40 ms in this run. This does not establish
that fonts account for all other cold-start delays.

Live samples found the Renderer in
`ps_quad_mask_SUPERELLIPSE_frag::distance_to_shaped_rect`, its corner-distance
calculation, and copysignf. The sampler now reads every user address through an
explicit per-process page walk and retains 32 instruction bytes. The original
GDB virtual-memory read could fail for an executing user PC despite a resident
page. The corrected physical-map reads matched the retained libxul ELF exactly
at live Renderer offsets `0x5f53112` and `0x84d1160`. Saved syscall contexts remain
explicitly distinct from live CPU registers and can be stale.

The generated SWGL code evaluated each of four corner-distance functions before
applying the per-lane condition to its result. Groups containing no pixels for
that corner still paid for the calculation. Patch 0062 adds SWGL-only
`anyInvocations` guards, using its existing scalar group-vote intrinsic. Empty
groups skip the corner; partially covered groups retain the original per-lane
mask and arithmetic. The non-SWGL shader path is unchanged. Generated C++ now
has four real `if (test_any(...))` branches around those calculations.

## Native corner workload

The existing browser runner now accepts `--shaped-corner-check` with local-page
native input. Eight visible fixtures exercise round, bevel, convex and concave
superellipses, mixed corners, shadows, subpixel translation, rotation and
perspective. Each trusted probe changes a corner radius with the DOM result and
response marker, forcing real mask updates. Computed corner styles and actual
viewport/fixture geometry are recorded; unsupported styling fails explicitly.

After the response, the host exports each fixture's actual native RGB region
and hash. Region placement is derived from the observed native readiness marker
and content viewport dimensions. These captures support exact old/new pixel
comparison without font, desktop-clock or cursor differences in the region.
They observe a bounded fixture, not every CSS corner configuration or physical
scanout. Ordinary input protocol v3 still supplies timing; this is a different
workload from the plain calculator, so compare matching fixture runs.

Fixture protocol `swgl_corner_fixture_v2_dom` uses a DOM response marker in the
same display-list update as the changed corners, and holds the guest on that
phase through its final pixel capture. An earlier canvas-marker protocol
acknowledged the response before its final screenshot and allowed the next
phase to run. Its first-frame shadow mismatch is retained in `matched-after-1/`
and excluded from comparisons. The corrected protocol also waits 250 ms after
the response for its functional capture; this wait is outside the measured
key-to-marker interval. The native metric still observes a marker, not physical
scanout or every pixel's presentation time.

The later shader-math investigation exposed a bottom-band mismatch when repeating
the original bundle. Current capture protocol `native_corner_stability_v1`
retains each settling observation and requires four identical native regions
spanning 300 ms, with an eight-second bound. It replaces the unconditional wait
described above. Comparisons require the same capture protocol; earlier raw
captures and the failure remain available.

`--reference-corners PATH/result.json` defaults to exact RGB comparison.
`--corner-channel-tolerance 1` explicitly permits one RGB quantization level,
while retaining raw changed-pixel counts and maximum channel deltas. The
pre-fix browser already varied by one level at a small number of edge pixels
between repeated visits. Larger errors still fail the run.

```sh
python3 ports/zen/benchmark_browser.py \
  --data-image PRIVATE_PREPARED_IMAGE --bundle BROWSER_ARCHIVE \
  --output build/perf/zen-corners --url local --repeat 2 \
  --native-input --input-samples 3 --shaped-corner-check \
  --diagnostics --diagnostic-samples 5
```

The runner clones the disk and creates a fresh profile; the input image is never
booted in place. Raw evidence is under `build/perf/zen-render-followup-20261106`.
Debugger and clock-calibrated runs are timing-contaminated and kept separate
from comparisons. Kernel stack-debug flags remain disabled.

## Installation exposed a separate writeback problem

The first candidate installation stalled before browser timing. Failure-only
AlixFS counters and automatic failure snapshots identified a failed 205,721,477
byte serialization allocation. The old counters reported 822,015,952 bytes in
use and a 1,027,740,672-byte peak against a 1,069,547,520-byte heap. Those reported
totals are not exact occupancy: the counter bug below was found later. The
failed contiguous 205 MB allocation itself is directly confirmed. Disk and node capacity
were available; device-write and chunk-allocation failure counters were zero.
The failure record is `storage-repro/`, separate from renderer comparisons.

Large-record writeback now uses a heap-owned 64 KiB buffer and a private extent.
Each slice is copied under the node lock, followed by unlocked IO. A changed
data generation discards the private extent and retries without publishing a mixed
record. Metadata-only and small-record paths retain their existing behavior.
The original record remains available on allocation/IO failure. No process-stack
buffer is shared with an IO worker.
The data generation increments under the same node lock as writes, append,
resize, truncate and mapped-page pulls. The existing dirty notification can
occur after unlocking; relying on that later notification would leave a race
in a multi-slice snapshot. Metadata changes still use the original dirty
generation for clearing/requeuing and do not invalidate unchanged file bytes.

An initial bounded-writeback attempt exposed the 128-entry free-span cache limit
(`stream-acceptance/`). Allocation now reconstructs gaps from the resident chunk
table before extending the frontier, with bounds/overlap validation and a
constant-stack kernel libc heapsort. Both-neighbour coalescing, tail reclamation
and removal of consumed final free-list entries prevent avoidable fragmentation.
The on-disk format stays unchanged. This is not journaling, checksumming or fsck.

The browser runner now captures heap, mount and failure-counter state on the
first guest sync failure and aborts that run, rather than waiting for a later
unrelated checksum command to time out. Such runs cannot support latency claims.

## Trustworthy memory and progress diagnostics

The VFS cache inventory exposed an impossible ledger: the old heap counter
reported 48 MB while visible VFS buffers alone occupied 415 MB. Kernel realloc
updated neither current nor peak counters when a block grew/shrank in place;
free could then subtract a larger block and reset the undercounted ledger to
zero. Resize accounting now uses the actual block payload before and after the
operation, under the allocator lock. No allocation behavior is changed by this
accounting fix.

The debugger profile independently walks bounded allocator metadata when the
heap lock is unowned, reporting allocated bytes, free bytes, largest free block,
block count and whether the walk covers the region and matches the ledger.
It also inventories VFS buffer capacities and the 24 largest paths. These are
metadata reads, not target function calls. Busy/truncated walks are explicit.
Initial and final summaries appear in `result.json` as well as raw logs.

Optional `--progress-profile-ms 5000 --stall-profile-limit 2` captures this
memory/VFS state plus native CPU/module/thread contexts after a browser stage
stops reporting progress. It requires matching `--zen-symbols`, cannot be used
with thread-ID counting, and marks timings as contaminated. It extends the
existing response-only sampler to startup/navigation/actor stalls.

The profile-heavy prepared disk still stalled during its second page in
`stream-acceptance-2/`; that manually investigated run is not an acceptance pass
or timing comparison. A separately formatted volume was created through the
existing eight-CPU native mapping acceptance, preserving all old images and
profiles. Renderer comparisons use that same clean volume for both bundles.

## Verified comparison

Four corrected-protocol boots ran old/new/new/old with the same kernel,
evaluator, clean source volume, fresh profile, two visits, six trusted inputs
and 110 content samples each. Both packages were installed and all member
hashes checked before timing, so this warms asset caches. No debugger watchdog,
clock calibration or identity counting was enabled in the comparison runs.
TCP captures also confirm identical 2,855-byte HTML in all four runs (SHA-256
`5e25c6abcfc00f9c64e5be10338428b487638a0ef3e9562802b8f3c5160bbb08`).
Each first document response is HTTP 200 and the repeat is cache-validated with
HTTP 304. The recovered page and `served-page-proof.json` preserve the actual
network inputs, independently of the current template file.

| Run | First window, host s | First-visit paint, guest ms | Repeat paint, guest ms | Renderer sampled ticks |
| --- | ---: | --- | --- | ---: |
| Before 1 | 11.238 | 1200, 1480, 2450 | 1150, 1080, 1150 | 2873 |
| Candidate 1 | 10.896 | 870, 810, 620 | 620, 580, 580 | 1880 |
| Candidate 2 | 10.746 | 1080, 800, 700 | 670, 550, 540 | 1919 |
| Before 2 | 10.601 | 2060, 1550, 1160 | 1330, 1330, 1380 | 2945 |

Across twelve inputs per bundle, average event-to-paint drops from 1,443 to
702 ms, and native DOM-marker upper bounds from 1,652 to 843 ms. The repeat-visit
paint averages are 1,237 and 590 ms. These descriptive small-sample results
support a roughly halved delay for this deliberately demanding corner workload;
they are not a general browser/startup or physical-machine speedup. First-window
times overlap. Renderer tick totals are workload samples, not exact CPU time.

Nine of twelve candidate RGB captures match the baseline exactly. The other
three differ at a total of seven pixel instances, each by one RGB level, out of
2,457,600 compared pixels. The second baseline itself differs by two one-level
pixels in one capture. All reference comparisons use an explicit tolerance of
one channel level; no larger discrepancy is accepted. Both early protocols and
their rejected first-frame capture are retained separately.

All four boots pass every input/content/native-region check, have zero AlixFS
snapshot/chunk/device-write failures, and leave source-image metadata unchanged.
All eight initial/final heap walks cover the complete heap and exactly match
the corrected ledger. `dom-comparison.json`, `dom-input-comparison.csv` and
`measurement-sources-dom-v2.json` retain measurements and implementation hashes.

## Native acceptance and remaining memory pressure

The candidate completes all twelve stationary-cursor samples, drag/bounds,
shrink, outside-window pixel preservation, browser exit status 0 and OS shutdown
on the clean volume. A further cold boot of that private checkpoint completes
the plain calculator, content checks, the same window/shutdown checks and two
actual progress-watchdog snapshots. A one-page run on the full prepared volume
also installs/verifies the candidate and passes input, content, window, exit and
shutdown checks, with one streamed-snapshot retry and no writeback failures.
On that heavy-volume run the native window rectangle shrank, but its recorded
client backing-buffer size had not changed before capture; full client reflow
there is not proven. The clean candidate and cold-remount captures do show the
smaller backing buffer. The geometry gate's native-bounds/pixel scope should not
be read as a universal client-reflow latency guarantee.
Watchdog runs are timing-contaminated and excluded from the comparison table.

Existing native shared/private mapping, cross-process ownership, independent
remount, legacy mapping isolation and filesystem primitives checks pass on eight
CPUs. The host AlixFS backend check passes versions 2/3/4, modes, metadata retry,
mount identity, payloads, bounded mount IO and parent ordering. The older host
writeback fixture still fails its private-mapping assumption with both the
pre-change and changed AlixFS source; it writes directly into a now-borrowed
cache page instead of exercising the VM's private-write copy. The backpressure
host fixture also expects the former void signature while the current API
returns bool. These fixtures were not weakened or replaced, and are not green.
The older Zen patch suite still lacks its historical import backup. Actual
checked patch application/repeat and the real Gecko build succeed.

Read-only image inventories verify allocated/free-cache bounds and non-overlap
after shutdown and cold remount. No original records disappear. All 7,141 records
on the prepared source survive; the nine changed paths are the installed browser,
its manifest/configuration and the benchmark terminal. Existing profile bytes,
ownership, permissions and timestamps are preserved. The clean initial fixture
is unchanged, and cold remount only changes its private benchmark configuration
among already existing paths. See `filesystem-integrity.json` for exact scope.

The full prepared volume still starts Zen with about 811 MB of VFS buffers in
an approximately 1 GiB kernel heap, including unrelated runtime/game assets and
inactive profile data. Corrected heap use reaches 982 MB in the successful
one-page run, leaving about 85 MB free. The final two-page stress run
(`heavy-two-page-final/`) still times out. Its second progress snapshot records
1,054,723,360 allocated payload bytes, 11,858,672 free bytes and a largest free
block of only 4,543,680 bytes; VFS buffers occupy 891,995,655 bytes. The ledger
matches a complete allocator walk and all writeback failure counters remain
zero. This establishes severe kernel-heap pressure, not a complete causal proof
of the navigation timeout. Diagnosing that timeout and reducing resident cache
pressure remain active work; the clean-volume comparison does not establish
that those limits are solved.

The validated component archive is published at
`build/ports/zen/zen-browser.zip`, SHA-256
`78cef06dccc5cef51555cb1a801cc40a90fb657af0b142302cbc1fc236bbb4bb`.
Its libxul build ID is `58b301a0860bcb055588b59048b06cbc1becc25f`.
`final-kernel.elf` preserves the verified kernel, SHA-256
`ef8f0835e89a4edb194469268ca386f1eeba07edaf09d29d644e475456d77545`.
The previous archive is `before-bundle.zip`; `published-bundle.json` links the
successful and failed runs separately. No benchmark actors/configuration are
included in the published archive. The original data image was not booted or
written, and all eight stack-debug feature flags remain zero.
