# Zen-specific performance diagnostics, 5 November 2026

The later [shader-math pass](zen-shader-math-performance-2026-11-06.md) documents
the offline `analyze-zen-stalls` command, including module identity, executable
instruction-byte checks and inline source frames for live captures.

The native performance app now has 86 default cases, including descriptor/path
metadata, missing-file lookup, directory metadata and symlink follow/no-follow.
The [resident metadata investigation](performance-pass8-2026-11-05.md) removes
unnecessary worker round trips and reduces CLI stat from 112 us to 15–16 us.
Those platform cases are complemented by diagnostics inside the actual Zen
browser, using the existing disposable-VM runner.

## Run the real browser diagnostics

```sh
make
python3 ports/zen/benchmark_browser.py \
  --data-image data.img \
  --output build/perf/zen-targeted \
  --url local --repeat 2 --native-input \
  --input-samples 3 --diagnostics --diagnostic-samples 5
```

The output directory must be new. `--diagnostics` defaults to the local page
when no URL is supplied. The installed browser image is cloned; a new profile
and privileged instrumentation are created only inside that private clone.
The original image is not booted or written, and saved profiles are not opened.
The runner records original image metadata before/after, evaluator hashes,
host load, kernel hash, raw events, native pixel captures and JSON results.

The new content diagnostics run after input probes on each visited page. Every
case retains raw samples, first-use cost, median, p95 and maximum:

| Case | What it isolates |
| --- | --- |
| Zero-delay timer | Main-thread task scheduling delay |
| Animation-frame wait | Refresh-driver/main-thread frame scheduling |
| Actor round trips at 0 / 4 KiB / 64 KiB | Real parent/content actor IPC, with exact payload echo checks |
| Batched 128-node layout | DOM mutations followed by one forced layout |
| Interleaved 128-node layout | Repeated synchronous layout flush sensitivity |
| Canvas fill/readback | Actual 2D pixels with exact RGBA verification |
| Font readiness | Document font-loading promise and its starting state |
| Font shaping/raster | Multiscript text measurement, first/cached use and nonblank raster readback |
| 1 MiB ArrayBuffer allocation/touch | Gecko/content allocation and page-touch path with data checks |

`--diagnostic-samples` accepts 3–30. DOM work is limited to 128 nodes and retained
allocation to at most 30 MiB. The temporary DOM fixture is removed. The report
fails on missing cases, incorrect data, invalid timing records or failed stages.
Unsupported long-task observation is explicitly reported as unsupported. This
build does not expose that observer; timers and frame callbacks still provide
main-thread delay observations. Navigation and the 16 slowest resources also
include DNS, connection, response and transfer-byte fields. Restricted resource
fields can be zero; zero is not interpreted as a cache hit.

## Input latency stages and native response pixels

Each real trusted Return probe records time to a microtask, result DOM mutation
observer, zero-delay timer, animation-frame callback and MozAfterPaint. The DOM
observer delay includes observer delivery. Null means a callback had not run
before the paint observation; it is not a measured zero.

With `--native-input`, the existing changing readiness marker first establishes
that the intended page/frame is visible. A different 8x8 marker is drawn only
after the expected result mutation. The host watches for those exact native
framebuffer pixels immediately after key injection and saves a response capture.
An acknowledgement holds that marker until observation, preventing the next
probe from overwriting it. Native observation runs independently of the delayed
paint/report arrival. This fixes the earlier instrumentation's conflation of
report delay and native response observation.

The new `trusted_dom_paint_native_response_v3` protocol must not be compared
numerically with the earlier post-report marker protocol. The native metric is
an upper bound including QMP delivery, a 50 ms key hold and screenshot polling.
It observes the response marker, not physical scanout or every text glyph.
MozAfterPaint also does not prove physical display completion. The standard
kernel clock is 10 ms; a 0 ms guest sample is below resolution. Small sample
percentiles are descriptive, not statistical confidence intervals.

## What the first verified run found

`build/perf/zen-diagnostics-20261105/native-response/result.json` contains two
local-page visits, 11 cases each, five samples per case, and six trusted input
probes with native response pixels. Every case passed; the original image's
inode, size and modification time remained unchanged. Both visits completed and
rendered. The captured calculator shows the expected Result: 15.

| Observation | First visit | Repeat visit |
| --- | ---: | ---: |
| Font shaping/raster, first sample | 770 ms | 90 ms |
| Font shaping/raster median | 10 ms | 10 ms |
| Batched layout median | 10 ms | 20 ms |
| Interleaved layout median | 70 ms | 70 ms |
| 64 KiB actor round-trip median | 20 ms | 20 ms |
| Animation-frame wait median | 10 ms | 20 ms |

The slowest cold input records a DOM observer at 10 ms, first frame callback at
50 ms and MozAfterPaint at 5,410 ms. Its response marker is observed within a
5,963.7 ms host upper bound after injection. Repeat-visit native upper bounds
are 128.3–254.3 ms. The remaining cold-input stall occurs after DOM update and
the initial frame callback; these diagnostics do not establish its root cause
or claim to fix it. Font first-use cost is another concrete investigation target.
Interleaved layout intentionally performs more work and is a sensitivity case,
not evidence that Zen itself uses that pattern.

Raw JSON/events, kernel profiles and screenshots are retained in the run folder.
`diagnostics.csv` and `input-phases.csv` in its parent summarize the verified
records. `verified-evidence.json` records hashes and checks. An earlier run caught
an Xray-wrapper error in the diagnostic's content-owned typed array; access was
corrected only for that owned allocation and both complete reruns passed. The
failed record is retained separately. These are eight-CPU, 4 GiB QEMU results,
not physical-machine performance. Kernel stack checks remain disabled.


## Live-stall and identity-counting follow-up

Content diagnostics v2 now record font setup/shaping/raster/readback separately.
Optional `--stall-profile-ms 50 --stall-profile-limit 2` captures live native
CPU/module/scheduler state while awaiting response pixels. Use `--zen-symbols`
for a matching unstripped executable. Optional `--thread-self-counts` arms a
kernel dispatch counter for the browser workload. Both modes mark timings as
contaminated. See [the runtime refresh investigation](zen-runtime-refresh-2026-11-06.md)
for verified counts, mixed latency results and remaining work.

The [software-rendering investigation](zen-software-rendering-2026-11-06.md)
adds optional bracketing clock calibration, blocked render-thread contexts and
controlled compositor-policy readback. These diagnostics locate remaining
post-DOM stalls in the actual software renderer and explain the fixed-width
vector-copy optimization.
The [corner-mask follow-up](zen-corner-mask-performance-2026-11-06.md) adds
DOM-scene response markers, native shape references, heap/VFS inventories and
progress watchdogs, with measured renderer and writeback improvements and an
explicit remaining memory-pressure case.
The [memory-pressure follow-up](zen-memory-pressure-2026-11-06.md) adds allocation
failure attribution, TCP receive-capacity tracking, exact resize acknowledgement
and post-close scheduler/lifetime captures. It records the demand-grown TCP
buffer change, bulk/persistence checks and the separate file-cache limit.
The [lazy-cache follow-up](zen-lazy-cache-performance-2026-11-06.md) adds an
opt-in committed-unloaded-file rename probe, deferred/resident byte inventories
and the demand-loading implementation with heavy-volume validation.
