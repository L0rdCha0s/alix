# Host Web Renderer Harness

The host harness renders a local HTML page with Alix's HTML parser, CSS parser,
ATK HTML layout code, font rasterizer, and image decoders. It runs as a native
host process, so renderer changes can be built and measured without creating an
OS image or starting QEMU.

The captured Stack Overflow page is the default target. From the repository
root, run:

```sh
python3 tests/web_render_harness.py
```

For that exact default input, the runner automatically enforces the reviewed
image count plus operation and pixel hashes shown below. Use `--no-baseline`
only while intentionally producing and reviewing a replacement baseline.

This builds `build/host-tests/web_render_harness`, renders at 1920x1080 in the
light colour scheme, and writes:

- `test-out/web-render/stackoverflow.png` - the rendered viewport.
- `test-out/web-render/report.json` - counts, hashes, phase timings, and
  per-run results.

`make web-render-stackoverflow` is the equivalent make target and additionally
asserts that all 16 captured local `<img>` assets decoded. To compile the
native worker without running it, use `make web-render-harness`.

## Fast repeat and stress cycles

A sequential repeat verifies that independent renders produce identical
render-operation and pixel hashes:

```sh
python3 tests/web_render_harness.py --repeat 10 --no-artifact
```

Parallel stress uses isolated worker processes because ATK's font/video state
is process-global and ATK widgets are intentionally owned by one UI thread. It
still exercises concurrent parsing, CSS matching, layout, rasterization, and
resource reads without introducing an unsupported shared-ATK threading model:

```sh
python3 tests/web_render_harness.py --stress 40 --parallel 4 --timeout 30 --no-artifact
```

Every worker has its own hard timeout. A timeout, signal/crash, non-zero exit,
malformed worker result, count mismatch, operation-hash mismatch, or pixel-hash
mismatch makes the overall command fail. `--stress` defaults to 25 runs and up
to four workers. `--layout-only` skips rasterization when profiling parser,
selector, or layout changes in isolation.

The report includes milliseconds for file read, HTML parse, CSS collection,
CSS parse, local-asset preload/decode, layout recording, pixel draw, and total
work. Human output shows p50/p95 asset, layout, draw, and total timings. It also
reports `<img>` candidates, successful decodes, failures, and skipped remote
sources. Use `--json` to also print the full report to stdout.

## Hash baselines

The Stack Overflow fixture's reviewed host-harness baseline is:

```text
nodes=4416 rules=10775 images=17 img_loaded=16 css_images=1 ops=1722
op_hash=0xBA0131C828C32D2E
pixel_hash=0xEB386E6FC697D74D
```

Pin either hash when a change is expected to preserve output:

```sh
python3 tests/web_render_harness.py \
  --repeat 5 \
  --expect-images 16 \
  --expect-op-hash 0xBA0131C828C32D2E \
  --expect-pixel-hash 0xEB386E6FC697D74D \
  --no-artifact
```

Those 16 ordinary local `<img src>` assets comprise 11 PNGs and five JPEGs in
the captured Stack Overflow fixture. The harness decodes them through Alix's
production image decoders before layout. Natural dimensions, image source,
placeholder state, and image-vs-text layout participate in the operation hash;
decoded pixel content participates in the pixel hash. Loaded pixels remain
owned by the HTML-view private state and are released by the normal harness
cleanup path.

An intentional rendering change can legitimately alter one or both hashes.
Run once with `--no-baseline`, inspect the PNG, then update the constants in
`tests/web_render_harness.py` and this document rather than silently weakening
the determinism check.

## Render another local page

The input may be any local HTML file. Linked stylesheets and images are
resolved relative to the HTML file's directory by default:

```sh
python3 tests/web_render_harness.py \
  --input tests/acid2.html \
  --output test-out/web-render/acid2.png \
  --report test-out/web-render/acid2.json
```

For a fixture whose resources live elsewhere, provide an explicit base:

```sh
python3 tests/web_render_harness.py \
  --input /tmp/page/index.html \
  --asset-root /tmp/page/resources \
  --output test-out/web-render/page.png
```

Inputs are deliberately local and deterministic. Ordinary local `<img src>`
assets, data-image URLs, CSS background images, and local stylesheets are
loaded. Remote stylesheets and images are not fetched by this harness; remote
image sources are counted as skipped. Save remote resources beside the fixture
first when they need to participate in a benchmark.

Before layout, the harness separately scans direct linked stylesheets so their
relative `url(...)` image references resolve against each stylesheet's own
directory. The saved Stack Overflow fixture loads one such SVG sprite and
reports 229 missing CSS assets plus one remote reference; those omissions in
the capture are visible in `assets_failed`/`assets_remote_skipped` rather than
being mistaken for decoder coverage. CSS `@import` chains are not recursively
loaded by the host adapter yet, so imported sheets should be flattened into a
benchmark fixture.

## Debugging and sanitizer runs

Enable the renderer's existing trace counters or dump a computed DOM subtree:

```sh
python3 tests/web_render_harness.py --trace --layout-only --verbose
python3 tests/web_render_harness.py --dump-dom=.s-post-summary --layout-only --verbose
```

For an AddressSanitizer/UndefinedBehaviorSanitizer cycle, force a rebuild with
the desired host flags, then reuse that binary:

```sh
make -B web-render-harness \
  HOST_CC=clang \
  WEB_RENDER_HARNESS_CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer'
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/web_render_harness.py --no-build --repeat 10 --no-artifact
```

The macOS AddressSanitizer runtime used by this repository does not support
LeakSanitizer; Linux hosts may change `detect_leaks` to `1`. Rebuild normally
afterward with `make -B web-render-harness`.

## JavaScript boundary

This harness covers deterministic HTML/CSS layout and pixel rendering only.
It does not execute `<script>` elements or the saved Stack Overflow JavaScript
files. That boundary is intentional: browser loading and JavaScript callbacks
are asynchronous, while the renderer consumes an owned DOM/stylesheet
snapshot on the UI side. JavaScript engine and DOM-binding regressions remain
in `make js-test`, `make html-js-test`, and the opt-in `make test262-test`.

The native worker reuses the established host adapters in
`tests/html_view_host_test.c` and links the same production parser, selector,
layout, font, and image source files used by the browser. It is not a second
renderer implementation.
