# Gecko graphics and font platform

`gfxAlixPlatform` connects Gecko's Thebes layer to its existing Skia software
backend, image surfaces, FreeType font list and software vsync source. Alix
has no native GL context API; this backend uses CPU surfaces. The outer window
and presentation bridge remains `widget/alix` and `sys_ui_present`.

The platform initializes Gecko's FreeType library and reuses `gfxFT2FontList`,
`gfxFT2FontBase`, `gfxFT2Font` and HarfBuzz. Installed and downloaded fonts retain
the upstream font-entry, face/cache ownership, shaping, variation, fallback and
font-resource machinery. Moz2D's FreeType factories support Alix font data,
descriptors and scaled instances. Parent/content font-list IPC uses the existing
FreeType entry format, with file paths and face/style metadata.

The native scanner in `gfx/thebes/AlixFontFiles.cpp` walks directories with an
owned heap queue. It preserves native filename bytes, bounds paths and skips
directory symlinks and special files. A callback runs synchronously for each
candidate. FreeType/HarfBuzz validate font contents; a matching extension alone
does not make a valid font. The font list checks system roots, the application's
`fonts` directory and the profile's existing font directory.

Nine unchanged font faces from the pinned Firefox source are registered with
the build's font install manifest: DejaVu Sans regular/bold/oblique/bold-oblique,
Charis SIL Compact regular/bold/italic/bold-italic and Fira Code regular. Native
font preferences select those families for sans-serif, serif and monospace.
`ports/zen/fonts.json` records hashes and family names. License notices accompany
the assets. `ports/zen/stage_fonts.py` installs only that configured font subset
and preserves other build outputs. Full browser packaging remains separate.

## Verification

The complete Thebes and Moz2D directories compile with the native platform,
font list and resource methods included. Font-list reconstruction and actual
application initialization still require the complete Gecko link and launch.

`make zen-alix-font-files-qemu-test` links the production scanner object with
configured FreeType/HarfBuzz, Mozilla's allocator/diagnostics and the pinned
prefixed zlib implementation. Its eight-CPU Alix guest verifies:

- Iterative scanning through 32 nested directories, mixed-case extensions and
  a filename containing a non-UTF-8 byte.
- 32 candidates, 24 valid face loads and eight malformed-font rejections.
- Actual FreeType glyph rasterization with identical pixels across CPUs.
- Real OpenType ligature substitution through HarfBuzz.
- Native `memalign`, including arbitrary sizes, small/large alignments,
  invalid/overflow requests and Mozilla's zero-size aligned allocation.

The host ASan/UBSan scanner fixture additionally checks 64-level traversal with
a 16-descriptor limit, file symlinks, directory cycles and a named FIFO. The
main native evidence is `build/test-out/alix-font-files-qemu.log`, with its
boot-image sidecar. These component checks do not establish a rendered Gecko
page or a running Zen application.
