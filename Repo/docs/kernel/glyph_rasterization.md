# Native WebRender glyph rasterization

Gecko's actual `wr_glyph_rasterizer` crate selects its existing FreeType backend
for `target_os = "alix"`. The target retains its Alix identity; it does not enable
the Unix or Linux target family. Gecko configures and builds its bundled
FreeType library and libpng with the native Alix C compiler and runtime.
The port does not use Alix's older browser or font renderer for these glyphs.

The backend keeps the upstream font cache, face mutexes, LCD-filter condition
variable, hinting, outlines and bitmap conversion. Alix links the bundled
FreeType variation functions directly, as Android does, so variable fonts do
not depend on optional symbol lookup. Font-file paths preserve native bytes,
including names that are not UTF-8. The shared face/cache ownership remains in
heap-backed Rust `Arc`, `Mutex` and `Condvar` objects.

The real configured FreeType objects also exposed executable `R_X86_64_GLOB_DAT`
GOT relocations. The native CRT now resolves those before constructors and SSP
initialization, alongside existing main-module TLS offsets. See
[dynamic loading](dynamic_loading.md) for the supported startup boundary.

Run `make zen-rust-glyph-rasterizer-qemu-test` to build the native components and
execute their acceptance program through `run-via-agent.sh`. Its private
eight-CPU guest verifies:

- 512 renders from eight CPU-pinned threads sharing the actual cached faces.
- Monochrome, alpha and subpixel glyphs with stable pixels and metrics.
- A real weight-axis change in Gecko's VotoSerifGX variable font.
- Matching raw-font/file-font pixels through FreeType's native file I/O,
  including a non-UTF-8 filename and subsequent file removal.
- Native thread completion and font/cache cleanup.

The main serial evidence is `build/test-out/rust-glyph-rasterizer-qemu.log`;
its `.boot-image.json` sidecar identifies the kernel, loader and tested ELF.
`build/ports/zen/rust-glyphs-native-link.json` identifies the real Rust libraries
and acceptance ELF. `native-freetype-objects.json` records the configured C
objects used to create the acceptance archive. The program links Gecko's
prefixed `libz-rs-sys` implementation for FreeType/libpng dependencies.

This is glyph-rasterizer execution evidence. It does not prove Gecko font
enumeration/fallback, shaping, color-font PNG decoding, compositor presentation
or complete Zen startup. The acceptance consumer uses the rasterizer without
Gecko telemetry. The target also runs `ports/zen/rust/check_glyph_gecko.py`,
which compiles its `gecko` and `capture` features with the real Glean crates.
A complete Gecko Rust root remains a separate gate.

The Thebes platform, native font discovery and bundled-font integration have
separate C++ component verification. See [Gecko graphics](gecko_graphics.md).
