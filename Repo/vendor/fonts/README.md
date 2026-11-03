# Alix system fonts

These unmodified, OFL-1.1 fonts are included in the normal offline build and
installed by `/usr/bin/dl.sh` into `/usr/share/fonts` on the persistent main
volume. `manifest.json` records each upstream commit, download URL, byte size,
SHA-256 digest, license and representative Unicode characters. The archive
includes the manifest and all four upstream font licenses.

The collection contains:

- Public Sans, Noto Sans and Noto Serif in regular, bold, italic and bold italic.
- Noto Sans Mono in regular and bold.
- Noto Sans Symbols, Symbols 2 and Math, plus Noto Color Emoji.
- Noto Sans CJK's regular collection, including Chinese, Japanese and Korean
  regional faces and its monospace faces.
- Arabic, Hebrew, Armenian, Georgian, Ethiopic, Devanagari, Bengali, Gujarati,
  Gurmukhi, Tamil, Telugu, Kannada, Malayalam, Sinhala, Thai, Lao, Khmer and
  Myanmar fonts.

## Build and install

Run `make` to create `build/fonts.zip` and refresh the embedded `dl.sh`.
The build verifies every source file against the manifest and needs no network
access or Python dependencies outside the standard library. Run `make fonts-fetch`
to restore missing or changed assets from their pinned upstream revisions.

With the usual download server running on gateway port 8000, boot the rebuilt
kernel and run `/usr/bin/dl.sh`. It extracts the font bundle into
`/root/usr/share/fonts`, exposed as `/usr/share/fonts`, using the same unzip
bootstrap as the application bundle. Existing fonts with other filenames remain
installed. The two downloads are kept separate so fonts never enter `/usr/bin`
or the read-only firmware boot volume.

After `make`, run `python3 tests/system_fonts_qemu_test.py` to install the real
bundle on a cloned main disk and verify every font, license and manifest hash
before and after a cold boot. If the usual repository HTTP server is already
running on port 8000, pass `--use-existing-server` to reuse it after a read-only
archive identity check. Evidence is written to `build/test-out/fonts-package/`.

## Integration boundary

These are system assets for Gecko's future font enumeration and fallback, and
for native applications that load font files directly. Packaging does not finish
the Gecko font platform or establish browser rendering, script shaping or color
emoji support. See [glyph rasterization](../../docs/kernel/glyph_rasterization.md)
for the tested rasterizer boundary. Suggested defaults are Public Sans for system UI, Noto Sans for
`sans-serif`, Noto Serif for `serif` and Noto Sans Mono for `monospace`; Gecko must
still implement these mappings and per-character fallback.

The pre-existing repository-root `PublicSans.ttf` identifies itself internally
as Apple's SF Pro, rather than Public Sans. This package does not redistribute
or replace that file or the native UI's existing `/usr/share/fonts/PublicSans.ttf`
selection. Genuine upstream Public Sans is included under `PublicSans-Regular.ttf`
and its style-specific filenames.

## Sources

- [Noto text, script, symbol and math fonts](https://github.com/notofonts/noto-fonts)
- [Noto CJK](https://github.com/notofonts/noto-cjk)
- [Noto Emoji](https://github.com/googlefonts/noto-emoji)
- [Public Sans](https://github.com/uswds/public-sans)

The archived Noto text repository supplies the static hinted TTF releases;
CJK and emoji come from their separate repositories. Exact source revisions are
in the manifest. Keep the accompanying copyright and OFL license files when
redistributing the fonts.
