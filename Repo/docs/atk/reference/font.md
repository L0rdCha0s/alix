# Font (`atk_font_*`)

Header: `include/atk/atk_font.h`

ATK’s font helpers provide line metrics and text drawing. Widgets typically use the clipped drawing API to avoid drawing outside their bounds.

Kernel `atk_init()` prepares `/usr/share/fonts/PublicSans.ttf` before taking the
desktop state lock; `video_init()` also reaches this point before render locking.
Preparation retains the VFS node, copies its bytes into an owned immutable
buffer, then releases the node before parsing. Later file changes cannot
invalidate the font's backing storage.

Kernel layout and drawing only inspect the prepared cache. A missing or invalid
font uses the bitmap fallback without retrying filesystem access on every frame.
An explicit `atk_font_prepare()` outside UI/render locks can retry, including
the next desktop initialization. Concurrent preparation is serialized without
making rendering wait for the loader. Userland ATK retains its lazy-loading path.

Both TrueType and bitmap text preserve pixels behind and between glyph strokes.
The `bg` argument is retained for compatibility; widgets paint their own
backgrounds. The bitmap fallback also respects the supplied clip rectangle.

## Key functions

- `atk_font_prepare()` – explicitly prepare the font outside UI/render locks.
- `atk_font_available()` – whether a font backend is available.
- `atk_font_text_width(text)` – pixel width of a UTF-8 string.
- `atk_font_line_height()` – pixel height of a line.
- `atk_font_baseline_for_rect(top, height)` – baseline Y coordinate for vertically centering text inside a rect.
- `atk_font_draw_string(x, baseline_y, text, fg, bg)` – draw at a baseline position.
- `atk_font_draw_string_clipped(x, baseline_y, text, fg, bg, clip)` – draw with a clip rectangle.
