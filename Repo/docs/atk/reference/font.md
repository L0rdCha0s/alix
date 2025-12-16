# Font (`atk_font_*`)

Header: `include/atk/atk_font.h`

ATK’s font helpers provide line metrics and text drawing. Widgets typically use the clipped drawing API to avoid drawing outside their bounds.

## Key functions

- `atk_font_available()` – whether a font backend is available.
- `atk_font_text_width(text)` – pixel width of a UTF-8 string.
- `atk_font_line_height()` – pixel height of a line.
- `atk_font_baseline_for_rect(top, height)` – baseline Y coordinate for vertically centering text inside a rect.
- `atk_font_draw_string(x, baseline_y, text, fg, bg)` – draw at a baseline position.
- `atk_font_draw_string_clipped(x, baseline_y, text, fg, bg, clip)` – draw with a clip rectangle.
