# Label (`atk_label_*`)

Header: `include/atk/atk_label.h`

Labels render wrapped, multi-line text inside their rectangle. They can also behave like a simple scrollback view (manual scroll position + “stick to bottom” mode).

## Key functions

- `atk_window_add_label(window, x, y, width, height)` – creates a label widget owned by the window.
- `atk_label_set_text(label, text)` – replaces the content.
- `atk_label_append_text(label, text)` – appends.
- `atk_label_text(label)` – returns the current text buffer.
- `atk_label_scroll_to_line(label, line)` – scroll to a wrapped line (disables stick-to-bottom).
- `atk_label_scroll_to_bottom(label)` – scroll to end and re-enable stick-to-bottom.
- `atk_label_draw(state, label)` / `atk_label_destroy(label)` – draw / destroy helpers.

## Notes

- `set_text`/`append_text` mark the label area dirty automatically.
