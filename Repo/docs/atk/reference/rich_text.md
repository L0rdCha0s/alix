# Rich Text (`atk_rich_text_*`)

Header: `include/atk/atk_rich_text.h`

The rich text widget is a styled text editor with cursor/selection, optional pagination, and vertical scrolling.

## Key functions

- `atk_window_add_rich_text(window, x, y, w, h)` – creates the editor.
- Focus:
  - `atk_rich_text_focus(state, editor)`
- Font size:
  - `atk_rich_text_set_font_size(editor, size_px)` (default for new text)
  - `atk_rich_text_apply_font_size(editor, size_px)` (selection/cursor)
  - `atk_rich_text_current_font_size(editor)` / `atk_rich_text_cursor_font_size(editor)`
- Style flags (`atk_rich_text_style_t`):
  - `atk_rich_text_apply_style(editor, flags, enabled)`
  - `atk_rich_text_toggle_style(editor, flags)`
  - `atk_rich_text_current_style(editor)` / `atk_rich_text_cursor_style(editor)`
- Content:
  - `atk_rich_text_set_text(editor, text)` / `atk_rich_text_append(editor, text)`
  - `atk_rich_text_copy_text(editor)` – returns a heap-allocated string (caller must `free()`).
- Pagination:
  - `atk_rich_text_set_pagination_enabled(editor, enabled)` / `atk_rich_text_pagination_enabled(editor)`
  - `atk_rich_text_page_count(editor)`
  - `atk_rich_text_insert_page_break(editor)` (uses `ATK_RICH_TEXT_PAGE_BREAK_CHAR`)
- Scrolling:
  - `atk_rich_text_scroll_to_top(editor)` / `atk_rich_text_scroll_to_bottom(editor)`
- Change notifications:
  - `atk_rich_text_set_change_handler(editor, handler, ctx)`
- Serialization:
  - `atk_rich_text_serialize(editor, &data, &size)` (caller must `free(data)`)
  - `atk_rich_text_deserialize(editor, data, size)`
