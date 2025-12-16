# Scrollbar (`atk_scrollbar_*`)

Header: `include/atk/atk_scrollbar.h`

Scrollbars manage a numeric value within a configured range and emit callbacks when the value changes. They’re commonly used by list views and rich text editors.

## Key functions

- `atk_window_add_scrollbar(window, x, y, w, h, orientation)` – creates a vertical or horizontal scrollbar.
- `atk_scrollbar_set_range(scrollbar, min, max, page_size)` – configures range and thumb sizing.
- `atk_scrollbar_set_value(scrollbar, value)` / `atk_scrollbar_value(scrollbar)`
- `atk_scrollbar_set_change_handler(scrollbar, handler, ctx)` – called on drags and programmatic value changes.
- `atk_scrollbar_begin_drag(scrollbar, px, py, &value_changed)` / `atk_scrollbar_drag_to(scrollbar, px, py)` / `atk_scrollbar_end_drag(scrollbar)` – explicit drag control.
- `atk_scrollbar_hit_test(scrollbar, origin_x, origin_y, px, py)` – hit testing.
- `atk_scrollbar_mark_dirty(scrollbar)` – mark region dirty.
- `atk_scrollbar_draw(state, scrollbar)` / `atk_scrollbar_destroy(scrollbar)`
