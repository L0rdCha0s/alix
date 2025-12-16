# List View (`atk_list_view_*`)

Header: `include/atk/atk_list_view.h`

List views are simple tables with a header row, optional selection, and an optional scrollbar. Cells hold small copied strings.

## Key functions

- Construction:
  - `atk_list_view_create()`
  - `atk_window_add_list_view(window, x, y, w, h)`
- Columns:
  - `atk_list_view_configure_columns(list, defs, count)` – titles are copied.
- Rows and cells:
  - `atk_list_view_set_row_count(list, rows)`
  - `atk_list_view_set_cell_text(list, row, col, text)`
  - `atk_list_view_clear(list)`
  - `atk_list_view_row_count(list)` / `atk_list_view_column_count(list)`
- Selection:
  - `atk_list_view_set_selected(list, row)` (use `ATK_LIST_VIEW_NO_SELECTION` to clear)
  - `atk_list_view_selected(list)`
  - `atk_list_view_set_select_handler(list, handler, ctx)`
- Layout/behavior:
  - `atk_list_view_relayout(list)` – call after size changes.
  - `atk_list_view_force_vertical_scrollbar(list, force)` – avoids jitter in resizable layouts.
  - `atk_list_view_is_over_separator(list, local_x, local_y)` – column resizing hit test.
- Rendering/lifetime:
  - `atk_list_view_draw(state, list)` / `atk_list_view_destroy(list)`
