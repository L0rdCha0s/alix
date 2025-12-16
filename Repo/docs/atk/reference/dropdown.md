# Dropdown (`atk_dropdown_*`)

Header: `include/atk/atk_dropdown.h`

Dropdowns provide either a combo-box style control (selected value + list) or a menu-button style control.

## Key functions

- `atk_window_add_dropdown(window, x, y, w, h, style, on_select, ctx)` – creates a dropdown.
- `atk_dropdown_add_item(dropdown, title, value)` / `atk_dropdown_clear(dropdown)` / `atk_dropdown_count(dropdown)`
- `atk_dropdown_set_title(dropdown, title)` / `atk_dropdown_title(dropdown)` – “placeholder” title.
- Selection (combo style):
  - `atk_dropdown_set_selected(dropdown, index)`
  - `atk_dropdown_selected(dropdown)` / `atk_dropdown_selected_value(dropdown)` / `atk_dropdown_selected_title(dropdown)`
- Open state:
  - `atk_dropdown_is_open(dropdown)`
  - `atk_dropdown_set_open(dropdown, open)`
