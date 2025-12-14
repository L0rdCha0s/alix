# Tabs / Tab View (`atk_tab_view_*`)

Header: `include/atk/atk_tabs.h`

Tab views own multiple “pages” (content widgets) and draw a tab strip for switching the active page.

## Key functions

- `atk_window_add_tab_view(window, x, y, w, h)` – creates a tab view.
- `atk_tab_view_add_page(tab_view, title, content)` – `content` becomes a child of the tab view.
- `atk_tab_view_set_active(tab_view, index)` / `atk_tab_view_active(tab_view)`
- `atk_tab_view_active_content(tab_view)`
- `atk_tab_view_set_change_handler(tab_view, handler, ctx)`
- `atk_tab_view_relayout(tab_view)` – call after size changes.

Hit testing/dispatch helpers:

- `atk_tab_view_contains_point(tab_view, px, py)`
- `atk_tab_view_point_in_tab_bar(tab_view, px, py)`
- `atk_tab_view_handle_mouse(tab_view, event)`
