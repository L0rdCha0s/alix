# Menu (`atk_menu_*`)

Header: `include/atk/atk_menu.h`

Menus are floating popup lists of actions. They’re used by the global menu bar and some widgets (dropdown/menu buttons).

## Key functions

- `atk_menu_create()` / `atk_menu_destroy(menu)`
- `atk_menu_add_item(menu, title, action, ctx)` – title is copied.
- `atk_menu_clear(menu)`
- `atk_menu_show(menu, x, y)` / `atk_menu_hide(menu)` / `atk_menu_is_visible(menu)`
- `atk_menu_contains(menu, px, py)` – absolute point inside bounds.
- `atk_menu_handle_click(menu, px, py)` – activates an item and calls its action.
- `atk_menu_update_hover(menu, px, py)` – updates hover state; returns true when hover changes.
- `atk_menu_draw(state, menu)`
