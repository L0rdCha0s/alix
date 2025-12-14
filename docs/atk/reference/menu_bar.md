# Menu Bar (`atk_menu_bar_*`)

Header: `src/atk/atk_menu_bar.h`

The menu bar is a global (kernel-managed) UI strip at the top of the screen. It owns menu entries independently of any specific window.

## Key functions

- `atk_menu_bar_set_enabled(state, enabled)` – enable/disable rendering and input.
- `atk_menu_bar_height(state)` – returns 0 when disabled.
- `atk_menu_bar_reset(state)` – clears menu entries and resets state.
- `atk_menu_bar_build_default(state)` – populates default entries (logo, clock, etc.).
- `atk_menu_bar_enable_clock_timer()` – enables periodic clock updates.
- `atk_menu_bar_draw(state)` – draws the menu bar.
- `atk_menu_bar_handle_mouse(...)` – routes mouse events and reports whether the menu bar consumed the event.

Userland remote-window apps usually disable the menu bar in their local ATK state (`atk_menu_bar_set_enabled(state, false)`).
