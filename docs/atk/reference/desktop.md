# Desktop (`atk_desktop_*`)

Header: `src/atk/atk_desktop.h`

The desktop is a kernel-managed layer behind all windows. It’s currently a list of icon-style buttons (often used as app launchers).

## Key functions

- `atk_desktop_reset(state)` – clears and rebuilds desktop buttons.
- `atk_desktop_draw_buttons(state, clip)` – draws desktop icons intersecting `clip`.
- `atk_desktop_add_button(...)` – adds an icon button at absolute screen coordinates.
- `atk_desktop_button_hit_test(state, x, y)` – returns the topmost desktop icon under a point.

Desktop buttons use the shared button widget implementation (`src/atk/atk_button.h`) with “absolute/desktop” styling enabled.
