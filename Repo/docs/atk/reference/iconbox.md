# Iconbox (`atk_iconbox_*`)

Header: `include/atk/atk_iconbox.h`

Iconboxes are grid containers for icon-style buttons.

## Key functions

- `atk_window_add_iconbox(window, x, y, w, h)` – creates an iconbox.
- `atk_iconbox_add_icon(iconbox, title, action, ctx)` – adds a button-style icon owned by the iconbox.
- `atk_iconbox_clear(iconbox)` – removes all icons.
- `atk_iconbox_set_active(iconbox, active)` – enable/disable input behavior.
- `atk_iconbox_relayout(iconbox)` – call after size changes.
- `atk_iconbox_count(iconbox)` – number of icons.
