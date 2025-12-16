# Button (`atk_button_*`)

Header: `src/atk/atk_button.h`

Buttons are used both inside windows (chrome/actions) and on the desktop (icon buttons). Most apps create buttons via a container helper such as `atk_window_add_button()` or `atk_desktop_add_button()`.

## Key functions

- `atk_button_configure(widget, title, style, draggable, absolute, action, context)` – turns an existing widget into a button.
- `atk_button_set_title(widget, title)` / `atk_button_title(widget)` – update/query title.
- `atk_button_invoke(widget)` – calls the configured action (callers should only invoke on confirmed clicks).
- `atk_button_hit_test(widget, origin_x, origin_y, px, py)` – hit test against an absolute point.
- `atk_button_draw(state, widget, origin_x, origin_y)` – draw the button.
- `atk_button_effective_height(widget)` – useful for icon layouts (`ATK_BUTTON_STYLE_TITLE_BELOW`).
- `atk_button_is_draggable(widget)` / `atk_button_is_absolute(widget)` – query flags.

## Styles

- `ATK_BUTTON_STYLE_TITLE_INSIDE` – normal button with title inside.
- `ATK_BUTTON_STYLE_TITLE_BELOW` – icon-style button with the label below.
