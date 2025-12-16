# Window (`atk_window_*`)

Header: `src/atk/atk_window.h`

ATK windows are top-level widgets managed by the window list in `atk_state_t` (Z-order, hit testing, dragging/resizing, chrome).

## Lifecycle

- `atk_window_create_at(state, x, y)` – creates and registers a new window.
- `atk_window_close(state, window)` – removes from the window list and destroys it.
- `atk_window_reset_all(state)` – clears all windows (used on `atk_enter_mode()`).

## Title and chrome

- `atk_window_title(window)` / `atk_window_set_title_text(window, title)`
- `atk_window_set_chrome_visible(window, visible)` / `atk_window_is_chrome_visible(window)`

In userland remote-window apps, you typically hide chrome in the *client* ATK window because the kernel already draws the outer chrome.

## Z-order and hit testing

- `atk_window_hit_test(state, x, y)` – returns the topmost window under a point (includes chrome).
- `atk_window_title_hit_test(state, x, y)` – returns the topmost window title bar under a point.
- `atk_window_bring_to_front(state, window)` / `atk_window_is_topmost(state, window)`
- `atk_window_contains(state, window)` – membership check.

## Invalidation and layout

- `atk_window_mark_dirty(window)` – invalidates any cached window surface and expands the dirty region.
- `atk_window_ensure_inside(window)` – clamps to the visible screen bounds.
- `atk_window_request_layout(window)` – recomputes layout after size changes and marks dirty.
- `atk_window_supports_resize(window)` – whether the window can be interactively resized.

## Children

- `atk_window_add_button(...)` adds a button child.
- Other widgets have their own `atk_window_add_*` constructors in their headers (label, text input, image, etc.).

## Drawing helpers (mostly internal)

- `atk_window_draw_all(state, clip)` / `atk_window_draw_all_except(state, clip, skip)`
- `atk_window_draw(state, window)` / `atk_window_draw_from(state, start_window)`

## Debugging

- `atk_window_list_validate(state)`
- `atk_window_list_dump(state, label)`
