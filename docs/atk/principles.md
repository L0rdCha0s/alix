# ATK Principles

ATK is a small retained-mode UI toolkit: widgets hold state, input mutates state, and rendering repaints only what is dirty.

## State and ownership

- `atk_init()` initializes a single global `atk_state_t` (declared in `src/atk/atk_internal.h`).
- Windows are owned by the ATK state’s window list (`atk_window_create_at()` / `atk_window_close()`).
- Most widgets are owned by their container (typically a window) and are destroyed with it.

## Rendering and dirty tracking

- ATK renders into the current video surface/backbuffer.
  - Kernel: hardware backbuffer managed by `src/drivers/video.c`.
  - Userland: software surface (`user/video_surface.c`) attached to an `atk_user_window_t` buffer.
- ATK maintains a “dirty rect” model:
  - UI mutations mark regions dirty (via widget helpers such as `atk_window_mark_dirty()` or internal `atk_dirty_mark_rect()`).
  - `atk_render()` repaints the current dirty region and is a no-op when nothing is dirty.
- Callers are responsible for presenting/flushing the backbuffer:
  - Kernel: `video_flush_dirty()` or the refresh path in `src/drivers/video.c`.
  - Userland: `atk_user_present()` / `atk_user_present_force()`.

Typical loop pattern:

1. Feed input into ATK (`atk_handle_mouse_event()` / `atk_handle_key_char()`).
2. If ATK reports `redraw`, call `atk_render()`.
3. Present/flush the backbuffer.

## Coordinates and clipping

- Widget coordinates are relative to their parent.
- Use `atk_widget_absolute_position()` / `atk_widget_absolute_bounds()` when you need screen-space geometry.
- Prefer clipped drawing helpers where available (for example `atk_font_draw_string_clipped()`) to avoid overdraw outside a widget’s bounds.

## Input dispatch, focus, capture

- Mouse and key input enter ATK via:
  - `atk_handle_mouse_event()` (absolute cursor coordinates + edge flags)
  - `atk_handle_key_char()` (typed characters)
- Focus (`state->focus_widget`) controls which widget receives key events. Text widgets expose explicit focus helpers (for example `atk_text_input_focus()`).
- Mouse capture (`state->mouse_capture_widget`) keeps routing mouse events to a widget while dragging even if the cursor leaves its bounds.

## Layout

- ATK supports anchor-based layout for widgets:
  - Call `atk_widget_set_layout()` after placing a widget to capture margins relative to its parent.
  - Call `atk_widget_apply_layout()` after the parent’s size changes to recompute the child’s `x/y/width/height`.
- `include/atk/layout.h` provides a small “layout cursor” helper (`atk_layout_take_top()`, `atk_layout_take_bottom()`, etc.) for simple UI composition.

## Performance and flicker avoidance

- Mark dirty rectangles as tightly as possible; avoid full-screen invalidation unless necessary.
- In userland, enable dirty tracking (`atk_user_enable_dirty_tracking(win, true)`) so `atk_user_present()` can skip redundant uploads to the kernel when nothing changed.
- For apps that draw directly into the buffer every frame (games), you can disable dirty tracking and present every frame (or use `atk_user_present_force()`).
- ATK assumes a single UI thread mutates UI state. Avoid modifying widgets concurrently from other threads.

## Debugging hooks

- Window debugging: `atk_window_list_validate()` / `atk_window_list_dump()` (`src/atk/atk_window.h`).
- Optional event tracing helpers: `src/atk/atk_event_debug.h`.
