# Core ATK API

Header: `include/atk.h`

ATK’s core entry points are intentionally small: you feed input in, ATK mutates state, and you render/present when needed.

## Key functions

- `atk_init()` – initialize ATK global state (call once during boot/process init).
- `atk_enter_mode()` – reset per-session UI state and mark the whole scene dirty (kernel “video mode” use).
- `atk_render()` – repaint the current dirty region into the backbuffer.
- `atk_handle_mouse_event(x, y, pressed_edge, released_edge, left_pressed)` – route a mouse event through window chrome and widgets; returns `atk_mouse_event_result_t`.
- `atk_handle_key_char(ch)` – route a typed character to the focused widget; returns `atk_key_event_result_t`.
- `atk_drag_active()` – true while the window manager is dragging a window (used by kernel video driver to coordinate compositing).

## Return structs

- `atk_mouse_event_result_t` / `atk_key_event_result_t`:
  - `redraw`: ATK changed visual state; call `atk_render()` and then present/flush.
  - `exit_video`: kernel video shell exit request (ignored by most userland apps).
