# Quick Start: Kernel ATK

This describes the typical “video mode” integration for ATK inside the kernel.

## Minimal flow

1. During boot: call `atk_init()` once.
2. When entering video mode: call `atk_enter_mode()` then `atk_render()` and flush/present.
3. For each input event:
   - call `atk_handle_mouse_event()` or `atk_handle_key_char()`
   - if `redraw` is true, call `atk_render()`
   - flush/present the dirty region

The kernel reference integration lives in `src/drivers/video.c`.

## Example skeleton

```c
#include "atk.h"
#include "video.h"

void ui_boot_init(void) {
    atk_init();
}

void ui_enter(void) {
    atk_enter_mode();
    atk_render();
    video_flush_dirty();
}

void ui_on_key(char ch) {
    atk_key_event_result_t r = atk_handle_key_char(ch);
    if (r.redraw) {
        atk_render();
        video_flush_dirty();
    }
    if (r.exit_video) {
        /* exit video mode */
    }
}

void ui_on_mouse(int x, int y, bool pressed_edge, bool released_edge, bool left_pressed) {
    atk_mouse_event_result_t r = atk_handle_mouse_event(x, y, pressed_edge, released_edge, left_pressed);
    if (r.redraw && !atk_drag_active()) {
        atk_render();
    }
    video_flush_dirty();
}
```

## Notes

- `atk_drag_active()` is used by the video driver to coordinate fast window-drag compositing with normal dirty-rect rendering.
- `atk_handle_*` APIs return `exit_video` for the kernel video shell path (userland apps typically ignore it).
