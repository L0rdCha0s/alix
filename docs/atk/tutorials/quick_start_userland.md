# Quick Start: Userland ATK (Remote Windows)

Userland ATK apps render into a software backbuffer and present it to a kernel-hosted “remote window”.

See `docs/user_atk.md` for the architecture and syscall model.

## Minimal flow

1. Create a remote window via `atk_user_window_open*()`.
2. Enable dirty tracking (`atk_user_enable_dirty_tracking(win, true)`) if your app primarily redraws via `atk_render()`.
3. Initialize ATK (`atk_init()`), build your UI, and render/present the first frame.
4. Enter the standard loop (`atk_main()`) or write your own loop with `atk_user_wait_event()` / `atk_user_poll_event()`.

## Example skeleton

This follows the pattern used by `user/atk_demo.c`.

```c
#include "atk_user.h"
#include "atk_app.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/atk_label.h"
#include "atk/atk_text_input.h"

static atk_user_window_t g_remote;

static bool build_ui(uint32_t width, uint32_t height) {
    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);

    atk_widget_t *window = atk_window_create_at(state, 0, 0);
    if (!window) return false;

    atk_window_set_chrome_visible(window, false); /* kernel provides chrome */
    window->x = 0;
    window->y = 0;
    window->width = (int)width;
    window->height = (int)height;

    atk_widget_t *label = atk_window_add_label(window, 16, 16, (int)width - 32, 96);
    atk_label_set_text(label, "Hello from userland ATK!");
    return true;
}

int main(void) {
    if (!atk_user_window_open(&g_remote, "My App", 800, 600)) return 1;
    atk_user_enable_dirty_tracking(&g_remote, true);

    if (!build_ui(g_remote.width, g_remote.height)) return 1;

    atk_render();
    atk_user_present_force(&g_remote);

    atk_main_config_t cfg = {
        .window = &g_remote,
        .present_on_idle = false,
        .legacy_input = false,
    };
    atk_main(&cfg);

    atk_user_close(&g_remote);
    return 0;
}
```

## Resizing

`atk_user_poll_event()` / `atk_user_wait_event()` transparently handle `USER_ATK_EVENT_RESIZE` by reallocating `atk_user_window_t.buffer` and reattaching the video surface. Apps should still update widget geometry/layout in response to resize events; `atk_main_register_resize_handler()` is the easiest place to do this.
