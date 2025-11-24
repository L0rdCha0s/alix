#include "atk_user.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_iconbox.h"
#include "atk_menu_bar.h"
#include "libc.h"
#include "serial.h"
#include "video.h"
#include "usyscall.h"
#include "user_atk_defs.h"

#define CP_WINDOW_WIDTH  820
#define CP_WINDOW_HEIGHT 520

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *iconbox;
    bool running;
} control_panel_app_t;

static void cp_log(const char *msg)
{
    if (msg)
    {
        serial_printf("%s", msg);
    }
}

static void cp_apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    state->theme.background = video_make_color(0x25, 0x2E, 0x38);
    state->theme.window_border = video_make_color(0x1A, 0x1F, 0x26);
    state->theme.window_title = video_make_color(0x35, 0x55, 0x86);
    state->theme.window_title_text = video_make_color(0xF3, 0xF6, 0xFA);
    state->theme.window_body = video_make_color(0xD8, 0xDB, 0xE0);
    state->theme.button_face = video_make_color(0x4A, 0x6B, 0x9A);
    state->theme.button_border = video_make_color(0x21, 0x2B, 0x38);
    state->theme.button_text = video_make_color(0xF5, 0xF7, 0xFB);
    state->theme.desktop_icon_face = video_make_color(0x56, 0x79, 0xA8);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    state->theme.menu_bar_face = video_make_color(0x1F, 0x27, 0x33);
    state->theme.menu_bar_text = video_make_color(0xEC, 0xEF, 0xF1);
    state->theme.menu_bar_highlight = video_make_color(0x2F, 0x3C, 0x4F);
    state->theme.menu_dropdown_face = video_make_color(0xF2, 0xF4, 0xF7);
    state->theme.menu_dropdown_border = video_make_color(0x2B, 0x31, 0x3B);
    state->theme.menu_dropdown_text = video_make_color(0x18, 0x1E, 0x26);
    state->theme.menu_dropdown_highlight = video_make_color(0x3C, 0x52, 0x75);
    atk_state_theme_commit(state);
}

static void cp_render(control_panel_app_t *app)
{
    if (!app)
    {
        return;
    }
    atk_render();
    atk_user_present(&app->remote);
}

static void cp_layout(control_panel_app_t *app)
{
    if (!app || !app->window || !app->iconbox)
    {
        return;
    }

    int chrome_top = atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    atk_layout_t layout;
    atk_layout_init(&layout,
                    0,
                    chrome_top,
                    app->window->width,
                    app->window->height - chrome_top);
    atk_layout_set_padding(&layout, 18, 18, 18, 18);
    atk_layout_region_t content = atk_layout_content(&layout);

    app->iconbox->x = content.x;
    app->iconbox->y = content.y;
    app->iconbox->width = content.width;
    app->iconbox->height = content.height;
    atk_iconbox_relayout(app->iconbox);
}

static void cp_icon_action(atk_widget_t *button, void *context)
{
    (void)button;
    const char *label = (const char *)context;
    cp_log(label ? label : "icon");
}

static bool cp_init_ui(control_panel_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_init();
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return false;
    }

    atk_menu_bar_set_enabled(state, false);
    cp_apply_theme(state);

    atk_widget_t *window = atk_window_create_at(state, CP_WINDOW_WIDTH / 2, CP_WINDOW_HEIGHT / 2);
    if (!window)
    {
        return false;
    }

    atk_window_set_chrome_visible(window, false);
    window->x = 0;
    window->y = 0;
    window->width = CP_WINDOW_WIDTH;
    window->height = CP_WINDOW_HEIGHT;
    atk_window_set_title_text(window, "Control Panel");
    atk_window_ensure_inside(window);

    atk_widget_t *iconbox = atk_window_add_iconbox(window,
                                                   0,
                                                   ATK_WINDOW_TITLE_HEIGHT,
                                                   window->width,
                                                   window->height - ATK_WINDOW_TITLE_HEIGHT);
    if (!iconbox)
    {
        atk_window_close(state, window);
        return false;
    }
    atk_widget_set_layout(iconbox,
                          ATK_WIDGET_ANCHOR_LEFT |
                          ATK_WIDGET_ANCHOR_TOP |
                          ATK_WIDGET_ANCHOR_RIGHT |
                          ATK_WIDGET_ANCHOR_BOTTOM);

    if (!atk_iconbox_add_icon(iconbox, "Hardware Info", cp_icon_action, "Hardware Info") ||
        !atk_iconbox_add_icon(iconbox, "Network Info", cp_icon_action, "Network Info"))
    {
        atk_window_close(state, window);
        return false;
    }

    app->window = window;
    app->iconbox = iconbox;
    cp_layout(app);
    atk_window_mark_dirty(window);
    return true;
}

static void cp_handle_mouse(const user_atk_event_t *event, bool *needs_render)
{
    if (!event || !needs_render)
    {
        return;
    }
    atk_mouse_event_result_t result = atk_handle_mouse_event(event->x,
                                                             event->y,
                                                             (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0,
                                                             (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0,
                                                             (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0);
    if (result.redraw)
    {
        *needs_render = true;
    }
}

static void cp_handle_key(const user_atk_event_t *event, bool *needs_render)
{
    if (!event || !needs_render)
    {
        return;
    }
    atk_key_event_result_t result = atk_handle_key_char((char)event->data0);
    if (result.redraw)
    {
        *needs_render = true;
    }
}

static void cp_handle_resize(control_panel_app_t *app, uint32_t width, uint32_t height)
{
    if (!app || !app->window)
    {
        return;
    }

    app->window->width = (int)width;
    app->window->height = (int)height;
    atk_window_request_layout(app->window);
    cp_layout(app);
}

int main(void)
{
    control_panel_app_t app;
    memset(&app, 0, sizeof(app));
    app.running = true;

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "Control Panel",
                                         CP_WINDOW_WIDTH,
                                         CP_WINDOW_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        cp_log("[cp] failed to open remote window");
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!cp_init_ui(&app))
    {
        cp_log("[cp] ui init failed");
        atk_user_close(&app.remote);
        return 1;
    }

    cp_render(&app);

    while (app.running)
    {
        bool needs_render = false;
        user_atk_event_t event;
        while (atk_user_poll_event(&app.remote, &event))
        {
            switch (event.type)
            {
                case USER_ATK_EVENT_MOUSE:
                    cp_handle_mouse(&event, &needs_render);
                    break;
                case USER_ATK_EVENT_KEY:
                    cp_handle_key(&event, &needs_render);
                    break;
                case USER_ATK_EVENT_CLOSE:
                    app.running = false;
                    break;
                case USER_ATK_EVENT_RESIZE:
                    cp_handle_resize(&app, (uint32_t)event.data0, (uint32_t)event.data1);
                    needs_render = true;
                    break;
                default:
                    break;
            }
        }

        if (!app.running)
        {
            break;
        }

        if (needs_render)
        {
            cp_render(&app);
        }

        sys_yield();
    }

    atk_user_close(&app.remote);
    return 0;
}
