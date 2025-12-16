#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_iconbox.h"
#include "atk/atk_nav_stack.h"
#include "atk/atk_font.h"
#include "atk_menu_bar.h"
#include "libc.h"
#include "serial.h"
#include "video.h"
#include "usyscall.h"
#include "user_atk_defs.h"

#define CP_WINDOW_WIDTH  820
#define CP_WINDOW_HEIGHT 520

typedef struct control_panel_app control_panel_app_t;

typedef struct
{
    control_panel_app_t *app;
    const char *title;
} cp_icon_ctx_t;

struct control_panel_app
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *nav;
    atk_widget_t *iconbox;
    cp_icon_ctx_t hw_ctx;
    cp_icon_ctx_t net_ctx;
    bool running;
};

typedef struct
{
    char title[64];
} cp_pane_priv_t;

static void cp_pane_draw(const atk_state_t *state, const atk_widget_t *widget, int origin_x, int origin_y, void *context);
static bool cp_pane_hit(const atk_widget_t *widget,
                        int origin_x,
                        int origin_y,
                        int px,
                        int py,
                        void *context);

static const atk_class_t CP_PANE_CLASS = { "CPPane", &ATK_WIDGET_CLASS, NULL, sizeof(cp_pane_priv_t) };

static const atk_widget_ops_t g_cp_pane_ops = {
    .destroy = NULL,
    .draw = cp_pane_draw,
    .hit_test = cp_pane_hit,
    .on_mouse = NULL,
    .on_key = NULL
};

static atk_widget_t *cp_create_pane(const char *title)
{
    atk_widget_t *pane = atk_widget_create(&CP_PANE_CLASS);
    if (!pane)
    {
        return NULL;
    }
    pane->used = true;
    pane->x = 0;
    pane->y = 0;
    pane->width = 0;
    pane->height = 0;
    atk_widget_set_ops(pane, &g_cp_pane_ops, NULL);

    cp_pane_priv_t *priv = (cp_pane_priv_t *)atk_widget_priv(pane, &CP_PANE_CLASS);
    if (priv && title)
    {
        size_t len = strlen(title);
        if (len >= sizeof(priv->title))
        {
            len = sizeof(priv->title) - 1;
        }
        memcpy(priv->title, title, len);
        priv->title[len] = '\0';
    }
    else if (priv)
    {
        priv->title[0] = '\0';
    }
    return pane;
}

static void cp_pane_draw(const atk_state_t *state, const atk_widget_t *widget, int origin_x, int origin_y, void *context)
{
    (void)context;
    if (!state || !widget || !widget->used)
    {
        return;
    }
    const atk_theme_t *theme = &state->theme;
    int x = origin_x + widget->x;
    int y = origin_y + widget->y;
    video_draw_rect(x, y, widget->width, widget->height, theme->window_body);
    cp_pane_priv_t *priv = (cp_pane_priv_t *)atk_widget_priv(widget, &CP_PANE_CLASS);
    const char *title = (priv && priv->title[0]) ? priv->title : "Details";
    int text_w = atk_font_text_width(title);
    int text_x = x + (widget->width - text_w) / 2;
    int baseline = atk_font_baseline_for_rect(y, widget->height);
    atk_font_draw_string(text_x, baseline, title, theme->window_title, theme->window_body);
}

static bool cp_pane_hit(const atk_widget_t *widget,
                        int origin_x,
                        int origin_y,
                        int px,
                        int py,
                        void *context)
{
    (void)context;
    if (!widget || !widget->used)
    {
        return false;
    }
    int x0 = origin_x + widget->x;
    int y0 = origin_y + widget->y;
    int x1 = x0 + widget->width;
    int y1 = y0 + widget->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

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
    atk_user_present_force(&app->remote);
}

static void cp_layout(control_panel_app_t *app)
{
    if (!app || !app->window || !app->nav)
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

    app->nav->x = content.x;
    app->nav->y = content.y;
    app->nav->width = content.width;
    app->nav->height = content.height;
    atk_nav_stack_relayout(app->nav);
}

static void cp_icon_action(atk_widget_t *button, void *context)
{
    (void)button;
    cp_icon_ctx_t *ctx = (cp_icon_ctx_t *)context;
    if (!ctx || !ctx->app || !ctx->app->nav)
    {
        return;
    }
    const char *label = ctx->title ? ctx->title : "Details";
    atk_widget_t *pane = cp_create_pane(label);
    if (!pane)
    {
        return;
    }
    atk_nav_stack_push(ctx->app->nav, pane, label);
    atk_window_mark_dirty(ctx->app->window);
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

    atk_widget_t *nav = atk_window_add_nav_stack(window,
                                                 0,
                                                 ATK_WINDOW_TITLE_HEIGHT,
                                                 window->width,
                                                 window->height - ATK_WINDOW_TITLE_HEIGHT);
    if (!nav)
    {
        atk_window_close(state, window);
        return false;
    }

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
    atk_nav_stack_push_owned(nav, iconbox, "Home", false);

    app->hw_ctx.app = app;
    app->hw_ctx.title = "Hardware Info";
    app->net_ctx.app = app;
    app->net_ctx.title = "Network Info";

    if (!atk_iconbox_add_icon(iconbox, "Hardware Info", cp_icon_action, &app->hw_ctx) ||
        !atk_iconbox_add_icon(iconbox, "Network Info", cp_icon_action, &app->net_ctx))
    {
        atk_window_close(state, window);
        return false;
    }

    app->nav = nav;
    app->window = window;
    app->iconbox = iconbox;
    cp_layout(app);
    atk_window_mark_dirty(window);
    return true;
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

static bool cp_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    cp_handle_resize((control_panel_app_t *)context, width, height);
    return true;
}

static void cp_on_close_event(void *context)
{
    control_panel_app_t *app = (control_panel_app_t *)context;
    if (app)
    {
        app->running = false;
    }
    atk_main_request_exit();
}

static bool cp_on_tick(void *context)
{
    control_panel_app_t *app = (control_panel_app_t *)context;
    if (!app)
    {
        return false;
    }
    bool sliding = app->nav && atk_nav_stack_sliding(app->nav);
    if (sliding && app->window)
    {
        atk_window_mark_dirty(app->window);
    }
    return sliding;
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

    atk_main_config_t main_cfg = {
        .window = &app.remote,
        .tick = cp_on_tick,
        .tick_context = &app,
        .present_on_idle = false,
        .legacy_input = false
    };

    atk_main_register_resize_handler(cp_on_resize_event, &app);
    atk_main_register_close_handler(cp_on_close_event, &app);

    atk_main(&main_cfg);

    atk_user_close(&app.remote);
    return 0;
}
