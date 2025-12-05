#include "atk_user.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk_menu_bar.h"
#include "atk/layout.h"
#include "atk_button.h"
#include "atk/atk_label.h"
#include "atk/atk_rich_text.h"
#include <stdio.h>
#include "libc.h"
#include "video.h"
#include "user_atk_defs.h"

#define RICH_APP_WIDTH  1000
#define RICH_APP_HEIGHT 720
#define RICH_APP_MARGIN 14
#define RICH_TOOLBAR_HEIGHT 42
#define RICH_FONT_BUTTONS 5

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *label;
    atk_widget_t *editor;
    atk_widget_t *font_buttons[RICH_FONT_BUTTONS];
    int font_sizes[RICH_FONT_BUTTONS];
    int current_font;
    bool running;
} rich_app_t;

static void apply_theme(atk_state_t *state);
static bool build_ui(rich_app_t *app);
static void relayout(rich_app_t *app);
static void update_font_buttons(rich_app_t *app);
static void populate_sample(rich_app_t *app);
static void on_font_button(atk_widget_t *button, void *context);
static void process_mouse(rich_app_t *app, const user_atk_event_t *event);
static void process_key(rich_app_t *app, const user_atk_event_t *event);
static bool handle_resize(rich_app_t *app, uint32_t width, uint32_t height);

static void apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme.background = video_make_color(0x12, 0x16, 0x1F);
    state->theme.window_border = video_make_color(0x2F, 0x38, 0x46);
    state->theme.window_title = video_make_color(0x28, 0x6A, 0xA8);
    state->theme.window_title_text = video_make_color(0xF3, 0xF5, 0xF7);
    state->theme.window_body = video_make_color(0x1B, 0x22, 0x2F);
    state->theme.button_face = video_make_color(0x28, 0x36, 0x48);
    state->theme.button_border = video_make_color(0x14, 0x1B, 0x26);
    state->theme.button_text = video_make_color(0xE4, 0xE9, 0xEF);
    state->theme.desktop_icon_face = video_make_color(0x3A, 0x78, 0xB0);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    state->theme.menu_bar_face = video_make_color(0x18, 0x22, 0x2E);
    state->theme.menu_bar_text = state->theme.button_text;
    state->theme.menu_bar_highlight = video_make_color(0x2D, 0x4D, 0x73);
    state->theme.menu_dropdown_face = video_make_color(0xF7, 0xF7, 0xF7);
    state->theme.menu_dropdown_border = video_make_color(0x38, 0x3D, 0x45);
    state->theme.menu_dropdown_text = video_make_color(0x20, 0x22, 0x24);
    state->theme.menu_dropdown_highlight = video_make_color(0x2F, 0x54, 0x83);
    atk_state_theme_commit(state);
}

static bool build_ui(rich_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);
    apply_theme(state);

    app->window = atk_window_create_at(state, RICH_APP_WIDTH / 2, RICH_APP_HEIGHT / 2);
    if (!app->window)
    {
        return false;
    }

    atk_window_set_chrome_visible(app->window, false);
    atk_window_set_title_text(app->window, "ATK Rich Text");
    app->window->x = 0;
    app->window->y = 0;
    app->window->width = RICH_APP_WIDTH;
    app->window->height = RICH_APP_HEIGHT;
    atk_window_ensure_inside(app->window);

    atk_layout_t layout;
    int chrome_top = (atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0) + RICH_APP_MARGIN;
    atk_layout_init(&layout,
                    RICH_APP_MARGIN,
                    chrome_top,
                    app->window->width - RICH_APP_MARGIN * 2,
                    app->window->height - chrome_top - RICH_APP_MARGIN);
    atk_layout_region_t toolbar = atk_layout_take_top(&layout, RICH_TOOLBAR_HEIGHT, 10);
    atk_layout_region_t editor_region = atk_layout_content(&layout);

    app->label = atk_window_add_label(app->window,
                                      toolbar.x,
                                      toolbar.y,
                                      140,
                                      RICH_TOOLBAR_HEIGHT - 4);
    if (!app->label)
    {
        return false;
    }
    atk_label_set_text(app->label, "Font size:");

    int btn_y = toolbar.y;
    int btn_x = toolbar.x + 150;
    int btn_w = 72;
    int btn_h = RICH_TOOLBAR_HEIGHT - 6;

    int sizes[RICH_FONT_BUTTONS] = { 14, 16, 20, 24, 32 };
    for (int i = 0; i < RICH_FONT_BUTTONS; ++i)
    {
        app->font_sizes[i] = sizes[i];
        char title[16];
        snprintf(title, sizeof(title), "%d px", sizes[i]);
        atk_widget_t *btn = atk_window_add_button(app->window,
                                                  title,
                                                  btn_x,
                                                  btn_y,
                                                  btn_w,
                                                  btn_h,
                                                  ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                  false,
                                                  on_font_button,
                                                  app);
        if (!btn)
        {
            return false;
        }
        atk_widget_set_layout(btn, ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT);
        app->font_buttons[i] = btn;
        btn_x += btn_w + 8;
    }

    app->editor = atk_window_add_rich_text(app->window,
                                           editor_region.x,
                                           editor_region.y,
                                           editor_region.width,
                                           editor_region.height);
    if (!app->editor)
    {
        return false;
    }
    atk_widget_set_layout(app->editor,
                          ATK_WIDGET_ANCHOR_LEFT | ATK_WIDGET_ANCHOR_RIGHT |
                          ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_BOTTOM);

    app->current_font = 20;
    atk_rich_text_set_font_size(app->editor, app->current_font);
    populate_sample(app);
    atk_rich_text_focus(state, app->editor);
    update_font_buttons(app);
    atk_window_mark_dirty(app->window);
    return true;
}

static void relayout(rich_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }
    atk_layout_t layout;
    int chrome_top = (atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0) + RICH_APP_MARGIN;
    atk_layout_init(&layout,
                    RICH_APP_MARGIN,
                    chrome_top,
                    app->window->width - RICH_APP_MARGIN * 2,
                    app->window->height - chrome_top - RICH_APP_MARGIN);
    atk_layout_region_t toolbar = atk_layout_take_top(&layout, RICH_TOOLBAR_HEIGHT, 10);
    atk_layout_region_t editor_region = atk_layout_content(&layout);

    if (app->label)
    {
        app->label->x = toolbar.x;
        app->label->y = toolbar.y;
        app->label->width = 140;
        app->label->height = RICH_TOOLBAR_HEIGHT - 4;
    }

    int btn_y = toolbar.y;
    int btn_x = toolbar.x + 150;
    int btn_w = 72;
    int btn_h = RICH_TOOLBAR_HEIGHT - 6;
    for (int i = 0; i < RICH_FONT_BUTTONS; ++i)
    {
        atk_widget_t *btn = app->font_buttons[i];
        if (btn)
        {
            btn->x = btn_x;
            btn->y = btn_y;
            btn->width = btn_w;
            btn->height = btn_h;
        }
        btn_x += btn_w + 8;
    }

    if (app->editor)
    {
        app->editor->x = editor_region.x;
        app->editor->y = editor_region.y;
        app->editor->width = editor_region.width;
        app->editor->height = editor_region.height;
    }
}

static void update_font_buttons(rich_app_t *app)
{
    if (!app)
    {
        return;
    }
    for (int i = 0; i < RICH_FONT_BUTTONS; ++i)
    {
        atk_widget_t *btn = app->font_buttons[i];
        if (!btn)
        {
            continue;
        }
        char title[16];
        if (app->font_sizes[i] == app->current_font)
        {
            snprintf(title, sizeof(title), "[%d px]", app->font_sizes[i]);
        }
        else
        {
            snprintf(title, sizeof(title), "%d px", app->font_sizes[i]);
        }
        atk_button_configure(btn,
                             title,
                             ATK_BUTTON_STYLE_TITLE_INSIDE,
                             false,
                             false,
                             on_font_button,
                             app);
    }
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void populate_sample(rich_app_t *app)
{
    if (!app || !app->editor)
    {
        return;
    }
    atk_rich_text_set_text(app->editor, "");

    atk_rich_text_set_font_size(app->editor, 26);
    atk_rich_text_append(app->editor, "Rich Text Editor\n");
    atk_rich_text_set_font_size(app->editor, 18);
    atk_rich_text_append(app->editor, "Use the toolbar to change the font size. ");
    atk_rich_text_append(app->editor, "This demo sticks to Public Sans.\n\n");

    atk_rich_text_set_font_size(app->editor, 14);
    atk_rich_text_append(app->editor,
                         "Click anywhere to move the caret and start typing. "
                         "Backspace and newline are supported, and the view will scroll as needed.\n\n");

    atk_rich_text_set_font_size(app->editor, app->current_font);
}

static void on_font_button(atk_widget_t *button, void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app || !button)
    {
        return;
    }

    for (int i = 0; i < RICH_FONT_BUTTONS; ++i)
    {
        if (app->font_buttons[i] == button)
        {
            app->current_font = app->font_sizes[i];
            atk_rich_text_apply_font_size(app->editor, app->current_font);
            atk_rich_text_focus(atk_state_get(), app->editor);
            update_font_buttons(app);
            atk_window_mark_dirty(app->window);
            return;
        }
    }
}

static void process_mouse(rich_app_t *app, const user_atk_event_t *event)
{
    if (!app || !event)
    {
        return;
    }
    bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
    bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
    bool release = (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0;
    atk_mouse_event_result_t result = atk_handle_mouse_event(event->x,
                                                             event->y,
                                                             press,
                                                             release,
                                                             left);
    if (result.redraw)
    {
        atk_render();
        atk_user_present(&app->remote);
    }
}

static void process_key(rich_app_t *app, const user_atk_event_t *event)
{
    if (!app || !event)
    {
        return;
    }
    atk_key_event_result_t result = atk_handle_key_char((char)event->data0);
    if (result.redraw)
    {
        atk_render();
        atk_user_present(&app->remote);
    }
}

static bool handle_resize(rich_app_t *app, uint32_t width, uint32_t height)
{
    if (!app || !app->window || width == 0 || height == 0)
    {
        return false;
    }
    app->window->width = (int)width;
    app->window->height = (int)height;
    relayout(app);
    atk_window_request_layout(app->window);
    atk_window_mark_dirty(app->window);
    atk_render();
    atk_user_present(&app->remote);
    return true;
}

int main(void)
{
    rich_app_t app;
    memset(&app, 0, sizeof(app));

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "ATK Rich Text",
                                         RICH_APP_WIDTH,
                                         RICH_APP_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("richtext: failed to open window\n");
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!build_ui(&app))
    {
        printf("richtext: failed to init UI\n");
        atk_user_close(&app.remote);
        return 1;
    }

    atk_render();
    atk_user_present(&app.remote);

    app.running = true;
    while (app.running)
    {
        user_atk_event_t event;
        if (!atk_user_wait_event(&app.remote, &event))
        {
            continue;
        }
        switch (event.type)
        {
            case USER_ATK_EVENT_MOUSE:
                process_mouse(&app, &event);
                break;
            case USER_ATK_EVENT_KEY:
                process_key(&app, &event);
                break;
            case USER_ATK_EVENT_RESIZE:
                handle_resize(&app, (uint32_t)event.data0, (uint32_t)event.data1);
                break;
            case USER_ATK_EVENT_CLOSE:
                app.running = false;
                break;
            default:
                break;
        }
    }

    atk_user_close(&app.remote);
    return 0;
}
