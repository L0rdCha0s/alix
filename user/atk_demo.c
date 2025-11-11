#include "atk_user.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/atk_label.h"
#include "atk/atk_text_input.h"
#include "libc.h"
#include "video.h"

static atk_user_window_t g_session;
static atk_widget_t *g_window = NULL;
static atk_widget_t *g_label = NULL;
static atk_widget_t *g_input = NULL;

static void apply_theme(atk_state_t *state)
{
    state->theme.background = video_make_color(0x20, 0x30, 0x50);
    state->theme.window_border = video_make_color(0x30, 0x30, 0x30);
    state->theme.window_title = video_make_color(0x40, 0x70, 0xC0);
    state->theme.window_title_text = video_make_color(0xFF, 0xFF, 0xFF);
    state->theme.window_body = video_make_color(0xF0, 0xF0, 0xF0);
    state->theme.button_face = video_make_color(0xE0, 0xE0, 0xE0);
    state->theme.button_border = video_make_color(0x40, 0x40, 0x40);
    state->theme.button_text = video_make_color(0x20, 0x20, 0x20);
    state->theme.desktop_icon_face = video_make_color(0x50, 0x90, 0xD0);
    state->theme.desktop_icon_text = state->theme.window_title_text;
}

static void on_input_submit(atk_widget_t *input, void *context)
{
    (void)context;
    if (!input || !g_label)
    {
        return;
    }
    const char *text = atk_text_input_text(input);
    atk_label_set_text(g_label, text);
    atk_text_input_clear(input);
    atk_window_mark_dirty(g_window);
}

static bool init_ui(void)
{
    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);
    apply_theme(state);

    g_window = atk_window_create_at(state, VIDEO_WIDTH / 2, VIDEO_HEIGHT / 2);
    if (!g_window)
    {
        return false;
    }

    atk_window_set_title_text(g_window, "ATK Demo");
    atk_window_set_chrome_visible(g_window, false);
    g_window->x = 0;
    g_window->y = 0;
    g_window->width = VIDEO_WIDTH;
    g_window->height = VIDEO_HEIGHT;

    int content_margin = 16;
    int chrome_top = atk_window_is_chrome_visible(g_window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int label_y = chrome_top + content_margin;
    g_label = atk_window_add_label(g_window,
                                   content_margin,
                                   label_y,
                                   VIDEO_WIDTH - content_margin * 2,
                                   96);
    if (!g_label)
    {
        return false;
    }
    atk_label_set_text(g_label, "Welcome to userland ATK!\nEnter text below.");

    int input_y = label_y + 120;
    g_input = atk_window_add_text_input(g_window,
                                        content_margin,
                                        input_y,
                                        VIDEO_WIDTH - content_margin * 2);
    if (!g_input)
    {
        return false;
    }
    atk_text_input_set_submit_handler(g_input, on_input_submit, NULL);
    atk_text_input_focus(state, g_input);
    return true;
}

static void process_mouse_event(const user_atk_event_t *event)
{
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
        atk_user_present(&g_session);
    }
}

static void process_key_event(const user_atk_event_t *event)
{
    atk_key_event_result_t result = atk_handle_key_char((char)event->data0);
    if (result.redraw)
    {
        atk_render();
        atk_user_present(&g_session);
    }
}

int main(void)
{
    if (!atk_user_window_open(&g_session, "ATK Demo", VIDEO_WIDTH, VIDEO_HEIGHT))
    {
        printf("atk_demo: failed to open window\n");
        return 1;
    }

    if (!init_ui())
    {
        printf("atk_demo: failed to init UI\n");
        atk_user_close(&g_session);
        return 1;
    }

    atk_render();
    atk_user_present(&g_session);

    bool running = true;
    while (running)
    {
        user_atk_event_t event;
        if (!atk_user_wait_event(&g_session, &event))
        {
            continue;
        }

        switch (event.type)
        {
            case USER_ATK_EVENT_MOUSE:
                process_mouse_event(&event);
                break;
            case USER_ATK_EVENT_KEY:
                process_key_event(&event);
                break;
            case USER_ATK_EVENT_CLOSE:
                running = false;
                break;
            default:
                break;
        }
    }

    atk_user_close(&g_session);
    return 0;
}
