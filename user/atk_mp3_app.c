#include "atk_user.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_label.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_text_input.h"
#include <stdio.h>
#include "libc.h"
#include "usyscall.h"
#include "user_atk_defs.h"
#include "video.h"

#define MP3_UI_WIDTH  720
#define MP3_UI_HEIGHT 360
#define MP3_MARGIN    14
#define MP3_ROW_SPACING 10
#define MP3_TITLE_HEIGHT (ATK_FONT_HEIGHT * 2)
#define MP3_BUTTON_HEIGHT (ATK_FONT_HEIGHT + 10)

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *title_label;
    atk_widget_t *status_label;
    atk_widget_t *file_label;
    atk_widget_t *file_input;
    atk_widget_t *open_button;
    atk_widget_t *rew_button;
    atk_widget_t *play_button;
    atk_widget_t *fwd_button;
    atk_widget_t *scrubber;
    bool running;
} mp3_ui_t;

static void apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme.background = video_make_color(0x11, 0x16, 0x1E);
    state->theme.window_border = video_make_color(0x2C, 0x35, 0x42);
    state->theme.window_title = video_make_color(0x28, 0x6A, 0xA8);
    state->theme.window_title_text = video_make_color(0xF5, 0xF7, 0xFA);
    state->theme.window_body = video_make_color(0x0C, 0x11, 0x17);
    state->theme.button_face = video_make_color(0x24, 0x34, 0x48);
    state->theme.button_border = video_make_color(0x12, 0x1A, 0x24);
    state->theme.button_text = video_make_color(0xEE, 0xEE, 0xEE);
    state->theme.desktop_icon_face = video_make_color(0x3A, 0x63, 0x95);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    state->theme.menu_bar_face = video_make_color(0x16, 0x1F, 0x29);
    state->theme.menu_bar_text = state->theme.button_text;
    state->theme.menu_bar_highlight = video_make_color(0x2F, 0x53, 0x83);
    state->theme.menu_dropdown_face = video_make_color(0xF7, 0xF7, 0xF7);
    state->theme.menu_dropdown_border = video_make_color(0x3A, 0x3F, 0x48);
    state->theme.menu_dropdown_text = video_make_color(0x1E, 0x21, 0x24);
    state->theme.menu_dropdown_highlight = video_make_color(0x2F, 0x54, 0x83);
    atk_state_theme_commit(state);
}

static void on_scrollbar_change(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    mp3_ui_t *ui = (mp3_ui_t *)context;
    if (!ui || !ui->status_label)
    {
        return;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "Scrub: %d", value);
    atk_label_set_text(ui->status_label, buf);
    atk_window_mark_dirty(ui->window);
}

static void on_placeholder_button(atk_widget_t *button, void *context)
{
    (void)button;
    mp3_ui_t *ui = (mp3_ui_t *)context;
    if (!ui || !ui->status_label)
    {
        return;
    }
    atk_label_set_text(ui->status_label, "TODO: implement playback");
    atk_window_mark_dirty(ui->window);
}

static void on_open_click(atk_widget_t *button, void *context)
{
    (void)button;
    mp3_ui_t *ui = (mp3_ui_t *)context;
    if (!ui || !ui->status_label)
    {
        return;
    }
    atk_label_set_text(ui->status_label, "Open: (file dialog placeholder)");
    atk_window_mark_dirty(ui->window);
}

static void build_ui(mp3_ui_t *ui)
{
    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);
    apply_theme(state);

    ui->window = atk_window_create_at(state, MP3_UI_WIDTH / 2, MP3_UI_HEIGHT / 2);
    if (!ui->window)
    {
        return;
    }
    ui->window->width = MP3_UI_WIDTH;
    ui->window->height = MP3_UI_HEIGHT;
    atk_window_set_title_text(ui->window, "ATK MP3 (UI Prototype)");

    int chrome_top = atk_window_is_chrome_visible(ui->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int x = MP3_MARGIN;
    int y = chrome_top + MP3_MARGIN;
    int content_w = ui->window->width - MP3_MARGIN * 2;

    ui->title_label = atk_window_add_label(ui->window, x, y, content_w, MP3_TITLE_HEIGHT);
    if (ui->title_label)
    {
        atk_label_set_text(ui->title_label, "No track loaded");
    }
    y += MP3_TITLE_HEIGHT + MP3_ROW_SPACING;

    ui->status_label = atk_window_add_label(ui->window, x, y, content_w, ATK_FONT_HEIGHT * 2);
    if (ui->status_label)
    {
        atk_label_set_text(ui->status_label, "Status: idle");
    }
    y += ATK_FONT_HEIGHT * 2 + MP3_ROW_SPACING;

    int input_h = ATK_FONT_HEIGHT + 8;
    ui->file_label = atk_window_add_label(ui->window, x, y, 48, input_h);
    if (ui->file_label)
    {
        atk_label_set_text(ui->file_label, "File:");
    }

    int button_w = 96;
    int input_x = x + 54;
    int input_w = content_w - (input_x - x) - button_w - MP3_ROW_SPACING;
    ui->file_input = atk_window_add_text_input(ui->window, input_x, y, input_w);
    ui->open_button = atk_window_add_button(ui->window,
                                            "Open...",
                                            input_x + input_w + MP3_ROW_SPACING,
                                            y,
                                            button_w,
                                            input_h,
                                            ATK_BUTTON_STYLE_TITLE_INSIDE,
                                            false,
                                            on_open_click,
                                            ui);
    y += input_h + MP3_ROW_SPACING;

    int control_h = MP3_BUTTON_HEIGHT;
    int btn_spacing = 10;
    ui->rew_button = atk_window_add_button(ui->window,
                                           "<<",
                                           x,
                                           y,
                                           60,
                                           control_h,
                                           ATK_BUTTON_STYLE_TITLE_INSIDE,
                                           false,
                                           on_placeholder_button,
                                           ui);
    ui->play_button = atk_window_add_button(ui->window,
                                            "Play/Pause",
                                            x + 60 + btn_spacing,
                                            y,
                                            110,
                                            control_h,
                                            ATK_BUTTON_STYLE_TITLE_INSIDE,
                                            false,
                                            on_placeholder_button,
                                            ui);
    ui->fwd_button = atk_window_add_button(ui->window,
                                           ">>",
                                           x + 60 + btn_spacing + 110 + btn_spacing,
                                           y,
                                           60,
                                           control_h,
                                           ATK_BUTTON_STYLE_TITLE_INSIDE,
                                           false,
                                           on_placeholder_button,
                                           ui);
    y += control_h + MP3_ROW_SPACING;

    ui->scrubber = atk_window_add_scrollbar(ui->window,
                                            x,
                                            y,
                                            content_w,
                                            28,
                                            ATK_SCROLLBAR_HORIZONTAL);
    if (ui->scrubber)
    {
        atk_scrollbar_set_range(ui->scrubber, 0, 100, 10);
        atk_scrollbar_set_value(ui->scrubber, 0);
        atk_scrollbar_set_change_handler(ui->scrubber, on_scrollbar_change, ui);
    }

    atk_window_mark_dirty(ui->window);
}

static bool dispatch_event(mp3_ui_t *ui, const user_atk_event_t *event)
{
    if (!ui || !event)
    {
        return false;
    }
    switch (event->type)
    {
        case USER_ATK_EVENT_MOUSE:
        {
            bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
            bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
            bool release = (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0;
            atk_mouse_event_result_t res = atk_handle_mouse_event(event->x, event->y, press, release, left);
            return res.redraw;
        }
        case USER_ATK_EVENT_KEY:
        {
            atk_key_event_result_t res = atk_handle_key_char((char)event->data0);
            return res.redraw;
        }
        case USER_ATK_EVENT_RESIZE:
        {
            if (ui->window)
            {
                ui->window->width = (int)event->data0;
                ui->window->height = (int)event->data1;
                atk_window_request_layout(ui->window);
                atk_window_mark_dirty(ui->window);
            }
            return true;
        }
        case USER_ATK_EVENT_CLOSE:
            ui->running = false;
            return false;
        default:
            break;
    }
    return false;
}

int main(void)
{
    mp3_ui_t ui;
    memset(&ui, 0, sizeof(ui));
    ui.running = true;

    if (!atk_user_window_open_with_flags(&ui.remote,
                                         "ATK MP3",
                                         MP3_UI_WIDTH,
                                         MP3_UI_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("atk_mp3_ui: failed to open window\n");
        return 1;
    }
    atk_user_enable_dirty_tracking(&ui.remote, true);

    build_ui(&ui);
    if (!ui.window)
    {
        printf("atk_mp3_ui: failed to build UI\n");
        atk_user_close(&ui.remote);
        return 1;
    }

    atk_render();
    atk_user_present_force(&ui.remote);

    while (ui.running)
    {
        bool redraw = false;
        bool had_event = false;
        user_atk_event_t ev;
        while (atk_user_poll_event(&ui.remote, &ev))
        {
            had_event = true;
            redraw |= dispatch_event(&ui, &ev);
        }
        if (redraw)
        {
            atk_render();
            atk_user_present(&ui.remote);
        }
        else if (!had_event)
        {
            sys_yield();
        }
    }

    atk_user_close(&ui.remote);
    return 0;
}
