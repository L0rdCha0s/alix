#include "atk.h"

#include <stddef.h>

#include "video.h"

#include "atk_desktop.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk/atk_text_input.h"
#include "atk/atk_shell.h"

static void atk_apply_default_theme(atk_state_t *state);
static void action_exit_to_text(atk_widget_t *button, void *context);
static void action_open_shell(atk_widget_t *button, void *context);

void atk_init(void)
{
    atk_state_t *state = atk_state_get();
    atk_window_reset_all(state);
    atk_desktop_reset(state);
    state->exit_requested = false;
}

void atk_enter_mode(void)
{
    atk_state_t *state = atk_state_get();

    atk_apply_default_theme(state);

    atk_window_reset_all(state);
    atk_desktop_reset(state);

    atk_desktop_add_button(state,
                           40,
                           40,
                           88,
                           88,
                           "Exit",
                           ATK_BUTTON_STYLE_TITLE_BELOW,
                           true,
                           action_exit_to_text,
                           state);

    atk_desktop_add_button(state,
                           140,
                           40,
                           88,
                           88,
                           "Shell",
                           ATK_BUTTON_STYLE_TITLE_BELOW,
                           true,
                           action_open_shell,
                           state);
}

void atk_render(void)
{
    atk_state_t *state = atk_state_get();

    video_invalidate_all();
    video_fill(state->theme.background);
    atk_desktop_draw_buttons(state);
    atk_window_draw_all(state);
}

atk_mouse_event_result_t atk_handle_mouse_event(int cursor_x,
                                                int cursor_y,
                                                bool pressed_edge,
                                                bool released_edge,
                                                bool left_pressed)
{
    atk_state_t *state = atk_state_get();
    atk_mouse_event_result_t result = { .redraw = false, .exit_video = false };

    if (pressed_edge)
    {
        state->dragging_window = NULL;
        state->dragging_desktop_button = NULL;
        state->desktop_drag_moved = false;
        state->pressed_window_button_window = NULL;
        state->pressed_window_button = NULL;
        state->pressed_desktop_button = NULL;

        bool handled = false;

        ATK_LIST_FOR_EACH_REVERSE(win_node, &state->windows)
        {
            if (handled)
            {
                break;
            }

            atk_widget_t *win = (atk_widget_t *)win_node->value;
            if (!win || !win->used)
            {
                continue;
            }

            atk_widget_t *btn = atk_window_get_button_at(win, cursor_x, cursor_y);
            if (btn)
            {
                atk_widget_t *prev_top = state->windows.tail ? (atk_widget_t *)state->windows.tail->value : NULL;
                bool moved = atk_window_bring_to_front(state, win);
                if (moved)
                {
                    atk_window_mark_dirty(win);
                    if (prev_top && prev_top != win)
                    {
                        atk_window_mark_dirty(prev_top);
                    }
                    result.redraw = true;
                }
                state->pressed_window_button_window = win;
                state->pressed_window_button = btn;
                atk_text_input_focus(state, NULL);
                handled = true;
            }
        }

        if (!handled)
        {
            atk_widget_t *win = atk_window_title_hit_test(state, cursor_x, cursor_y);
            if (win && win->used)
            {
                atk_widget_t *prev_top = state->windows.tail ? (atk_widget_t *)state->windows.tail->value : NULL;
                bool moved = atk_window_bring_to_front(state, win);
                if (moved)
                {
                    atk_window_mark_dirty(win);
                    if (prev_top && prev_top != win)
                    {
                        atk_window_mark_dirty(prev_top);
                    }
                    result.redraw = true;
                }
                state->dragging_window = win;
                state->drag_offset_x = cursor_x - win->x;
                state->drag_offset_y = cursor_y - win->y;
                handled = true;
            }
        }

        if (!handled)
        {
            atk_widget_t *win = atk_window_hit_test(state, cursor_x, cursor_y);
            if (win && win->used)
            {
                atk_widget_t *prev_top = state->windows.tail ? (atk_widget_t *)state->windows.tail->value : NULL;
                bool moved = atk_window_bring_to_front(state, win);
                if (moved)
                {
                    atk_window_mark_dirty(win);
                    if (prev_top && prev_top != win)
                    {
                        atk_window_mark_dirty(prev_top);
                    }
                    result.redraw = true;
                }

                atk_widget_t *input_widget = atk_window_text_input_at(win, cursor_x, cursor_y);
                if (input_widget)
                {
                    atk_text_input_focus(state, input_widget);
                }
                else
                {
                    atk_text_input_focus(state, NULL);
                }

                handled = true;
            }
        }

        if (!handled)
        {
            atk_widget_t *btn = atk_desktop_button_hit_test(state, cursor_x, cursor_y);
            if (btn && btn->used)
            {
                state->pressed_desktop_button = btn;
                if (atk_button_is_draggable(btn))
                {
                    state->dragging_desktop_button = btn;
                    state->desktop_drag_offset_x = cursor_x - btn->x;
                    state->desktop_drag_offset_y = cursor_y - btn->y;
                    state->desktop_drag_moved = false;
                }
                atk_text_input_focus(state, NULL);
                handled = true;
            }
        }

        if (!handled)
        {
            atk_text_input_focus(state, NULL);
            atk_widget_t *created = atk_window_create_at(state, cursor_x, cursor_y);
            if (created)
            {
                atk_window_mark_dirty(created);
                result.redraw = true;
            }
        }
    }
    else if (released_edge)
    {
        state->dragging_window = NULL;

        if (state->dragging_desktop_button)
        {
            state->dragging_desktop_button = NULL;
        }

        if (state->pressed_window_button_window && state->pressed_window_button)
        {
            atk_widget_t *win = state->pressed_window_button_window;
            atk_widget_t *btn = state->pressed_window_button;
            if (win->used && btn->used && atk_button_hit_test(btn, win->x, win->y, cursor_x, cursor_y))
            {
                atk_button_invoke(btn);
                result.redraw = true;
            }
        }
        state->pressed_window_button_window = NULL;
        state->pressed_window_button = NULL;

        if (state->pressed_desktop_button && state->pressed_desktop_button->used)
        {
            bool inside = atk_button_hit_test(state->pressed_desktop_button, 0, 0, cursor_x, cursor_y);
            if (!state->desktop_drag_moved && inside)
            {
                atk_button_invoke(state->pressed_desktop_button);
            }
        }
        state->pressed_desktop_button = NULL;
        state->desktop_drag_moved = false;
    }

    if (left_pressed && state->dragging_window && state->dragging_window->used)
    {
        atk_widget_t *win = state->dragging_window;
        int old_x = win->x;
        int old_y = win->y;
        int old_width = win->width;
        int old_height = win->height;

        int new_x = cursor_x - state->drag_offset_x;
        int new_y = cursor_y - state->drag_offset_y;
        win->x = new_x;
        win->y = new_y;
        atk_window_ensure_inside(win);
        if (win->x != old_x || win->y != old_y)
        {
            video_invalidate_rect(old_x - ATK_WINDOW_BORDER,
                                  old_y - ATK_WINDOW_BORDER,
                                  old_width + ATK_WINDOW_BORDER * 2,
                                  old_height + ATK_WINDOW_BORDER * 2);
            atk_window_mark_dirty(win);
            result.redraw = true;
        }
    }

    if (left_pressed && state->dragging_desktop_button && state->dragging_desktop_button->used)
    {
        atk_widget_t *btn = state->dragging_desktop_button;
        int old_x = btn->x;
        int old_y = btn->y;
        int old_width = btn->width;
        int old_height = atk_button_effective_height(btn);

        int new_x = cursor_x - state->desktop_drag_offset_x;
        int new_y = cursor_y - state->desktop_drag_offset_y;

        if (new_x < 0) new_x = 0;
        if (new_y < 0) new_y = 0;
        int max_x = VIDEO_WIDTH - btn->width;
        int max_y = VIDEO_HEIGHT - atk_button_effective_height(btn);
        if (max_x < 0) max_x = 0;
        if (max_y < 0) max_y = 0;
        if (new_x > max_x) new_x = max_x;
        if (new_y > max_y) new_y = max_y;

        btn->x = new_x;
        btn->y = new_y;

        if (btn->x != old_x || btn->y != old_y)
        {
            state->desktop_drag_moved = true;
            video_invalidate_rect(old_x, old_y, old_width, old_height);
            video_invalidate_rect(btn->x, btn->y, btn->width, atk_button_effective_height(btn));
            result.redraw = true;
        }
    }

    if (state->exit_requested)
    {
        result.exit_video = true;
        state->exit_requested = false;
    }

    return result;
}

static void atk_apply_default_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    state->theme.background = video_make_color(0xFF, 0x80, 0x20);
    state->theme.window_border = video_make_color(0x20, 0x20, 0x20);
    state->theme.window_title = video_make_color(0x30, 0x60, 0xA0);
    state->theme.window_title_text = video_make_color(0xFF, 0xFF, 0xFF);
    state->theme.window_body = video_make_color(0xF0, 0xF0, 0xF0);
    state->theme.button_face = video_make_color(0xE0, 0xE0, 0xE0);
    state->theme.button_border = video_make_color(0x40, 0x40, 0x40);
    state->theme.button_text = video_make_color(0x10, 0x10, 0x10);
    state->theme.desktop_icon_face = video_make_color(0x50, 0x90, 0xD0);
    state->theme.desktop_icon_text = state->theme.window_title_text;
}

static void action_exit_to_text(atk_widget_t *button, void *context)
{
    (void)button;
    atk_state_t *state = (atk_state_t *)context;
    if (state)
    {
        state->exit_requested = true;
    }
}

atk_key_event_result_t atk_handle_key_char(char ch)
{
    atk_state_t *state = atk_state_get();
    atk_key_event_result_t result = { .redraw = false, .exit_video = false };

    if (!state)
    {
        return result;
    }

    atk_widget_t *input = state->focused_input;
    if (!input || !input->used)
    {
        return result;
    }

    atk_text_input_event_t event = atk_text_input_handle_char(input, ch);
    if (event == ATK_TEXT_INPUT_EVENT_CHANGED || event == ATK_TEXT_INPUT_EVENT_SUBMIT)
    {
        result.redraw = true;
    }
    return result;
}

static void action_open_shell(atk_widget_t *button, void *context)
{
    (void)button;
    atk_state_t *state = (atk_state_t *)context;
    if (!state)
    {
        return;
    }
    atk_shell_open(state);
}
