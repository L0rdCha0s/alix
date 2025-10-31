#include "atk_desktop.h"

#include "libc.h"
#include "video.h"

void atk_desktop_reset(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    for (int i = 0; i < ATK_MAX_DESKTOP_BUTTONS; ++i)
    {
        void *storage = state->desktop_button_storage[i];
        state->desktop_buttons[i] = atk_widget_init(storage, &ATK_BUTTON_CLASS);
    }

    state->desktop_button_count = 0;
    state->pressed_desktop_button = -1;
    state->dragging_desktop_button = -1;
    state->desktop_drag_offset_x = 0;
    state->desktop_drag_offset_y = 0;
    state->desktop_drag_moved = false;
}

void atk_desktop_draw_buttons(const atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    for (int i = 0; i < state->desktop_button_count; ++i)
    {
        atk_widget_t *widget = state->desktop_buttons[i];
        if (widget && widget->used)
        {
            atk_button_draw(state, widget, 0, 0);
        }
    }
}

atk_widget_t *atk_desktop_add_button(atk_state_t *state,
                                     int x,
                                     int y,
                                     int width,
                                     int height,
                                     const char *title,
                                     atk_button_style_t style,
                                     bool draggable,
                                     atk_button_action_t action,
                                     void *context)
{
    if (!state || state->desktop_button_count >= ATK_MAX_DESKTOP_BUTTONS)
    {
        return 0;
    }

    int slot = state->desktop_button_count++;
    void *storage = state->desktop_button_storage[slot];
    atk_widget_t *widget = atk_widget_init(storage, &ATK_BUTTON_CLASS);
    state->desktop_buttons[slot] = widget;

    widget->x = x;
    widget->y = y;
    widget->width = width;
    widget->height = height;
    widget->parent = 0;

    atk_button_configure(widget,
                         title,
                         style,
                         draggable,
                         true,
                         action,
                         context);
    return widget;
}

int atk_desktop_button_hit_test(const atk_state_t *state, int px, int py)
{
    if (!state)
    {
        return -1;
    }

    for (int i = state->desktop_button_count - 1; i >= 0; --i)
    {
        atk_widget_t *widget = state->desktop_buttons[i];
        if (!widget || !widget->used)
        {
            continue;
        }
        if (atk_button_hit_test(widget, 0, 0, px, py))
        {
            return i;
        }
    }
    return -1;
}
