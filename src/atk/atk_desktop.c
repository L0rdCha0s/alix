#include "atk_desktop.h"

#include "libc.h"
#include "video.h"

static void desktop_button_destroy(void *value);

void atk_desktop_reset(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    atk_list_clear(&state->desktop_buttons, desktop_button_destroy);
    atk_list_init(&state->desktop_buttons);

    state->pressed_desktop_button = 0;
    state->dragging_desktop_button = 0;
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

    ATK_LIST_FOR_EACH(node, &state->desktop_buttons)
    {
        atk_widget_t *widget = (atk_widget_t *)node->value;
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
    if (!state)
    {
        return 0;
    }

    atk_widget_t *widget = atk_widget_create(&ATK_BUTTON_CLASS);
    if (!widget)
    {
        return 0;
    }

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

    atk_list_node_t *node = atk_list_push_back(&state->desktop_buttons, widget);
    if (!node)
    {
        atk_widget_destroy(widget);
        return 0;
    }

    atk_button_priv_t *priv = (atk_button_priv_t *)atk_widget_priv(widget, &ATK_BUTTON_CLASS);
    if (priv)
    {
        priv->list_node = node;
    }

    return widget;
}

atk_widget_t *atk_desktop_button_hit_test(const atk_state_t *state, int px, int py)
{
    if (!state)
    {
        return 0;
    }

    ATK_LIST_FOR_EACH_REVERSE(node, &state->desktop_buttons)
    {
        atk_widget_t *widget = (atk_widget_t *)node->value;
        if (!widget || !widget->used)
        {
            continue;
        }
        if (atk_button_hit_test(widget, 0, 0, px, py))
        {
            return widget;
        }
    }
    return 0;
}

static void desktop_button_destroy(void *value)
{
    atk_widget_t *widget = (atk_widget_t *)value;
    if (!widget)
    {
        return;
    }

    atk_button_priv_t *priv = (atk_button_priv_t *)atk_widget_priv(widget, &ATK_BUTTON_CLASS);
    if (priv)
    {
        priv->list_node = 0;
    }

    atk_widget_destroy(widget);
}
