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

static bool desktop_button_intersects(const atk_rect_t *clip,
                                      const atk_widget_t *widget,
                                      int effective_height)
{
    if (!clip || !widget)
    {
        return true;
    }
    int x0 = widget->x;
    int y0 = widget->y;
    int x1 = x0 + widget->width;
    int y1 = y0 + effective_height;
    int clip_x1 = clip->x + clip->width;
    int clip_y1 = clip->y + clip->height;
    if (x1 <= clip->x || y1 <= clip->y || x0 >= clip_x1 || y0 >= clip_y1)
    {
        return false;
    }
    return true;
}

void atk_desktop_draw_buttons(const atk_state_t *state, const atk_rect_t *clip)
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
            int eff_height = atk_button_effective_height(widget);
            if (!desktop_button_intersects(clip, widget, eff_height))
            {
                continue;
            }
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

    atk_dirty_mark_rect(widget->x, widget->y, widget->width, atk_button_effective_height(widget));
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
