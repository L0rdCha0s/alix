#include "atk_internal.h"

#include "atk_button.h"
#include "atk/atk_image.h"
#include "atk/atk_label.h"
#include "atk/atk_list_view.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_tabs.h"
#include "atk/atk_menu.h"
#ifndef KERNEL_BUILD
#include "atk/atk_terminal.h"
#endif
#include "atk/atk_text_input.h"

void atk_widget_draw_any(const atk_state_t *state, const atk_widget_t *widget)
{
    if (!state || !widget || !widget->used)
    {
        return;
    }

    if (atk_widget_is_a(widget, &ATK_BUTTON_CLASS))
    {
        int origin_x = 0;
        int origin_y = 0;
        if (widget->parent)
        {
            atk_widget_absolute_position(widget->parent, &origin_x, &origin_y);
        }
        atk_button_draw(state, widget, origin_x, origin_y);
    }
    else if (atk_widget_is_a(widget, &ATK_LABEL_CLASS))
    {
        atk_label_draw(state, widget);
    }
    else if (atk_widget_is_a(widget, &ATK_IMAGE_CLASS))
    {
        atk_image_draw(state, widget);
    }
    else if (atk_widget_is_a(widget, &ATK_TEXT_INPUT_CLASS))
    {
        atk_text_input_draw(state, widget);
    }
#ifndef KERNEL_BUILD
    else if (atk_widget_is_a(widget, &ATK_TERMINAL_CLASS))
    {
        atk_terminal_draw(state, widget);
    }
#endif
    else if (atk_widget_is_a(widget, &ATK_SCROLLBAR_CLASS))
    {
        atk_scrollbar_draw(state, widget);
    }
    else if (atk_widget_is_a(widget, &ATK_LIST_VIEW_CLASS))
    {
        atk_list_view_draw(state, widget);
    }
    else if (atk_widget_is_a(widget, &ATK_TAB_VIEW_CLASS))
    {
        atk_tab_view_draw(state, widget);
    }
    else if (atk_widget_is_a(widget, &ATK_MENU_CLASS))
    {
        atk_menu_draw(state, widget);
    }
}

void atk_widget_destroy_any(atk_widget_t *widget)
{
    if (!widget)
    {
        return;
    }

    if (atk_widget_is_a(widget, &ATK_BUTTON_CLASS))
    {
        atk_button_priv_t *priv = (atk_button_priv_t *)atk_widget_priv(widget, &ATK_BUTTON_CLASS);
        if (priv)
        {
            priv->list_node = NULL;
        }
        atk_widget_destroy(widget);
    }
    else if (atk_widget_is_a(widget, &ATK_LABEL_CLASS))
    {
        atk_label_destroy(widget);
        atk_widget_destroy(widget);
    }
    else if (atk_widget_is_a(widget, &ATK_IMAGE_CLASS))
    {
        atk_image_destroy(widget);
        atk_widget_destroy(widget);
    }
    else if (atk_widget_is_a(widget, &ATK_TEXT_INPUT_CLASS))
    {
        atk_text_input_destroy(widget);
        atk_widget_destroy(widget);
    }
#ifndef KERNEL_BUILD
    else if (atk_widget_is_a(widget, &ATK_TERMINAL_CLASS))
    {
        atk_terminal_destroy(widget);
        atk_widget_destroy(widget);
    }
#endif
    else if (atk_widget_is_a(widget, &ATK_SCROLLBAR_CLASS))
    {
        atk_scrollbar_destroy(widget);
        atk_widget_destroy(widget);
    }
    else if (atk_widget_is_a(widget, &ATK_LIST_VIEW_CLASS))
    {
        atk_list_view_destroy(widget);
        atk_widget_destroy(widget);
    }
    else if (atk_widget_is_a(widget, &ATK_TAB_VIEW_CLASS))
    {
        atk_tab_view_destroy(widget);
        atk_widget_destroy(widget);
    }
    else if (atk_widget_is_a(widget, &ATK_MENU_CLASS))
    {
        atk_menu_destroy(widget);
    }
    else
    {
        atk_widget_destroy(widget);
    }
}
