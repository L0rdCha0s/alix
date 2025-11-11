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

    const atk_widget_ops_t *ops = atk_widget_get_ops(widget);
    if (!ops || !ops->draw)
    {
        return;
    }

    int origin_x = 0;
    int origin_y = 0;
    if (widget->parent)
    {
        atk_widget_absolute_position(widget->parent, &origin_x, &origin_y);
    }

    ops->draw(state, widget, origin_x, origin_y, atk_widget_ops_context(widget));
}

void atk_widget_destroy_any(atk_widget_t *widget)
{
    if (!widget)
    {
        return;
    }

    const atk_widget_ops_t *ops = atk_widget_get_ops(widget);
    if (ops && ops->destroy)
    {
        ops->destroy(widget, atk_widget_ops_context(widget));
        return;
    }

    atk_widget_destroy(widget);
}
