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
#if ATK_DEBUG && defined(KERNEL_BUILD)
#include "serial.h"
#endif

#if ATK_DEBUG && defined(KERNEL_BUILD)
static const char *atk_widget_class_name(const atk_widget_t *widget)
{
    if (!widget || !widget->cls || !widget->cls->name)
    {
        return "unknown";
    }
    return widget->cls->name;
}

static void atk_widget_log_invalid(const char *label, const atk_widget_t *widget)
{
    serial_write_string("[atk][widget] invalid ");
    serial_write_string(label ? label : "ptr");
    serial_write_string(" class=");
    serial_write_string(atk_widget_class_name(widget));
    serial_write_string(" ptr=0x");
    serial_write_hex64((uint64_t)(uintptr_t)widget);
    serial_write_string("\r\n");
}
#else
#define atk_widget_log_invalid(label, widget) ((void)0)
#endif

void atk_widget_draw_any(const atk_state_t *state, const atk_widget_t *widget)
{
    if (!state || !widget || !widget->used)
    {
        return;
    }

#if ATK_DEBUG
    if (!atk_widget_validate(widget, "atk_widget_draw_any self"))
    {
        atk_widget_log_invalid("self", widget);
        return;
    }
#endif

    const atk_widget_ops_t *ops = atk_widget_get_ops(widget);
    if (!ops || !ops->draw)
    {
        return;
    }

    int origin_x = 0;
    int origin_y = 0;
    if (widget->parent)
    {
#if ATK_DEBUG
        if (!atk_widget_validate(widget->parent, "atk_widget_draw_any parent"))
        {
            atk_widget_log_invalid("parent", widget->parent);
            return;
        }
#endif
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
