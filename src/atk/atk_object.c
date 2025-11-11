#include "atk/object.h"

size_t atk_class_total_payload(const atk_class_t *cls)
{
    size_t total = 0;
    const atk_class_t *current = cls;
    while (current)
    {
        total += current->payload_size;
        current = current->parent;
    }
    return total;
}

atk_widget_t *atk_widget_init(void *memory, const atk_class_t *cls)
{
    if (!memory || !cls)
    {
        return 0;
    }

    size_t size = sizeof(atk_widget_t) + atk_class_total_payload(cls);
    memset(memory, 0, size);

    atk_widget_t *widget = (atk_widget_t *)memory;
    widget->cls = cls;
    widget->used = false;
    widget->parent = 0;
    widget->flags = 0;
    widget->ops = NULL;
    widget->ops_context = NULL;
    return widget;
}

atk_widget_t *atk_widget_create(const atk_class_t *cls)
{
    if (!cls)
    {
        return 0;
    }

    size_t size = sizeof(atk_widget_t) + atk_class_total_payload(cls);
    void *memory = malloc(size);
    if (!memory)
    {
        return 0;
    }

    return atk_widget_init(memory, cls);
}

void atk_widget_destroy(atk_widget_t *widget)
{
    if (!widget)
    {
        return;
    }

    free(widget);
}

bool atk_widget_is_a(const atk_widget_t *widget, const atk_class_t *cls)
{
    if (!widget || !cls)
    {
        return false;
    }

    const atk_class_t *current = widget->cls;
    while (current)
    {
        if (current == cls)
        {
            return true;
        }
        current = current->parent;
    }
    return false;
}

void *atk_widget_priv(const atk_widget_t *widget, const atk_class_t *cls)
{
    if (!widget || !cls)
    {
        return 0;
    }

    if (!atk_widget_is_a(widget, cls))
    {
        return 0;
    }

    size_t offset = 0;
    const atk_class_t *current = widget->cls;
    while (current && current != cls)
    {
        offset += current->payload_size;
        current = current->parent;
    }

    uint8_t *base = (uint8_t *)(widget + 1);
    return base + offset;
}

void atk_widget_absolute_position(const atk_widget_t *widget, int *x_out, int *y_out)
{
    int x = 0;
    int y = 0;
    const atk_widget_t *current = widget;
    while (current)
    {
        x += current->x;
        y += current->y;
        current = current->parent;
    }
    if (x_out)
    {
        *x_out = x;
    }
    if (y_out)
    {
        *y_out = y;
    }
}

void atk_widget_absolute_bounds(const atk_widget_t *widget, int *x_out, int *y_out, int *width_out, int *height_out)
{
    if (!widget)
    {
        if (x_out) *x_out = 0;
        if (y_out) *y_out = 0;
        if (width_out) *width_out = 0;
        if (height_out) *height_out = 0;
        return;
    }
    int x = 0;
    int y = 0;
    atk_widget_absolute_position(widget, &x, &y);
    if (x_out) *x_out = x;
    if (y_out) *y_out = y;
    if (width_out) *width_out = widget->width;
    if (height_out) *height_out = widget->height;
}

void atk_widget_set_ops(atk_widget_t *widget, const atk_widget_ops_t *ops, void *context)
{
    if (!widget)
    {
        return;
    }
    widget->ops = ops;
    widget->ops_context = context;
}

void atk_widget_clear_ops(atk_widget_t *widget)
{
    if (!widget)
    {
        return;
    }
    widget->ops = NULL;
    widget->ops_context = NULL;
}

const atk_widget_ops_t *atk_widget_get_ops(const atk_widget_t *widget)
{
    if (!widget)
    {
        return NULL;
    }
    return widget->ops;
}

void *atk_widget_ops_context(const atk_widget_t *widget)
{
    if (!widget)
    {
        return NULL;
    }
    return widget->ops_context;
}

bool atk_widget_hit_test(const atk_widget_t *widget, int origin_x, int origin_y, int px, int py)
{
    if (!widget || !widget->used)
    {
        return false;
    }

    const atk_widget_ops_t *ops = widget->ops;
    if (ops && ops->hit_test)
    {
        return ops->hit_test(widget, origin_x, origin_y, px, py, widget->ops_context);
    }

    int x0 = origin_x;
    int y0 = origin_y;
    int x1 = x0 + widget->width;
    int y1 = y0 + widget->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

atk_mouse_response_t atk_widget_dispatch_mouse(atk_widget_t *widget, const atk_mouse_event_t *event)
{
    if (!widget || !widget->used || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    const atk_widget_ops_t *ops = widget->ops;
    if (!ops || !ops->on_mouse)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    return ops->on_mouse(widget, event, widget->ops_context);
}

atk_key_response_t atk_widget_dispatch_key(atk_widget_t *widget, int key, int modifiers, int action)
{
    if (!widget || !widget->used)
    {
        return ATK_KEY_RESPONSE_NONE;
    }

    const atk_widget_ops_t *ops = widget->ops;
    if (!ops || !ops->on_key)
    {
        return ATK_KEY_RESPONSE_NONE;
    }

    return ops->on_key(widget, key, modifiers, action, widget->ops_context);
}
