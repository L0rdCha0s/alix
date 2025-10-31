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
