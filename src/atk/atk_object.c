#include "atk/object.h"

#ifdef KERNEL_BUILD
#include "serial.h"
#endif

#define ATK_WIDGET_GUARD_META_MAGIC   0x574944474D455441ULL /* 'WIDGMETA' */
#define ATK_WIDGET_GUARD_CANARY_FRONT 0x5749444747554152ULL /* 'WIDGGUAR' */
#define ATK_WIDGET_GUARD_CANARY_BACK  0x574944474F4B424BULL /* 'WIDGOKBK' */
#define ATK_WIDGET_GUARD_MAX_PAYLOAD  (64ULL * 1024ULL * 1024ULL)

typedef struct atk_widget_guard_header
{
    uint64_t meta_magic;
    uint64_t front_canary;
    size_t payload_size;
    const atk_class_t *cls;
    atk_widget_t *widget;
    struct atk_widget_guard_header *next;
    struct atk_widget_guard_header *prev;
} atk_widget_guard_header_t;

static atk_widget_guard_header_t *g_widget_guard_head = NULL;

static size_t atk_widget_guard_aligned_payload(size_t size)
{
    const size_t align = sizeof(uint64_t) - 1;
    return (size + align) & ~align;
}

static void atk_widget_guard_insert(atk_widget_guard_header_t *header)
{
    if (!header)
    {
        return;
    }
    header->prev = NULL;
    header->next = g_widget_guard_head;
    if (g_widget_guard_head)
    {
        g_widget_guard_head->prev = header;
    }
    g_widget_guard_head = header;
}

static void atk_widget_guard_remove(atk_widget_guard_header_t *header)
{
    if (!header)
    {
        return;
    }
    if (header->prev)
    {
        header->prev->next = header->next;
    }
    else if (g_widget_guard_head == header)
    {
        g_widget_guard_head = header->next;
    }
    if (header->next)
    {
        header->next->prev = header->prev;
    }
    header->next = NULL;
    header->prev = NULL;
}

static atk_widget_guard_header_t *atk_widget_guard_lookup(const atk_widget_t *widget)
{
    if (!widget)
    {
        return NULL;
    }
    atk_widget_guard_header_t *current = g_widget_guard_head;
    while (current)
    {
        if (current->widget == widget)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

static uint64_t *atk_widget_guard_tail_slot(const atk_widget_guard_header_t *header)
{
    if (!header)
    {
        return NULL;
    }
    size_t payload = header->payload_size;
    if (payload == 0 || payload > ATK_WIDGET_GUARD_MAX_PAYLOAD)
    {
        return NULL;
    }
    uint8_t *base = (uint8_t *)(header + 1);
    return (uint64_t *)(base + payload);
}

#ifdef KERNEL_BUILD
static const char *atk_widget_guard_class_name(const atk_widget_guard_header_t *header)
{
    if (!header || !header->cls || !header->cls->name)
    {
        return "unknown";
    }
    return header->cls->name;
}

static void atk_widget_guard_log_ptr(const char *label, const atk_widget_t *widget, const char *reason)
{
    serial_printf("%s", "[atk][guard] ptr=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)widget));
    serial_printf("%s", " reason=");
    serial_printf("%s", reason ? reason : "invalid");
    if (label)
    {
        serial_printf("%s", " via=");
        serial_printf("%s", label);
    }
    serial_printf("%s", "\r\n");
}

static void atk_widget_guard_log_violation(const atk_widget_guard_header_t *header,
                                           const atk_widget_t *widget,
                                           const char *label,
                                           const char *field,
                                           uint64_t actual,
                                           uint64_t expected)
{
    serial_printf("%s", "[atk][guard] class=");
    serial_printf("%s", atk_widget_guard_class_name(header));
    serial_printf("%s", " widget=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)widget));
    serial_printf("%s", " field=");
    serial_printf("%s", field ? field : "unknown");
    serial_printf("%s", " actual=0x");
    serial_printf("%016llX", (unsigned long long)(actual));
    serial_printf("%s", " expected=0x");
    serial_printf("%016llX", (unsigned long long)(expected));
    if (label)
    {
        serial_printf("%s", " via=");
        serial_printf("%s", label);
    }
    serial_printf("%s", "\r\n");
}
#else
static void atk_widget_guard_log_ptr(const char *label, const atk_widget_t *widget, const char *reason)
{
    (void)label;
    (void)widget;
    (void)reason;
}

static void atk_widget_guard_log_violation(const atk_widget_guard_header_t *header,
                                           const atk_widget_t *widget,
                                           const char *label,
                                           const char *field,
                                           uint64_t actual,
                                           uint64_t expected)
{
    (void)header;
    (void)widget;
    (void)label;
    (void)field;
    (void)actual;
    (void)expected;
}
#endif

bool atk_widget_validate(const atk_widget_t *widget, const char *label)
{
    if (!widget)
    {
        return false;
    }

    atk_widget_guard_header_t *header = atk_widget_guard_lookup(widget);
    if (!header)
    {
        atk_widget_guard_log_ptr(label, widget, "unknown");
        return false;
    }

    bool ok = true;
    if (header->front_canary != ATK_WIDGET_GUARD_CANARY_FRONT)
    {
        atk_widget_guard_log_violation(header, widget, label, "front", header->front_canary, ATK_WIDGET_GUARD_CANARY_FRONT);
        ok = false;
    }

    uint64_t *tail = atk_widget_guard_tail_slot(header);
    uint64_t tail_value = tail ? *tail : 0;
    if (!tail || tail_value != ATK_WIDGET_GUARD_CANARY_BACK)
    {
        atk_widget_guard_log_violation(header, widget, label, "tail", tail_value, ATK_WIDGET_GUARD_CANARY_BACK);
        ok = false;
    }

    return ok;
}

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

    size_t widget_bytes = sizeof(atk_widget_t) + atk_class_total_payload(cls);
    size_t payload_bytes = atk_widget_guard_aligned_payload(widget_bytes);
    size_t total_bytes = sizeof(atk_widget_guard_header_t) + payload_bytes + sizeof(uint64_t);

    atk_widget_guard_header_t *header = (atk_widget_guard_header_t *)malloc(total_bytes);
    if (!header)
    {
        return 0;
    }

    memset(header, 0, total_bytes);
    header->meta_magic = ATK_WIDGET_GUARD_META_MAGIC;
    header->front_canary = ATK_WIDGET_GUARD_CANARY_FRONT;
    header->payload_size = payload_bytes;
    header->cls = cls;
    header->widget = (atk_widget_t *)(header + 1);

    uint64_t *tail = atk_widget_guard_tail_slot(header);
    if (tail)
    {
        *tail = ATK_WIDGET_GUARD_CANARY_BACK;
    }

    atk_widget_guard_insert(header);
    return atk_widget_init(header->widget, cls);
}

void atk_widget_destroy(atk_widget_t *widget)
{
    if (!widget)
    {
        return;
    }

    atk_widget_guard_header_t *header = atk_widget_guard_lookup(widget);
    if (header)
    {
        atk_widget_guard_remove(header);
        uint64_t *tail = atk_widget_guard_tail_slot(header);
        if (tail)
        {
            *tail = 0;
        }
        header->front_canary = 0;
        header->meta_magic = 0;
        header->widget = NULL;
        free(header);
        return;
    }

    /* Fallback for legacy allocations without guard headers */
    free(widget);
}

bool atk_widget_is_a(const atk_widget_t *widget, const atk_class_t *cls)
{
    if (!widget || !cls)
    {
        return false;
    }

    if (!atk_widget_validate(widget, "atk_widget_is_a"))
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

    if (!atk_widget_validate(widget, "atk_widget_priv"))
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
        if (!atk_widget_validate(current, "atk_widget_absolute_position"))
        {
#if ATK_DEBUG && defined(KERNEL_BUILD)
            serial_printf("%s", "[atk][debug] abs_pos invalid widget=0x");
            serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)widget));
            serial_printf("%s", " current=0x");
            serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)current));
            serial_printf("%s", " caller=0x");
            serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)__builtin_return_address(0)));
            serial_printf("%s", "\r\n");
#endif
            break;
        }
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
    if (!atk_widget_validate(widget, "atk_widget_absolute_bounds"))
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
    if (!atk_widget_validate(widget, "atk_widget_set_ops"))
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
    if (!atk_widget_validate(widget, "atk_widget_clear_ops"))
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
    if (!atk_widget_validate(widget, "atk_widget_get_ops"))
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
    if (!atk_widget_validate(widget, "atk_widget_ops_context"))
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
    if (!atk_widget_validate(widget, "atk_widget_hit_test"))
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
    if (!widget || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }
    if (!atk_widget_validate(widget, "atk_widget_dispatch_mouse") || !widget->used)
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
    if (!widget)
    {
        return ATK_KEY_RESPONSE_NONE;
    }
    if (!atk_widget_validate(widget, "atk_widget_dispatch_key") || !widget->used)
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

void atk_widget_set_layout(atk_widget_t *widget, uint32_t anchors)
{
    if (!widget)
    {
        return;
    }
    if (!atk_widget_validate(widget, "atk_widget_set_layout"))
    {
        return;
    }

    atk_widget_t *parent = widget->parent;
    if (parent && !atk_widget_validate(parent, "atk_widget_set_layout parent"))
    {
        return;
    }

    widget->flags = anchors;

    int parent_width = parent ? parent->width : widget->width;
    int parent_height = parent ? parent->height : widget->height;
    if (parent_width < 0) parent_width = 0;
    if (parent_height < 0) parent_height = 0;

    widget->layout_margin_left = widget->x;
    widget->layout_margin_top = widget->y;
    widget->layout_margin_right = parent_width - (widget->x + widget->width);
    widget->layout_margin_bottom = parent_height - (widget->y + widget->height);

    if (widget->layout_margin_right < 0) widget->layout_margin_right = 0;
    if (widget->layout_margin_bottom < 0) widget->layout_margin_bottom = 0;
}

void atk_widget_apply_layout(atk_widget_t *widget)
{
    if (!widget)
    {
        return;
    }
    if (!atk_widget_validate(widget, "atk_widget_apply_layout"))
    {
        return;
    }
    if (!widget->parent || widget->flags == 0)
    {
        return;
    }

    atk_widget_t *parent = widget->parent;
    if (!atk_widget_validate(parent, "atk_widget_apply_layout parent"))
    {
        return;
    }

    int parent_width = parent->width;
    int parent_height = parent->height;
    if (parent_width < 0) parent_width = 0;
    if (parent_height < 0) parent_height = 0;

    bool anchor_left = (widget->flags & ATK_WIDGET_ANCHOR_LEFT) != 0;
    bool anchor_right = (widget->flags & ATK_WIDGET_ANCHOR_RIGHT) != 0;
    bool anchor_top = (widget->flags & ATK_WIDGET_ANCHOR_TOP) != 0;
    bool anchor_bottom = (widget->flags & ATK_WIDGET_ANCHOR_BOTTOM) != 0;

    int new_x = widget->x;
    int new_y = widget->y;
    int new_width = widget->width;
    int new_height = widget->height;

    if (anchor_left && anchor_right)
    {
        new_x = widget->layout_margin_left;
        new_width = parent_width - widget->layout_margin_left - widget->layout_margin_right;
    }
    else if (anchor_left)
    {
        new_x = widget->layout_margin_left;
    }
    else if (anchor_right)
    {
        new_x = parent_width - widget->layout_margin_right - new_width;
    }

    if (anchor_top && anchor_bottom)
    {
        new_y = widget->layout_margin_top;
        new_height = parent_height - widget->layout_margin_top - widget->layout_margin_bottom;
    }
    else if (anchor_top)
    {
        new_y = widget->layout_margin_top;
    }
    else if (anchor_bottom)
    {
        new_y = parent_height - widget->layout_margin_bottom - new_height;
    }

    if (new_width < 0) new_width = 0;
    if (new_height < 0) new_height = 0;

    widget->x = new_x;
    widget->y = new_y;
    widget->width = new_width;
    widget->height = new_height;
}
