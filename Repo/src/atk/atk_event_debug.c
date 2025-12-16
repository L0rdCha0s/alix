#include "atk_event_debug.h"

#if ATK_EVENT_DEBUG && defined(KERNEL_BUILD)

#include "serial.h"
#include "atk_internal.h"

static const char *atk_event_debug_class_name(const atk_widget_t *widget)
{
    if (!widget || !widget->cls || !widget->cls->name)
    {
        return "unknown";
    }
    return widget->cls->name;
}

static void atk_event_debug_print_response(atk_mouse_response_t response)
{
    bool first = true;
    if (response & ATK_MOUSE_RESPONSE_HANDLED)
    {
        serial_printf("%s", "HANDLED");
        first = false;
    }
    if (response & ATK_MOUSE_RESPONSE_REDRAW)
    {
        serial_printf("%s", first ? "REDRAW" : "|REDRAW");
        first = false;
    }
    if (response & ATK_MOUSE_RESPONSE_CAPTURE)
    {
        serial_printf("%s", first ? "CAPTURE" : "|CAPTURE");
        first = false;
    }
    if (response & ATK_MOUSE_RESPONSE_RELEASE)
    {
        serial_printf("%s", first ? "RELEASE" : "|RELEASE");
        first = false;
    }
    if (first)
    {
        serial_printf("%s", "none");
    }
}

uint64_t atk_event_debug_next_id(void)
{
    static uint64_t g_event_seq = 0;
    return __atomic_add_fetch(&g_event_seq, 1u, __ATOMIC_SEQ_CST);
}

void atk_event_debug_mouse_begin(uint64_t id,
                                 int cursor_x,
                                 int cursor_y,
                                 bool pressed_edge,
                                 bool released_edge,
                                 bool left_pressed)
{
    serial_printf("[atk][event] id=%016llX cursor=(%d,%d) press=%d release=%d left=%d\r\n",
                  (unsigned long long)id,
                  cursor_x,
                  cursor_y,
                  pressed_edge ? 1 : 0,
                  released_edge ? 1 : 0,
                  left_pressed ? 1 : 0);
}

void atk_event_debug_mouse_dispatch(uint64_t id,
                                    const char *stage,
                                    const atk_widget_t *widget,
                                    const atk_mouse_event_t *event,
                                    atk_mouse_response_t response)
{
    if (!event)
    {
        return;
    }
    if (!event->pressed_edge && !event->released_edge)
    {
        return;
    }

    serial_printf("[atk][event] id=%016llX stage=%s cls=%s ptr=0x%016llX cursor=(%d,%d) local=(%d,%d) origin=(%d,%d) press=%d release=%d left=%d resp=",
                  (unsigned long long)id,
                  stage ? stage : "dispatch",
                  atk_event_debug_class_name(widget),
                  (unsigned long long)((uint64_t)(uintptr_t)widget),
                  event->cursor_x,
                  event->cursor_y,
                  event->local_x,
                  event->local_y,
                  event->origin_x,
                  event->origin_y,
                  event->pressed_edge ? 1 : 0,
                  event->released_edge ? 1 : 0,
                  event->left_pressed ? 1 : 0);
    atk_event_debug_print_response(response);
    serial_printf("%s", "\r\n");
}

void atk_event_debug_tab_hit(uint64_t id,
                             const atk_widget_t *tab_view,
                             size_t tab_index,
                             const char *title,
                             size_t prev_index)
{
    serial_printf("%s", "[atk][event][tab] id=");
    serial_printf("%016llX", (unsigned long long)id);
    serial_printf("%s", " ptr=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)tab_view));
    serial_printf("%s", " cls=");
    serial_printf("%s", atk_event_debug_class_name(tab_view));
    serial_printf("%s", " hit=");
    serial_printf("%llu", (unsigned long long)tab_index);
    serial_printf("%s", " prev=");
    serial_printf("%llu", (unsigned long long)prev_index);
    serial_printf("%s", " title=");
    serial_printf("%s", title ? title : "");
    serial_printf("%s", "\r\n");
}

void atk_event_debug_tab_miss(uint64_t id,
                              const atk_widget_t *tab_view,
                              int local_x,
                              int local_y,
                              const char *reason)
{
    serial_printf("%s", "[atk][event][tab] id=");
    serial_printf("%016llX", (unsigned long long)id);
    serial_printf("%s", " ptr=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)tab_view));
    serial_printf("%s", " cls=");
    serial_printf("%s", atk_event_debug_class_name(tab_view));
    serial_printf("%s", " miss local=(");
    serial_printf("%d", local_x);
    serial_printf("%s", ",");
    serial_printf("%d", local_y);
    serial_printf("%s", ")");
    if (reason)
    {
        serial_printf("%s", " reason=");
        serial_printf("%s", reason);
    }
    serial_printf("%s", "\r\n");
}

void atk_event_debug_remote(uint64_t id, const atk_widget_t *window, bool handled)
{
    serial_printf("%s", "[atk][event][remote] id=");
    serial_printf("%016llX", (unsigned long long)id);
    serial_printf("%s", " window=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)window));
    serial_printf("%s", " cls=");
    serial_printf("%s", atk_event_debug_class_name(window));
    serial_printf("%s", " handled=");
    serial_printf("%d", handled ? 1 : 0);
    serial_printf("%s", "\r\n");
}

#endif /* ATK_EVENT_DEBUG && KERNEL_BUILD */
