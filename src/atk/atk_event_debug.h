#ifndef ATK_EVENT_DEBUG_H
#define ATK_EVENT_DEBUG_H

#include "types.h"
#include "atk/object.h"

#ifndef ATK_EVENT_DEBUG
#define ATK_EVENT_DEBUG 0
#endif

#if ATK_EVENT_DEBUG
uint64_t atk_event_debug_next_id(void);
void atk_event_debug_mouse_begin(uint64_t id,
                                 int cursor_x,
                                 int cursor_y,
                                 bool pressed_edge,
                                 bool released_edge,
                                 bool left_pressed);
void atk_event_debug_mouse_dispatch(uint64_t id,
                                    const char *stage,
                                    const atk_widget_t *widget,
                                    const atk_mouse_event_t *event,
                                    atk_mouse_response_t response);
void atk_event_debug_tab_hit(uint64_t id,
                             const atk_widget_t *tab_view,
                             size_t tab_index,
                             const char *title,
                             size_t prev_index);
void atk_event_debug_tab_miss(uint64_t id,
                              const atk_widget_t *tab_view,
                              int local_x,
                              int local_y,
                              const char *reason);
void atk_event_debug_remote(uint64_t id, const atk_widget_t *window, bool handled);
#else
static inline uint64_t atk_event_debug_next_id(void)
{
    return 0;
}
static inline void atk_event_debug_mouse_begin(uint64_t id,
                                               int cursor_x,
                                               int cursor_y,
                                               bool pressed_edge,
                                               bool released_edge,
                                               bool left_pressed)
{
    (void)id;
    (void)cursor_x;
    (void)cursor_y;
    (void)pressed_edge;
    (void)released_edge;
    (void)left_pressed;
}
static inline void atk_event_debug_mouse_dispatch(uint64_t id,
                                                  const char *stage,
                                                  const atk_widget_t *widget,
                                                  const atk_mouse_event_t *event,
                                                  atk_mouse_response_t response)
{
    (void)id;
    (void)stage;
    (void)widget;
    (void)event;
    (void)response;
}
static inline void atk_event_debug_tab_hit(uint64_t id,
                                           const atk_widget_t *tab_view,
                                           size_t tab_index,
                                           const char *title,
                                           size_t prev_index)
{
    (void)id;
    (void)tab_view;
    (void)tab_index;
    (void)title;
    (void)prev_index;
}
static inline void atk_event_debug_tab_miss(uint64_t id,
                                            const atk_widget_t *tab_view,
                                            int local_x,
                                            int local_y,
                                            const char *reason)
{
    (void)id;
    (void)tab_view;
    (void)local_x;
    (void)local_y;
    (void)reason;
}
static inline void atk_event_debug_remote(uint64_t id, const atk_widget_t *window, bool handled)
{
    (void)id;
    (void)window;
    (void)handled;
}
#endif

#endif
