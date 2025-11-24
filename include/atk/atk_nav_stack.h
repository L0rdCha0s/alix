#ifndef ATK_NAV_STACK_H
#define ATK_NAV_STACK_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

atk_widget_t *atk_window_add_nav_stack(atk_widget_t *window, int x, int y, int width, int height);
atk_widget_t *atk_nav_stack_create(void);
bool atk_nav_stack_push_owned(atk_widget_t *nav, atk_widget_t *frame, const char *title, bool owned);
bool atk_nav_stack_push(atk_widget_t *nav, atk_widget_t *frame, const char *title);
bool atk_nav_stack_pop(atk_widget_t *nav);
void atk_nav_stack_relayout(atk_widget_t *nav);
bool atk_nav_stack_sliding(const atk_widget_t *nav);

extern const atk_class_t ATK_NAV_STACK_CLASS;

#ifdef __cplusplus
}
#endif

#endif
