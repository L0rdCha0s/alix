#ifndef ATK_NAV_STACK_H
#define ATK_NAV_STACK_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

/*
 * Create a navigation stack widget as a child of `window`.
 *
 * A nav stack manages a stack of "frames" (widgets) with optional title and
 * animated push/pop transitions.
 */
atk_widget_t *atk_window_add_nav_stack(atk_widget_t *window, int x, int y, int width, int height);

/* Create a standalone nav stack widget (not attached to a window). */
atk_widget_t *atk_nav_stack_create(void);

/*
 * Push a frame onto the stack.
 *
 * If `owned` is true, the nav stack will destroy `frame` when popped/destroyed.
 */
bool atk_nav_stack_push_owned(atk_widget_t *nav, atk_widget_t *frame, const char *title, bool owned);

/* Convenience wrapper for pushing a non-owned frame. */
bool atk_nav_stack_push(atk_widget_t *nav, atk_widget_t *frame, const char *title);

/*
 * Pop the top frame from the stack.
 *
 * Returns false if there is nothing to pop.
 */
bool atk_nav_stack_pop(atk_widget_t *nav);

/* Recompute layout after size changes. */
void atk_nav_stack_relayout(atk_widget_t *nav);

/* Return true while an animated transition is in progress. */
bool atk_nav_stack_sliding(const atk_widget_t *nav);

extern const atk_class_t ATK_NAV_STACK_CLASS;

#ifdef __cplusplus
}
#endif

#endif
