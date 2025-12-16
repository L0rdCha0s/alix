#ifndef ATK_TABS_H
#define ATK_TABS_H

#include "atk/object.h"

struct atk_state;

#define ATK_TAB_TITLE_MAX 32

typedef void (*atk_tab_view_change_t)(atk_widget_t *tab_view, void *context, size_t new_index);

/*
 * Create a tab view widget as a child of `window`.
 *
 * A tab view owns a set of pages (content widgets) and draws a tab strip for
 * switching the active page.
 */
atk_widget_t *atk_window_add_tab_view(atk_widget_t *window, int x, int y, int width, int height);

/*
 * Add a page to a tab view.
 *
 * `content` becomes a child of the tab view. Returns false on allocation failure
 * or invalid input.
 */
bool atk_tab_view_add_page(atk_widget_t *tab_view, const char *title, atk_widget_t *content);

/* Set the active page index (clamped to available pages). */
void atk_tab_view_set_active(atk_widget_t *tab_view, size_t index);

/* Return the current active page index. */
size_t atk_tab_view_active(const atk_widget_t *tab_view);

/* Return the currently active content widget (or NULL if no pages exist). */
atk_widget_t *atk_tab_view_active_content(const atk_widget_t *tab_view);

/* Install a callback invoked when the active page changes. */
void atk_tab_view_set_change_handler(atk_widget_t *tab_view, atk_tab_view_change_t handler, void *context);

/* Recompute layout after size changes. */
void atk_tab_view_relayout(atk_widget_t *tab_view);

/* Return true if an absolute point lies within the tab view bounds. */
bool atk_tab_view_contains_point(const atk_widget_t *tab_view, int px, int py);

/*
 * Handle a mouse event for the tab view.
 *
 * Returns true if the tab view consumed the event (tab clicks, scroll, etc.).
 */
bool atk_tab_view_handle_mouse(atk_widget_t *tab_view, const atk_mouse_event_t *event);

/* Return true if an absolute point lies within the tab bar strip. */
bool atk_tab_view_point_in_tab_bar(const atk_widget_t *tab_view, int px, int py);

/* Draw the tab view into the current backbuffer. */
void atk_tab_view_draw(const struct atk_state *state, const atk_widget_t *tab_view);

/* Destroy resources owned by the tab view and its pages. */
void atk_tab_view_destroy(atk_widget_t *tab_view);

extern const atk_class_t ATK_TAB_VIEW_CLASS;

#endif
