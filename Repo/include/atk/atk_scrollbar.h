#ifndef ATK_SCROLLBAR_H
#define ATK_SCROLLBAR_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

typedef enum
{
    ATK_SCROLLBAR_VERTICAL = 0,
    ATK_SCROLLBAR_HORIZONTAL = 1
} atk_scrollbar_orientation_t;

typedef void (*atk_scrollbar_change_t)(atk_widget_t *scrollbar, void *context, int value);

/*
 * Create a scrollbar widget as a child of `window`.
 *
 * The scrollbar manages a numeric value in a configured range and emits
 * callbacks on change. It is commonly used by list views and rich text.
 */
atk_widget_t *atk_window_add_scrollbar(atk_widget_t *window,
                                       int x,
                                       int y,
                                       int width,
                                       int height,
                                       atk_scrollbar_orientation_t orientation);

/* Set a callback invoked whenever the value changes (dragging or programmatic). */
void atk_scrollbar_set_change_handler(atk_widget_t *scrollbar, atk_scrollbar_change_t handler, void *context);

/*
 * Configure the scrollbar range and page size.
 *
 * - `min_value`/`max_value` define the scrollable range.
 * - `page_size` is the visible window size; it affects thumb size/clamping.
 */
void atk_scrollbar_set_range(atk_widget_t *scrollbar, int min_value, int max_value, int page_size);

/* Set the current value (clamped to range) and mark the widget dirty. */
void atk_scrollbar_set_value(atk_widget_t *scrollbar, int value);

/* Return the current scrollbar value (0 if uninitialized). */
int atk_scrollbar_value(const atk_widget_t *scrollbar);

/* Hit test a scrollbar against an absolute point. */
bool atk_scrollbar_hit_test(const atk_widget_t *scrollbar, int origin_x, int origin_y, int px, int py);

/*
 * Begin a drag operation.
 *
 * Returns true if the scrollbar entered "dragging" mode. If `value_changed` is
 * non-NULL, it is set when the value changed as part of the drag start.
 */
bool atk_scrollbar_begin_drag(atk_widget_t *scrollbar, int px, int py, bool *value_changed);

/*
 * Update an active drag operation.
 *
 * Returns true if the value changed.
 */
bool atk_scrollbar_drag_to(atk_widget_t *scrollbar, int px, int py);

/* End an active drag operation. */
void atk_scrollbar_end_drag(atk_widget_t *scrollbar);

/* Mark the scrollbar region dirty without changing state. */
void atk_scrollbar_mark_dirty(const atk_widget_t *scrollbar);

/* Draw the scrollbar into the current backbuffer. */
void atk_scrollbar_draw(const struct atk_state *state, const atk_widget_t *scrollbar);

/* Destroy resources owned by the scrollbar widget. */
void atk_scrollbar_destroy(atk_widget_t *scrollbar);

extern const atk_class_t ATK_SCROLLBAR_CLASS;

#ifdef __cplusplus
}
#endif

#endif
