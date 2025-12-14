#ifndef ATK_LABEL_H
#define ATK_LABEL_H

#include "atk/object.h"
#include "types.h"
#include <stddef.h>

struct atk_state;

/*
 * Create a label widget as a child of `window`.
 *
 * Labels render wrapped, multi-line text into their rectangle.
 */
atk_widget_t *atk_window_add_label(atk_widget_t *window, int x, int y, int width, int height);

/* Replace the label text and mark the label area dirty. */
void atk_label_set_text(atk_widget_t *label, const char *text);

/* Append to the label text and mark the label area dirty. */
void atk_label_append_text(atk_widget_t *label, const char *text);

/* Return the current label text buffer (always non-NULL). */
const char *atk_label_text(const atk_widget_t *label);

/*
 * Scroll the label to a specific wrapped line index.
 *
 * This disables "stick to bottom" behavior until `atk_label_scroll_to_bottom()`
 * is called again.
 */
void atk_label_scroll_to_line(atk_widget_t *label, size_t line);

/*
 * Scroll the label to show the end of the text.
 *
 * This enables "stick to bottom" behavior so appends keep the view anchored.
 */
void atk_label_scroll_to_bottom(atk_widget_t *label);

/* Draw the label into the current backbuffer. */
void atk_label_draw(const struct atk_state *state, const atk_widget_t *label);

/* Destroy label-owned resources (text buffer). */
void atk_label_destroy(atk_widget_t *label);

#endif
