#ifndef ATK_CHECKBOX_H
#define ATK_CHECKBOX_H

#include "atk/object.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

typedef void (*atk_checkbox_change_t)(atk_widget_t *checkbox, void *context, bool checked);

/*
 * Create a checkbox widget as a child of `window`.
 *
 * The checkbox draws a toggle box followed by an optional label string.
 */
atk_widget_t *atk_window_add_checkbox(atk_widget_t *window,
                                      const char *label,
                                      int rel_x,
                                      int rel_y,
                                      int width);

/* Update the checkbox label text (NULL becomes empty). */
void atk_checkbox_set_label(atk_widget_t *checkbox, const char *label);

/* Return the current label string (always non-NULL). */
const char *atk_checkbox_label(const atk_widget_t *checkbox);

/* Set a callback invoked when the checked state changes due to user input. */
void atk_checkbox_set_change_handler(atk_widget_t *checkbox, atk_checkbox_change_t handler, void *context);

/* Set/get the checked state. */
void atk_checkbox_set_checked(atk_widget_t *checkbox, bool checked);
bool atk_checkbox_checked(const atk_widget_t *checkbox);

/* Mark the checkbox region dirty without changing state. */
void atk_checkbox_mark_dirty(const atk_widget_t *checkbox);

/* Draw the checkbox into the current backbuffer. */
void atk_checkbox_draw(const struct atk_state *state, const atk_widget_t *checkbox);

/* Destroy resources owned by the checkbox widget (label). */
void atk_checkbox_destroy(atk_widget_t *checkbox);

extern const atk_class_t ATK_CHECKBOX_CLASS;

#ifdef __cplusplus
}
#endif

#endif /* ATK_CHECKBOX_H */

