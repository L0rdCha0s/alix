#ifndef ATK_ICONBOX_H
#define ATK_ICONBOX_H

#include "atk_button.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

/*
 * Create an iconbox widget as a child of `window`.
 *
 * An iconbox is a grid container for button-style icons.
 */
atk_widget_t *atk_window_add_iconbox(atk_widget_t *window, int x, int y, int width, int height);

/* Enable/disable the iconbox (inactive boxes may ignore input). */
void atk_iconbox_set_active(atk_widget_t *iconbox, bool active);

/*
 * Add an icon button to the iconbox.
 *
 * Returns false on allocation failure. The iconbox owns the created widget.
 */
bool atk_iconbox_add_icon(atk_widget_t *iconbox, const char *title, atk_button_action_t action, void *context);

/* Remove all icons from the iconbox. */
void atk_iconbox_clear(atk_widget_t *iconbox);

/* Recompute layout of icons after size changes. */
void atk_iconbox_relayout(atk_widget_t *iconbox);

/* Return the number of icons currently in the iconbox. */
size_t atk_iconbox_count(const atk_widget_t *iconbox);

extern const atk_class_t ATK_ICONBOX_CLASS;

#ifdef __cplusplus
}
#endif

#endif
