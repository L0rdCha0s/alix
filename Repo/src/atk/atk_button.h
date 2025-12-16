#ifndef ATK_BUTTON_H
#define ATK_BUTTON_H

#include "atk_internal.h"

/*
 * Configure a widget as an ATK button.
 *
 * This installs the button ops, sets the label/style, and wires an optional
 * `action` callback invoked by `atk_button_invoke()`.
 *
 * - `draggable` is used by the desktop and some containers to enable drag moves.
 * - `absolute` selects "desktop icon" styling (vs. window chrome styling).
 */
void atk_button_configure(atk_widget_t *widget,
                          const char *title,
                          atk_button_style_t style,
                          bool draggable,
                          bool absolute,
                          atk_button_action_t action,
                          void *context);

/* Update the button title and mark its area dirty. */
void atk_button_set_title(atk_widget_t *widget, const char *title);

/*
 * Return the effective pixel height used for hit testing and layout.
 *
 * For `ATK_BUTTON_STYLE_TITLE_BELOW`, this includes the extra label block under
 * the button face.
 */
int atk_button_effective_height(const atk_widget_t *widget);

/*
 * Hit test a button against an absolute point.
 *
 * `origin_x`/`origin_y` are the absolute position of the parent/container.
 */
bool atk_button_hit_test(const atk_widget_t *widget, int origin_x, int origin_y, int px, int py);

/*
 * Draw a button into the current clip/scene.
 *
 * This is typically called by window/desktop drawing code rather than directly
 * by apps.
 */
void atk_button_draw(const atk_state_t *state, const atk_widget_t *widget, int origin_x, int origin_y);

/* Return the current title string (always non-NULL). */
const char *atk_button_title(const atk_widget_t *widget);

/* Return true if the button is marked draggable. */
bool atk_button_is_draggable(const atk_widget_t *widget);

/* Return true if the button uses "desktop icon" styling. */
bool atk_button_is_absolute(const atk_widget_t *widget);

/*
 * Invoke the button action callback, if present.
 *
 * This does not perform hit testing; callers should only invoke when a click
 * is confirmed.
 */
void atk_button_invoke(atk_widget_t *widget);

#endif
