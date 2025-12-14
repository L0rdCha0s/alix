#ifndef ATK_DESKTOP_H
#define ATK_DESKTOP_H

#include "atk_button.h"

/*
 * Clear and rebuild the desktop button list.
 *
 * This is typically called on `atk_enter_mode()` and when switching themes or
 * desktop content. It does not affect window state.
 */
void atk_desktop_reset(atk_state_t *state);

/*
 * Draw desktop buttons (icons) that intersect `clip`.
 *
 * The desktop is drawn behind all windows; callers usually invoke this as part
 * of full-scene rendering.
 */
void atk_desktop_draw_buttons(const atk_state_t *state, const atk_rect_t *clip);

/*
 * Add a desktop icon button at absolute screen coordinates.
 *
 * Returns the created button widget, owned by the desktop list, or NULL on
 * allocation failure.
 */
atk_widget_t *atk_desktop_add_button(atk_state_t *state,
                                     int x,
                                     int y,
                                     int width,
                                     int height,
                                     const char *title,
                                     atk_button_style_t style,
                                     bool draggable,
                                     atk_button_action_t action,
                                     void *context);

/*
 * Return the topmost desktop button under an absolute point.
 *
 * This is used by the ATK mouse dispatcher to start icon drags/clicks.
 */
atk_widget_t *atk_desktop_button_hit_test(const atk_state_t *state, int px, int py);

#endif
