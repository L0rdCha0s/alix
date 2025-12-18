#ifndef ATK_RADIO_H
#define ATK_RADIO_H

#include "atk/object.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

typedef struct atk_radio_group atk_radio_group_t;
typedef void (*atk_radio_change_t)(atk_widget_t *radio, void *context, bool selected);

/* Create/destroy a radio group which enforces single selection among members. */
atk_radio_group_t *atk_radio_group_create(void);
void atk_radio_group_destroy(atk_radio_group_t *group);

/*
 * Create a radio button widget as a child of `window` and add it to `group`.
 *
 * The radio button draws a circular selector followed by an optional label.
 */
atk_widget_t *atk_window_add_radio_button(atk_widget_t *window,
                                         atk_radio_group_t *group,
                                         const char *label,
                                         int rel_x,
                                         int rel_y,
                                         int width);

/* Update the radio button label text (NULL becomes empty). */
void atk_radio_button_set_label(atk_widget_t *radio, const char *label);

/* Return the current label string (always non-NULL). */
const char *atk_radio_button_label(const atk_widget_t *radio);

/* Return the group this radio button belongs to (may be NULL if ungrouped). */
const atk_radio_group_t *atk_radio_button_group(const atk_widget_t *radio);

/* Set a callback invoked when the selected state changes due to user input. */
void atk_radio_button_set_change_handler(atk_widget_t *radio, atk_radio_change_t handler, void *context);

/* Set/get selected state. Selecting true clears other members in the group. */
void atk_radio_button_set_selected(atk_widget_t *radio, bool selected);
bool atk_radio_button_selected(const atk_widget_t *radio);

/* Mark the radio button region dirty without changing state. */
void atk_radio_button_mark_dirty(const atk_widget_t *radio);

/* Draw the radio button into the current backbuffer. */
void atk_radio_button_draw(const struct atk_state *state, const atk_widget_t *radio);

/* Destroy resources owned by the radio button widget (label, group membership). */
void atk_radio_button_destroy(atk_widget_t *radio);

extern const atk_class_t ATK_RADIO_BUTTON_CLASS;

#ifdef __cplusplus
}
#endif

#endif /* ATK_RADIO_H */

