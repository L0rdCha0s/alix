#ifndef ATK_DROPDOWN_H
#define ATK_DROPDOWN_H

#include "atk/object.h"
#include "types.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    ATK_DROPDOWN_STYLE_COMBO = 0,
    ATK_DROPDOWN_STYLE_MENU = 1,
} atk_dropdown_style_t;

typedef void (*atk_dropdown_select_t)(atk_widget_t *dropdown,
                                      void *context,
                                      size_t index,
                                      uintptr_t value);

/*
 * Create a dropdown widget as a child of `window`.
 *
 * - `ATK_DROPDOWN_STYLE_COMBO`: displays a selected value and opens a list.
 * - `ATK_DROPDOWN_STYLE_MENU`: behaves like a menu button (no persistent selection).
 *
 * When an item is selected, `on_select` is invoked with the selected index/value.
 */
atk_widget_t *atk_window_add_dropdown(atk_widget_t *window,
                                      int x,
                                      int y,
                                      int width,
                                      int height,
                                      atk_dropdown_style_t style,
                                      atk_dropdown_select_t on_select,
                                      void *context);

/* Remove all items and reset selection/open state. */
void atk_dropdown_clear(atk_widget_t *dropdown);

/* Append an item (title/value) to the dropdown. Returns false on allocation failure. */
bool atk_dropdown_add_item(atk_widget_t *dropdown, const char *title, uintptr_t value);

/* Return the current item count. */
size_t atk_dropdown_count(const atk_widget_t *dropdown);

/* Set the title shown when no selection is active (or for menu-style dropdowns). */
void atk_dropdown_set_title(atk_widget_t *dropdown, const char *title);

/* Return the current title string (always non-NULL). */
const char *atk_dropdown_title(const atk_widget_t *dropdown);

/*
 * Set the selected item index.
 *
 * For combo-style dropdowns this updates the visible selection and may trigger
 * `on_select`. Returns false for out-of-range indices.
 */
bool atk_dropdown_set_selected(atk_widget_t *dropdown, size_t index);

/* Return the selected index, or (size_t)-1 if nothing is selected. */
size_t atk_dropdown_selected(const atk_widget_t *dropdown);

/* Return the selected value, or 0 if nothing is selected. */
uintptr_t atk_dropdown_selected_value(const atk_widget_t *dropdown);

/* Return the selected title string, or "" if nothing is selected. */
const char *atk_dropdown_selected_title(const atk_widget_t *dropdown);

/* Return whether the dropdown list is currently open. */
bool atk_dropdown_is_open(const atk_widget_t *dropdown);

/* Programmatically open/close the dropdown list. */
void atk_dropdown_set_open(atk_widget_t *dropdown, bool open);

#ifdef __cplusplus
}
#endif

#endif
