#ifndef ATK_MENU_H
#define ATK_MENU_H

#include "atk/object.h"

struct atk_state;

typedef void (*atk_menu_action_t)(void *context);

#define ATK_MENU_ITEM_TITLE_MAX 64

/*
 * Create a floating menu widget.
 *
 * Menus are typically used by the global menu bar and dropdown-style widgets.
 */
atk_widget_t *atk_menu_create(void);

/* Destroy menu-owned resources and the menu widget. */
void atk_menu_destroy(atk_widget_t *menu);

/*
 * Add an item to the menu.
 *
 * The title is copied (truncated to `ATK_MENU_ITEM_TITLE_MAX - 1`).
 */
bool atk_menu_add_item(atk_widget_t *menu,
                       const char *title,
                       atk_menu_action_t action,
                       void *context);

/* Remove all items from the menu. */
void atk_menu_clear(atk_widget_t *menu);

/* Show the menu with its top-left corner at (x,y) in screen space. */
void atk_menu_show(atk_widget_t *menu, int x, int y);

/* Hide the menu (no-op if already hidden). */
void atk_menu_hide(atk_widget_t *menu);

/* Return true if the menu is currently visible. */
bool atk_menu_is_visible(const atk_widget_t *menu);

/* Return true if an absolute point lies within the menu bounds. */
bool atk_menu_contains(const atk_widget_t *menu, int px, int py);

/*
 * Handle a click at an absolute point.
 *
 * Returns true if an item was activated (and its action invoked).
 */
bool atk_menu_handle_click(atk_widget_t *menu, int px, int py);

/*
 * Update hover state for an absolute point.
 *
 * Returns true if the hover item changed (caller should redraw).
 */
bool atk_menu_update_hover(atk_widget_t *menu, int px, int py);

/* Draw the menu into the current backbuffer. */
void atk_menu_draw(const struct atk_state *state, const atk_widget_t *menu);

#endif
