#ifndef ATK_MENU_H
#define ATK_MENU_H

#include "atk/object.h"

struct atk_state;

typedef void (*atk_menu_action_t)(void *context);

#define ATK_MENU_ITEM_TITLE_MAX 64

atk_widget_t *atk_menu_create(void);
void atk_menu_destroy(atk_widget_t *menu);
bool atk_menu_add_item(atk_widget_t *menu,
                       const char *title,
                       atk_menu_action_t action,
                       void *context);
void atk_menu_clear(atk_widget_t *menu);
void atk_menu_show(atk_widget_t *menu, int x, int y);
void atk_menu_hide(atk_widget_t *menu);
bool atk_menu_is_visible(const atk_widget_t *menu);
bool atk_menu_contains(const atk_widget_t *menu, int px, int py);
bool atk_menu_handle_click(atk_widget_t *menu, int px, int py);
bool atk_menu_update_hover(atk_widget_t *menu, int px, int py);
void atk_menu_draw(const struct atk_state *state, const atk_widget_t *menu);

#endif
