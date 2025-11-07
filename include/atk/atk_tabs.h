#ifndef ATK_TABS_H
#define ATK_TABS_H

#include "atk/object.h"

struct atk_state;

#define ATK_TAB_TITLE_MAX 32

typedef void (*atk_tab_view_change_t)(atk_widget_t *tab_view, void *context, size_t new_index);

atk_widget_t *atk_window_add_tab_view(atk_widget_t *window, int x, int y, int width, int height);
bool atk_tab_view_add_page(atk_widget_t *tab_view, const char *title, atk_widget_t *content);
void atk_tab_view_set_active(atk_widget_t *tab_view, size_t index);
size_t atk_tab_view_active(const atk_widget_t *tab_view);
atk_widget_t *atk_tab_view_active_content(const atk_widget_t *tab_view);
void atk_tab_view_set_change_handler(atk_widget_t *tab_view, atk_tab_view_change_t handler, void *context);
void atk_tab_view_relayout(atk_widget_t *tab_view);
bool atk_tab_view_contains_point(const atk_widget_t *tab_view, int px, int py);
bool atk_tab_view_handle_mouse(atk_widget_t *tab_view, int px, int py);
void atk_tab_view_draw(const struct atk_state *state, const atk_widget_t *tab_view);
void atk_tab_view_destroy(atk_widget_t *tab_view);

extern const atk_class_t ATK_TAB_VIEW_CLASS;

#endif
