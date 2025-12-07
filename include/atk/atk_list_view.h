#ifndef ATK_LIST_VIEW_H
#define ATK_LIST_VIEW_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

#define ATK_LIST_VIEW_MAX_COLUMNS 12
#define ATK_LIST_VIEW_COLUMN_TITLE_MAX 24
#define ATK_LIST_VIEW_CELL_TEXT_MAX 64
#define ATK_LIST_VIEW_NO_SELECTION ((size_t)-1)

typedef struct
{
    const char *title;
    int width; /* pixels; <=0 means flex */
} atk_list_view_column_def_t;

typedef void (*atk_list_view_select_t)(atk_widget_t *list, void *context, size_t row);

atk_widget_t *atk_list_view_create(void);
atk_widget_t *atk_window_add_list_view(atk_widget_t *window, int x, int y, int width, int height);
bool atk_list_view_configure_columns(atk_widget_t *list, const atk_list_view_column_def_t *defs, size_t count);
void atk_list_view_set_row_count(atk_widget_t *list, size_t rows);
void atk_list_view_set_cell_text(atk_widget_t *list, size_t row, size_t column, const char *text);
void atk_list_view_clear(atk_widget_t *list);
size_t atk_list_view_row_count(const atk_widget_t *list);
size_t atk_list_view_column_count(const atk_widget_t *list);
void atk_list_view_set_selected(atk_widget_t *list, size_t row);
size_t atk_list_view_selected(const atk_widget_t *list);
void atk_list_view_set_select_handler(atk_widget_t *list, atk_list_view_select_t handler, void *context);
void atk_list_view_force_vertical_scrollbar(atk_widget_t *list, bool force);
void atk_list_view_draw(const struct atk_state *state, const atk_widget_t *list);
void atk_list_view_destroy(atk_widget_t *list);
void atk_list_view_relayout(atk_widget_t *list);
bool atk_list_view_is_over_separator(const atk_widget_t *list, int local_x, int local_y);

extern const atk_class_t ATK_LIST_VIEW_CLASS;

#ifdef __cplusplus
}
#endif

#endif
