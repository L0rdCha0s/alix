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

typedef struct
{
    const char *title;
    int width; /* pixels; <=0 means flex */
} atk_list_view_column_def_t;

atk_widget_t *atk_list_view_create(void);
atk_widget_t *atk_window_add_list_view(atk_widget_t *window, int x, int y, int width, int height);
bool atk_list_view_configure_columns(atk_widget_t *list, const atk_list_view_column_def_t *defs, size_t count);
void atk_list_view_set_row_count(atk_widget_t *list, size_t rows);
void atk_list_view_set_cell_text(atk_widget_t *list, size_t row, size_t column, const char *text);
void atk_list_view_clear(atk_widget_t *list);
size_t atk_list_view_row_count(const atk_widget_t *list);
size_t atk_list_view_column_count(const atk_widget_t *list);
void atk_list_view_draw(const struct atk_state *state, const atk_widget_t *list);
void atk_list_view_destroy(atk_widget_t *list);
void atk_list_view_relayout(atk_widget_t *list);

extern const atk_class_t ATK_LIST_VIEW_CLASS;

#ifdef __cplusplus
}
#endif

#endif
