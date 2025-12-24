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

/*
 * Create a standalone list view widget.
 *
 * Most callers use `atk_window_add_list_view()` instead to attach it to a window.
 */
atk_widget_t *atk_list_view_create(void);

/*
 * Create a list view widget as a child of `window`.
 *
 * A list view is a simple table with a header row and optional selection.
 */
atk_widget_t *atk_window_add_list_view(atk_widget_t *window, int x, int y, int width, int height);

/*
 * Define the table columns.
 *
 * `defs` must remain valid only for the duration of the call; titles are copied.
 * Returns false on allocation failure or invalid input.
 */
bool atk_list_view_configure_columns(atk_widget_t *list, const atk_list_view_column_def_t *defs, size_t count);

/* Set the number of rows in the list view (cells are cleared as needed). */
void atk_list_view_set_row_count(atk_widget_t *list, size_t rows);

/* Set cell text for a specific row/column (text is copied). */
void atk_list_view_set_cell_text(atk_widget_t *list, size_t row, size_t column, const char *text);

/* Clear all rows/cells and reset selection. */
void atk_list_view_clear(atk_widget_t *list);

/* Return the current row count. */
size_t atk_list_view_row_count(const atk_widget_t *list);

/* Return the current column count. */
size_t atk_list_view_column_count(const atk_widget_t *list);

/* Programmatically select a row (use `ATK_LIST_VIEW_NO_SELECTION` to clear). */
void atk_list_view_set_selected(atk_widget_t *list, size_t row);

/* Return the currently selected row or `ATK_LIST_VIEW_NO_SELECTION`. */
size_t atk_list_view_selected(const atk_widget_t *list);

/*
 * Install a selection change callback.
 *
 * Called when the user clicks a row or selection changes programmatically.
 */
void atk_list_view_set_select_handler(atk_widget_t *list, atk_list_view_select_t handler, void *context);

/*
 * Force a vertical scrollbar to appear even if content fits.
 *
 * Useful when embedding in resizable layouts to prevent horizontal jitter.
 */
void atk_list_view_force_vertical_scrollbar(atk_widget_t *list, bool force);

/* Enable/disable the list view (inactive lists may ignore input). */
void atk_list_view_set_active(atk_widget_t *list, bool active);

/* Draw the list view into the current backbuffer. */
void atk_list_view_draw(const struct atk_state *state, const atk_widget_t *list);

/* Destroy resources owned by the list view widget. */
void atk_list_view_destroy(atk_widget_t *list);

/* Recompute layout after size changes (columns, scrollbar, header). */
void atk_list_view_relayout(atk_widget_t *list);

/* Return true if (local_x, local_y) lies on a column resize separator. */
bool atk_list_view_is_over_separator(const atk_widget_t *list, int local_x, int local_y);

/*
 * Return the row index under (local_x, local_y).
 *
 * Returns `ATK_LIST_VIEW_NO_SELECTION` when no row hits.
 */
size_t atk_list_view_row_at(atk_widget_t *list, int local_x, int local_y);

extern const atk_class_t ATK_LIST_VIEW_CLASS;

#ifdef __cplusplus
}
#endif

#endif
