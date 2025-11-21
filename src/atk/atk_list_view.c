#include "atk/atk_list_view.h"

#include "atk_internal.h"
#include "atk/atk_scrollbar.h"
#include "video.h"
#include "libc.h"
#include "atk/atk_font.h"
#include <stdint.h>

#if ATK_LIST_VIEW_MAX_COLUMNS < 10
#error "ATK_LIST_VIEW_MAX_COLUMNS must be at least 10 to support task manager views"
#endif

#define ATK_LIST_VIEW_MIN_COLUMN_WIDTH      (ATK_FONT_WIDTH * 4)
#define ATK_LIST_VIEW_RESIZE_MARGIN         4
#define ATK_LIST_VIEW_SCROLLBAR_SIZE        14

typedef struct
{
    char text[ATK_LIST_VIEW_CELL_TEXT_MAX];
} atk_list_view_cell_t;

typedef struct
{
    char title[ATK_LIST_VIEW_COLUMN_TITLE_MAX];
    int width;
    bool flexible;
} atk_list_view_column_t;

typedef struct
{
    atk_list_view_column_t columns[ATK_LIST_VIEW_MAX_COLUMNS];
    size_t column_count;
    atk_list_view_cell_t *cells;
    size_t cell_capacity;
    size_t row_count;
    int header_height;
    int header_visible_height;
    int row_height;
    int cell_padding;
    atk_widget_t *vscroll;
    atk_widget_t *hscroll;
    int scrollbar_size;
    int scroll_row;
    int scroll_x;
    int client_width;
    int client_height;
    int content_width;
    int content_height;
    int hover_separator;
    atk_list_node_t *list_node;
    bool resizing;
    size_t resizing_column;
    int resize_start_x;
    int resize_width_left;
    int resize_width_right;
    int last_layout_width;
    int last_layout_height;
    bool layout_dirty;
} atk_list_view_priv_t;

static void list_view_mark_dirty(const atk_widget_t *list);
static atk_widget_t *list_view_window(const atk_widget_t *list);
static void list_view_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value);
static int list_view_layout_columns(atk_list_view_priv_t *priv, int client_width);
static void list_view_update_scrollbars(atk_widget_t *list,
                                        atk_list_view_priv_t *priv,
                                        bool need_vscroll,
                                        bool need_hscroll,
                                        int client_width,
                                        int client_height,
                                        int header_h,
                                        int visible_rows,
                                        int max_scroll_row,
                                        int max_scroll_x);
static void list_view_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context);
static void list_view_destroy_cb(atk_widget_t *widget, void *context);

static atk_list_view_priv_t *list_priv_mut(atk_widget_t *list);
static const atk_list_view_priv_t *list_priv(const atk_widget_t *list);
static void list_view_sync_layout(atk_widget_t *list, atk_list_view_priv_t *priv);
static size_t list_view_hit_separator(const atk_widget_t *list,
                                      const atk_list_view_priv_t *priv,
                                      int cursor_x,
                                      int cursor_y);
static void list_view_update_hover(atk_widget_t *list,
                                   atk_list_view_priv_t *priv,
                                   int cursor_x,
                                   int cursor_y);
static bool list_view_apply_column_resize(atk_widget_t *list,
                                          atk_list_view_priv_t *priv,
                                          int cursor_x);
static atk_mouse_response_t list_view_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context);
static bool list_view_ensure_capacity(atk_list_view_priv_t *priv, size_t rows);

static const atk_widget_vtable_t list_view_vtable = { 0 };
static const atk_widget_ops_t g_list_view_ops = {
    .destroy = list_view_destroy_cb,
    .draw = list_view_draw_cb,
    .hit_test = NULL,
    .on_mouse = list_view_mouse_cb,
    .on_key = NULL
};
const atk_class_t ATK_LIST_VIEW_CLASS = { "ListView", &ATK_WIDGET_CLASS, &list_view_vtable, sizeof(atk_list_view_priv_t) };

atk_widget_t *atk_list_view_create(void)
{
    atk_widget_t *widget = atk_widget_create(&ATK_LIST_VIEW_CLASS);
    if (!widget)
    {
        return NULL;
    }

    widget->used = true;
    widget->x = 0;
    widget->y = 0;
    widget->width = 0;
    widget->height = 0;
    widget->parent = NULL;
    atk_widget_set_ops(widget, &g_list_view_ops, NULL);

    atk_list_view_priv_t *priv = list_priv_mut(widget);
    if (!priv)
    {
        atk_widget_destroy(widget);
        return NULL;
    }

    priv->column_count = 0;
    priv->cells = NULL;
    priv->cell_capacity = 0;
    priv->row_count = 0;
    int line_height = atk_font_line_height();
    priv->header_height = line_height + 6;
    priv->header_visible_height = 0;
    priv->row_height = line_height + 4;
    priv->cell_padding = 4;
    priv->vscroll = NULL;
    priv->hscroll = NULL;
    priv->scrollbar_size = ATK_LIST_VIEW_SCROLLBAR_SIZE;
    priv->scroll_row = 0;
    priv->scroll_x = 0;
    priv->client_width = 0;
    priv->client_height = 0;
    priv->content_width = 0;
    priv->content_height = 0;
    priv->hover_separator = -1;
    priv->list_node = NULL;
    priv->resizing = false;
    priv->resizing_column = 0;
    priv->resize_start_x = 0;
    priv->resize_width_left = 0;
    priv->resize_width_right = 0;
    priv->last_layout_width = -1;
    priv->last_layout_height = -1;
    priv->layout_dirty = true;

    return widget;
}

atk_widget_t *atk_window_add_list_view(atk_widget_t *window, int x, int y, int width, int height)
{
    if (!window || width <= 0 || height <= 0)
    {
        return NULL;
    }

    atk_window_priv_t *priv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!priv)
    {
        return NULL;
    }

    atk_widget_t *list = atk_list_view_create();
    if (!list)
    {
        return NULL;
    }

    list->x = x;
    list->y = y;
    list->width = width;
    list->height = height;
    list->parent = window;

    atk_list_node_t *child_node = atk_list_push_back(&priv->children, list);
    if (!child_node)
    {
        atk_list_view_destroy(list);
        atk_widget_destroy(list);
        return NULL;
    }

    atk_list_view_priv_t *list_priv = list_priv_mut(list);
    list_priv->list_node = child_node;
    return list;
}

bool atk_list_view_configure_columns(atk_widget_t *list, const atk_list_view_column_def_t *defs, size_t count)
{
    atk_list_view_priv_t *priv = list_priv_mut(list);
    if (!priv || !defs || count == 0 || count > ATK_LIST_VIEW_MAX_COLUMNS)
    {
        return false;
    }

    priv->column_count = count;
    for (size_t i = 0; i < count; ++i)
    {
        const atk_list_view_column_def_t *def = &defs[i];
        atk_list_view_column_t *col = &priv->columns[i];
        if (def->title)
        {
            size_t len = strlen(def->title);
            if (len >= ATK_LIST_VIEW_COLUMN_TITLE_MAX)
            {
                len = ATK_LIST_VIEW_COLUMN_TITLE_MAX - 1;
            }
            memcpy(col->title, def->title, len);
            col->title[len] = '\0';
        }
        else
        {
            col->title[0] = '\0';
        }
        if (def->width <= 0)
        {
            col->width = ATK_LIST_VIEW_MIN_COLUMN_WIDTH;
            col->flexible = true;
        }
        else
        {
            col->width = def->width;
            col->flexible = false;
        }
    }

    priv->row_count = 0;
    priv->scroll_row = 0;
    priv->scroll_x = 0;
    priv->layout_dirty = true;
    priv->last_layout_width = -1;
    priv->last_layout_height = -1;
    priv->hover_separator = -1;
    return true;
}

void atk_list_view_set_row_count(atk_widget_t *list, size_t rows)
{
    atk_list_view_priv_t *priv = list_priv_mut(list);
    if (!priv || priv->column_count == 0)
    {
        return;
    }
    if (!list_view_ensure_capacity(priv, rows))
    {
        return;
    }
    priv->row_count = rows;
    if (rows == 0)
    {
        priv->scroll_row = 0;
    }
    else if (priv->scroll_row >= (int)rows)
    {
        priv->scroll_row = (int)rows - 1;
    }
    priv->layout_dirty = true;
}

void atk_list_view_set_cell_text(atk_widget_t *list, size_t row, size_t column, const char *text)
{
    atk_list_view_priv_t *priv = list_priv_mut(list);
    if (!priv || row >= priv->row_count || column >= priv->column_count)
    {
        return;
    }

    size_t index = row * priv->column_count + column;
    if (!priv->cells || index >= priv->cell_capacity)
    {
        return;
    }

    atk_list_view_cell_t *cell = &priv->cells[index];
    if (!text)
    {
        cell->text[0] = '\0';
        return;
    }

    size_t len = strlen(text);
    if (len >= ATK_LIST_VIEW_CELL_TEXT_MAX)
    {
        len = ATK_LIST_VIEW_CELL_TEXT_MAX - 1;
    }
    memcpy(cell->text, text, len);
    cell->text[len] = '\0';
}

void atk_list_view_clear(atk_widget_t *list)
{
    atk_list_view_priv_t *priv = list_priv_mut(list);
    if (!priv)
    {
        return;
    }
    priv->row_count = 0;
    priv->scroll_row = 0;
    priv->scroll_x = 0;
    priv->hover_separator = -1;
    priv->layout_dirty = true;
}

size_t atk_list_view_row_count(const atk_widget_t *list)
{
    const atk_list_view_priv_t *priv = list_priv(list);
    return priv ? priv->row_count : 0;
}

size_t atk_list_view_column_count(const atk_widget_t *list)
{
    const atk_list_view_priv_t *priv = list_priv(list);
    return priv ? priv->column_count : 0;
}

bool atk_list_view_is_over_separator(const atk_widget_t *list, int local_x, int local_y)
{
    const atk_list_view_priv_t *priv = list_priv(list);
    if (!priv || priv->column_count < 2)
    {
        return false;
    }
    int header_h = priv->header_visible_height;
    if (local_y < 0 || local_y >= header_h)
    {
        return false;
    }
    if (local_x < 0 || local_x >= priv->client_width)
    {
        return false;
    }

    int boundary = -priv->scroll_x;
    for (size_t i = 0; i < priv->column_count - 1; ++i)
    {
        boundary += priv->columns[i].width;
        if (local_x >= boundary - ATK_LIST_VIEW_RESIZE_MARGIN &&
            local_x <= boundary + ATK_LIST_VIEW_RESIZE_MARGIN)
        {
            return true;
        }
    }
    return false;
}

void atk_list_view_draw(const atk_state_t *state, const atk_widget_t *list)
{
    atk_list_view_priv_t *priv_mut = list_priv_mut((atk_widget_t *)list);
    if (!state || !list || !list->used || !priv_mut || list->width <= 0 || list->height <= 0 || priv_mut->column_count == 0)
    {
        return;
    }
    atk_list_view_priv_t *priv_write = priv_mut;
    list_view_sync_layout((atk_widget_t *)list, priv_write);
    const atk_list_view_priv_t *priv = (const atk_list_view_priv_t *)priv_write;

    atk_state_theme_validate(state, "atk_list_view_draw");

    int origin_x = 0;
    int origin_y = 0;
    atk_widget_absolute_position(list, &origin_x, &origin_y);

    const atk_theme_t *theme = &state->theme;
    video_draw_rect(origin_x, origin_y, list->width, list->height, theme->window_body);

    int client_width = list->width;
    int client_height = list->height;
    if (priv->vscroll && priv->vscroll->used)
    {
        client_width -= priv->vscroll->width;
    }
    if (priv->hscroll && priv->hscroll->used)
    {
        client_height -= priv->hscroll->height;
    }

    if (client_width <= 0 || client_height <= 0 || priv->row_height <= 0)
    {
        video_draw_rect_outline(origin_x, origin_y, list->width, list->height, theme->window_border);
        return;
    }

    int header_h = priv->header_visible_height;
    if (header_h < 0)
    {
        header_h = 0;
    }
    if (header_h > client_height)
    {
        header_h = client_height;
    }

    if (header_h > 0 && client_width > 0)
    {
        video_draw_rect(origin_x, origin_y, client_width, header_h, theme->button_face);
    }

    int row_area_height = client_height - header_h;
    if (row_area_height < 0)
    {
        row_area_height = 0;
    }

    int clip_left = origin_x;
    int clip_right = origin_x + client_width;

    int column_x = origin_x - priv->scroll_x;
    if (header_h > 0)
    {
        for (size_t c = 0; c < priv->column_count; ++c)
        {
            const atk_list_view_column_t *col = &priv->columns[c];
            int col_width = col->width;
            if (col_width <= 0)
            {
                column_x += col_width;
                continue;
            }

            int col_end = column_x + col_width;
            if (col_end <= clip_left)
            {
                column_x = col_end;
                continue;
            }
            if (column_x >= clip_right)
            {
                break;
            }

            int visible_width = col_end > clip_right ? (clip_right - column_x) : col_width;
            if (visible_width <= 0)
            {
                column_x = col_end;
                continue;
            }

            int text_x = column_x + priv->cell_padding;
            if (text_x < column_x)
            {
                text_x = column_x;
            }
            int baseline = atk_font_baseline_for_rect(origin_y, header_h);
            atk_rect_t clip = { column_x, origin_y, visible_width, header_h };
            atk_font_draw_string_clipped(text_x,
                                         baseline,
                                         col->title,
                                         theme->button_text,
                                         theme->button_face,
                                         &clip);
            column_x = col_end;
        }
    }

    int row_y = origin_y + header_h;
    size_t visible_rows = (priv->row_height > 0 && row_area_height >= priv->row_height)
                              ? (size_t)(row_area_height / priv->row_height)
                              : 0;
    size_t row_index = (priv->scroll_row >= 0) ? (size_t)priv->scroll_row : 0;
    video_color_t stripe_colors[2] = { theme->window_body, theme->button_face };

    for (size_t drawn = 0; drawn < visible_rows && row_index < priv->row_count; ++drawn, ++row_index)
    {
        int row_height = priv->row_height;
        if (row_y + row_height > origin_y + client_height)
        {
            row_height = origin_y + client_height - row_y;
            if (row_height <= 0)
            {
                break;
            }
        }

        video_color_t row_bg = stripe_colors[row_index % 2];
        if (row_height > 0 && client_width > 0)
        {
            video_draw_rect(origin_x, row_y, client_width, row_height, row_bg);
        }

        int cell_x = origin_x - priv->scroll_x;
        for (size_t column = 0; column < priv->column_count; ++column)
        {
            const atk_list_view_column_t *col = &priv->columns[column];
            int col_width = col->width;
            if (col_width <= 0)
            {
                cell_x += col_width;
                continue;
            }

            int cell_end = cell_x + col_width;
            if (cell_end <= clip_left)
            {
                cell_x = cell_end;
                continue;
            }
            if (cell_x >= clip_right)
            {
                break;
            }

            size_t cell_index = row_index * priv->column_count + column;
            const char *text = "";
            if (priv->cells && cell_index < priv->cell_capacity)
            {
                text = priv->cells[cell_index].text;
            }

            int visible_width = cell_end > clip_right ? (clip_right - cell_x) : col_width;
            if (visible_width <= 0)
            {
                cell_x = cell_end;
                continue;
            }

            int text_x = cell_x + priv->cell_padding;
            if (text_x < cell_x)
            {
                text_x = cell_x;
            }
            int baseline = atk_font_baseline_for_rect(row_y, row_height);
            atk_rect_t clip = { cell_x, row_y, visible_width, row_height };
            atk_font_draw_string_clipped(text_x, baseline, text, theme->button_text, row_bg, &clip);
            cell_x = cell_end;
        }

        row_y += row_height;
    }

    if (client_width > 0 && client_height > 0 && priv->column_count > 1)
    {
        int line_top = origin_y;
        int line_bottom = origin_y + client_height;
        if (line_bottom > line_top)
        {
            int boundary = origin_x - priv->scroll_x;
            for (size_t i = 0; i < priv->column_count - 1; ++i)
            {
                boundary += priv->columns[i].width;
                if (boundary <= origin_x || boundary >= origin_x + client_width)
                {
                    continue;
                }
                video_draw_rect(boundary, line_top, 1, line_bottom - line_top, theme->window_border);
            }
        }
    }

    if (priv->hover_separator >= 0 && priv->hover_separator < (int)priv->column_count)
    {
        int hover_x = origin_x - priv->scroll_x;
        for (int i = 0; i <= priv->hover_separator; ++i)
        {
            hover_x += priv->columns[i].width;
        }
        if (hover_x >= origin_x && hover_x < origin_x + client_width)
        {
            int line_height = client_height;
            if (line_height < 0)
            {
                line_height = 0;
            }
            video_draw_rect(hover_x, origin_y, 1, line_height, theme->window_border);
        }
    }

    if (header_h > 0)
    {
        video_draw_rect(origin_x,
                        origin_y + header_h - 1,
                        client_width,
                        1,
                        theme->window_border);
    }
    video_draw_rect_outline(origin_x, origin_y, list->width, list->height, theme->window_border);
}

void atk_list_view_destroy(atk_widget_t *list)
{
    atk_list_view_priv_t *priv = list_priv_mut(list);
    if (!priv)
    {
        return;
    }
    if (priv->vscroll)
    {
        priv->vscroll->used = false;
    }
    if (priv->hscroll)
    {
        priv->hscroll->used = false;
    }
    if (priv->cells)
    {
        free(priv->cells);
        priv->cells = NULL;
    }
    priv->cell_capacity = 0;
    priv->row_count = 0;
    priv->column_count = 0;
    priv->list_node = NULL;
    priv->layout_dirty = true;
    priv->hover_separator = -1;
}

void atk_list_view_relayout(atk_widget_t *list)
{
    atk_list_view_priv_t *priv = list_priv_mut(list);
    if (!priv)
    {
        return;
    }
    priv->layout_dirty = true;
    list_view_sync_layout(list, priv);
    list_view_mark_dirty(list);
}

static void list_view_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context)
{
    (void)origin_x;
    (void)origin_y;
    (void)context;
    atk_list_view_draw(state, widget);
}

static void list_view_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_list_view_destroy(widget);
    atk_widget_destroy(widget);
}

static void list_view_mark_dirty(const atk_widget_t *list)
{
    if (!list)
    {
        return;
    }
    int x = 0;
    int y = 0;
    int w = 0;
    int h = 0;
    atk_widget_absolute_bounds(list, &x, &y, &w, &h);
    if (w > 0 && h > 0)
    {
        atk_dirty_mark_rect(x, y, w, h);
    }
}

static atk_widget_t *list_view_window(const atk_widget_t *list)
{
    atk_widget_t *current = list ? list->parent : NULL;
    while (current)
    {
        if (atk_widget_is_a(current, &ATK_WINDOW_CLASS))
        {
            return current;
        }
        current = current->parent;
    }
    return NULL;
}

static void list_view_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    atk_widget_t *list = (atk_widget_t *)context;
    atk_list_view_priv_t *priv = list_priv_mut(list);
    if (!priv)
    {
        return;
    }

    if (scrollbar == priv->vscroll)
    {
        if (value < 0)
        {
            value = 0;
        }
        priv->scroll_row = value;
    }
    else if (scrollbar == priv->hscroll)
    {
        if (value < 0)
        {
            value = 0;
        }
        priv->scroll_x = value;
    }
    list_view_mark_dirty(list);
}

static int list_view_layout_columns(atk_list_view_priv_t *priv, int client_width)
{
    if (!priv)
    {
        return 0;
    }

    int total_width = 0;
    size_t flex_count = 0;
    for (size_t i = 0; i < priv->column_count; ++i)
    {
        atk_list_view_column_t *col = &priv->columns[i];
        if (col->width < ATK_LIST_VIEW_MIN_COLUMN_WIDTH)
        {
            col->width = ATK_LIST_VIEW_MIN_COLUMN_WIDTH;
        }
        total_width += col->width;
        if (col->flexible)
        {
            flex_count++;
        }
    }

    int remaining = client_width - total_width;
    if (client_width > 0 && remaining > 0)
    {
        size_t flex_remaining = flex_count;
        int share = flex_remaining > 0 ? (remaining / (int)flex_remaining) : 0;
        for (size_t i = 0; i < priv->column_count && remaining > 0; ++i)
        {
            atk_list_view_column_t *col = &priv->columns[i];
            if (!col->flexible)
            {
                continue;
            }
            int add = share;
            if (--flex_remaining == 0)
            {
                add = remaining;
            }
            col->width += add;
            remaining -= add;
        }

        if (flex_count == 0 && priv->column_count > 0 && remaining > 0)
        {
            priv->columns[priv->column_count - 1].width += remaining;
            remaining = 0;
        }

        total_width = 0;
        for (size_t i = 0; i < priv->column_count; ++i)
        {
            total_width += priv->columns[i].width;
        }
    }

    return total_width;
}

static void list_view_update_scrollbars(atk_widget_t *list,
                                        atk_list_view_priv_t *priv,
                                        bool need_vscroll,
                                        bool need_hscroll,
                                        int client_width,
                                        int client_height,
                                        int header_h,
                                        int visible_rows,
                                        int max_scroll_row,
                                        int max_scroll_x)
{
    (void)header_h;
    int scrollbar_size = (priv->scrollbar_size > 0) ? priv->scrollbar_size : ATK_LIST_VIEW_SCROLLBAR_SIZE;
    atk_widget_t *window = list_view_window(list);
    if (!window)
    {
        if (priv->vscroll)
        {
            priv->vscroll->used = false;
        }
        if (priv->hscroll)
        {
            priv->hscroll->used = false;
        }
        return;
    }

    int window_x = 0;
    int window_y = 0;
    int list_x = 0;
    int list_y = 0;
    atk_widget_absolute_position(window, &window_x, &window_y);
    atk_widget_absolute_position(list, &list_x, &list_y);
    int rel_x = list_x - window_x;
    int rel_y = list_y - window_y;

    if (need_vscroll && client_height > 0 && scrollbar_size > 0)
    {
        if (!priv->vscroll)
        {
            priv->vscroll = atk_window_add_scrollbar(window,
                                                     rel_x + client_width,
                                                     rel_y,
                                                     scrollbar_size,
                                                     client_height,
                                                     ATK_SCROLLBAR_VERTICAL);
            if (priv->vscroll)
            {
                atk_scrollbar_set_change_handler(priv->vscroll, list_view_scrollbar_changed, list);
            }
        }
        if (priv->vscroll)
        {
            priv->vscroll->used = true;
            priv->vscroll->x = rel_x + client_width;
            priv->vscroll->y = rel_y;
            priv->vscroll->width = scrollbar_size;
            priv->vscroll->height = client_height;
            if (priv->vscroll->width < 1)
            {
                priv->vscroll->width = 1;
            }
            if (priv->vscroll->height < 1)
            {
                priv->vscroll->height = 1;
            }
            int page = (visible_rows > 0) ? visible_rows : 1;
            atk_scrollbar_set_range(priv->vscroll, 0, max_scroll_row, page);
            atk_scrollbar_set_value(priv->vscroll, priv->scroll_row);
            atk_scrollbar_mark_dirty(priv->vscroll);
        }
    }
    else if (priv->vscroll)
    {
        priv->vscroll->used = false;
        atk_scrollbar_mark_dirty(priv->vscroll);
        list_view_mark_dirty(list);
    }

    if (need_hscroll && client_width > 0 && scrollbar_size > 0)
    {
        if (!priv->hscroll)
        {
            priv->hscroll = atk_window_add_scrollbar(window,
                                                     rel_x,
                                                     rel_y + client_height,
                                                     client_width,
                                                     scrollbar_size,
                                                     ATK_SCROLLBAR_HORIZONTAL);
            if (priv->hscroll)
            {
                atk_scrollbar_set_change_handler(priv->hscroll, list_view_scrollbar_changed, list);
            }
        }
        if (priv->hscroll)
        {
            priv->hscroll->used = true;
            priv->hscroll->x = rel_x;
            priv->hscroll->y = rel_y + client_height;
            priv->hscroll->width = client_width;
            priv->hscroll->height = scrollbar_size;
            if (priv->hscroll->width < 1)
            {
                priv->hscroll->width = 1;
            }
            if (priv->hscroll->height < 1)
            {
                priv->hscroll->height = 1;
            }
            int page = (client_width > 0) ? client_width : 1;
            atk_scrollbar_set_range(priv->hscroll, 0, max_scroll_x, page);
            atk_scrollbar_set_value(priv->hscroll, priv->scroll_x);
            atk_scrollbar_mark_dirty(priv->hscroll);
        }
    }
    else if (priv->hscroll)
    {
        priv->hscroll->used = false;
        atk_scrollbar_mark_dirty(priv->hscroll);
        list_view_mark_dirty(list);
    }
}

static void list_view_sync_layout(atk_widget_t *list, atk_list_view_priv_t *priv)
{
    if (!list || !priv || priv->column_count == 0)
    {
        return;
    }

    int list_width = list->width;
    int list_height = list->height;
    if (list_width < 0)
    {
        list_width = 0;
    }
    if (list_height < 0)
    {
        list_height = 0;
    }

    int scrollbar_size = (priv->scrollbar_size > 0) ? priv->scrollbar_size : ATK_LIST_VIEW_SCROLLBAR_SIZE;
    bool need_vscroll = false;
    bool need_hscroll = false;
    int client_width = list_width;
    int client_height = list_height;
    int header_h = priv->header_height;
    int total_width = 0;
    int row_area = 0;
    int visible_rows = 0;
    int max_scroll_row = 0;
    int max_scroll_x = 0;

    for (int iter = 0; iter < 3; ++iter)
    {
        client_width = list_width - (need_vscroll ? scrollbar_size : 0);
        if (client_width < 0)
        {
            client_width = 0;
        }

        total_width = list_view_layout_columns(priv, client_width);
        bool next_need_hscroll = total_width > client_width;

        client_height = list_height - (next_need_hscroll ? scrollbar_size : 0);
        if (client_height < 0)
        {
            client_height = 0;
        }

        header_h = priv->header_height;
        if (header_h > client_height)
        {
            header_h = client_height;
        }
        row_area = client_height - header_h;
        if (row_area < 0)
        {
            row_area = 0;
        }

        visible_rows = (priv->row_height > 0) ? (row_area / priv->row_height) : 0;
        bool next_need_vscroll = (priv->row_height > 0) &&
                                 ((int)(priv->row_count * priv->row_height) > row_area);

        if (need_vscroll == next_need_vscroll && need_hscroll == next_need_hscroll)
        {
            break;
        }
        need_vscroll = next_need_vscroll;
        need_hscroll = next_need_hscroll;
    }

    client_width = list_width - (need_vscroll ? scrollbar_size : 0);
    if (client_width < 0)
    {
        client_width = 0;
    }

    total_width = list_view_layout_columns(priv, client_width);
    need_hscroll = total_width > client_width;

    client_height = list_height - (need_hscroll ? scrollbar_size : 0);
    if (client_height < 0)
    {
        client_height = 0;
    }

    header_h = priv->header_height;
    if (header_h > client_height)
    {
        header_h = client_height;
    }
    row_area = client_height - header_h;
    if (row_area < 0)
    {
        row_area = 0;
    }
    visible_rows = (priv->row_height > 0) ? (row_area / priv->row_height) : 0;

    max_scroll_row = 0;
    if (visible_rows > 0 && priv->row_count > (size_t)visible_rows)
    {
        max_scroll_row = (int)priv->row_count - visible_rows;
    }
    else if (visible_rows == 0 && priv->row_count > 0)
    {
        max_scroll_row = (int)priv->row_count - 1;
    }

    max_scroll_x = (total_width > client_width) ? (total_width - client_width) : 0;

    if (!need_vscroll)
    {
        priv->scroll_row = 0;
    }
    if (priv->scroll_row < 0)
    {
        priv->scroll_row = 0;
    }
    if (priv->scroll_row > max_scroll_row)
    {
        priv->scroll_row = max_scroll_row;
    }

    if (!need_hscroll)
    {
        priv->scroll_x = 0;
    }
    if (priv->scroll_x < 0)
    {
        priv->scroll_x = 0;
    }
    if (priv->scroll_x > max_scroll_x)
    {
        priv->scroll_x = max_scroll_x;
    }

    if (need_hscroll && priv->resizing && priv->resizing_column < priv->column_count)
    {
        int separator_x = 0;
        for (size_t i = 0; i <= priv->resizing_column; ++i)
        {
            separator_x += priv->columns[i].width;
        }
        int margin = ATK_LIST_VIEW_RESIZE_MARGIN + 6;
        int desired_scroll = priv->scroll_x;
        int local_separator = separator_x - priv->scroll_x;
        if (local_separator > client_width - margin)
        {
            desired_scroll = separator_x - (client_width - margin);
        }
        else if (local_separator < margin)
        {
            desired_scroll = separator_x - margin;
        }
        if (desired_scroll < 0)
        {
            desired_scroll = 0;
        }
        if (desired_scroll > max_scroll_x)
        {
            desired_scroll = max_scroll_x;
        }
        priv->scroll_x = desired_scroll;
    }

    priv->content_width = total_width;
    priv->content_height = (priv->row_height > 0)
                               ? (priv->row_height * (int)priv->row_count + header_h)
                               : header_h;
    priv->client_width = client_width;
    priv->client_height = client_height;
    priv->header_visible_height = header_h;

    list_view_update_scrollbars(list,
                                priv,
                                need_vscroll,
                                need_hscroll,
                                client_width,
                                client_height,
                                header_h,
                                visible_rows,
                                max_scroll_row,
                                max_scroll_x);

    bool v_used = priv->vscroll && priv->vscroll->used;
    bool h_used = priv->hscroll && priv->hscroll->used;
    int actual_client_width = list_width - (v_used ? scrollbar_size : 0);
    if (actual_client_width < 0)
    {
        actual_client_width = 0;
    }
    int actual_client_height = list_height - (h_used ? scrollbar_size : 0);
    if (actual_client_height < 0)
    {
        actual_client_height = 0;
    }

    int actual_header = priv->header_visible_height;
    if (actual_header > actual_client_height)
    {
        actual_header = actual_client_height;
    }
    int actual_row_area = actual_client_height - actual_header;
    if (actual_row_area < 0)
    {
        actual_row_area = 0;
    }
    int actual_visible_rows = (priv->row_height > 0) ? (actual_row_area / priv->row_height) : 0;

    int actual_max_scroll_row = 0;
    if (actual_visible_rows > 0 && priv->row_count > (size_t)actual_visible_rows)
    {
        actual_max_scroll_row = (int)priv->row_count - actual_visible_rows;
    }
    else if (actual_visible_rows == 0 && priv->row_count > 0)
    {
        actual_max_scroll_row = (int)priv->row_count - 1;
    }

    int actual_max_scroll_x = (priv->content_width > actual_client_width) ? (priv->content_width - actual_client_width) : 0;

    if (!v_used)
    {
        priv->scroll_row = 0;
    }
    if (priv->scroll_row < 0)
    {
        priv->scroll_row = 0;
    }
    if (priv->scroll_row > actual_max_scroll_row)
    {
        priv->scroll_row = actual_max_scroll_row;
    }

    if (!h_used)
    {
        priv->scroll_x = 0;
    }
    if (priv->scroll_x < 0)
    {
        priv->scroll_x = 0;
    }
    if (priv->scroll_x > actual_max_scroll_x)
    {
        priv->scroll_x = actual_max_scroll_x;
    }

    if (v_used)
    {
        int page = (actual_visible_rows > 0) ? actual_visible_rows : 1;
        atk_scrollbar_set_range(priv->vscroll, 0, actual_max_scroll_row, page);
        atk_scrollbar_set_value(priv->vscroll, priv->scroll_row);
    }
    if (h_used)
    {
        int page = (actual_client_width > 0) ? actual_client_width : 1;
        atk_scrollbar_set_range(priv->hscroll, 0, actual_max_scroll_x, page);
        atk_scrollbar_set_value(priv->hscroll, priv->scroll_x);
    }

    priv->client_width = actual_client_width;
    priv->client_height = actual_client_height;
    priv->header_visible_height = actual_header;
    priv->last_layout_width = list_width;
    priv->last_layout_height = list_height;
    priv->layout_dirty = false;
}

static size_t list_view_hit_separator(const atk_widget_t *list,
                                      const atk_list_view_priv_t *priv,
                                      int cursor_x,
                                      int cursor_y)
{
    if (!list || !priv || priv->column_count < 2)
    {
        return SIZE_MAX;
    }
    int header_h = priv->header_visible_height;
    if (cursor_y < 0 || cursor_y >= header_h)
    {
        return SIZE_MAX;
    }
    if (cursor_x < 0 || cursor_x >= priv->client_width)
    {
        return SIZE_MAX;
    }

    int boundary = -priv->scroll_x;
    for (size_t i = 0; i < priv->column_count - 1; ++i)
    {
        boundary += priv->columns[i].width;
        if (cursor_x >= boundary - ATK_LIST_VIEW_RESIZE_MARGIN &&
            cursor_x <= boundary + ATK_LIST_VIEW_RESIZE_MARGIN)
        {
            return i;
        }
    }
    return SIZE_MAX;
}

static void list_view_update_hover(atk_widget_t *list,
                                   atk_list_view_priv_t *priv,
                                   int cursor_x,
                                   int cursor_y)
{
    if (!priv)
    {
        return;
    }

    size_t column = list_view_hit_separator(list, priv, cursor_x, cursor_y);
    int new_hover = (column == SIZE_MAX) ? -1 : (int)column;
    if (new_hover != priv->hover_separator)
    {
        priv->hover_separator = new_hover;
        list_view_mark_dirty(list);
    }
}

static bool list_view_apply_column_resize(atk_widget_t *list,
                                          atk_list_view_priv_t *priv,
                                          int cursor_x)
{
    if (!priv || !priv->resizing || priv->resizing_column >= priv->column_count - 1)
    {
        return false;
    }

    int delta = cursor_x - priv->resize_start_x;
    int left_width = priv->resize_width_left + delta;

    if (left_width < ATK_LIST_VIEW_MIN_COLUMN_WIDTH)
    {
        left_width = ATK_LIST_VIEW_MIN_COLUMN_WIDTH;
    }

    atk_list_view_column_t *left = &priv->columns[priv->resizing_column];

    if (left->width == left_width)
    {
        return false;
    }

    left->width = left_width;
    left->flexible = false;
    priv->layout_dirty = true;
    list_view_mark_dirty(list);
    list_view_sync_layout(list, priv);
    return true;
}

static atk_mouse_response_t list_view_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context)
{
    (void)context;
    atk_list_view_priv_t *priv = list_priv_mut(widget);
    if (!priv || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    if (priv->layout_dirty)
    {
        list_view_sync_layout(widget, priv);
    }

    if (event->pressed_edge)
    {
        size_t column = list_view_hit_separator(widget, priv, event->local_x, event->local_y);
        if (column != SIZE_MAX)
        {
            priv->resizing = true;
            priv->resizing_column = column;
            priv->resize_start_x = event->cursor_x;
            priv->resize_width_left = priv->columns[column].width;
            priv->resize_width_right = 0;
            priv->hover_separator = (int)column;
            return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE;
        }
    }
    else if (event->released_edge && priv->resizing)
    {
        priv->resizing = false;
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_RELEASE | ATK_MOUSE_RESPONSE_REDRAW;
    }
    else if (event->left_pressed && priv->resizing)
    {
        if (list_view_apply_column_resize(widget, priv, event->cursor_x))
        {
            return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW;
        }
        return ATK_MOUSE_RESPONSE_HANDLED;
    }

    if (!event->pressed_edge && !event->released_edge && !event->left_pressed)
    {
        list_view_update_hover(widget, priv, event->local_x, event->local_y);
    }
    else if (!priv->resizing && priv->hover_separator != -1)
    {
        size_t column = list_view_hit_separator(widget, priv, event->local_x, event->local_y);
        if (column == SIZE_MAX)
        {
            priv->hover_separator = -1;
            list_view_mark_dirty(widget);
        }
        else
        {
            list_view_update_hover(widget, priv, event->local_x, event->local_y);
        }
    }

    return ATK_MOUSE_RESPONSE_NONE;
}

static atk_list_view_priv_t *list_priv_mut(atk_widget_t *list)
{
    if (!list)
    {
        return NULL;
    }
    return (atk_list_view_priv_t *)atk_widget_priv(list, &ATK_LIST_VIEW_CLASS);
}

static const atk_list_view_priv_t *list_priv(const atk_widget_t *list)
{
    if (!list)
    {
        return NULL;
    }
    return (const atk_list_view_priv_t *)atk_widget_priv(list, &ATK_LIST_VIEW_CLASS);
}

static bool list_view_ensure_capacity(atk_list_view_priv_t *priv, size_t rows)
{
    if (!priv)
    {
        return false;
    }
    size_t needed_cells = rows * priv->column_count;
    if (needed_cells <= priv->cell_capacity)
    {
        return true;
    }

    size_t new_capacity = priv->cell_capacity ? priv->cell_capacity : (priv->column_count ? priv->column_count * 8 : 8);
    while (new_capacity < needed_cells)
    {
        new_capacity *= 2;
    }

    size_t bytes = new_capacity * sizeof(atk_list_view_cell_t);
    atk_list_view_cell_t *cells = (atk_list_view_cell_t *)realloc(priv->cells, bytes);
    if (!cells)
    {
        return false;
    }

    if (new_capacity > priv->cell_capacity)
    {
        size_t old_bytes = priv->cell_capacity * sizeof(atk_list_view_cell_t);
        memset((uint8_t *)cells + old_bytes, 0, bytes - old_bytes);
    }

    priv->cells = cells;
    priv->cell_capacity = new_capacity;
    return true;
}
