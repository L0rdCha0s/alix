#include "atk/atk_list_view.h"

#include "atk_internal.h"
#include "video.h"
#include "libc.h"
#include "atk/atk_font.h"

#if ATK_LIST_VIEW_MAX_COLUMNS < 10
#error "ATK_LIST_VIEW_MAX_COLUMNS must be at least 10 to support task manager views"
#endif

#define ATK_LIST_VIEW_MIN_COLUMN_WIDTH      (ATK_FONT_WIDTH * 4)

typedef struct
{
    char text[ATK_LIST_VIEW_CELL_TEXT_MAX];
} atk_list_view_cell_t;

typedef struct
{
    char title[ATK_LIST_VIEW_COLUMN_TITLE_MAX];
    int width;
} atk_list_view_column_t;

typedef struct
{
    atk_list_view_column_t columns[ATK_LIST_VIEW_MAX_COLUMNS];
    size_t column_count;
    atk_list_view_cell_t *cells;
    size_t cell_capacity;
    size_t row_count;
    int header_height;
    int row_height;
    int cell_padding;
    atk_list_node_t *list_node;
} atk_list_view_priv_t;

static void list_view_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context);
static void list_view_destroy_cb(atk_widget_t *widget, void *context);

static const atk_widget_vtable_t list_view_vtable = { 0 };
static const atk_widget_ops_t g_list_view_ops = {
    .destroy = list_view_destroy_cb,
    .draw = list_view_draw_cb,
    .hit_test = NULL,
    .on_mouse = NULL,
    .on_key = NULL
};
const atk_class_t ATK_LIST_VIEW_CLASS = { "ListView", &ATK_WIDGET_CLASS, &list_view_vtable, sizeof(atk_list_view_priv_t) };

static atk_list_view_priv_t *list_priv_mut(atk_widget_t *list);
static const atk_list_view_priv_t *list_priv(const atk_widget_t *list);
static void list_view_compute_column_widths(const atk_widget_t *list,
                                            const atk_list_view_priv_t *priv,
                                            int *out_widths);
static bool list_view_ensure_capacity(atk_list_view_priv_t *priv, size_t rows);

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
    priv->row_height = line_height + 4;
    priv->cell_padding = 4;
    priv->list_node = NULL;

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
        col->width = def->width;
    }

    priv->row_count = 0;
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

void atk_list_view_draw(const atk_state_t *state, const atk_widget_t *list)
{
    const atk_list_view_priv_t *priv = list_priv(list);
    if (!state || !list || !list->used || !priv || list->width <= 0 || list->height <= 0)
    {
        return;
    }

    int origin_x = 0;
    int origin_y = 0;
    atk_widget_absolute_position(list, &origin_x, &origin_y);

    const atk_theme_t *theme = &state->theme;
    video_draw_rect(origin_x, origin_y, list->width, list->height, theme->window_body);

    int header_h = priv->header_height;
    if (header_h > list->height)
    {
        header_h = list->height;
    }

    video_draw_rect(origin_x,
                    origin_y,
                    list->width,
                    header_h,
                    theme->button_face);
    int column_widths[ATK_LIST_VIEW_MAX_COLUMNS] = { 0 };
    list_view_compute_column_widths(list, priv, column_widths);

    int column_x = origin_x;
    for (size_t c = 0; c < priv->column_count; ++c)
    {
        const atk_list_view_column_t *col = &priv->columns[c];
        int col_width = column_widths[c];
        if (col_width <= 0)
        {
            continue;
        }

        int text_x = column_x + priv->cell_padding;
        if (text_x < column_x)
        {
            text_x = column_x;
        }
        int baseline = atk_font_baseline_for_rect(origin_y, header_h);
        atk_rect_t clip = { column_x, origin_y, col_width, header_h };
        atk_font_draw_string_clipped(text_x,
                                     baseline,
                                     col->title,
                                     theme->button_text,
                                     theme->button_face,
                                     &clip);
        column_x += col_width;
    }

    int row_y = origin_y + header_h;
    int row_bottom_limit = origin_y + list->height;
    uint16_t stripe_colors[2] = { theme->window_body, theme->button_face };

    for (size_t row = 0; row < priv->row_count; ++row)
    {
        if (row_y >= row_bottom_limit)
        {
            break;
        }
        uint16_t row_bg = stripe_colors[row % 2];
        int row_height = priv->row_height;
        if (row_y + row_height > row_bottom_limit)
        {
            row_height = row_bottom_limit - row_y;
        }
        video_draw_rect(origin_x, row_y, list->width, row_height, row_bg);

        int cell_x = origin_x;
        for (size_t column = 0; column < priv->column_count; ++column)
        {
            int col_width = column_widths[column];
            if (col_width <= 0)
            {
                continue;
            }

            size_t cell_index = row * priv->column_count + column;
            const char *text = "";
            if (priv->cells && cell_index < priv->cell_capacity)
            {
                text = priv->cells[cell_index].text;
            }

            int text_x = cell_x + priv->cell_padding;
            int baseline = atk_font_baseline_for_rect(row_y, row_height);
            atk_rect_t clip = { cell_x, row_y, col_width, row_height };
            atk_font_draw_string_clipped(text_x, baseline, text, theme->button_text, row_bg, &clip);
            cell_x += col_width;
        }

        row_y += priv->row_height;
    }

    if (header_h > 0)
    {
        video_draw_rect(origin_x,
                        origin_y + header_h - 1,
                        list->width,
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
    if (priv->cells)
    {
        free(priv->cells);
        priv->cells = NULL;
    }
    priv->cell_capacity = 0;
    priv->row_count = 0;
    priv->column_count = 0;
    priv->list_node = NULL;
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

static void list_view_compute_column_widths(const atk_widget_t *list,
                                            const atk_list_view_priv_t *priv,
                                            int *out_widths)
{
    if (!list || !priv || !out_widths)
    {
        return;
    }

    int total_width = list->width;
    if (total_width < 0)
    {
        total_width = 0;
    }

    size_t flex_remaining = 0;
    for (size_t i = 0; i < priv->column_count; ++i)
    {
        if (priv->columns[i].width <= 0)
        {
            flex_remaining++;
        }
    }

    int consumed = 0;

    for (size_t i = 0; i < priv->column_count; ++i)
    {
        int width = priv->columns[i].width;
        if (width <= 0)
        {
            int remaining_space = total_width - consumed;
            size_t remaining_columns = flex_remaining > 0 ? flex_remaining : 1;
            width = (remaining_columns > 0) ? (remaining_space / (int)remaining_columns) : 0;
            if (width < ATK_LIST_VIEW_MIN_COLUMN_WIDTH)
            {
                width = ATK_LIST_VIEW_MIN_COLUMN_WIDTH;
            }
            if (flex_remaining > 0)
            {
                flex_remaining--;
            }
        }

        if (width < 0)
        {
            width = 0;
        }
        if (consumed + width > total_width)
        {
            width = total_width - consumed;
            if (width < 0)
            {
                width = 0;
            }
        }

        out_widths[i] = width;
        consumed += width;
    }

    if (consumed < total_width && priv->column_count > 0)
    {
        out_widths[priv->column_count - 1] += (total_width - consumed);
    }
}
