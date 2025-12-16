#include "atk/atk_dropdown.h"

#include "atk_internal.h"
#include "atk/atk_font.h"
#include "libc.h"
#include "video.h"

#define ATK_DROPDOWN_TITLE_MAX 32
#define ATK_DROPDOWN_ITEM_TITLE_MAX 64
#define ATK_DROPDOWN_PADDING_X 8
#define ATK_DROPDOWN_ARROW_W 18

typedef struct
{
    char title[ATK_DROPDOWN_ITEM_TITLE_MAX];
    uintptr_t value;
} atk_dropdown_item_t;

typedef struct
{
    atk_dropdown_item_t *items;
    size_t count;
    size_t capacity;

    bool has_selected;
    size_t selected;

    int highlighted;
    bool open;
    bool open_down;

    atk_dropdown_style_t style;
    char title[ATK_DROPDOWN_TITLE_MAX];

    atk_dropdown_select_t on_select;
    void *on_select_ctx;

    atk_list_node_t *list_node;
    int item_height;
} atk_dropdown_priv_t;

static atk_dropdown_priv_t *dropdown_priv_mut(atk_widget_t *dropdown);
static const atk_dropdown_priv_t *dropdown_priv_const(const atk_widget_t *dropdown);
static bool dropdown_ensure_capacity(atk_dropdown_priv_t *priv, size_t desired);
static void dropdown_invalidate(const atk_widget_t *dropdown);
static void dropdown_invalidate_list(const atk_widget_t *dropdown, const atk_dropdown_priv_t *priv);
static void dropdown_calc_list_rect(const atk_widget_t *widget,
                                    atk_dropdown_priv_t *priv,
                                    int origin_x,
                                    int origin_y,
                                    atk_rect_t *out);
static void dropdown_raise_if_possible(atk_widget_t *dropdown, atk_dropdown_priv_t *priv);
static void dropdown_draw_arrow(int x, int y, int w, int h, video_color_t color);
static int dropdown_default_item_height(void);
static int dropdown_item_index_at(const atk_widget_t *widget,
                                  atk_dropdown_priv_t *priv,
                                  int origin_x,
                                  int origin_y,
                                  int px,
                                  int py);

static atk_mouse_response_t dropdown_mouse_cb(atk_widget_t *widget,
                                              const atk_mouse_event_t *event,
                                              void *context);
static bool dropdown_hit_test_cb(const atk_widget_t *widget,
                                 int origin_x,
                                 int origin_y,
                                 int px,
                                 int py,
                                 void *context);
static void dropdown_draw_cb(const atk_state_t *state,
                             const atk_widget_t *widget,
                             int origin_x,
                             int origin_y,
                             void *context);
static void dropdown_destroy_cb(atk_widget_t *widget, void *context);

static const atk_widget_vtable_t dropdown_vtable = { 0 };
static const atk_widget_ops_t g_dropdown_ops = {
    .destroy = dropdown_destroy_cb,
    .draw = dropdown_draw_cb,
    .hit_test = dropdown_hit_test_cb,
    .on_mouse = dropdown_mouse_cb,
    .on_key = NULL,
};

const atk_class_t ATK_DROPDOWN_CLASS = { "Dropdown", &ATK_WIDGET_CLASS, &dropdown_vtable, sizeof(atk_dropdown_priv_t) };

atk_widget_t *atk_window_add_dropdown(atk_widget_t *window,
                                      int x,
                                      int y,
                                      int width,
                                      int height,
                                      atk_dropdown_style_t style,
                                      atk_dropdown_select_t on_select,
                                      void *context)
{
    if (!window || width <= 0 || height <= 0)
    {
        return NULL;
    }

    atk_window_priv_t *win_priv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!win_priv)
    {
        return NULL;
    }

    atk_widget_t *dropdown = atk_widget_create(&ATK_DROPDOWN_CLASS);
    if (!dropdown)
    {
        return NULL;
    }

    dropdown->x = x;
    dropdown->y = y;
    dropdown->width = width;
    dropdown->height = height;
    dropdown->parent = window;
    dropdown->used = true;
    atk_widget_set_ops(dropdown, &g_dropdown_ops, NULL);

    atk_dropdown_priv_t *priv = dropdown_priv_mut(dropdown);
    if (!priv)
    {
        atk_widget_destroy(dropdown);
        return NULL;
    }

    memset(priv, 0, sizeof(*priv));
    priv->items = NULL;
    priv->count = 0;
    priv->capacity = 0;
    priv->has_selected = false;
    priv->selected = 0;
    priv->highlighted = -1;
    priv->open = false;
    priv->open_down = true;
    priv->style = style;
    priv->title[0] = '\0';
    priv->on_select = on_select;
    priv->on_select_ctx = context;
    priv->list_node = NULL;
    priv->item_height = dropdown_default_item_height();

    atk_list_node_t *child_node = atk_list_push_back(&win_priv->children, dropdown);
    if (!child_node)
    {
        atk_widget_destroy(dropdown);
        return NULL;
    }
    priv->list_node = child_node;
    return dropdown;
}

void atk_dropdown_clear(atk_widget_t *dropdown)
{
    atk_dropdown_priv_t *priv = dropdown_priv_mut(dropdown);
    if (!priv)
    {
        return;
    }
    if (priv->items)
    {
        free(priv->items);
    }
    priv->items = NULL;
    priv->count = 0;
    priv->capacity = 0;
    priv->has_selected = false;
    priv->selected = 0;
    priv->highlighted = -1;
    if (priv->open)
    {
        priv->open = false;
    }
    dropdown_invalidate(dropdown);
}

bool atk_dropdown_add_item(atk_widget_t *dropdown, const char *title, uintptr_t value)
{
    atk_dropdown_priv_t *priv = dropdown_priv_mut(dropdown);
    if (!priv || !title)
    {
        return false;
    }

    if (!dropdown_ensure_capacity(priv, priv->count + 1))
    {
        return false;
    }

    atk_dropdown_item_t *item = &priv->items[priv->count++];
    size_t len = strlen(title);
    if (len >= sizeof(item->title))
    {
        len = sizeof(item->title) - 1;
    }
    memcpy(item->title, title, len);
    item->title[len] = '\0';
    item->value = value;

    if (!priv->has_selected && priv->style == ATK_DROPDOWN_STYLE_COMBO)
    {
        priv->has_selected = true;
        priv->selected = 0;
    }

    dropdown_invalidate(dropdown);
    return true;
}

size_t atk_dropdown_count(const atk_widget_t *dropdown)
{
    const atk_dropdown_priv_t *priv = dropdown_priv_const(dropdown);
    return priv ? priv->count : 0;
}

void atk_dropdown_set_title(atk_widget_t *dropdown, const char *title)
{
    atk_dropdown_priv_t *priv = dropdown_priv_mut(dropdown);
    if (!priv)
    {
        return;
    }
    const char *src = title ? title : "";
    size_t len = strlen(src);
    if (len >= sizeof(priv->title))
    {
        len = sizeof(priv->title) - 1;
    }
    memcpy(priv->title, src, len);
    priv->title[len] = '\0';
    dropdown_invalidate(dropdown);
}

const char *atk_dropdown_title(const atk_widget_t *dropdown)
{
    const atk_dropdown_priv_t *priv = dropdown_priv_const(dropdown);
    return priv ? priv->title : "";
}

bool atk_dropdown_set_selected(atk_widget_t *dropdown, size_t index)
{
    atk_dropdown_priv_t *priv = dropdown_priv_mut(dropdown);
    if (!priv || priv->style != ATK_DROPDOWN_STYLE_COMBO)
    {
        return false;
    }
    if (index >= priv->count)
    {
        return false;
    }
    if (priv->has_selected && priv->selected == index)
    {
        return true;
    }
    priv->has_selected = true;
    priv->selected = index;
    dropdown_invalidate(dropdown);
    return true;
}

size_t atk_dropdown_selected(const atk_widget_t *dropdown)
{
    const atk_dropdown_priv_t *priv = dropdown_priv_const(dropdown);
    if (!priv || !priv->has_selected)
    {
        return 0;
    }
    return priv->selected;
}

uintptr_t atk_dropdown_selected_value(const atk_widget_t *dropdown)
{
    const atk_dropdown_priv_t *priv = dropdown_priv_const(dropdown);
    if (!priv || !priv->has_selected || priv->selected >= priv->count)
    {
        return 0;
    }
    return priv->items[priv->selected].value;
}

const char *atk_dropdown_selected_title(const atk_widget_t *dropdown)
{
    const atk_dropdown_priv_t *priv = dropdown_priv_const(dropdown);
    if (!priv || !priv->has_selected || priv->selected >= priv->count)
    {
        return "";
    }
    return priv->items[priv->selected].title;
}

bool atk_dropdown_is_open(const atk_widget_t *dropdown)
{
    const atk_dropdown_priv_t *priv = dropdown_priv_const(dropdown);
    return priv ? priv->open : false;
}

void atk_dropdown_set_open(atk_widget_t *dropdown, bool open)
{
    atk_dropdown_priv_t *priv = dropdown_priv_mut(dropdown);
    if (!priv)
    {
        return;
    }
    if (open == priv->open)
    {
        return;
    }
    dropdown_invalidate_list(dropdown, priv);
    priv->open = open;
    priv->highlighted = -1;
    if (open)
    {
        dropdown_raise_if_possible(dropdown, priv);
    }
    dropdown_invalidate(dropdown);
}

static atk_dropdown_priv_t *dropdown_priv_mut(atk_widget_t *dropdown)
{
    if (!dropdown)
    {
        return NULL;
    }
    return (atk_dropdown_priv_t *)atk_widget_priv(dropdown, &ATK_DROPDOWN_CLASS);
}

static const atk_dropdown_priv_t *dropdown_priv_const(const atk_widget_t *dropdown)
{
    if (!dropdown)
    {
        return NULL;
    }
    return (const atk_dropdown_priv_t *)atk_widget_priv(dropdown, &ATK_DROPDOWN_CLASS);
}

static bool dropdown_ensure_capacity(atk_dropdown_priv_t *priv, size_t desired)
{
    if (!priv)
    {
        return false;
    }
    if (desired <= priv->capacity)
    {
        return true;
    }
    size_t new_cap = priv->capacity ? priv->capacity * 2 : 8;
    while (new_cap < desired)
    {
        new_cap *= 2;
    }
    atk_dropdown_item_t *items = (atk_dropdown_item_t *)realloc(priv->items, new_cap * sizeof(atk_dropdown_item_t));
    if (!items)
    {
        return false;
    }
    priv->items = items;
    priv->capacity = new_cap;
    return true;
}

static void dropdown_invalidate(const atk_widget_t *dropdown)
{
    if (!dropdown || !dropdown->used || !dropdown->parent)
    {
        return;
    }
    const atk_dropdown_priv_t *priv = dropdown_priv_const(dropdown);
    int ox = dropdown->parent->x + dropdown->x;
    int oy = dropdown->parent->y + dropdown->y;
    atk_dirty_mark_rect(ox, oy, dropdown->width, dropdown->height);
    if (priv && priv->open)
    {
        dropdown_invalidate_list(dropdown, priv);
    }
}

static void dropdown_invalidate_list(const atk_widget_t *dropdown, const atk_dropdown_priv_t *priv)
{
    if (!dropdown || !dropdown->used || !dropdown->parent || !priv || !priv->open)
    {
        return;
    }
    atk_dropdown_priv_t tmp = *priv;
    atk_rect_t list_rect = { 0 };
    dropdown_calc_list_rect(dropdown, &tmp, dropdown->parent->x, dropdown->parent->y, &list_rect);
    if (list_rect.width > 0 && list_rect.height > 0)
    {
        atk_dirty_mark_rect(list_rect.x, list_rect.y, list_rect.width, list_rect.height);
    }
}

static void dropdown_calc_list_rect(const atk_widget_t *widget,
                                    atk_dropdown_priv_t *priv,
                                    int origin_x,
                                    int origin_y,
                                    atk_rect_t *out)
{
    if (!out)
    {
        return;
    }
    out->x = 0;
    out->y = 0;
    out->width = 0;
    out->height = 0;
    if (!widget || !priv || priv->count == 0)
    {
        return;
    }

    int abs_x = origin_x + widget->x;
    int abs_y = origin_y + widget->y;
    int list_w = widget->width;
    int list_h = (int)priv->count * priv->item_height;
    if (list_w <= 0 || list_h <= 0)
    {
        return;
    }

    int parent_top = origin_y;
    int parent_bottom = origin_y + (widget->parent ? widget->parent->height : 0);
    int below_y = abs_y + widget->height;
    int above_y = abs_y - list_h;

    priv->open_down = true;
    int list_y = below_y;
    if (widget->parent && parent_bottom > parent_top)
    {
        if (below_y + list_h <= parent_bottom)
        {
            priv->open_down = true;
            list_y = below_y;
        }
        else if (above_y >= parent_top)
        {
            priv->open_down = false;
            list_y = above_y;
        }
    }

    out->x = abs_x;
    out->y = list_y;
    out->width = list_w;
    out->height = list_h;
}

static void dropdown_raise_if_possible(atk_widget_t *dropdown, atk_dropdown_priv_t *priv)
{
    if (!dropdown || !priv || !dropdown->parent || !priv->list_node)
    {
        return;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(dropdown->parent, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return;
    }
    atk_list_move_to_back(&wpriv->children, priv->list_node);
}

static void dropdown_draw_arrow(int x, int y, int w, int h, video_color_t color)
{
    int cx = x + w / 2;
    int cy = y + h / 2 + 1;
    int half = h / 6;
    if (half < 2)
    {
        half = 2;
    }
    int thickness = 2;
    for (int i = 0; i < half; ++i)
    {
        int row_w = (i + 1) * 2;
        video_draw_rect(cx - row_w / 2, cy + i, row_w, thickness, color);
    }
}

static int dropdown_default_item_height(void)
{
    int line_h = atk_font_line_height();
    if (line_h < ATK_FONT_HEIGHT)
    {
        line_h = ATK_FONT_HEIGHT;
    }
    return line_h + 8;
}

static int dropdown_item_index_at(const atk_widget_t *widget,
                                  atk_dropdown_priv_t *priv,
                                  int origin_x,
                                  int origin_y,
                                  int px,
                                  int py)
{
    if (!widget || !priv || !priv->open || priv->count == 0)
    {
        return -1;
    }

    atk_rect_t list_rect = { 0 };
    dropdown_calc_list_rect(widget, priv, origin_x, origin_y, &list_rect);
    if (list_rect.width <= 0 || list_rect.height <= 0)
    {
        return -1;
    }
    if (px < list_rect.x || px >= list_rect.x + list_rect.width ||
        py < list_rect.y || py >= list_rect.y + list_rect.height)
    {
        return -1;
    }

    int row = (py - list_rect.y) / priv->item_height;
    if (row < 0 || (size_t)row >= priv->count)
    {
        return -1;
    }
    return row;
}

static atk_mouse_response_t dropdown_mouse_cb(atk_widget_t *widget,
                                              const atk_mouse_event_t *event,
                                              void *context)
{
    (void)context;
    if (!widget || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }
    atk_dropdown_priv_t *priv = dropdown_priv_mut(widget);
    if (!priv)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    int abs_x = event->origin_x + widget->x;
    int abs_y = event->origin_y + widget->y;
    bool in_main = (event->cursor_x >= abs_x &&
                    event->cursor_x < abs_x + widget->width &&
                    event->cursor_y >= abs_y &&
                    event->cursor_y < abs_y + widget->height);

    if (priv->open)
    {
        int item = dropdown_item_index_at(widget, priv, event->origin_x, event->origin_y, event->cursor_x, event->cursor_y);
        if (item != priv->highlighted)
        {
            priv->highlighted = item;
            dropdown_invalidate_list(widget, priv);
        }

        if (event->pressed_edge && event->left_pressed)
        {
            if (in_main)
            {
                dropdown_invalidate_list(widget, priv);
                priv->open = false;
                priv->highlighted = -1;
                dropdown_invalidate(widget);
                return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW | ATK_MOUSE_RESPONSE_RELEASE;
            }

            if (item < 0)
            {
                dropdown_invalidate_list(widget, priv);
                priv->open = false;
                priv->highlighted = -1;
                dropdown_invalidate(widget);
                return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW | ATK_MOUSE_RESPONSE_RELEASE;
            }
            return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE;
        }

        if (event->released_edge)
        {
            if (item >= 0 && (size_t)item < priv->count)
            {
                if (priv->style == ATK_DROPDOWN_STYLE_COMBO)
                {
                    priv->has_selected = true;
                    priv->selected = (size_t)item;
                }
                if (priv->on_select)
                {
                    priv->on_select(widget, priv->on_select_ctx, (size_t)item, priv->items[item].value);
                }
            }
            dropdown_invalidate_list(widget, priv);
            priv->open = false;
            priv->highlighted = -1;
            dropdown_invalidate(widget);
            (void)state;
            return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW | ATK_MOUSE_RESPONSE_RELEASE;
        }

        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE;
    }

    if (event->pressed_edge && event->left_pressed && in_main)
    {
        if (priv->count == 0)
        {
            return ATK_MOUSE_RESPONSE_HANDLED;
        }
        dropdown_raise_if_possible(widget, priv);
        priv->open = true;
        priv->highlighted = priv->has_selected ? (int)priv->selected : -1;
        dropdown_invalidate(widget);
        dropdown_invalidate_list(widget, priv);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW | ATK_MOUSE_RESPONSE_CAPTURE;
    }

    return ATK_MOUSE_RESPONSE_NONE;
}

static bool dropdown_hit_test_cb(const atk_widget_t *widget,
                                 int origin_x,
                                 int origin_y,
                                 int px,
                                 int py,
                                 void *context)
{
    (void)context;
    if (!widget || !widget->used)
    {
        return false;
    }
    const atk_dropdown_priv_t *priv_const = dropdown_priv_const(widget);
    if (!priv_const)
    {
        return false;
    }
    int abs_x = origin_x + widget->x;
    int abs_y = origin_y + widget->y;
    if (px >= abs_x && px < abs_x + widget->width && py >= abs_y && py < abs_y + widget->height)
    {
        return true;
    }
    if (priv_const->open)
    {
        atk_dropdown_priv_t tmp = *priv_const;
        atk_rect_t list_rect = { 0 };
        dropdown_calc_list_rect(widget, &tmp, origin_x, origin_y, &list_rect);
        if (px >= list_rect.x && px < list_rect.x + list_rect.width &&
            py >= list_rect.y && py < list_rect.y + list_rect.height)
        {
            return true;
        }
    }
    return false;
}

static void dropdown_draw_cb(const atk_state_t *state,
                             const atk_widget_t *widget,
                             int origin_x,
                             int origin_y,
                             void *context)
{
    (void)context;
    if (!state || !widget)
    {
        return;
    }
    atk_dropdown_priv_t *priv = dropdown_priv_mut((atk_widget_t *)widget);
    if (!priv)
    {
        return;
    }

    atk_state_theme_validate(state, "atk_dropdown_draw");
    const atk_theme_t *theme = &state->theme;

    int abs_x = origin_x + widget->x;
    int abs_y = origin_y + widget->y;

    video_color_t face = theme->button_face;
    video_color_t border = theme->window_border;
    video_color_t fg = theme->button_text;
    if (priv->style == ATK_DROPDOWN_STYLE_MENU)
    {
        face = theme->menu_bar_face;
        fg = theme->menu_bar_text;
    }
    if (priv->open)
    {
        face = theme->menu_bar_highlight;
        if (priv->style == ATK_DROPDOWN_STYLE_MENU)
        {
            fg = theme->menu_bar_face;
        }
    }

    video_draw_rect(abs_x, abs_y, widget->width, widget->height, face);
    video_draw_rect_outline(abs_x, abs_y, widget->width, widget->height, border);

    const char *display = "";
    if (priv->style == ATK_DROPDOWN_STYLE_MENU)
    {
        display = priv->title;
    }
    else if (priv->has_selected && priv->selected < priv->count)
    {
        display = priv->items[priv->selected].title;
    }
    else
    {
        display = priv->title;
    }

    int arrow_w = ATK_DROPDOWN_ARROW_W;
    if (arrow_w > widget->width / 2)
    {
        arrow_w = widget->width / 2;
    }
    int text_area_w = widget->width - arrow_w - ATK_DROPDOWN_PADDING_X * 2;
    if (text_area_w < 0)
    {
        text_area_w = 0;
    }
    int text_x = abs_x + ATK_DROPDOWN_PADDING_X;
    int baseline = atk_font_baseline_for_rect(abs_y, widget->height);
    atk_rect_t clip = { abs_x, abs_y, widget->width - arrow_w, widget->height };
    if (text_area_w > 0)
    {
        atk_font_draw_string_clipped(text_x, baseline, display, fg, face, &clip);
    }
    dropdown_draw_arrow(abs_x + widget->width - arrow_w,
                        abs_y,
                        arrow_w,
                        widget->height,
                        fg);

    if (!priv->open || priv->count == 0)
    {
        return;
    }

    atk_rect_t list_rect = { 0 };
    dropdown_calc_list_rect(widget, priv, origin_x, origin_y, &list_rect);
    if (list_rect.width <= 0 || list_rect.height <= 0)
    {
        return;
    }

    video_draw_rect(list_rect.x, list_rect.y, list_rect.width, list_rect.height, theme->menu_dropdown_face);
    video_draw_rect_outline(list_rect.x, list_rect.y, list_rect.width, list_rect.height, theme->menu_dropdown_border);

    int item_w = list_rect.width;
    int item_h = priv->item_height;
    for (size_t i = 0; i < priv->count; ++i)
    {
        int row_y = list_rect.y + (int)i * item_h;
        video_color_t row_bg = theme->menu_dropdown_face;
        video_color_t row_fg = theme->menu_dropdown_text;
        bool highlighted = ((int)i == priv->highlighted);
        if (highlighted)
        {
            row_bg = theme->menu_dropdown_highlight;
            row_fg = theme->menu_dropdown_face;
        }
        video_draw_rect(list_rect.x + 1, row_y, item_w - 2, item_h, row_bg);

        int row_baseline = atk_font_baseline_for_rect(row_y, item_h);
        int text_start_x = list_rect.x + ATK_DROPDOWN_PADDING_X;
        atk_rect_t row_clip = { list_rect.x + 1, row_y, item_w - 2, item_h };
        const char *title = priv->items[i].title;
        atk_font_draw_string_clipped(text_start_x, row_baseline, title, row_fg, row_bg, &row_clip);
    }
}

static void dropdown_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    if (!widget)
    {
        return;
    }
    atk_dropdown_priv_t *priv = dropdown_priv_mut(widget);
    if (priv)
    {
        if (widget->parent && priv->list_node)
        {
            atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(widget->parent, &ATK_WINDOW_CLASS);
            if (wpriv)
            {
                atk_list_remove(&wpriv->children, priv->list_node);
            }
        }
        if (priv->items)
        {
            free(priv->items);
            priv->items = NULL;
        }
        priv->count = 0;
        priv->capacity = 0;
        priv->list_node = NULL;
    }
    atk_widget_destroy(widget);
}
