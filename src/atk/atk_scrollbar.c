#include "atk/atk_scrollbar.h"

#include "atk_internal.h"
#include "libc.h"
#include "video.h"

#define ATK_SCROLLBAR_MIN_THUMB 12

typedef struct
{
    atk_list_node_t *list_node;
    atk_scrollbar_orientation_t orientation;
    int min_value;
    int max_value;
    int page_size;
    int value;
    bool dragging;
    int drag_offset;
    atk_scrollbar_change_t change;
    void *change_context;
} atk_scrollbar_priv_t;

static atk_mouse_response_t scrollbar_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context);
static void scrollbar_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context);
static bool scrollbar_hit_test_cb(const atk_widget_t *widget,
                                   int origin_x,
                                   int origin_y,
                                   int px,
                                   int py,
                                   void *context);
static void scrollbar_destroy_cb(atk_widget_t *widget, void *context);

static const atk_widget_vtable_t scrollbar_vtable = { 0 };
static const atk_widget_ops_t g_scrollbar_ops = {
    .destroy = scrollbar_destroy_cb,
    .draw = scrollbar_draw_cb,
    .hit_test = scrollbar_hit_test_cb,
    .on_mouse = scrollbar_mouse_cb,
    .on_key = NULL
};
const atk_class_t ATK_SCROLLBAR_CLASS = { "Scrollbar", &ATK_WIDGET_CLASS, &scrollbar_vtable, sizeof(atk_scrollbar_priv_t) };

static atk_scrollbar_priv_t *scrollbar_priv_mut(atk_widget_t *scrollbar);
static const atk_scrollbar_priv_t *scrollbar_priv(const atk_widget_t *scrollbar);
static void scrollbar_invalidate(const atk_widget_t *scrollbar);
static bool scrollbar_set_value_internal(atk_widget_t *scrollbar, atk_scrollbar_priv_t *priv, int value, bool from_user);
static int scrollbar_track_length(const atk_widget_t *scrollbar, const atk_scrollbar_priv_t *priv);
static int scrollbar_thumb_length(const atk_widget_t *scrollbar, const atk_scrollbar_priv_t *priv, int track_length);
static int scrollbar_thumb_start(const atk_widget_t *scrollbar,
                                 const atk_scrollbar_priv_t *priv,
                                 int track_length,
                                 int thumb_length);
static int scrollbar_axis_coord(const atk_widget_t *scrollbar, const atk_scrollbar_priv_t *priv, int px, int py);
static int scrollbar_value_from_coord(const atk_widget_t *scrollbar,
                                      const atk_scrollbar_priv_t *priv,
                                      int coord,
                                      int track_length,
                                      int thumb_length);

atk_widget_t *atk_window_add_scrollbar(atk_widget_t *window,
                                       int x,
                                       int y,
                                       int width,
                                       int height,
                                       atk_scrollbar_orientation_t orientation)
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

    atk_widget_t *scrollbar = atk_widget_create(&ATK_SCROLLBAR_CLASS);
    if (!scrollbar)
    {
        return NULL;
    }

    scrollbar->x = x;
    scrollbar->y = y;
    scrollbar->width = width;
    scrollbar->height = height;
    scrollbar->parent = window;
    scrollbar->used = true;
    atk_widget_set_ops(scrollbar, &g_scrollbar_ops, NULL);

    atk_scrollbar_priv_t *sb_priv = scrollbar_priv_mut(scrollbar);
    sb_priv->orientation = orientation;
    sb_priv->min_value = 0;
    sb_priv->max_value = 0;
    sb_priv->page_size = 1;
    sb_priv->value = 0;
    sb_priv->dragging = false;
    sb_priv->drag_offset = 0;
    sb_priv->change = NULL;
    sb_priv->change_context = NULL;
    sb_priv->list_node = NULL;

    atk_list_node_t *child_node = atk_list_push_back(&priv->children, scrollbar);
    if (!child_node)
    {
        atk_widget_destroy(scrollbar);
        return NULL;
    }

    atk_list_node_t *sb_node = atk_list_push_back(&priv->scrollbars, scrollbar);
    if (!sb_node)
    {
        atk_list_remove(&priv->children, child_node);
        atk_widget_destroy(scrollbar);
        return NULL;
    }

    sb_priv->list_node = sb_node;
    return scrollbar;
}

void atk_scrollbar_set_change_handler(atk_widget_t *scrollbar, atk_scrollbar_change_t handler, void *context)
{
    atk_scrollbar_priv_t *priv = scrollbar_priv_mut(scrollbar);
    if (!priv)
    {
        return;
    }
    priv->change = handler;
    priv->change_context = context;
}

void atk_scrollbar_set_range(atk_widget_t *scrollbar, int min_value, int max_value, int page_size)
{
    atk_scrollbar_priv_t *priv = scrollbar_priv_mut(scrollbar);
    if (!priv)
    {
        return;
    }
    if (page_size < 1)
    {
        page_size = 1;
    }
    if (max_value < min_value)
    {
        max_value = min_value;
    }
    priv->min_value = min_value;
    priv->max_value = max_value;
    priv->page_size = page_size;
    scrollbar_set_value_internal(scrollbar, priv, priv->value, false);
    scrollbar_invalidate(scrollbar);
}

void atk_scrollbar_set_value(atk_widget_t *scrollbar, int value)
{
    atk_scrollbar_priv_t *priv = scrollbar_priv_mut(scrollbar);
    if (!priv)
    {
        return;
    }
    scrollbar_set_value_internal(scrollbar, priv, value, false);
}

int atk_scrollbar_value(const atk_widget_t *scrollbar)
{
    const atk_scrollbar_priv_t *priv = scrollbar_priv(scrollbar);
    return priv ? priv->value : 0;
}

bool atk_scrollbar_hit_test(const atk_widget_t *scrollbar, int origin_x, int origin_y, int px, int py)
{
    if (!scrollbar || !scrollbar->used)
    {
        return false;
    }
    int x0 = origin_x + scrollbar->x;
    int y0 = origin_y + scrollbar->y;
    int x1 = x0 + scrollbar->width;
    int y1 = y0 + scrollbar->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

bool atk_scrollbar_begin_drag(atk_widget_t *scrollbar, int px, int py, bool *value_changed)
{
    if (value_changed)
    {
        *value_changed = false;
    }

    atk_scrollbar_priv_t *priv = scrollbar_priv_mut(scrollbar);
    if (!priv)
    {
        return false;
    }

    int track_length = scrollbar_track_length(scrollbar, priv);
    if (track_length <= 0)
    {
        priv->dragging = false;
        priv->drag_offset = 0;
        return false;
    }

    int thumb_length = scrollbar_thumb_length(scrollbar, priv, track_length);
    int thumb_start = scrollbar_thumb_start(scrollbar, priv, track_length, thumb_length);
    int coord = scrollbar_axis_coord(scrollbar, priv, px, py);
    if (coord < 0) coord = 0;
    if (coord > track_length) coord = track_length;

    priv->dragging = true;

    if (coord >= thumb_start && coord < thumb_start + thumb_length)
    {
        priv->drag_offset = coord - thumb_start;
        return true;
    }

    int scrollable = track_length - thumb_length;
    if (scrollable <= 0)
    {
        priv->drag_offset = 0;
        return true;
    }

    priv->drag_offset = thumb_length / 2;
    int new_coord = coord - priv->drag_offset;
    if (new_coord < 0) new_coord = 0;
    if (new_coord > scrollable) new_coord = scrollable;

    int new_value = scrollbar_value_from_coord(scrollbar, priv, new_coord, track_length, thumb_length);
    bool changed = scrollbar_set_value_internal(scrollbar, priv, new_value, true);
    if (value_changed)
    {
        *value_changed = changed;
    }
    return true;
}

bool atk_scrollbar_drag_to(atk_widget_t *scrollbar, int px, int py)
{
    atk_scrollbar_priv_t *priv = scrollbar_priv_mut(scrollbar);
    if (!priv || !priv->dragging)
    {
        return false;
    }

    int track_length = scrollbar_track_length(scrollbar, priv);
    if (track_length <= 0)
    {
        return false;
    }

    int thumb_length = scrollbar_thumb_length(scrollbar, priv, track_length);
    int scrollable = track_length - thumb_length;
    if (scrollable <= 0)
    {
        return false;
    }

    int coord = scrollbar_axis_coord(scrollbar, priv, px, py) - priv->drag_offset;
    if (coord < 0) coord = 0;
    if (coord > scrollable) coord = scrollable;

    int new_value = scrollbar_value_from_coord(scrollbar, priv, coord, track_length, thumb_length);
    return scrollbar_set_value_internal(scrollbar, priv, new_value, true);
}

void atk_scrollbar_end_drag(atk_widget_t *scrollbar)
{
    atk_scrollbar_priv_t *priv = scrollbar_priv_mut(scrollbar);
    if (!priv)
    {
        return;
    }
    priv->dragging = false;
    priv->drag_offset = 0;
}

void atk_scrollbar_mark_dirty(const atk_widget_t *scrollbar)
{
    scrollbar_invalidate(scrollbar);
}

void atk_scrollbar_draw(const atk_state_t *state, const atk_widget_t *scrollbar)
{
    (void)state;
    if (!scrollbar || !scrollbar->used)
    {
        return;
    }

    const atk_scrollbar_priv_t *priv = scrollbar_priv(scrollbar);
    if (!priv)
    {
        return;
    }

    int origin_x = scrollbar->parent ? scrollbar->parent->x : 0;
    int origin_y = scrollbar->parent ? scrollbar->parent->y : 0;
    int x = origin_x + scrollbar->x;
    int y = origin_y + scrollbar->y;

    const atk_theme_t *theme = state ? &state->theme : NULL;
    uint16_t track_color = theme ? theme->window_body : video_make_color(0xD0, 0xD0, 0xD0);
    uint16_t track_border = theme ? theme->window_border : video_make_color(0x70, 0x70, 0x70);
    uint16_t thumb_face = theme ? theme->button_face : video_make_color(0xB0, 0xB0, 0xB0);
    uint16_t thumb_border = theme ? theme->button_border : video_make_color(0x50, 0x50, 0x50);

    video_draw_rect(x, y, scrollbar->width, scrollbar->height, track_color);
    video_draw_rect_outline(x, y, scrollbar->width, scrollbar->height, track_border);

    int track_length = scrollbar_track_length(scrollbar, priv);
    if (track_length <= 0)
    {
        return;
    }

    int thumb_length = scrollbar_thumb_length(scrollbar, priv, track_length);
    int thumb_start = scrollbar_thumb_start(scrollbar, priv, track_length, thumb_length);

    if (priv->orientation == ATK_SCROLLBAR_VERTICAL)
    {
        int thumb_y = y + thumb_start;
        int thumb_height = thumb_length;
        int thumb_width = scrollbar->width > 2 ? scrollbar->width - 2 : scrollbar->width;
        int thumb_x = x + (scrollbar->width - thumb_width) / 2;
        video_draw_rect(thumb_x, thumb_y, thumb_width, thumb_height, thumb_face);
        video_draw_rect_outline(thumb_x, thumb_y, thumb_width, thumb_height, thumb_border);
    }
    else
    {
        int thumb_x = x + thumb_start;
        int thumb_width = thumb_length;
        int thumb_height = scrollbar->height > 2 ? scrollbar->height - 2 : scrollbar->height;
        int thumb_y = y + (scrollbar->height - thumb_height) / 2;
        video_draw_rect(thumb_x, thumb_y, thumb_width, thumb_height, thumb_face);
        video_draw_rect_outline(thumb_x, thumb_y, thumb_width, thumb_height, thumb_border);
    }
}

void atk_scrollbar_destroy(atk_widget_t *scrollbar)
{
    atk_scrollbar_priv_t *priv = scrollbar_priv_mut(scrollbar);
    if (!priv)
    {
        return;
    }

    if (scrollbar && scrollbar->parent && priv->list_node)
    {
        atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(scrollbar->parent, &ATK_WINDOW_CLASS);
        if (wpriv)
        {
            atk_list_remove(&wpriv->scrollbars, priv->list_node);
        }
    }

    priv->list_node = NULL;
    priv->change = NULL;
    priv->change_context = NULL;
    priv->dragging = false;
    priv->drag_offset = 0;
}

static atk_mouse_response_t scrollbar_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context)
{
    (void)context;
    atk_scrollbar_priv_t *priv = scrollbar_priv_mut(widget);
    if (!priv || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_mouse_response_t response = ATK_MOUSE_RESPONSE_NONE;

    if (event->pressed_edge)
    {
        bool value_changed = false;
        if (atk_scrollbar_begin_drag(widget, event->cursor_x, event->cursor_y, &value_changed))
        {
            response |= ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE;
            if (value_changed)
            {
                response |= ATK_MOUSE_RESPONSE_REDRAW;
            }
        }
    }
    else if (event->released_edge)
    {
        if (priv->dragging)
        {
            atk_scrollbar_end_drag(widget);
            response |= ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_RELEASE;
        }
    }
    else if (event->left_pressed && priv->dragging)
    {
        if (atk_scrollbar_drag_to(widget, event->cursor_x, event->cursor_y))
        {
            response |= ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW;
        }
    }

    return response;
}

static void scrollbar_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context)
{
    (void)origin_x;
    (void)origin_y;
    (void)context;
    atk_scrollbar_draw(state, widget);
}

static bool scrollbar_hit_test_cb(const atk_widget_t *widget,
                                   int origin_x,
                                   int origin_y,
                                   int px,
                                   int py,
                                   void *context)
{
    (void)context;
    return atk_scrollbar_hit_test(widget, origin_x, origin_y, px, py);
}

static void scrollbar_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_scrollbar_destroy(widget);
    atk_widget_destroy(widget);
}

static atk_scrollbar_priv_t *scrollbar_priv_mut(atk_widget_t *scrollbar)
{
    if (!scrollbar)
    {
        return NULL;
    }
    return (atk_scrollbar_priv_t *)atk_widget_priv(scrollbar, &ATK_SCROLLBAR_CLASS);
}

static const atk_scrollbar_priv_t *scrollbar_priv(const atk_widget_t *scrollbar)
{
    if (!scrollbar)
    {
        return NULL;
    }
    return (const atk_scrollbar_priv_t *)atk_widget_priv(scrollbar, &ATK_SCROLLBAR_CLASS);
}

static void scrollbar_invalidate(const atk_widget_t *scrollbar)
{
    if (!scrollbar || !scrollbar->parent)
    {
        return;
    }
    int origin_x = scrollbar->parent->x + scrollbar->x;
    int origin_y = scrollbar->parent->y + scrollbar->y;
    atk_dirty_mark_rect(origin_x, origin_y, scrollbar->width, scrollbar->height);
    video_request_refresh_window(scrollbar->parent);
}

static bool scrollbar_set_value_internal(atk_widget_t *scrollbar, atk_scrollbar_priv_t *priv, int value, bool from_user)
{
    if (!priv)
    {
        return false;
    }
    if (value < priv->min_value) value = priv->min_value;
    if (value > priv->max_value) value = priv->max_value;
    if (value == priv->value)
    {
        return false;
    }
    priv->value = value;
    scrollbar_invalidate(scrollbar);
    if (from_user && priv->change)
    {
        priv->change(scrollbar, priv->change_context, priv->value);
    }
    return true;
}

static int scrollbar_track_length(const atk_widget_t *scrollbar, const atk_scrollbar_priv_t *priv)
{
    if (!scrollbar || !priv)
    {
        return 0;
    }
    return (priv->orientation == ATK_SCROLLBAR_VERTICAL) ? scrollbar->height : scrollbar->width;
}

static int scrollbar_thumb_length(const atk_widget_t *scrollbar, const atk_scrollbar_priv_t *priv, int track_length)
{
    if (!scrollbar || !priv || track_length <= 0)
    {
        return 0;
    }

    int page = priv->page_size > 0 ? priv->page_size : 1;
    int range = priv->max_value - priv->min_value;
    int total = range + page;
    int thumb = track_length;

    if (total > 0)
    {
        thumb = (int)((int64_t)track_length * page / total);
    }

    if (thumb < ATK_SCROLLBAR_MIN_THUMB) thumb = ATK_SCROLLBAR_MIN_THUMB;
    if (thumb > track_length) thumb = track_length;
    return thumb;
}

static int scrollbar_thumb_start(const atk_widget_t *scrollbar,
                                 const atk_scrollbar_priv_t *priv,
                                 int track_length,
                                 int thumb_length)
{
    if (!scrollbar || !priv || track_length <= 0)
    {
        return 0;
    }

    int range = priv->max_value - priv->min_value;
    if (range <= 0)
    {
        return 0;
    }

    int scrollable = track_length - thumb_length;
    if (scrollable <= 0)
    {
        return 0;
    }

    int value = priv->value - priv->min_value;
    if (value < 0) value = 0;
    if (value > range) value = range;

    return (int)((int64_t)value * scrollable / range);
}

static int scrollbar_axis_coord(const atk_widget_t *scrollbar, const atk_scrollbar_priv_t *priv, int px, int py)
{
    (void)priv;
    int origin_x = scrollbar->parent ? scrollbar->parent->x : 0;
    int origin_y = scrollbar->parent ? scrollbar->parent->y : 0;
    int local_x = px - (origin_x + scrollbar->x);
    int local_y = py - (origin_y + scrollbar->y);
    return (priv->orientation == ATK_SCROLLBAR_VERTICAL) ? local_y : local_x;
}

static int scrollbar_value_from_coord(const atk_widget_t *scrollbar,
                                      const atk_scrollbar_priv_t *priv,
                                      int coord,
                                      int track_length,
                                      int thumb_length)
{
    if (!scrollbar || !priv)
    {
        return 0;
    }

    int range = priv->max_value - priv->min_value;
    if (range <= 0)
    {
        return priv->min_value;
    }

    int scrollable = track_length - thumb_length;
    if (scrollable <= 0)
    {
        return priv->min_value;
    }

    if (coord < 0) coord = 0;
    if (coord > scrollable) coord = scrollable;

    int value = (int)((int64_t)coord * range / scrollable);
    return priv->min_value + value;
}
