#include "atk/atk_nav_stack.h"

#include "atk_internal.h"
#include "atk_button.h"
#include "atk/atk_iconbox.h"
#include "atk/atk_font.h"
#include "atk_window.h"
#include "libc.h"
#include "video.h"

#define ATK_NAV_TITLE_MAX   48
#define ATK_NAV_HEADER_H    36
#define ATK_NAV_PADDING     10
#define ATK_NAV_BACK_W      70
#define ATK_NAV_BACK_H      26
#define ATK_NAV_SLIDE_STEP  48

typedef struct
{
    atk_widget_t *widget;
    char title[ATK_NAV_TITLE_MAX];
    bool owned;
} atk_nav_entry_t;

typedef struct
{
    atk_nav_entry_t *entries;
    size_t count;
    size_t capacity;
    int header_h;
    int padding;
    bool sliding;
    bool post_pop_refresh;
    int slide_offset;
    atk_widget_t *popping;
} atk_nav_priv_t;

static void nav_destroy_cb(atk_widget_t *widget, void *context);
static void nav_draw_cb(const atk_state_t *state,
                        const atk_widget_t *widget,
                        int origin_x,
                        int origin_y,
                        void *context);
static bool nav_hit_test_cb(const atk_widget_t *widget,
                            int origin_x,
                            int origin_y,
                            int px,
                            int py,
                            void *context);
static atk_mouse_response_t nav_mouse_cb(atk_widget_t *widget,
                                         const atk_mouse_event_t *event,
                                         void *context);
static atk_key_response_t nav_key_cb(atk_widget_t *widget, int key, int modifiers, int action, void *context);

static const atk_widget_vtable_t nav_vtable = { 0 };
static const atk_widget_ops_t g_nav_ops = {
    .destroy = nav_destroy_cb,
    .draw = nav_draw_cb,
    .hit_test = nav_hit_test_cb,
    .on_mouse = nav_mouse_cb,
    .on_key = nav_key_cb
};
const atk_class_t ATK_NAV_STACK_CLASS = { "NavStack", &ATK_WIDGET_CLASS, &nav_vtable, sizeof(atk_nav_priv_t) };

static atk_nav_priv_t *nav_priv_mut(atk_widget_t *nav)
{
    if (!nav)
    {
        return NULL;
    }
    return (atk_nav_priv_t *)atk_widget_priv(nav, &ATK_NAV_STACK_CLASS);
}

static void nav_mark_dirty(const atk_widget_t *nav)
{
    if (!nav)
    {
        return;
    }
    int x = 0, y = 0, w = 0, h = 0;
    atk_widget_absolute_bounds(nav, &x, &y, &w, &h);
    atk_dirty_mark_rect(x, y, w, h);
}

static void nav_request_refresh(const atk_widget_t *nav)
{
    if (!nav)
    {
        return;
    }
    if (nav->parent)
    {
        video_request_refresh_window(nav->parent);
    }
    else
    {
        video_request_refresh();
    }
}

static bool nav_ensure_capacity(atk_nav_priv_t *priv, size_t needed)
{
    if (!priv)
    {
        return false;
    }
    if (needed <= priv->capacity)
    {
        return true;
    }
    size_t new_cap = priv->capacity ? priv->capacity * 2 : 4;
    while (new_cap < needed)
    {
        new_cap *= 2;
    }
    atk_nav_entry_t *entries = (atk_nav_entry_t *)realloc(priv->entries, new_cap * sizeof(atk_nav_entry_t));
    if (!entries)
    {
        return false;
    }
    priv->entries = entries;
    priv->capacity = new_cap;
    return true;
}

static void nav_content_bounds(const atk_widget_t *nav, const atk_nav_priv_t *priv, atk_rect_t *out)
{
    if (!nav || !priv || !out)
    {
        return;
    }
    int x = priv->padding;
    int y = priv->header_h + priv->padding;
    int w = nav->width - priv->padding * 2;
    int h = nav->height - priv->header_h - priv->padding * 2;
    if (w < 0) w = 0;
    if (h < 0) h = 0;
    out->x = x;
    out->y = y;
    out->width = w;
    out->height = h;
}

static void nav_layout_frames(atk_widget_t *nav, atk_nav_priv_t *priv)
{
    if (!nav || !priv)
    {
        return;
    }
    atk_rect_t content = { 0, 0, 0, 0 };
    nav_content_bounds(nav, priv, &content);
    for (size_t i = 0; i < priv->count; ++i)
    {
        atk_widget_t *frame = priv->entries[i].widget;
        if (!frame)
        {
            continue;
        }
        frame->x = content.x;
        frame->y = content.y;
        frame->width = content.width;
        frame->height = content.height;
    }
}

static void nav_finish_pop(atk_widget_t *nav, atk_nav_priv_t *priv)
{
    if (!nav || !priv || priv->count == 0 || !priv->popping)
    {
        priv->sliding = false;
        priv->popping = NULL;
        priv->slide_offset = 0;
        return;
    }

    atk_widget_t *old = priv->entries[priv->count - 1].widget;
    if (old && old == priv->popping)
    {
        atk_widget_destroy_any(old);
    }
    size_t popped_index = priv->count - 1;
    priv->count--;
    priv->entries[popped_index].widget = NULL;
    priv->entries[popped_index].title[0] = '\0';
    priv->entries[popped_index].owned = false;
    priv->popping = NULL;
    priv->sliding = false;
    priv->post_pop_refresh = true;
    priv->slide_offset = 0;
    nav_layout_frames(nav, priv);
    if (priv->count > 0)
    {
        atk_widget_t *top = priv->entries[priv->count - 1].widget;
        if (top)
        {
            top->used = true;
            if (atk_widget_is_a(top, &ATK_ICONBOX_CLASS))
            {
                atk_iconbox_set_active(top, true);
            }
        }
    }
    nav_mark_dirty(nav);
    nav_request_refresh(nav);
}

atk_widget_t *atk_nav_stack_create(void)
{
    atk_widget_t *nav = atk_widget_create(&ATK_NAV_STACK_CLASS);
    if (!nav)
    {
        return NULL;
    }
    nav->used = true;
    nav->parent = NULL;
    nav->x = 0;
    nav->y = 0;
    nav->width = 0;
    nav->height = 0;
    atk_widget_set_ops(nav, &g_nav_ops, NULL);

    atk_nav_priv_t *priv = nav_priv_mut(nav);
    if (!priv)
    {
        atk_widget_destroy(nav);
        return NULL;
    }
    priv->entries = NULL;
    priv->count = 0;
    priv->capacity = 0;
    priv->header_h = ATK_NAV_HEADER_H;
    priv->padding = ATK_NAV_PADDING;
    priv->sliding = false;
    priv->post_pop_refresh = false;
    priv->slide_offset = 0;
    priv->popping = NULL;
    return nav;
}

atk_widget_t *atk_window_add_nav_stack(atk_widget_t *window, int x, int y, int width, int height)
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
    atk_widget_t *nav = atk_nav_stack_create();
    if (!nav)
    {
        return NULL;
    }

    nav->x = x;
    nav->y = y;
    nav->width = width;
    nav->height = height;
    nav->parent = window;

    atk_list_node_t *node = atk_list_push_back(&win_priv->children, nav);
    if (!node)
    {
        atk_widget_destroy(nav);
        return NULL;
    }

    atk_nav_priv_t *priv = nav_priv_mut(nav);
    if (priv)
    {
        priv->popping = NULL;
    }
    return nav;
}

bool atk_nav_stack_push_owned(atk_widget_t *nav, atk_widget_t *frame, const char *title, bool owned)
{
    atk_nav_priv_t *priv = nav_priv_mut(nav);
    if (!nav || !priv || !frame)
    {
        return false;
    }
    if (priv->count > 0)
    {
        atk_widget_t *top = priv->entries[priv->count - 1].widget;
        if (top)
        {
            top->used = false;
            if (atk_widget_is_a(top, &ATK_ICONBOX_CLASS))
            {
                atk_iconbox_set_active(top, false);
            }
        }
    }
    if (!nav_ensure_capacity(priv, priv->count + 1))
    {
        return false;
    }

    frame->parent = nav;
    nav->used = true;
    frame->used = true;
    if (atk_widget_is_a(frame, &ATK_ICONBOX_CLASS))
    {
        atk_iconbox_set_active(frame, true);
    }

    atk_nav_entry_t *entry = &priv->entries[priv->count];
    entry->widget = frame;
    size_t len = title ? strlen(title) : 0;
    if (len >= ATK_NAV_TITLE_MAX)
    {
        len = ATK_NAV_TITLE_MAX - 1;
    }
    if (title && len > 0)
    {
        memcpy(entry->title, title, len);
        entry->title[len] = '\0';
    }
    else
    {
        entry->title[0] = '\0';
    }
    entry->owned = owned;
    priv->count++;
    nav_layout_frames(nav, priv);
    nav_mark_dirty(nav);
    return true;
}

bool atk_nav_stack_push(atk_widget_t *nav, atk_widget_t *frame, const char *title)
{
    return atk_nav_stack_push_owned(nav, frame, title, true);
}

bool atk_nav_stack_pop(atk_widget_t *nav)
{
    atk_nav_priv_t *priv = nav_priv_mut(nav);
    if (!priv || priv->count <= 1 || priv->sliding)
    {
        return false;
    }
    priv->popping = priv->entries[priv->count - 1].widget;
    if (priv->popping)
    {
        priv->popping->used = true;
        priv->popping->parent = nav;
    }
    if (priv->count >= 2)
    {
        atk_widget_t *under = priv->entries[priv->count - 2].widget;
        if (under)
        {
            under->used = true;
            if (atk_widget_is_a(under, &ATK_ICONBOX_CLASS))
            {
                atk_iconbox_set_active(under, true);
            }
        }
    }
    priv->sliding = true;
    priv->slide_offset = 0;
    nav_mark_dirty(nav);
    return true;
}

void atk_nav_stack_relayout(atk_widget_t *nav)
{
    atk_nav_priv_t *priv = nav_priv_mut(nav);
    if (!priv)
    {
        return;
    }
    nav_layout_frames(nav, priv);
    nav_mark_dirty(nav);
}

bool atk_nav_stack_sliding(const atk_widget_t *nav)
{
    const atk_nav_priv_t *priv = (const atk_nav_priv_t *)atk_widget_priv(nav, &ATK_NAV_STACK_CLASS);
    return priv ? (priv->sliding || priv->post_pop_refresh) : false;
}

static void nav_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_nav_priv_t *priv = nav_priv_mut(widget);
    if (priv)
    {
        for (size_t i = 0; i < priv->count; ++i)
        {
            atk_widget_t *child = priv->entries[i].widget;
            if (child && priv->entries[i].owned)
            {
                atk_widget_destroy_any(child);
            }
        }
        free(priv->entries);
        priv->entries = NULL;
        priv->count = 0;
        priv->capacity = 0;
        priv->popping = NULL;
    }
    atk_widget_destroy(widget);
}

static void nav_draw_header(const atk_state_t *state,
                            const atk_widget_t *nav,
                            const atk_nav_priv_t *priv,
                            int origin_x,
                            int origin_y)
{
    const atk_theme_t *theme = &state->theme;
    int header_x = origin_x + nav->x;
    int header_y = origin_y + nav->y;
    video_draw_rect(header_x, header_y, nav->width, priv->header_h, theme->window_title);
    video_draw_rect_outline(header_x, header_y, nav->width, priv->header_h, theme->window_border);

    bool show_back = priv->count > 1;
    if (show_back)
    {
        int bx = header_x + priv->padding;
        int by = header_y + (priv->header_h - ATK_NAV_BACK_H) / 2;
        video_draw_rect(bx, by, ATK_NAV_BACK_W, ATK_NAV_BACK_H, theme->button_face);
        video_draw_rect_outline(bx, by, ATK_NAV_BACK_W, ATK_NAV_BACK_H, theme->button_border);
        const char *label = "< Back";
        int text_w = atk_font_text_width(label);
        int text_x = bx + (ATK_NAV_BACK_W - text_w) / 2;
        int baseline = atk_font_baseline_for_rect(by, ATK_NAV_BACK_H);
        atk_font_draw_string(text_x, baseline, label, theme->button_text, theme->button_face);
    }

    const char *title = (priv->count > 0 && priv->entries)
                            ? priv->entries[priv->count - 1].title
                            : "";
    if (title && *title)
    {
        int text_w = atk_font_text_width(title);
        int text_x = header_x + nav->width / 2 - text_w / 2;
        if (text_x < header_x + priv->padding)
        {
            text_x = header_x + priv->padding;
        }
        int baseline = atk_font_baseline_for_rect(header_y, priv->header_h);
        atk_font_draw_string(text_x, baseline, title, theme->window_title_text, theme->window_title);
    }
}

static void nav_draw_frame(const atk_state_t *state,
                           atk_widget_t *frame,
                           int dx)
{
    if (!frame || !frame->used)
    {
        return;
    }

    int old_x = frame->x;
    if (dx != 0)
    {
        frame->x = old_x + dx;
    }
    atk_widget_draw_any(state, frame);
    frame->x = old_x;
}

static void nav_draw_cb(const atk_state_t *state,
                        const atk_widget_t *widget,
                        int origin_x,
                        int origin_y,
                        void *context)
{
    (void)context;
    atk_nav_priv_t *priv_mut = nav_priv_mut((atk_widget_t *)widget);
    const atk_nav_priv_t *priv = priv_mut;
    if (!state || !widget || !widget->used || !priv)
    {
        return;
    }

    const atk_theme_t *theme = &state->theme;
    int nav_x = origin_x + widget->x;
    int nav_y = origin_y + widget->y;
    video_draw_rect(nav_x, nav_y, widget->width, widget->height, theme->window_body);

    nav_draw_header(state, widget, priv, origin_x, origin_y);

    if (priv->count == 0 || !priv->entries)
    {
        priv_mut->post_pop_refresh = false;
        if (priv->count > 0 && !priv->entries)
        {
            priv_mut->count = 0;
        }
        return;
    }

    atk_widget_t *top = priv->entries[priv->count - 1].widget;
    atk_widget_t *under = (priv->count > 1) ? priv->entries[priv->count - 2].widget : NULL;

    if (priv->sliding && priv->popping)
    {
        if (under)
        {
            nav_draw_frame(state, under, 0);
        }

        priv_mut->slide_offset += ATK_NAV_SLIDE_STEP;
        if (priv_mut->slide_offset > widget->width)
        {
            priv_mut->slide_offset = widget->width;
        }
        nav_draw_frame(state, priv->popping, priv_mut->slide_offset);

        if (priv_mut->slide_offset < widget->width)
        {
            nav_mark_dirty(widget);
            nav_request_refresh(widget);
        }
        else
        {
            nav_finish_pop((atk_widget_t *)widget, priv_mut);
            const atk_nav_priv_t *priv_after = nav_priv_mut((atk_widget_t *)widget);
            if (priv_after)
            {
                nav_draw_header(state, widget, priv_after, origin_x, origin_y);
                if (priv_after->count > 0)
                {
                    atk_widget_t *new_top = priv_after->entries[priv_after->count - 1].widget;
                    nav_draw_frame(state, new_top, 0);
                }
                nav_mark_dirty(widget);
                nav_request_refresh(widget);
            }
        }
        return;
    }

    nav_draw_frame(state, top, 0);
    priv_mut->post_pop_refresh = false;
}

static bool nav_hit_test_cb(const atk_widget_t *widget,
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
    int x0 = origin_x + widget->x;
    int y0 = origin_y + widget->y;
    int x1 = x0 + widget->width;
    int y1 = y0 + widget->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

static bool nav_hit_back(const atk_widget_t *nav,
                         const atk_nav_priv_t *priv,
                         const atk_mouse_event_t *event)
{
    if (!nav || !priv || !event || priv->count <= 1)
    {
        return false;
    }
    int lx = event->local_x;
    int ly = event->local_y;
    return (lx >= priv->padding &&
            lx < priv->padding + ATK_NAV_BACK_W &&
            ly >= (priv->header_h - ATK_NAV_BACK_H) / 2 &&
            ly < (priv->header_h - ATK_NAV_BACK_H) / 2 + ATK_NAV_BACK_H);
}

static bool nav_point_in_content(const atk_widget_t *nav,
                                 const atk_nav_priv_t *priv,
                                 const atk_mouse_event_t *event)
{
    if (!nav || !priv || !event)
    {
        return false;
    }
    int x0 = priv->padding;
    int y0 = priv->header_h + priv->padding;
    int w = nav->width - priv->padding * 2;
    int h = nav->height - priv->header_h - priv->padding * 2;
    if (w < 0) w = 0;
    if (h < 0) h = 0;
    int lx = event->local_x;
    int ly = event->local_y;
    return (lx >= x0 && lx < x0 + w && ly >= y0 && ly < y0 + h);
}

static atk_mouse_response_t nav_dispatch_mouse_to_child(atk_widget_t *child,
                                                        const atk_mouse_event_t *event)
{
    if (!child || !child->used || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_mouse_event_t ev = *event;
    int abs_x = 0, abs_y = 0;
    atk_widget_absolute_position(child, &abs_x, &abs_y);
    ev.origin_x = abs_x - child->x;
    ev.origin_y = abs_y - child->y;
    ev.local_x = event->cursor_x - abs_x;
    ev.local_y = event->cursor_y - abs_y;
    return atk_widget_dispatch_mouse(child, &ev);
}

static atk_key_response_t nav_dispatch_key_to_child(atk_widget_t *child, int key, int modifiers, int action)
{
    if (!child || !child->used)
    {
        return ATK_KEY_RESPONSE_NONE;
    }
    return atk_widget_dispatch_key(child, key, modifiers, action);
}

static atk_mouse_response_t nav_mouse_cb(atk_widget_t *widget,
                                         const atk_mouse_event_t *event,
                                         void *context)
{
    (void)context;
    atk_nav_priv_t *priv = nav_priv_mut(widget);
    if (!priv || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    if (priv->sliding)
    {
        return ATK_MOUSE_RESPONSE_HANDLED;
    }

    if (event->pressed_edge && nav_hit_back(widget, priv, event))
    {
        atk_nav_stack_pop(widget);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW;
    }

    if (priv->count == 0)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    if (!nav_point_in_content(widget, priv, event))
    {
        return ATK_MOUSE_RESPONSE_HANDLED;
    }

    atk_widget_t *top = priv->entries[priv->count - 1].widget;
    atk_mouse_response_t resp = nav_dispatch_mouse_to_child(top, event);
    if (resp & ATK_MOUSE_RESPONSE_REDRAW)
    {
        nav_mark_dirty(widget);
    }
    return resp;
}

static atk_key_response_t nav_key_cb(atk_widget_t *widget, int key, int modifiers, int action, void *context)
{
    (void)context;
    atk_nav_priv_t *priv = nav_priv_mut(widget);
    if (!priv || priv->count == 0)
    {
        return ATK_KEY_RESPONSE_NONE;
    }
    atk_widget_t *top = priv->entries[priv->count - 1].widget;
    atk_key_response_t resp = nav_dispatch_key_to_child(top, key, modifiers, action);
    if (resp & ATK_KEY_RESPONSE_REDRAW)
    {
        nav_mark_dirty(widget);
    }
    return resp;
}
