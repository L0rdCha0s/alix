#include "atk/atk_radio.h"

#include "atk/atk_font.h"
#include "atk_internal.h"
#include "libc.h"
#include "video.h"

#define ATK_RADIO_PADDING_X 4
#define ATK_RADIO_PADDING_Y 2

struct atk_radio_group
{
    atk_list_t members;
    size_t refcount;
    bool destroying;
};

typedef struct
{
    bool selected;
    bool pressed;
    char *label;
    atk_radio_group_t *group;
    atk_list_node_t *group_node;
    atk_radio_change_t on_change;
    void *on_change_context;
} atk_radio_priv_t;

static atk_radio_priv_t *radio_priv_mut(atk_widget_t *widget)
{
    return (atk_radio_priv_t *)atk_widget_priv(widget, &ATK_RADIO_BUTTON_CLASS);
}

static const atk_radio_priv_t *radio_priv(const atk_widget_t *widget)
{
    return (const atk_radio_priv_t *)atk_widget_priv(widget, &ATK_RADIO_BUTTON_CLASS);
}

static char *radio_strdup(const char *src)
{
    if (!src)
    {
        src = "";
    }
    size_t len = strlen(src);
    char *dst = (char *)malloc(len + 1);
    if (!dst)
    {
        return NULL;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

static void radio_invalidate(const atk_widget_t *radio)
{
    if (!radio)
    {
        return;
    }
    int x = 0;
    int y = 0;
    int w = 0;
    int h = 0;
    atk_widget_absolute_bounds(radio, &x, &y, &w, &h);
    atk_dirty_mark_rect(x, y, w, h);

    atk_widget_t *win = radio->parent;
    while (win && !atk_widget_is_a(win, &ATK_WINDOW_CLASS))
    {
        win = win->parent;
    }
    if (win)
    {
        video_request_refresh_window(win);
    }
}

static void radio_draw_filled_circle(int cx, int cy, int r, video_color_t color)
{
    if (r <= 0)
    {
        return;
    }
    int r2 = r * r;
    for (int dy = -r; dy <= r; ++dy)
    {
        int y = cy + dy;
        int dx_max = 0;
        int rem = r2 - dy * dy;
        while ((dx_max + 1) * (dx_max + 1) <= rem)
        {
            dx_max++;
        }
        int x0 = cx - dx_max;
        int w = dx_max * 2 + 1;
        video_draw_rect(x0, y, w, 1, color);
    }
}

static void radio_draw_circle_outline(int cx, int cy, int r, video_color_t border, video_color_t fill)
{
    if (r <= 0)
    {
        return;
    }
    radio_draw_filled_circle(cx, cy, r, border);
    if (r > 1)
    {
        radio_draw_filled_circle(cx, cy, r - 1, fill);
    }
}

static void radio_group_notify_change(atk_widget_t *widget, bool selected)
{
    atk_radio_priv_t *priv = radio_priv_mut(widget);
    if (priv && priv->on_change)
    {
        priv->on_change(widget, priv->on_change_context, selected);
    }
}

static void radio_group_select(atk_radio_group_t *group, atk_widget_t *selected_widget)
{
    if (!group)
    {
        return;
    }

    ATK_LIST_FOR_EACH(node, &group->members)
    {
        atk_widget_t *member = (atk_widget_t *)node->value;
        if (!member)
        {
            continue;
        }
        atk_radio_priv_t *priv = radio_priv_mut(member);
        if (!priv)
        {
            continue;
        }
        bool should_select = (member == selected_widget);
        if (priv->selected == should_select)
        {
            continue;
        }
        priv->selected = should_select;
        if (member->used)
        {
            radio_invalidate(member);
        }
        radio_group_notify_change(member, priv->selected);
    }
}

static bool radio_hit_test_cb(const atk_widget_t *widget,
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

static void radio_draw_cb(const atk_state_t *state,
                          const atk_widget_t *widget,
                          int origin_x,
                          int origin_y,
                          void *context)
{
    (void)context;
    atk_radio_button_draw(state, widget);
    (void)origin_x;
    (void)origin_y;
}

static atk_mouse_response_t radio_mouse_cb(atk_widget_t *widget,
                                           const atk_mouse_event_t *event,
                                           void *context)
{
    (void)context;
    if (!widget || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_radio_priv_t *priv = radio_priv_mut(widget);
    if (!priv)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    bool inside = atk_widget_hit_test(widget, event->origin_x, event->origin_y, event->cursor_x, event->cursor_y);

    if (event->pressed_edge && event->left_pressed && inside)
    {
        priv->pressed = true;
        radio_invalidate(widget);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE | ATK_MOUSE_RESPONSE_REDRAW;
    }

    if (event->released_edge)
    {
        priv->pressed = false;
        if (inside && !priv->selected)
        {
            if (priv->group)
            {
                radio_group_select(priv->group, widget);
            }
            else
            {
                priv->selected = true;
                radio_invalidate(widget);
                radio_group_notify_change(widget, true);
            }
        }
        radio_invalidate(widget);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_RELEASE | ATK_MOUSE_RESPONSE_REDRAW;
    }

    if (event->left_pressed && priv->pressed)
    {
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE;
    }

    return ATK_MOUSE_RESPONSE_NONE;
}

static void radio_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_radio_button_destroy(widget);
    atk_widget_destroy(widget);
}

static const atk_widget_vtable_t radio_vtable = { 0 };
static const atk_widget_ops_t g_radio_ops = {
    .destroy = radio_destroy_cb,
    .draw = radio_draw_cb,
    .hit_test = radio_hit_test_cb,
    .on_mouse = radio_mouse_cb,
    .on_key = NULL
};

const atk_class_t ATK_RADIO_BUTTON_CLASS = { "RadioButton", &ATK_WIDGET_CLASS, &radio_vtable, sizeof(atk_radio_priv_t) };

atk_radio_group_t *atk_radio_group_create(void)
{
    atk_radio_group_t *group = (atk_radio_group_t *)calloc(1, sizeof(*group));
    if (!group)
    {
        return NULL;
    }
    atk_list_init(&group->members);
    group->refcount = 0;
    group->destroying = false;
    return group;
}

void atk_radio_group_destroy(atk_radio_group_t *group)
{
    if (!group)
    {
        return;
    }
    group->destroying = true;

    ATK_LIST_FOR_EACH(node, &group->members)
    {
        atk_widget_t *member = (atk_widget_t *)node->value;
        if (!member)
        {
            continue;
        }
        atk_radio_priv_t *priv = radio_priv_mut(member);
        if (priv)
        {
            priv->group = NULL;
            priv->group_node = NULL;
        }
    }

    atk_list_clear(&group->members, NULL);
    free(group);
}

atk_widget_t *atk_window_add_radio_button(atk_widget_t *window,
                                         atk_radio_group_t *group,
                                         const char *label,
                                         int rel_x,
                                         int rel_y,
                                         int width)
{
    if (!window || width <= 0 || !group || group->destroying)
    {
        return NULL;
    }
    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return NULL;
    }

    atk_widget_t *radio = atk_widget_create(&ATK_RADIO_BUTTON_CLASS);
    if (!radio)
    {
        return NULL;
    }

    radio->x = rel_x;
    radio->y = rel_y;
    radio->width = width;
    int line_h = atk_font_line_height();
    if (line_h < ATK_FONT_HEIGHT)
    {
        line_h = ATK_FONT_HEIGHT;
    }
    radio->height = line_h + ATK_RADIO_PADDING_Y * 2;
    radio->parent = window;
    radio->used = true;
    atk_widget_set_ops(radio, &g_radio_ops, NULL);

    atk_radio_priv_t *priv = radio_priv_mut(radio);
    if (!priv)
    {
        atk_widget_destroy(radio);
        return NULL;
    }
    priv->selected = false;
    priv->pressed = false;
    priv->label = radio_strdup(label);
    priv->group = group;
    priv->group_node = atk_list_push_back(&group->members, radio);
    priv->on_change = NULL;
    priv->on_change_context = NULL;

    if (!priv->group_node)
    {
        atk_widget_destroy_any(radio);
        return NULL;
    }

    if (!atk_list_push_back(&wpriv->children, radio))
    {
        atk_list_remove(&group->members, priv->group_node);
        priv->group_node = NULL;
        atk_widget_destroy_any(radio);
        return NULL;
    }
    group->refcount++;

    return radio;
}

void atk_radio_button_set_label(atk_widget_t *radio, const char *label)
{
    atk_radio_priv_t *priv = radio_priv_mut(radio);
    if (!priv)
    {
        return;
    }
    free(priv->label);
    priv->label = radio_strdup(label);
    radio_invalidate(radio);
}

const char *atk_radio_button_label(const atk_widget_t *radio)
{
    const atk_radio_priv_t *priv = radio_priv(radio);
    return (priv && priv->label) ? priv->label : "";
}

const atk_radio_group_t *atk_radio_button_group(const atk_widget_t *radio)
{
    const atk_radio_priv_t *priv = radio_priv(radio);
    return priv ? priv->group : NULL;
}

void atk_radio_button_set_change_handler(atk_widget_t *radio, atk_radio_change_t handler, void *context)
{
    atk_radio_priv_t *priv = radio_priv_mut(radio);
    if (!priv)
    {
        return;
    }
    priv->on_change = handler;
    priv->on_change_context = context;
}

void atk_radio_button_set_selected(atk_widget_t *radio, bool selected)
{
    atk_radio_priv_t *priv = radio_priv_mut(radio);
    if (!priv)
    {
        return;
    }
    if (selected)
    {
        if (priv->group)
        {
            radio_group_select(priv->group, radio);
            return;
        }
    }
    if (priv->selected == selected)
    {
        return;
    }
    priv->selected = selected;
    radio_invalidate(radio);
}

bool atk_radio_button_selected(const atk_widget_t *radio)
{
    const atk_radio_priv_t *priv = radio_priv(radio);
    return priv ? priv->selected : false;
}

void atk_radio_button_mark_dirty(const atk_widget_t *radio)
{
    radio_invalidate(radio);
}

void atk_radio_button_draw(const atk_state_t *state, const atk_widget_t *radio)
{
    const atk_radio_priv_t *priv = radio_priv(radio);
    if (!state || !radio || !radio->used || !priv)
    {
        return;
    }

    atk_state_theme_validate(state, "atk_radio_button_draw");

    int origin_x = 0;
    int origin_y = 0;
    if (radio->parent)
    {
        atk_widget_absolute_position(radio->parent, &origin_x, &origin_y);
    }
    int x = origin_x + radio->x;
    int y = origin_y + radio->y;
    int w = radio->width;
    int h = radio->height;

    video_color_t face = state->theme.window_body;
    video_draw_rect(x, y, w, h, face);

    int line_h = atk_font_line_height();
    int r = (line_h - 2) / 2;
    if (r < 5) r = 5;
    int cx = x + ATK_RADIO_PADDING_X + r;
    int cy = y + h / 2;

    video_color_t border = state->theme.window_border;
    video_color_t fill = state->theme.button_face;
    radio_draw_circle_outline(cx, cy, r, border, fill);

    if (priv->selected)
    {
        int inner_r = r - 3;
        if (inner_r < 2) inner_r = 2;
        radio_draw_filled_circle(cx, cy, inner_r, state->theme.window_title);
    }

    const char *label = (priv->label ? priv->label : "");
    if (label[0] != '\0')
    {
        int text_x = cx + r + 8;
        int baseline = atk_font_baseline_for_rect(y, h);
        atk_rect_t clip = { x, y, w, h };
        atk_font_draw_string_clipped(text_x, baseline, label, state->theme.button_text, face, &clip);
    }
}

void atk_radio_button_destroy(atk_widget_t *radio)
{
    atk_radio_priv_t *priv = radio_priv_mut(radio);
    if (!priv)
    {
        return;
    }
    atk_radio_group_t *group = priv->group;
    if (group && priv->group_node)
    {
        atk_list_remove(&group->members, priv->group_node);
        priv->group_node = NULL;
    }
    priv->group = NULL;

    if (group && !group->destroying && group->refcount > 0)
    {
        group->refcount--;
        if (group->refcount == 0)
        {
            atk_list_clear(&group->members, NULL);
            free(group);
            group = NULL;
        }
    }
    free(priv->label);
    priv->label = NULL;
    priv->selected = false;
    priv->pressed = false;
    priv->on_change = NULL;
    priv->on_change_context = NULL;
}
