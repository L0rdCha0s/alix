#include "atk/atk_checkbox.h"

#include "atk/atk_font.h"
#include "atk_internal.h"
#include "libc.h"
#include "video.h"

#define ATK_CHECKBOX_PADDING_X 4
#define ATK_CHECKBOX_PADDING_Y 2

typedef struct
{
    bool checked;
    bool pressed;
    char *label;
    atk_checkbox_change_t on_change;
    void *on_change_context;
} atk_checkbox_priv_t;

static atk_checkbox_priv_t *checkbox_priv_mut(atk_widget_t *widget)
{
    return (atk_checkbox_priv_t *)atk_widget_priv(widget, &ATK_CHECKBOX_CLASS);
}

static const atk_checkbox_priv_t *checkbox_priv(const atk_widget_t *widget)
{
    return (const atk_checkbox_priv_t *)atk_widget_priv(widget, &ATK_CHECKBOX_CLASS);
}

static void checkbox_invalidate(const atk_widget_t *checkbox)
{
    if (!checkbox)
    {
        return;
    }
    int x = 0;
    int y = 0;
    int w = 0;
    int h = 0;
    atk_widget_absolute_bounds(checkbox, &x, &y, &w, &h);
    atk_dirty_mark_rect(x, y, w, h);

    atk_widget_t *win = checkbox->parent;
    while (win && !atk_widget_is_a(win, &ATK_WINDOW_CLASS))
    {
        win = win->parent;
    }
    if (win)
    {
        video_request_refresh_window(win);
    }
}

static bool checkbox_hit_test_cb(const atk_widget_t *widget,
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

static void checkbox_draw_cb(const atk_state_t *state,
                             const atk_widget_t *widget,
                             int origin_x,
                             int origin_y,
                             void *context)
{
    (void)context;
    atk_checkbox_draw(state, widget);
    (void)origin_x;
    (void)origin_y;
}

static atk_mouse_response_t checkbox_mouse_cb(atk_widget_t *widget,
                                              const atk_mouse_event_t *event,
                                              void *context)
{
    (void)context;
    if (!widget || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_checkbox_priv_t *priv = checkbox_priv_mut(widget);
    if (!priv)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    bool inside = atk_widget_hit_test(widget, event->origin_x, event->origin_y, event->cursor_x, event->cursor_y);

    if (event->pressed_edge && event->left_pressed && inside)
    {
        priv->pressed = true;
        checkbox_invalidate(widget);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE | ATK_MOUSE_RESPONSE_REDRAW;
    }

    if (event->released_edge)
    {
        priv->pressed = false;
        if (inside)
        {
            priv->checked = !priv->checked;
            if (priv->on_change)
            {
                priv->on_change(widget, priv->on_change_context, priv->checked);
            }
        }
        checkbox_invalidate(widget);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_RELEASE | ATK_MOUSE_RESPONSE_REDRAW;
    }

    if (event->left_pressed && priv->pressed)
    {
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE;
    }

    return ATK_MOUSE_RESPONSE_NONE;
}

static void checkbox_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_checkbox_destroy(widget);
    atk_widget_destroy(widget);
}

static const atk_widget_vtable_t checkbox_vtable = { 0 };
static const atk_widget_ops_t g_checkbox_ops = {
    .destroy = checkbox_destroy_cb,
    .draw = checkbox_draw_cb,
    .hit_test = checkbox_hit_test_cb,
    .on_mouse = checkbox_mouse_cb,
    .on_key = NULL
};

const atk_class_t ATK_CHECKBOX_CLASS = { "Checkbox", &ATK_WIDGET_CLASS, &checkbox_vtable, sizeof(atk_checkbox_priv_t) };

static char *checkbox_strdup(const char *src)
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

atk_widget_t *atk_window_add_checkbox(atk_widget_t *window,
                                      const char *label,
                                      int rel_x,
                                      int rel_y,
                                      int width)
{
    if (!window || width <= 0)
    {
        return NULL;
    }
    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return NULL;
    }

    atk_widget_t *checkbox = atk_widget_create(&ATK_CHECKBOX_CLASS);
    if (!checkbox)
    {
        return NULL;
    }

    checkbox->x = rel_x;
    checkbox->y = rel_y;
    checkbox->width = width;
    int line_h = atk_font_line_height();
    if (line_h < ATK_FONT_HEIGHT)
    {
        line_h = ATK_FONT_HEIGHT;
    }
    checkbox->height = line_h + ATK_CHECKBOX_PADDING_Y * 2;
    checkbox->parent = window;
    checkbox->used = true;
    atk_widget_set_ops(checkbox, &g_checkbox_ops, NULL);

    atk_checkbox_priv_t *priv = checkbox_priv_mut(checkbox);
    if (!priv)
    {
        atk_widget_destroy(checkbox);
        return NULL;
    }

    priv->checked = false;
    priv->pressed = false;
    priv->on_change = NULL;
    priv->on_change_context = NULL;
    priv->label = checkbox_strdup(label);

    if (!atk_list_push_back(&wpriv->children, checkbox))
    {
        atk_widget_destroy_any(checkbox);
        return NULL;
    }

    return checkbox;
}

void atk_checkbox_set_label(atk_widget_t *checkbox, const char *label)
{
    atk_checkbox_priv_t *priv = checkbox_priv_mut(checkbox);
    if (!priv)
    {
        return;
    }
    free(priv->label);
    priv->label = checkbox_strdup(label);
    checkbox_invalidate(checkbox);
}

const char *atk_checkbox_label(const atk_widget_t *checkbox)
{
    const atk_checkbox_priv_t *priv = checkbox_priv(checkbox);
    return (priv && priv->label) ? priv->label : "";
}

void atk_checkbox_set_change_handler(atk_widget_t *checkbox, atk_checkbox_change_t handler, void *context)
{
    atk_checkbox_priv_t *priv = checkbox_priv_mut(checkbox);
    if (!priv)
    {
        return;
    }
    priv->on_change = handler;
    priv->on_change_context = context;
}

void atk_checkbox_set_checked(atk_widget_t *checkbox, bool checked)
{
    atk_checkbox_priv_t *priv = checkbox_priv_mut(checkbox);
    if (!priv)
    {
        return;
    }
    if (priv->checked == checked)
    {
        return;
    }
    priv->checked = checked;
    checkbox_invalidate(checkbox);
}

bool atk_checkbox_checked(const atk_widget_t *checkbox)
{
    const atk_checkbox_priv_t *priv = checkbox_priv(checkbox);
    return priv ? priv->checked : false;
}

void atk_checkbox_mark_dirty(const atk_widget_t *checkbox)
{
    checkbox_invalidate(checkbox);
}

void atk_checkbox_draw(const atk_state_t *state, const atk_widget_t *checkbox)
{
    const atk_checkbox_priv_t *priv = checkbox_priv(checkbox);
    if (!state || !checkbox || !checkbox->used || !priv)
    {
        return;
    }

    atk_state_theme_validate(state, "atk_checkbox_draw");

    int origin_x = 0;
    int origin_y = 0;
    if (checkbox->parent)
    {
        atk_widget_absolute_position(checkbox->parent, &origin_x, &origin_y);
    }
    int x = origin_x + checkbox->x;
    int y = origin_y + checkbox->y;
    int w = checkbox->width;
    int h = checkbox->height;

    video_color_t face = state->theme.window_body;
    video_draw_rect(x, y, w, h, face);

    int line_h = atk_font_line_height();
    int box = line_h - 2;
    if (box < 10) box = 10;
    if (box > h - 2) box = h - 2;
    int box_x = x + ATK_CHECKBOX_PADDING_X;
    int box_y = y + (h - box) / 2;

    video_color_t border = state->theme.window_border;
    video_color_t fill = state->theme.button_face;
    video_draw_rect(box_x, box_y, box, box, fill);
    video_draw_rect_outline(box_x, box_y, box, box, border);

    if (priv->checked)
    {
        int inner = box - 6;
        if (inner < 4) inner = box - 2;
        if (inner < 2) inner = 2;
        int ix = box_x + (box - inner) / 2;
        int iy = box_y + (box - inner) / 2;
        video_draw_rect(ix, iy, inner, inner, state->theme.window_title);
    }

    const char *label = (priv->label ? priv->label : "");
    if (label[0] != '\0')
    {
        int text_x = box_x + box + 8;
        int baseline = atk_font_baseline_for_rect(y, h);
        atk_rect_t clip = { x, y, w, h };
        atk_font_draw_string_clipped(text_x, baseline, label, state->theme.button_text, face, &clip);
    }
}

void atk_checkbox_destroy(atk_widget_t *checkbox)
{
    atk_checkbox_priv_t *priv = checkbox_priv_mut(checkbox);
    if (!priv)
    {
        return;
    }
    free(priv->label);
    priv->label = NULL;
    priv->on_change = NULL;
    priv->on_change_context = NULL;
    priv->checked = false;
    priv->pressed = false;
}
