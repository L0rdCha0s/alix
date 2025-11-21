#include "atk_button.h"

#include <stddef.h>

#include "libc.h"
#include "video.h"
#include "atk/atk_font.h"

static void button_set_title(atk_button_priv_t *priv, const char *title);
static atk_button_priv_t *button_priv_mut(atk_widget_t *widget);
static const atk_button_priv_t *button_priv(const atk_widget_t *widget);

static const atk_widget_vtable_t button_vtable = { 0 };
static void button_draw_cb(const atk_state_t *state,
                           const atk_widget_t *widget,
                           int origin_x,
                           int origin_y,
                           void *context);
static bool button_hit_test_cb(const atk_widget_t *widget,
                               int origin_x,
                               int origin_y,
                               int px,
                               int py,
                               void *context);
static void button_destroy_cb(atk_widget_t *widget, void *context);

static const atk_widget_ops_t g_button_ops = {
    .destroy = button_destroy_cb,
    .draw = button_draw_cb,
    .hit_test = button_hit_test_cb,
    .on_mouse = NULL,
    .on_key = NULL
};

const atk_class_t ATK_WIDGET_CLASS = { "Widget", 0, 0, 0 };
const atk_class_t ATK_BUTTON_CLASS = { "Button", &ATK_WIDGET_CLASS, &button_vtable, sizeof(atk_button_priv_t) };

void atk_button_configure(atk_widget_t *widget,
                          const char *title,
                          atk_button_style_t style,
                          bool draggable,
                          bool absolute,
                          atk_button_action_t action,
                          void *context)
{
    if (!widget)
    {
        return;
    }

    atk_button_priv_t *priv = button_priv_mut(widget);
    widget->used = true;
    atk_widget_set_ops(widget, &g_button_ops, NULL);
    priv->style = style;
    priv->draggable = draggable;
    priv->absolute = absolute;
    priv->action = action;
    priv->action_context = context;
    priv->list_node = NULL;
    button_set_title(priv, title ? title : "");
}

int atk_button_effective_height(const atk_widget_t *widget)
{
    if (!widget || !widget->used)
    {
        return 0;
    }

    const atk_button_priv_t *priv = button_priv(widget);
    int height = widget->height;
    if (priv->style == ATK_BUTTON_STYLE_TITLE_BELOW)
    {
        int label_height = atk_font_line_height();
        int extra = (label_height + 9) / 10; /* ~10% padding */
        label_height += extra;
        height += label_height + 4;
    }
    return height;
}

bool atk_button_hit_test(const atk_widget_t *widget, int origin_x, int origin_y, int px, int py)
{
    if (!widget || !widget->used)
    {
        return false;
    }

    int x0 = origin_x + widget->x;
    int y0 = origin_y + widget->y;
    int x1 = x0 + widget->width;
    int y1 = y0 + atk_button_effective_height(widget);

    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

void atk_button_draw(const atk_state_t *state, const atk_widget_t *widget, int origin_x, int origin_y)
{
    if (!state || !widget || !widget->used)
    {
        return;
    }

    atk_state_theme_validate(state, "atk_button_draw");

    const atk_button_priv_t *priv = button_priv(widget);
    const atk_theme_t *theme = &state->theme;

    int bx = origin_x + widget->x;
    int by = origin_y + widget->y;

    video_color_t border_color = priv->absolute ? theme->button_border : theme->window_border;
    video_color_t face_color = priv->absolute ? theme->desktop_icon_face : theme->button_face;
    video_color_t text_color = priv->absolute ? theme->desktop_icon_text : theme->button_text;

    if (!priv->absolute && priv->style == ATK_BUTTON_STYLE_TITLE_INSIDE)
    {
        face_color = theme->window_title;
        text_color = theme->window_title_text;
    }

    video_draw_rect(bx, by, widget->width, widget->height, face_color);
    video_draw_rect_outline(bx, by, widget->width, widget->height, border_color);

    const char *title = priv->title;
    int title_px_width = atk_font_text_width(title);
    int text_x = bx + 4;

    if (priv->style == ATK_BUTTON_STYLE_TITLE_INSIDE)
    {
        if (title_px_width < widget->width)
        {
            text_x = bx + (widget->width - title_px_width) / 2;
        }
        int baseline = atk_font_baseline_for_rect(by, widget->height);
        atk_rect_t clip = { bx, by, widget->width, widget->height };
        atk_font_draw_string_clipped(text_x, baseline, title, text_color, face_color, &clip);
    }
    else
    {
        int label_y = by + widget->height + 2;
        if (title_px_width < widget->width)
        {
            text_x = bx + (widget->width - title_px_width) / 2;
        }
        else
        {
            text_x = bx;
        }
        int label_height = atk_font_line_height();
        int extra = (label_height + 9) / 10;
        label_height += extra;
        int baseline = atk_font_baseline_for_rect(label_y, label_height);
        atk_rect_t clip = { bx, label_y, widget->width, label_height };
        atk_font_draw_string_clipped(text_x, baseline, title, text_color, theme->background, &clip);
    }
}

const char *atk_button_title(const atk_widget_t *widget)
{
    const atk_button_priv_t *priv = button_priv(widget);
    if (!priv)
    {
        return "";
    }
    return priv->title;
}

bool atk_button_is_draggable(const atk_widget_t *widget)
{
    const atk_button_priv_t *priv = button_priv(widget);
    return priv ? priv->draggable : false;
}

bool atk_button_is_absolute(const atk_widget_t *widget)
{
    const atk_button_priv_t *priv = button_priv(widget);
    return priv ? priv->absolute : false;
}

void atk_button_invoke(atk_widget_t *widget)
{
    atk_button_priv_t *priv = button_priv_mut(widget);
    if (!priv || !priv->action)
    {
        return;
    }
    priv->action(widget, priv->action_context);
}

static void button_set_title(atk_button_priv_t *priv, const char *title)
{
    if (!priv || !title)
    {
        return;
    }

    size_t i = 0;
    for (; title[i] != '\0' && i < ATK_BUTTON_TITLE_MAX - 1; ++i)
    {
        priv->title[i] = title[i];
    }
    priv->title[i] = '\0';
}

static atk_button_priv_t *button_priv_mut(atk_widget_t *widget)
{
    if (!widget)
    {
        return 0;
    }
    return (atk_button_priv_t *)atk_widget_priv(widget, &ATK_BUTTON_CLASS);
}

static const atk_button_priv_t *button_priv(const atk_widget_t *widget)
{
    if (!widget)
    {
        return 0;
    }
    return (const atk_button_priv_t *)atk_widget_priv(widget, &ATK_BUTTON_CLASS);
}

static void button_draw_cb(const atk_state_t *state,
                           const atk_widget_t *widget,
                           int origin_x,
                           int origin_y,
                           void *context)
{
    (void)context;
    atk_button_draw(state, widget, origin_x, origin_y);
}

static bool button_hit_test_cb(const atk_widget_t *widget,
                               int origin_x,
                               int origin_y,
                               int px,
                               int py,
                               void *context)
{
    (void)context;
    return atk_button_hit_test(widget, origin_x, origin_y, px, py);
}

static void button_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_button_priv_t *priv = button_priv_mut(widget);
    if (priv)
    {
        priv->list_node = NULL;
    }
    atk_widget_destroy(widget);
}
