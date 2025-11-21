#include "atk_button.h"

#include <stddef.h>

#include "libc.h"
#include "video.h"
#include "atk/atk_font.h"

static void button_set_title(atk_button_priv_t *priv, const char *title);
static atk_button_priv_t *button_priv_mut(atk_widget_t *widget);
static const atk_button_priv_t *button_priv(const atk_widget_t *widget);

static const atk_widget_vtable_t button_vtable = { 0 };
static const int k_button_label_max_lines = 2;
static const int k_button_label_line_spacing = 2;

typedef struct
{
    char lines[3][ATK_BUTTON_TITLE_MAX];
    int count;
} button_label_layout_t;

static void button_layout_label(const char *title, int max_width, button_label_layout_t *out);
static int button_label_height_px(const atk_widget_t *widget, const atk_button_priv_t *priv);
static void button_append_ellipsis(char *line, int max_width);
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
        height += button_label_height_px(widget, priv) + 2;
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
        button_label_layout_t layout;
        button_layout_label(title, widget->width, &layout);
        int line_height = atk_font_line_height();
        int extra = (line_height + 9) / 10;
        int block_height = layout.count * line_height +
                           (layout.count > 1 ? (layout.count - 1) * k_button_label_line_spacing : 0);
        int label_height = block_height + extra;
        int start_y = label_y + (label_height - block_height) / 2;
        int y = start_y;
        for (int i = 0; i < layout.count; ++i)
        {
            int line_w = atk_font_text_width(layout.lines[i]);
            int line_x = (line_w < widget->width) ? bx + (widget->width - line_w) / 2 : bx;
            atk_rect_t clip = { bx, y, widget->width, line_height };
            int baseline = atk_font_baseline_for_rect(y, line_height);
            atk_font_draw_string_clipped(line_x, baseline, layout.lines[i], text_color, theme->background, &clip);
            y += line_height + k_button_label_line_spacing;
        }
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

static void button_layout_label(const char *title, int max_width, button_label_layout_t *out)
{
    if (!out)
    {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (!title || *title == '\0' || max_width <= 0)
    {
        return;
    }

    const int max_lines = k_button_label_max_lines;
    const char *cursor = title;
    int line_idx = 0;

    while (*cursor != '\0' && line_idx < max_lines)
    {
        while (*cursor == ' ')
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }

        char line_buf[ATK_BUTTON_TITLE_MAX];
        int line_len = 0;
        int last_space_len = -1;
        const char *start = cursor;
        while (*cursor != '\0' && *cursor != '\n')
        {
            if (line_len < ATK_BUTTON_TITLE_MAX - 1)
            {
                line_buf[line_len++] = *cursor;
                line_buf[line_len] = '\0';
            }

            int width = atk_font_text_width(line_buf);
            if (width > max_width)
            {
                if (last_space_len >= 0)
                {
                    line_len = last_space_len;
                    line_buf[line_len] = '\0';
                    cursor = start + last_space_len; /* point at the space; skip it below */
                }
                else if (line_len > 1)
                {
                    while (line_len > 0 && atk_font_text_width(line_buf) > max_width)
                    {
                        --line_len;
                        line_buf[line_len] = '\0';
                    }
                }
                break;
            }

            if (*cursor == ' ')
            {
                last_space_len = line_len;
            }
            ++cursor;
        }

        while (line_len > 0 && line_buf[line_len - 1] == ' ')
        {
            --line_len;
            line_buf[line_len] = '\0';
        }

        if (line_len == 0 && *cursor != '\0')
        {
            /* prevent infinite loop */
            line_buf[0] = *cursor;
            line_buf[1] = '\0';
            ++cursor;
            line_len = 1;
        }

        size_t copy_len = (size_t)line_len;
        if (copy_len >= ATK_BUTTON_TITLE_MAX)
        {
            copy_len = ATK_BUTTON_TITLE_MAX - 1;
        }
        memcpy(out->lines[line_idx], line_buf, copy_len);
        out->lines[line_idx][copy_len] = '\0';
        ++line_idx;

        while (*cursor == ' ')
        {
            ++cursor;
        }
        if (*cursor == '\n')
        {
            ++cursor;
        }
    }

    out->count = line_idx > 0 ? line_idx : 1;
    if (*cursor != '\0' && out->count > 0)
    {
        button_append_ellipsis(out->lines[out->count - 1], max_width);
    }
}

static int button_label_height_px(const atk_widget_t *widget, const atk_button_priv_t *priv)
{
    if (!widget || !priv)
    {
        return 0;
    }

    button_label_layout_t layout;
    button_layout_label(priv->title, widget->width, &layout);

    int line_height = atk_font_line_height();
    int extra = (line_height + 9) / 10;
    int block_height = layout.count * line_height +
                       (layout.count > 1 ? (layout.count - 1) * k_button_label_line_spacing : 0);
    return block_height + extra;
}

static void button_append_ellipsis(char *line, int max_width)
{
    if (!line || max_width <= 0)
    {
        return;
    }

    const char ellipsis[] = "...";
    size_t len = strlen(line);
    size_t ellipsis_len = sizeof(ellipsis) - 1;

    if (len == 0)
    {
        size_t copy_len = (ellipsis_len < ATK_BUTTON_TITLE_MAX - 1) ? ellipsis_len : (ATK_BUTTON_TITLE_MAX - 1);
        memcpy(line, ellipsis, copy_len);
        line[copy_len] = '\0';
        return;
    }

    while (len > 0)
    {
        char tmp[ATK_BUTTON_TITLE_MAX];
        size_t copy_len = (len < sizeof(tmp) - 1) ? len : sizeof(tmp) - 1;
        memcpy(tmp, line, copy_len);
        tmp[copy_len] = '\0';
        if (copy_len + ellipsis_len < sizeof(tmp))
        {
            memcpy(tmp + copy_len, ellipsis, ellipsis_len + 1);
        }
        int width = atk_font_text_width(tmp);
        if (width <= max_width)
        {
            size_t to_copy = strlen(tmp);
            if (to_copy >= ATK_BUTTON_TITLE_MAX)
            {
                to_copy = ATK_BUTTON_TITLE_MAX - 1;
            }
            memcpy(line, tmp, to_copy);
            line[to_copy] = '\0';
            return;
        }
        --len;
        line[len] = '\0';
    }

    size_t copy_len = (ellipsis_len < ATK_BUTTON_TITLE_MAX - 1) ? ellipsis_len : (ATK_BUTTON_TITLE_MAX - 1);
    memcpy(line, ellipsis, copy_len);
    line[copy_len] = '\0';
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
