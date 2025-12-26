#include "atk_button.h"

#include <stddef.h>

#include "libc.h"
#include "video.h"
#include "atk/atk_font.h"

static void button_set_title(atk_button_priv_t *priv, const char *title);
static atk_button_priv_t *button_priv_mut(atk_widget_t *widget);
static const atk_button_priv_t *button_priv(const atk_widget_t *widget);
static void button_clear_icon(atk_button_priv_t *priv);

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
static bool button_clip_rect(const atk_rect_t *clip, const atk_rect_t *rect, atk_rect_t *out);
static void button_draw_rect_clipped(int x, int y, int width, int height, video_color_t color, const atk_rect_t *clip);
static void button_draw_gradient_clipped(int x, int y, int width, int height, video_color_t top, video_color_t bottom, const atk_rect_t *clip);
static void button_draw_bevel_outline_clipped(int x, int y, int width, int height, video_color_t light, video_color_t dark, const atk_rect_t *clip);
static void button_blit_rgba32_clipped(int x,
                                       int y,
                                       int width,
                                       int height,
                                       const video_color_t *pixels,
                                       int stride_bytes,
                                       bool use_alpha,
                                       const atk_rect_t *clip);
static void button_draw_cb(const atk_state_t *state,
                           const atk_widget_t *widget,
                           int origin_x,
                           int origin_y,
                           void *context);
static atk_mouse_response_t button_mouse_cb(atk_widget_t *widget,
                                            const atk_mouse_event_t *event,
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
    .on_mouse = button_mouse_cb,
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
    button_clear_icon(priv);
    priv->style = style;
    priv->draggable = draggable;
    priv->absolute = absolute;
    priv->pressed = false;
    priv->action = action;
    priv->action_context = context;
    priv->list_node = NULL;
    button_set_title(priv, title ? title : "");
}

void atk_button_set_title(atk_widget_t *widget, const char *title)
{
    if (!widget || !title)
    {
        return;
    }

    atk_button_priv_t *priv = button_priv_mut(widget);
    if (!priv)
    {
        return;
    }

    button_set_title(priv, title);
    int origin_x = widget->parent ? widget->parent->x : 0;
    int origin_y = widget->parent ? widget->parent->y : 0;
    int height = atk_button_effective_height(widget);
    atk_dirty_mark_rect(origin_x + widget->x, origin_y + widget->y, widget->width, height);
    if (widget->parent)
    {
        video_request_refresh_window(widget->parent);
    }
}

void atk_button_set_icon(atk_widget_t *widget,
                         video_color_t *pixels,
                         int width,
                         int height,
                         int stride_bytes,
                         bool use_alpha,
                         bool take_ownership)
{
    if (!widget)
    {
        return;
    }

    atk_button_priv_t *priv = button_priv_mut(widget);
    if (!priv)
    {
        return;
    }

    button_clear_icon(priv);
    if (!pixels || width <= 0 || height <= 0)
    {
        return;
    }

    priv->icon_pixels = pixels;
    priv->icon_width = width;
    priv->icon_height = height;
    priv->icon_stride_bytes = (stride_bytes > 0) ? stride_bytes : width * (int)sizeof(video_color_t);
    priv->icon_use_alpha = use_alpha;
    priv->icon_owned = take_ownership;

    int origin_x = widget->parent ? widget->parent->x : 0;
    int origin_y = widget->parent ? widget->parent->y : 0;
    int height_px = atk_button_effective_height(widget);
    atk_dirty_mark_rect(origin_x + widget->x, origin_y + widget->y, widget->width, height_px);
    if (widget->parent)
    {
        video_request_refresh_window(widget->parent);
    }
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
    atk_button_draw_ex(state, widget, origin_x, origin_y, NULL);
}

void atk_button_draw_ex(const atk_state_t *state,
                        const atk_widget_t *widget,
                        int origin_x,
                        int origin_y,
                        const atk_button_draw_opts_t *opts)
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

    if (opts && opts->override_text_color)
    {
        text_color = opts->text_color;
    }

    const atk_rect_t *clip = opts ? opts->clip : NULL;
    video_color_t face_top = atk_color_tint(face_color, priv->pressed ? -10 : 16);
    video_color_t face_bottom = atk_color_tint(face_color, priv->pressed ? 6 : -12);
    video_color_t edge_light = atk_color_tint(border_color, priv->pressed ? -6 : 28);
    video_color_t edge_dark = atk_color_tint(border_color, priv->pressed ? -24 : -18);
    button_draw_gradient_clipped(bx, by, widget->width, widget->height, face_top, face_bottom, clip);
    button_draw_bevel_outline_clipped(bx, by, widget->width, widget->height, edge_light, edge_dark, clip);

    if (priv->style == ATK_BUTTON_STYLE_TITLE_BELOW &&
        priv->icon_pixels &&
        priv->icon_width > 0 &&
        priv->icon_height > 0)
    {
        int pad = 6;
        int max_w = widget->width - pad * 2;
        int max_h = widget->height - pad * 2;
        if (max_w < 1)
        {
            max_w = widget->width;
        }
        if (max_h < 1)
        {
            max_h = widget->height;
        }
        int draw_w = priv->icon_width;
        int draw_h = priv->icon_height;
        if (draw_w > max_w)
        {
            draw_w = max_w;
        }
        if (draw_h > max_h)
        {
            draw_h = max_h;
        }
        if (draw_w > 0 && draw_h > 0)
        {
            int draw_x = bx + (widget->width - draw_w) / 2;
            int draw_y = by + (widget->height - draw_h) / 2;
            if (priv->pressed)
            {
                draw_x += 1;
                draw_y += 1;
            }
            button_blit_rgba32_clipped(draw_x,
                                       draw_y,
                                       draw_w,
                                       draw_h,
                                       priv->icon_pixels,
                                       priv->icon_stride_bytes,
                                       priv->icon_use_alpha,
                                       clip);
        }
    }

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
        if (priv->pressed)
        {
            text_x += 1;
            baseline += 1;
        }
        atk_rect_t rect = { bx, by, widget->width, widget->height };
        atk_rect_t clip_rect;
        if (button_clip_rect(clip, &rect, &clip_rect))
        {
            atk_font_draw_string_clipped(text_x, baseline, title, text_color, face_color, &clip_rect);
        }
    }
    else
    {
        video_color_t label_bg = theme->background;
        if (opts && opts->override_label_bg)
        {
            label_bg = opts->label_bg;
        }
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
            atk_rect_t rect = { bx, y, widget->width, line_height };
            atk_rect_t clip_rect;
            if (button_clip_rect(clip, &rect, &clip_rect))
            {
                int baseline = atk_font_baseline_for_rect(y, line_height);
                atk_font_draw_string_clipped(line_x, baseline, layout.lines[i], text_color, label_bg, &clip_rect);
            }
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

static void button_clear_icon(atk_button_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    if (priv->icon_pixels && priv->icon_owned)
    {
        free(priv->icon_pixels);
    }
    priv->icon_pixels = NULL;
    priv->icon_width = 0;
    priv->icon_height = 0;
    priv->icon_stride_bytes = 0;
    priv->icon_use_alpha = false;
    priv->icon_owned = false;
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

static bool button_clip_rect(const atk_rect_t *clip, const atk_rect_t *rect, atk_rect_t *out)
{
    if (!rect || !out)
    {
        return false;
    }
    if (!clip)
    {
        *out = *rect;
        return (rect->width > 0 && rect->height > 0);
    }

    int x0 = rect->x;
    int y0 = rect->y;
    int x1 = rect->x + rect->width;
    int y1 = rect->y + rect->height;
    int clip_x1 = clip->x + clip->width;
    int clip_y1 = clip->y + clip->height;

    if (x1 <= clip->x || x0 >= clip_x1 || y1 <= clip->y || y0 >= clip_y1)
    {
        return false;
    }

    if (x0 < clip->x) x0 = clip->x;
    if (y0 < clip->y) y0 = clip->y;
    if (x1 > clip_x1) x1 = clip_x1;
    if (y1 > clip_y1) y1 = clip_y1;

    int w = x1 - x0;
    int h = y1 - y0;
    if (w <= 0 || h <= 0)
    {
        return false;
    }

    out->x = x0;
    out->y = y0;
    out->width = w;
    out->height = h;
    return true;
}

static void button_draw_rect_clipped(int x, int y, int width, int height, video_color_t color, const atk_rect_t *clip)
{
    atk_rect_t rect = { x, y, width, height };
    atk_rect_t clip_rect;
    if (!button_clip_rect(clip, &rect, &clip_rect))
    {
        return;
    }
    video_draw_rect(clip_rect.x, clip_rect.y, clip_rect.width, clip_rect.height, color);
}

static void button_draw_gradient_clipped(int x, int y, int width, int height, video_color_t top, video_color_t bottom, const atk_rect_t *clip)
{
    if (width <= 0 || height <= 0)
    {
        return;
    }
    if (height == 1)
    {
        button_draw_rect_clipped(x, y, width, height, top, clip);
        return;
    }
    for (int i = 0; i < height; ++i)
    {
        uint8_t t = (uint8_t)((i * 255) / (height - 1));
        button_draw_rect_clipped(x, y + i, width, 1, atk_color_mix(top, bottom, t), clip);
    }
}

static void button_draw_bevel_outline_clipped(int x, int y, int width, int height, video_color_t light, video_color_t dark, const atk_rect_t *clip)
{
    if (width <= 0 || height <= 0)
    {
        return;
    }
    button_draw_rect_clipped(x, y, width, 1, light, clip);
    button_draw_rect_clipped(x, y, 1, height, light, clip);
    button_draw_rect_clipped(x, y + height - 1, width, 1, dark, clip);
    button_draw_rect_clipped(x + width - 1, y, 1, height, dark, clip);
}

static void button_blit_rgba32_clipped(int x,
                                       int y,
                                       int width,
                                       int height,
                                       const video_color_t *pixels,
                                       int stride_bytes,
                                       bool use_alpha,
                                       const atk_rect_t *clip)
{
    if (!pixels || width <= 0 || height <= 0)
    {
        return;
    }

    if (!clip)
    {
        int stride = stride_bytes > 0 ? stride_bytes : width * (int)sizeof(video_color_t);
        video_blit_rgba32(x, y, width, height, pixels, stride, use_alpha);
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + width;
    int y1 = y + height;
    int clip_x0 = clip->x;
    int clip_y0 = clip->y;
    int clip_x1 = clip->x + clip->width;
    int clip_y1 = clip->y + clip->height;

    if (x1 <= clip_x0 || x0 >= clip_x1 || y1 <= clip_y0 || y0 >= clip_y1)
    {
        return;
    }

    int src_x = 0;
    int src_y = 0;
    if (x0 < clip_x0)
    {
        src_x = clip_x0 - x0;
        x0 = clip_x0;
    }
    if (y0 < clip_y0)
    {
        src_y = clip_y0 - y0;
        y0 = clip_y0;
    }
    if (x1 > clip_x1)
    {
        x1 = clip_x1;
    }
    if (y1 > clip_y1)
    {
        y1 = clip_y1;
    }

    int draw_w = x1 - x0;
    int draw_h = y1 - y0;
    if (draw_w <= 0 || draw_h <= 0)
    {
        return;
    }

    int stride = stride_bytes > 0 ? stride_bytes : width * (int)sizeof(video_color_t);
    const uint8_t *src = (const uint8_t *)pixels +
                         (size_t)src_y * (size_t)stride +
                         (size_t)src_x * sizeof(video_color_t);
    video_blit_rgba32(x0,
                      y0,
                      draw_w,
                      draw_h,
                      (const video_color_t *)src,
                      stride,
                      use_alpha);
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

static atk_mouse_response_t button_mouse_cb(atk_widget_t *widget,
                                            const atk_mouse_event_t *event,
                                            void *context)
{
    (void)context;
    if (!widget || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_button_priv_t *priv = button_priv_mut(widget);
    if (!priv)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    bool inside = atk_button_hit_test(widget,
                                      event->origin_x,
                                      event->origin_y,
                                      event->cursor_x,
                                      event->cursor_y);

    if (event->pressed_edge && event->left_pressed && inside)
    {
        priv->pressed = true;
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE | ATK_MOUSE_RESPONSE_REDRAW;
    }

    if (event->released_edge)
    {
        bool should_invoke = priv->pressed && inside;
        priv->pressed = false;
        if (should_invoke)
        {
            atk_button_invoke(widget);
            return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW | ATK_MOUSE_RESPONSE_RELEASE;
        }
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_RELEASE | ATK_MOUSE_RESPONSE_REDRAW;
    }

    if (event->left_pressed && priv->pressed)
    {
        /* Continue to consume while held if we claimed capture. */
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE;
    }

    return ATK_MOUSE_RESPONSE_NONE;
}

static void button_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_button_priv_t *priv = button_priv_mut(widget);
    if (priv)
    {
        button_clear_icon(priv);
        priv->list_node = NULL;
    }
    atk_widget_destroy(widget);
}
