#include "atk/atk_label.h"

#include "atk_internal.h"
#include "atk/atk_font.h"
#include <stddef.h>
#include <stdbool.h>
#include "video.h"
#include "libc.h"
#include "utf8.h"

typedef struct
{
    char *text;
    size_t length;
    size_t capacity;
    atk_list_node_t *list_node;
    size_t scroll_line;
    bool stick_to_bottom;
} atk_label_priv_t;

static void label_invalidate(const atk_widget_t *label);
static bool label_ensure_capacity(atk_label_priv_t *priv, size_t extra);
static size_t label_line_length(const char *text,
                                int max_width,
                                char *scratch,
                                size_t scratch_cap);
static size_t label_count_wrapped_lines(const char *text,
                                        int max_width,
                                        char *scratch,
                                        size_t scratch_cap);
static const char *label_skip_wrapped_lines(const char *text,
                                            size_t skip,
                                            int max_width,
                                            char *scratch,
                                            size_t scratch_cap);
static void label_draw_cb(const atk_state_t *state,
                          const atk_widget_t *widget,
                          int origin_x,
                          int origin_y,
                          void *context);
static void label_destroy_cb(atk_widget_t *widget, void *context);

static const atk_widget_vtable_t label_vtable = { 0 };
static const atk_widget_ops_t g_label_ops = {
    .destroy = label_destroy_cb,
    .draw = label_draw_cb,
    .hit_test = NULL,
    .on_mouse = NULL,
    .on_key = NULL
};
const atk_class_t ATK_LABEL_CLASS = { "Label", &ATK_WIDGET_CLASS, &label_vtable, sizeof(atk_label_priv_t) };

atk_widget_t *atk_window_add_label(atk_widget_t *window, int x, int y, int width, int height)
{
    if (!window)
    {
        return NULL;
    }

    atk_window_priv_t *priv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!priv)
    {
        return NULL;
    }

    atk_widget_t *label = atk_widget_create(&ATK_LABEL_CLASS);
    if (!label)
    {
        return NULL;
    }

    label->x = x;
    label->y = y;
    label->width = width;
    label->height = height;
    label->parent = window;
    label->used = true;
    atk_widget_set_ops(label, &g_label_ops, NULL);

    atk_label_priv_t *label_priv = (atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    atk_list_node_t *child_node = atk_list_push_back(&priv->children, label);
    if (!child_node)
    {
        atk_widget_destroy(label);
        return NULL;
    }
    label_priv->list_node = child_node;
    label_priv->text = NULL;
    label_priv->length = 0;
    label_priv->capacity = 0;
    label_priv->scroll_line = 0;
    label_priv->stick_to_bottom = false;

    return label;
}

static void label_invalidate(const atk_widget_t *label)
{
    if (!label || !label->parent)
    {
        return;
    }

    int origin_x = label->parent->x + label->x;
    int origin_y = label->parent->y + label->y;
    atk_dirty_mark_rect(origin_x, origin_y, label->width, label->height);
}

static bool label_ensure_capacity(atk_label_priv_t *priv, size_t extra)
{
    size_t needed = priv->length + extra + 1;
    if (needed <= priv->capacity)
    {
        return true;
    }
    size_t new_capacity = priv->capacity ? priv->capacity : 128;
    while (new_capacity < needed)
    {
        new_capacity *= 2;
    }
    char *buffer = (char *)realloc(priv->text, new_capacity);
    if (!buffer)
    {
        return false;
    }
    priv->text = buffer;
    priv->capacity = new_capacity;
    return true;
}

void atk_label_set_text(atk_widget_t *label, const char *text)
{
    if (!label)
    {
        return;
    }
    atk_label_priv_t *priv = (atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    if (!priv)
    {
        return;
    }

    size_t text_len = text ? strlen(text) : 0;
    if (!label_ensure_capacity(priv, text_len))
    {
        return;
    }
    if (text_len > 0 && text)
    {
        memcpy(priv->text, text, text_len);
    }
    priv->text[text_len] = '\0';
    priv->length = text_len;
    label_invalidate(label);
}

void atk_label_append_text(atk_widget_t *label, const char *text)
{
    if (!label || !text || *text == '\0')
    {
        return;
    }
    atk_label_priv_t *priv = (atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    if (!priv)
    {
        return;
    }

    size_t add_len = strlen(text);
    if (!label_ensure_capacity(priv, add_len))
    {
        return;
    }
    memcpy(priv->text + priv->length, text, add_len);
    priv->length += add_len;
    priv->text[priv->length] = '\0';
    label_invalidate(label);
}

const char *atk_label_text(const atk_widget_t *label)
{
    const atk_label_priv_t *priv = (const atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    return priv ? (priv->text ? priv->text : "") : "";
}

void atk_label_draw(const atk_state_t *state, const atk_widget_t *label)
{
    atk_label_priv_t *priv = (atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    if (!state || !label || !label->used || !priv)
    {
        return;
    }

    atk_state_theme_validate(state, "atk_label_draw");

    int origin_x = label->parent ? label->parent->x : 0;
    int origin_y = label->parent ? label->parent->y : 0;
    int x = origin_x + label->x;
    int y = origin_y + label->y;
    int width = label->width;
    int height = label->height;

    video_draw_rect(x, y, width, height, state->theme.window_body);

    const char *text = priv->text ? priv->text : "";
    int content_width = width - 4;
    int content_height = height - 4;
    if (content_width <= 0 || content_height <= 0)
    {
        return;
    }

    int line_height = atk_font_line_height();
    int max_lines = (line_height > 0) ? (content_height / line_height) : 0;
    if (line_height <= 0 || max_lines <= 0)
    {
        return;
    }

    char scratch[512];
    size_t total_lines = label_count_wrapped_lines(text, content_width, scratch, sizeof(scratch));
    size_t start_line = 0;
    if (priv->stick_to_bottom)
    {
        if (total_lines > (size_t)max_lines)
        {
            start_line = total_lines - (size_t)max_lines;
        }
    }
    else
    {
        size_t max_start = 0;
        if (total_lines > (size_t)max_lines)
        {
            max_start = total_lines - (size_t)max_lines;
        }
        if (priv->scroll_line > max_start)
        {
            priv->scroll_line = max_start;
        }
        start_line = priv->scroll_line;
    }

    const char *draw_text = label_skip_wrapped_lines(text, start_line, content_width, scratch, sizeof(scratch));
    int draw_y = y + 2;
    for (int line = 0; line < max_lines && draw_text && *draw_text != '\0'; ++line)
    {
        size_t len = label_line_length(draw_text, content_width, scratch, sizeof(scratch));
        if (len == 0)
        {
            break;
        }

        size_t copy_len = len;
        if (copy_len >= sizeof(scratch))
        {
            copy_len = sizeof(scratch) - 1;
        }
        memcpy(scratch, draw_text, copy_len);
        scratch[copy_len] = '\0';

        atk_rect_t clip = { x + 2, draw_y, content_width, line_height };
        int baseline = atk_font_baseline_for_rect(draw_y, line_height);
        atk_font_draw_string_clipped(x + 2,
                                     baseline,
                                     scratch,
                                     state->theme.button_text,
                                     state->theme.window_body,
                                     &clip);

        draw_text += len;
        if (*draw_text == '\n')
        {
            ++draw_text;
        }
        draw_y += line_height;
    }
}

void atk_label_scroll_to_line(atk_widget_t *label, size_t line)
{
    if (!label)
    {
        return;
    }
    atk_label_priv_t *priv = (atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    if (!priv)
    {
        return;
    }

    priv->stick_to_bottom = false;
    priv->scroll_line = line;
    label_invalidate(label);
}

void atk_label_scroll_to_bottom(atk_widget_t *label)
{
    if (!label)
    {
        return;
    }
    atk_label_priv_t *priv = (atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    if (!priv)
    {
        return;
    }

    priv->stick_to_bottom = true;
    label_invalidate(label);
}

void atk_label_destroy(atk_widget_t *label)
{
    if (!label)
    {
        return;
    }
    atk_label_priv_t *priv = (atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    if (priv && priv->text)
    {
        free(priv->text);
        priv->text = NULL;
        priv->length = 0;
        priv->capacity = 0;
    }
}

static void label_draw_cb(const atk_state_t *state,
                          const atk_widget_t *widget,
                          int origin_x,
                          int origin_y,
                          void *context)
{
    (void)origin_x;
    (void)origin_y;
    (void)context;
    atk_label_draw(state, widget);
}

static void label_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_label_destroy(widget);
    atk_widget_destroy(widget);
}

static size_t label_line_length(const char *text,
                                int max_width,
                                char *scratch,
                                size_t scratch_cap)
{
    if (!text || !scratch || scratch_cap < 2 || max_width <= 0)
    {
        return 0;
    }

    size_t pos = 0;
    size_t scratch_len = 0;
    size_t last_break = (size_t)-1;

    scratch[0] = '\0';

    while (text[pos] != '\0' && text[pos] != '\n')
    {
        utf8_decode_result_t dec = utf8_decode_one(text + pos);
        if (dec.consumed == 0)
        {
            break;
        }

        if (scratch_len + (size_t)dec.consumed + 1 > scratch_cap)
        {
            return (last_break != (size_t)-1 && last_break > 0) ? last_break : pos;
        }

        memcpy(scratch + scratch_len, text + pos, (size_t)dec.consumed);
        scratch_len += (size_t)dec.consumed;
        scratch[scratch_len] = '\0';

        int width = atk_font_text_width(scratch);
        if (width > max_width)
        {
            if (pos == 0)
            {
                return (size_t)dec.consumed;
            }
            if (last_break != (size_t)-1 && last_break > 0)
            {
                return last_break;
            }
            return pos;
        }

        if (dec.codepoint == ' ' || dec.codepoint == '\t')
        {
            last_break = pos + (size_t)dec.consumed;
        }

        pos += (size_t)dec.consumed;
    }

    return pos;
}

static size_t label_count_wrapped_lines(const char *text,
                                        int max_width,
                                        char *scratch,
                                        size_t scratch_cap)
{
    if (!text || max_width <= 0)
    {
        return 0;
    }

    size_t lines = 0;
    const char *cursor = text;
    while (*cursor != '\0')
    {
        size_t len = label_line_length(cursor, max_width, scratch, scratch_cap);
        if (len == 0)
        {
            ++lines;
            break;
        }
        cursor += len;
        if (*cursor == '\n')
        {
            ++cursor;
        }
        ++lines;
    }

    if (lines == 0)
    {
        lines = 1;
    }
    return lines;
}

static const char *label_skip_wrapped_lines(const char *text,
                                            size_t skip,
                                            int max_width,
                                            char *scratch,
                                            size_t scratch_cap)
{
    if (!text || max_width <= 0)
    {
        return text;
    }

    const char *cursor = text;
    while (*cursor != '\0' && skip > 0)
    {
        size_t len = label_line_length(cursor, max_width, scratch, scratch_cap);
        if (len == 0)
        {
            return cursor;
        }
        cursor += len;
        if (*cursor == '\n')
        {
            ++cursor;
        }
        --skip;
    }
    return cursor;
}
