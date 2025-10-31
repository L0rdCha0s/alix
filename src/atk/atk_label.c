#include "atk/atk_label.h"

#include "atk_internal.h"
#include <stddef.h>

#include "video.h"
#include "libc.h"

typedef struct
{
    char *text;
    size_t length;
    size_t capacity;
    atk_list_node_t *list_node;
} atk_label_priv_t;

static void label_invalidate(const atk_widget_t *label);
static bool label_ensure_capacity(atk_label_priv_t *priv, size_t extra);

static const atk_widget_vtable_t label_vtable = { 0 };
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

    atk_label_priv_t *label_priv = (atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    atk_list_node_t *child_node = atk_list_push_back(&priv->children, label);
    if (!child_node)
    {
        atk_widget_destroy(label);
        return NULL;
    }
    label_priv->list_node = child_node;

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
    video_invalidate_rect(origin_x, origin_y, label->width, label->height);
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
    (void)state;
    const atk_label_priv_t *priv = (const atk_label_priv_t *)atk_widget_priv(label, &ATK_LABEL_CLASS);
    if (!label || !label->used || !priv)
    {
        return;
    }

    int origin_x = label->parent ? label->parent->x : 0;
    int origin_y = label->parent ? label->parent->y : 0;
    int x = origin_x + label->x;
    int y = origin_y + label->y;
    int width = label->width;
    int height = label->height;

    video_draw_rect(x, y, width, height, state->theme.window_body);

    const char *text = priv->text ? priv->text : "";
    int cursor_y = y + 2;
    const char *line_cursor = text;
    while (*line_cursor != '\0' && cursor_y <= y + height - ATK_FONT_HEIGHT)
    {
        const char *line_end = line_cursor;
        while (*line_end != '\0' && *line_end != '\n')
        {
            ++line_end;
        }
        size_t line_len = (size_t)(line_end - line_cursor);
        char *line_buffer = (char *)malloc(line_len + 1);
        if (!line_buffer)
        {
            break;
        }
        memcpy(line_buffer, line_cursor, line_len);
        line_buffer[line_len] = '\0';
        video_draw_text(x + 2, cursor_y, line_buffer, state->theme.button_text, state->theme.window_body);
        free(line_buffer);

        cursor_y += ATK_FONT_HEIGHT + 2;
        if (*line_end == '\n')
        {
            line_cursor = line_end + 1;
        }
        else
        {
            break;
        }
    }
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
