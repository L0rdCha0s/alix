#include "atk/atk_text_input.h"

#include "atk_internal.h"
#include <stddef.h>

#include "video.h"
#include "libc.h"

#define ATK_TEXT_INPUT_PADDING_X 4
#define ATK_TEXT_INPUT_PADDING_Y 4

typedef struct
{
    char *text;
    size_t length;
    size_t capacity;
    atk_list_node_t *list_node;
    atk_text_input_submit_t submit;
    void *submit_context;
    bool focused;
} atk_text_input_priv_t;

static const atk_widget_vtable_t text_input_vtable = { 0 };
const atk_class_t ATK_TEXT_INPUT_CLASS = { "TextInput", &ATK_WIDGET_CLASS, &text_input_vtable, sizeof(atk_text_input_priv_t) };

static void text_input_invalidate(const atk_widget_t *input)
{
    if (!input || !input->parent)
    {
        return;
    }
    int origin_x = input->parent->x + input->x;
    int origin_y = input->parent->y + input->y;
    video_invalidate_rect(origin_x, origin_y, input->width, input->height);
}

static bool text_input_ensure_capacity(atk_text_input_priv_t *priv, size_t extra)
{
    size_t needed = priv->length + extra + 1;
    if (needed <= priv->capacity)
    {
        return true;
    }
    size_t new_capacity = priv->capacity ? priv->capacity : 64;
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

atk_widget_t *atk_window_add_text_input(atk_widget_t *window, int x, int y, int width)
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

    atk_widget_t *input = atk_widget_create(&ATK_TEXT_INPUT_CLASS);
    if (!input)
    {
        return NULL;
    }

    input->x = x;
    input->y = y;
    input->width = width;
    input->height = ATK_FONT_HEIGHT + ATK_TEXT_INPUT_PADDING_Y * 2;
    input->parent = window;
    input->used = true;

    atk_text_input_priv_t *input_priv = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    input_priv->submit = NULL;
    input_priv->submit_context = NULL;
    input_priv->focused = false;

    atk_list_node_t *child_node = atk_list_push_back(&priv->children, input);
    if (!child_node)
    {
        atk_widget_destroy(input);
        return NULL;
    }

    atk_list_node_t *input_node = atk_list_push_back(&priv->text_inputs, input);
    if (!input_node)
    {
        atk_list_remove(&priv->children, child_node);
        atk_widget_destroy(input);
        return NULL;
    }
    input_priv->list_node = input_node;

    return input;
}

void atk_text_input_set_submit_handler(atk_widget_t *input, atk_text_input_submit_t handler, void *context)
{
    atk_text_input_priv_t *priv = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    if (!priv)
    {
        return;
    }
    priv->submit = handler;
    priv->submit_context = context;
}

const char *atk_text_input_text(const atk_widget_t *input)
{
    const atk_text_input_priv_t *priv = (const atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    return priv ? (priv->text ? priv->text : "") : "";
}

void atk_text_input_clear(atk_widget_t *input)
{
    atk_text_input_priv_t *priv = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    if (!priv)
    {
        return;
    }
    if (priv->text)
    {
        priv->text[0] = '\0';
    }
    priv->length = 0;
    text_input_invalidate(input);
}

bool atk_text_input_hit_test(const atk_widget_t *input, int origin_x, int origin_y, int px, int py)
{
    if (!input || !input->used)
    {
        return false;
    }
    int x0 = origin_x + input->x;
    int y0 = origin_y + input->y;
    int x1 = x0 + input->width;
    int y1 = y0 + input->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

bool atk_text_input_is_focused(const atk_widget_t *input)
{
    atk_text_input_priv_t *priv = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    return priv ? priv->focused : false;
}

void atk_text_input_request_redraw(atk_widget_t *input)
{
    text_input_invalidate(input);
}

void atk_text_input_focus(atk_state_t *state, atk_widget_t *input)
{
    if (!state)
    {
        return;
    }

    if (state->focused_input == input)
    {
        return;
    }

    if (state->focused_input)
    {
        atk_text_input_priv_t *prev = (atk_text_input_priv_t *)atk_widget_priv(state->focused_input, &ATK_TEXT_INPUT_CLASS);
        if (prev)
        {
            prev->focused = false;
            text_input_invalidate(state->focused_input);
        }
    }

    state->focused_input = input;

    if (input)
    {
        atk_text_input_priv_t *curr = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
        if (curr)
        {
            curr->focused = true;
            text_input_invalidate(input);
        }
    }
}

void atk_text_input_blur(atk_state_t *state, atk_widget_t *input)
{
    if (!state)
    {
        return;
    }
    if (state->focused_input != input)
    {
        return;
    }
    atk_text_input_focus(state, NULL);
}

atk_text_input_event_t atk_text_input_handle_char(atk_widget_t *input, char ch)
{
    atk_text_input_priv_t *priv = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    if (!priv)
    {
        return ATK_TEXT_INPUT_EVENT_NONE;
    }

    if (ch == '\r' || ch == '\n')
    {
        if (priv->submit)
        {
            priv->submit(input, priv->submit_context);
        }
        return ATK_TEXT_INPUT_EVENT_SUBMIT;
    }

    if (ch == '\b' || ch == 0x7F)
    {
        if (priv->length > 0)
        {
            priv->length--;
            if (priv->text)
            {
                priv->text[priv->length] = '\0';
            }
            text_input_invalidate(input);
            return ATK_TEXT_INPUT_EVENT_CHANGED;
        }
        return ATK_TEXT_INPUT_EVENT_NONE;
    }

    if (ch < ' ' || ch > '~')
    {
        return ATK_TEXT_INPUT_EVENT_NONE;
    }

    if (!text_input_ensure_capacity(priv, 1))
    {
        return ATK_TEXT_INPUT_EVENT_NONE;
    }

    priv->text[priv->length++] = ch;
    priv->text[priv->length] = '\0';
    text_input_invalidate(input);
    return ATK_TEXT_INPUT_EVENT_CHANGED;
}

void atk_text_input_draw(const atk_state_t *state, const atk_widget_t *input)
{
    const atk_text_input_priv_t *priv = (const atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    if (!state || !input || !input->used || !priv)
    {
        return;
    }

    int origin_x = input->parent ? input->parent->x : 0;
    int origin_y = input->parent ? input->parent->y : 0;
    int x = origin_x + input->x;
    int y = origin_y + input->y;
    int width = input->width;
    int height = input->height;

    uint16_t face = state->theme.window_body;
    uint16_t border = priv->focused ? state->theme.window_title : state->theme.button_border;

    video_draw_rect(x, y, width, height, face);
    video_draw_rect_outline(x, y, width, height, border);

    const char *text = priv->text ? priv->text : "";
    video_draw_text(x + ATK_TEXT_INPUT_PADDING_X, y + ATK_TEXT_INPUT_PADDING_Y, text, state->theme.button_text, face);

    if (priv->focused)
    {
        int caret_x = x + ATK_TEXT_INPUT_PADDING_X + (int)priv->length * ATK_FONT_WIDTH;
        if (caret_x > x + width - 2)
        {
            caret_x = x + width - 2;
        }
        video_draw_rect(caret_x, y + ATK_TEXT_INPUT_PADDING_Y, 2, height - ATK_TEXT_INPUT_PADDING_Y * 2, state->theme.button_text);
    }
}

void atk_text_input_destroy(atk_widget_t *input)
{
    atk_text_input_priv_t *priv = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    if (!priv)
    {
        return;
    }
    if (priv->text)
    {
        free(priv->text);
        priv->text = NULL;
    }
    priv->capacity = 0;
    priv->length = 0;
    priv->submit = NULL;
    priv->submit_context = NULL;
    priv->focused = false;
}
