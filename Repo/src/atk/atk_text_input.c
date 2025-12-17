#include "atk/atk_text_input.h"

#include "atk_internal.h"
#include <stddef.h>

#include "video.h"
#include "atk/atk_font.h"
#include "libc.h"
#include "utf8.h"

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
    bool multiline;
} atk_text_input_priv_t;

static atk_mouse_response_t text_input_mouse_cb(atk_widget_t *widget,
                                                const atk_mouse_event_t *event,
                                                void *context);
static bool text_input_hit_test_cb(const atk_widget_t *widget,
                                    int origin_x,
                                    int origin_y,
                                    int px,
                                    int py,
                                    void *context);
static void text_input_draw_cb(const atk_state_t *state,
                               const atk_widget_t *widget,
                               int origin_x,
                               int origin_y,
                               void *context);
static void text_input_destroy_cb(atk_widget_t *widget, void *context);
static atk_key_response_t text_input_key_cb(atk_widget_t *widget,
                                            int key,
                                            int modifiers,
                                            int action,
                                            void *context);

static const atk_widget_vtable_t text_input_vtable = { 0 };
static const atk_widget_ops_t g_text_input_ops = {
    .destroy = text_input_destroy_cb,
    .draw = text_input_draw_cb,
    .hit_test = text_input_hit_test_cb,
    .on_mouse = text_input_mouse_cb,
    .on_key = text_input_key_cb
};
const atk_class_t ATK_TEXT_INPUT_CLASS = { "TextInput", &ATK_WIDGET_CLASS, &text_input_vtable, sizeof(atk_text_input_priv_t) };

static void text_input_invalidate(const atk_widget_t *input)
{
    if (!input || !input->parent)
    {
        return;
    }
    int origin_x = input->parent->x + input->x;
    int origin_y = input->parent->y + input->y;
    atk_dirty_mark_rect(origin_x, origin_y, input->width, input->height);
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
    int line_height = atk_font_line_height();
    if (line_height < ATK_FONT_HEIGHT)
    {
        line_height = ATK_FONT_HEIGHT;
    }
    input->height = line_height + ATK_TEXT_INPUT_PADDING_Y * 2;
    input->parent = window;
    input->used = true;
    atk_widget_set_ops(input, &g_text_input_ops, NULL);

    atk_text_input_priv_t *input_priv = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    input_priv->submit = NULL;
    input_priv->submit_context = NULL;
    input_priv->focused = false;
    input_priv->multiline = false;

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

void atk_text_input_set_text(atk_widget_t *input, const char *text)
{
    atk_text_input_priv_t *priv = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    if (!priv)
    {
        return;
    }
    const char *src = text ? text : "";
    size_t len = strlen(src);
    size_t needed = len + 1;
    if (needed > priv->capacity)
    {
        if (!text_input_ensure_capacity(priv, len))
        {
            return;
        }
    }

    if (priv->text && len > 0)
    {
        memcpy(priv->text, src, len);
        priv->text[len] = '\0';
    }
    else if (priv->text)
    {
        priv->text[0] = '\0';
    }
    priv->length = len;
    text_input_invalidate(input);
}

void atk_text_input_set_multiline(atk_widget_t *input, bool multiline)
{
    atk_text_input_priv_t *priv = (atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    if (!priv)
    {
        return;
    }
    if (priv->multiline == multiline)
    {
        return;
    }
    priv->multiline = multiline;
    text_input_invalidate(input);
}

bool atk_text_input_is_multiline(const atk_widget_t *input)
{
    const atk_text_input_priv_t *priv = (const atk_text_input_priv_t *)atk_widget_priv(input, &ATK_TEXT_INPUT_CLASS);
    return priv ? priv->multiline : false;
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

    atk_widget_t *current = atk_state_focus_widget(state);
    if (current == input)
    {
        return;
    }

    if (current && atk_widget_is_a(current, &ATK_TEXT_INPUT_CLASS))
    {
        atk_text_input_priv_t *prev = (atk_text_input_priv_t *)atk_widget_priv(current, &ATK_TEXT_INPUT_CLASS);
        if (prev)
        {
            prev->focused = false;
            text_input_invalidate(current);
        }
    }

    atk_state_set_focus_widget(state, input);

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
    if (atk_state_focus_widget(state) != input)
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
        if (priv->multiline)
        {
            if (!text_input_ensure_capacity(priv, 1))
            {
                return ATK_TEXT_INPUT_EVENT_NONE;
            }
            priv->text[priv->length++] = '\n';
            priv->text[priv->length] = '\0';
            text_input_invalidate(input);
            return ATK_TEXT_INPUT_EVENT_CHANGED;
        }

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
            size_t new_len = priv->text ? utf8_prev_char_start(priv->text, priv->length) : 0;
            if (new_len > priv->length)
            {
                new_len = priv->length - 1;
            }
            priv->length = new_len;
            if (priv->text)
            {
                priv->text[new_len] = '\0';
            }
            text_input_invalidate(input);
            return ATK_TEXT_INPUT_EVENT_CHANGED;
        }
        return ATK_TEXT_INPUT_EVENT_NONE;
    }

    uint8_t byte = (uint8_t)(unsigned char)ch;
    if (byte < 0x20u)
    {
        return ATK_TEXT_INPUT_EVENT_NONE;
    }

    if (!text_input_ensure_capacity(priv, 1))
    {
        return ATK_TEXT_INPUT_EVENT_NONE;
    }

    priv->text[priv->length++] = (char)byte;
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

    atk_state_theme_validate(state, "atk_text_input_draw");

    int origin_x = 0;
    int origin_y = 0;
    if (input->parent)
    {
        atk_widget_absolute_position(input->parent, &origin_x, &origin_y);
    }
    int x = origin_x + input->x;
    int y = origin_y + input->y;
    int width = input->width;
    int height = input->height;

    video_color_t face = state->theme.window_body;
    video_color_t border = priv->focused ? state->theme.window_title : state->theme.button_border;

    video_draw_rect(x, y, width, height, face);
    video_draw_rect_outline(x, y, width, height, border);

    const char *text = priv->text ? priv->text : "";
    int font_h = atk_font_line_height();
    int line_height = font_h;
    int pad_x = ATK_TEXT_INPUT_PADDING_X;
    int pad_y = ATK_TEXT_INPUT_PADDING_Y;
    if (height < font_h + pad_y * 2)
    {
        int avail = height - font_h;
        pad_y = avail > 0 ? (avail / 2) : 0;
    }

    int content_x = x + pad_x;
    int content_y = y + pad_y;
    int content_w = width - pad_x * 2;
    int content_h = height - pad_y * 2;
    if (content_w < 0) content_w = 0;
    if (content_h < 0) content_h = 0;

    atk_rect_t clip = { content_x, content_y, content_w, content_h };

    if (!priv->multiline)
    {
        int baseline = atk_font_baseline_for_rect(content_y, content_h);
        atk_font_draw_string_clipped(content_x,
                                     baseline,
                                     text,
                                     state->theme.button_text,
                                     face,
                                     &clip);

        if (priv->focused)
        {
            int caret_x = content_x + atk_font_text_width(text);
            if (caret_x > x + width - 2)
            {
                caret_x = x + width - 2;
            }
            int caret_height = line_height;
            int caret_y = baseline - caret_height + 1;
            if (caret_y < content_y)
            {
                caret_y = content_y;
            }
            if (caret_y + caret_height > y + height)
            {
                caret_height = (y + height) - caret_y;
            }
            if (caret_height > 0)
            {
                video_draw_rect(caret_x, caret_y, 2, caret_height, state->theme.button_text);
            }
        }
        return;
    }

    size_t total_lines = 1;
    for (const char *p = text; *p; ++p)
    {
        if (*p == '\n')
        {
            total_lines++;
        }
    }

    int visible_lines = (line_height > 0) ? (content_h / line_height) : 1;
    if (visible_lines < 1)
    {
        visible_lines = 1;
    }
    size_t start_line = 0;
    if (total_lines > (size_t)visible_lines)
    {
        start_line = total_lines - (size_t)visible_lines;
    }

    const char *line_start = text;
    size_t line_index = 0;
    size_t drawn = 0;

    while (line_start && *line_start)
    {
        const char *line_end = strchr(line_start, '\n');
        size_t line_len = line_end ? (size_t)(line_end - line_start) : strlen(line_start);

        if (line_index >= start_line)
        {
            int draw_top = content_y + (int)drawn * line_height;
            int baseline = atk_font_baseline_for_rect(draw_top, line_height);

            char scratch[128];
            const char *to_draw = NULL;
            char *heap = NULL;
            if (line_len < sizeof(scratch))
            {
                memcpy(scratch, line_start, line_len);
                scratch[line_len] = '\0';
                to_draw = scratch;
            }
            else
            {
                heap = (char *)malloc(line_len + 1);
                if (heap)
                {
                    memcpy(heap, line_start, line_len);
                    heap[line_len] = '\0';
                    to_draw = heap;
                }
            }
            if (to_draw)
            {
                atk_font_draw_string_clipped(content_x,
                                             baseline,
                                             to_draw,
                                             state->theme.button_text,
                                             face,
                                             &clip);
            }
            free(heap);

            drawn++;
            if (drawn >= (size_t)visible_lines)
            {
                break;
            }
        }

        if (!line_end)
        {
            break;
        }
        line_start = line_end + 1;
        line_index++;
    }

    if (priv->focused)
    {
        const char *last_nl = strrchr(text, '\n');
        const char *last_line = last_nl ? (last_nl + 1) : text;
        int caret_line_visible = (int)(total_lines - 1 - start_line);
        if (caret_line_visible < 0)
        {
            caret_line_visible = 0;
        }
        if (caret_line_visible >= visible_lines)
        {
            caret_line_visible = visible_lines - 1;
        }
        int caret_x = content_x + atk_font_text_width(last_line);
        if (caret_x > x + width - 2)
        {
            caret_x = x + width - 2;
        }
        int caret_top = content_y + caret_line_visible * line_height;
        int caret_baseline = atk_font_baseline_for_rect(caret_top, line_height);
        int caret_height = line_height;
        int caret_y = caret_baseline - caret_height + 1;
        if (caret_y < content_y)
        {
            caret_y = content_y;
        }
        if (caret_y + caret_height > y + height)
        {
            caret_height = (y + height) - caret_y;
        }
        if (caret_height > 0)
        {
            video_draw_rect(caret_x, caret_y, 2, caret_height, state->theme.button_text);
        }
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
    priv->multiline = false;
}

static atk_mouse_response_t text_input_mouse_cb(atk_widget_t *widget,
                                                const atk_mouse_event_t *event,
                                                void *context)
{
    (void)context;
    if (!event || !event->pressed_edge)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_state_t *state = atk_state_get();
    atk_text_input_focus(state, widget);
    return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW;
}

static bool text_input_hit_test_cb(const atk_widget_t *widget,
                                    int origin_x,
                                    int origin_y,
                                    int px,
                                    int py,
                                    void *context)
{
    (void)context;
    return atk_text_input_hit_test(widget, origin_x, origin_y, px, py);
}

static void text_input_draw_cb(const atk_state_t *state,
                               const atk_widget_t *widget,
                               int origin_x,
                               int origin_y,
                               void *context)
{
    (void)origin_x;
    (void)origin_y;
    (void)context;
    atk_text_input_draw(state, widget);
}

static void text_input_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_text_input_destroy(widget);
    atk_widget_destroy(widget);
}

static atk_key_response_t text_input_key_cb(atk_widget_t *widget,
                                            int key,
                                            int modifiers,
                                            int action,
                                            void *context)
{
    (void)modifiers;
    (void)action;
    (void)context;
    if (!widget)
    {
        return ATK_KEY_RESPONSE_NONE;
    }

    atk_text_input_event_t event = atk_text_input_handle_char(widget, (char)key);
    if (event == ATK_TEXT_INPUT_EVENT_CHANGED || event == ATK_TEXT_INPUT_EVENT_SUBMIT)
    {
        return ATK_KEY_RESPONSE_HANDLED | ATK_KEY_RESPONSE_REDRAW;
    }
    return (event == ATK_TEXT_INPUT_EVENT_NONE) ? ATK_KEY_RESPONSE_NONE : ATK_KEY_RESPONSE_HANDLED;
}
