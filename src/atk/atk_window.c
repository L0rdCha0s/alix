#include "atk_window.h"

#include <stddef.h>
#include "libc.h"
#include "serial.h"
#include "video.h"
#include "atk/atk_label.h"
#include "atk/atk_text_input.h"

static void atk_log(const char *msg);
static void format_window_title(char *buffer, size_t capacity, int id);
static void window_get_bounds(const atk_widget_t *window, int *x, int *y, int *width, int *height);
static atk_widget_t *window_add_button(atk_widget_t *window,
                                       const char *title,
                                       int rel_x,
                                       int rel_y,
                                       int width,
                                       int height,
                                       atk_button_style_t style,
                                       bool draggable,
                                       atk_button_action_t action,
                                       void *context);
static void action_window_close(atk_widget_t *button, void *context);
static void window_draw(const atk_state_t *state, const atk_widget_t *window);
static atk_window_priv_t *window_priv_mut(atk_widget_t *window);
static const atk_window_priv_t *window_priv(const atk_widget_t *window);
static void window_destroy(atk_widget_t *window);
static void window_destroy_value(void *value);
static void button_destroy_value(void *value);

extern const atk_class_t ATK_BUTTON_CLASS;
static const atk_widget_vtable_t window_vtable = { 0 };
const atk_class_t ATK_WINDOW_CLASS = { "Window", &ATK_WIDGET_CLASS, &window_vtable, sizeof(atk_window_priv_t) };

void atk_window_reset_all(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    atk_list_clear(&state->windows, window_destroy_value);
    atk_list_init(&state->windows);

    state->next_window_id = 1;
    state->dragging_window = 0;
    state->drag_offset_x = 0;
    state->drag_offset_y = 0;
    state->pressed_window_button_window = 0;
    state->pressed_window_button = 0;
    state->focused_input = NULL;
}

void atk_window_draw_all(const atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    ATK_LIST_FOR_EACH(node, &state->windows)
    {
        atk_widget_t *window = (atk_widget_t *)node->value;
        if (window && window->used)
        {
            window_draw(state, window);
        }
    }
}

bool atk_window_bring_to_front(atk_state_t *state, atk_widget_t *window)
{
    if (!state || !window)
    {
        return false;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv || !priv->list_node)
    {
        return false;
    }

    if (state->windows.tail == priv->list_node)
    {
        return false;
    }

    atk_list_move_to_back(&state->windows, priv->list_node);
    return true;
}

atk_widget_t *atk_window_hit_test(const atk_state_t *state, int x, int y)
{
    if (!state)
    {
        return 0;
    }

    ATK_LIST_FOR_EACH_REVERSE(node, &state->windows)
    {
        atk_widget_t *window = (atk_widget_t *)node->value;
        if (!window || !window->used)
        {
            continue;
        }
        if (x >= window->x && x < window->x + window->width &&
            y >= window->y && y < window->y + window->height)
        {
            return window;
        }
    }
    return 0;
}

atk_widget_t *atk_window_title_hit_test(const atk_state_t *state, int x, int y)
{
    if (!state)
    {
        return 0;
    }

    ATK_LIST_FOR_EACH_REVERSE(node, &state->windows)
    {
        atk_widget_t *window = (atk_widget_t *)node->value;
        if (!window || !window->used)
        {
            continue;
        }
        if (x >= window->x && x < window->x + window->width &&
            y >= window->y && y < window->y + ATK_WINDOW_TITLE_HEIGHT)
        {
            return window;
        }
    }
    return 0;
}

atk_widget_t *atk_window_get_button_at(atk_widget_t *window, int px, int py)
{
    if (!window || !window->used)
    {
        return 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return 0;
    }

    ATK_LIST_FOR_EACH_REVERSE(node, &priv->buttons)
    {
        atk_widget_t *btn = (atk_widget_t *)node->value;
        if (!btn || !btn->used)
        {
            continue;
        }
        if (atk_button_hit_test(btn, window->x, window->y, px, py))
        {
            return btn;
        }
    }
    return 0;
}

atk_widget_t *atk_window_text_input_at(atk_widget_t *window, int px, int py)
{
    if (!window || !window->used)
    {
        return NULL;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return NULL;
    }

    ATK_LIST_FOR_EACH_REVERSE(node, &priv->text_inputs)
    {
        atk_widget_t *input = (atk_widget_t *)node->value;
        if (!input || !input->used)
        {
            continue;
        }
        if (atk_text_input_hit_test(input, window->x, window->y, px, py))
        {
            return input;
        }
    }
    return NULL;
}

void atk_window_mark_dirty(const atk_widget_t *window)
{
    int x, y, w, h;
    window_get_bounds(window, &x, &y, &w, &h);
    if (w <= 0 || h <= 0)
    {
        return;
    }
    video_invalidate_rect(x, y, w, h);
}

void atk_window_ensure_inside(atk_widget_t *window)
{
    if (!window)
    {
        return;
    }

    if (window->width > VIDEO_WIDTH)
    {
        window->width = VIDEO_WIDTH;
    }
    if (window->height > VIDEO_HEIGHT)
    {
        window->height = VIDEO_HEIGHT;
    }

    int max_x = VIDEO_WIDTH - window->width;
    int max_y = VIDEO_HEIGHT - window->height;

    if (window->x < 0) window->x = 0;
    if (window->y < 0) window->y = 0;
    if (window->x > max_x) window->x = max_x;
    if (window->y > max_y) window->y = max_y;
}

atk_widget_t *atk_window_create_at(atk_state_t *state, int x, int y)
{
    if (!state)
    {
        return 0;
    }

    atk_widget_t *window = atk_widget_create(&ATK_WINDOW_CLASS);
    if (!window)
    {
        atk_log("window_create_at: allocation failed");
        return 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        atk_widget_destroy(window);
        return 0;
    }

    atk_list_init(&priv->buttons);
    atk_list_init(&priv->children);
    atk_list_init(&priv->text_inputs);
    priv->list_node = 0;
    priv->user_context = NULL;
    priv->on_destroy = NULL;

    window->used = true;
    window->width = 600;
    window->height = 400;
    window->x = x - window->width / 2;
    window->y = y - ATK_WINDOW_TITLE_HEIGHT / 2;
    window->parent = 0;

    format_window_title(priv->title, sizeof(priv->title), state->next_window_id++);

    atk_window_ensure_inside(window);

    int btn_margin = 4;
    int btn_width = ATK_WINDOW_TITLE_HEIGHT - btn_margin * 2;
    if (btn_width < ATK_FONT_WIDTH + 4)
    {
        btn_width = ATK_FONT_WIDTH + 4;
    }
    int btn_height = ATK_WINDOW_TITLE_HEIGHT - btn_margin * 2;

    if (!window_add_button(window,
                           "X",
                           window->width - btn_width - btn_margin,
                           btn_margin,
                           btn_width,
                           btn_height,
                           ATK_BUTTON_STYLE_TITLE_INSIDE,
                           false,
                           action_window_close,
                           window))
    {
        window_destroy(window);
        atk_log("window_create_at: failed to add close button");
        return 0;
    }

    atk_list_node_t *node = atk_list_push_back(&state->windows, window);
    if (!node)
    {
        window_destroy(window);
        atk_log("window_create_at: failed to track window");
        return 0;
    }

    priv->list_node = node;

    return window;
}

void atk_window_close(atk_state_t *state, atk_widget_t *window)
{
    if (!state || !window)
    {
        return;
    }

    if (state->dragging_window == window)
    {
        state->dragging_window = 0;
    }

    if (state->pressed_window_button_window == window)
    {
        state->pressed_window_button_window = 0;
        state->pressed_window_button = 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (priv && priv->list_node)
    {
        atk_list_remove(&state->windows, priv->list_node);
        priv->list_node = 0;
    }

    if (state->focused_input && state->focused_input->parent == window)
    {
        atk_text_input_focus(state, NULL);
    }

    if (priv && priv->on_destroy && priv->user_context)
    {
        priv->on_destroy(priv->user_context);
        priv->user_context = NULL;
    }

    window_destroy(window);
}

const char *atk_window_title(const atk_widget_t *window)
{
    const atk_window_priv_t *priv = window_priv(window);
    if (!priv)
    {
        return "";
    }
    return priv->title;
}

void atk_window_set_context(atk_widget_t *window, void *context, void (*on_destroy)(void *context))
{
    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return;
    }
    priv->user_context = context;
    priv->on_destroy = on_destroy;
}

void *atk_window_context(const atk_widget_t *window)
{
    const atk_window_priv_t *priv = window_priv(window);
    return priv ? priv->user_context : NULL;
}

static void atk_log(const char *msg)
{
    serial_write_string(msg);
    serial_write_string("\r\n");
}

static void window_draw(const atk_state_t *state, const atk_widget_t *window)
{
    if (!state || !window || !window->used)
    {
        return;
    }

    const atk_theme_t *theme = &state->theme;
    const atk_window_priv_t *priv = window_priv(window);

    video_draw_rect(window->x - ATK_WINDOW_BORDER,
                    window->y - ATK_WINDOW_BORDER,
                    window->width + ATK_WINDOW_BORDER * 2,
                    window->height + ATK_WINDOW_BORDER * 2,
                    theme->window_border);

    video_draw_rect(window->x,
                    window->y,
                    window->width,
                    window->height,
                    theme->window_body);

    video_draw_rect(window->x,
                    window->y,
                    window->width,
                    ATK_WINDOW_TITLE_HEIGHT,
                    theme->window_title);

    video_draw_rect_outline(window->x,
                            window->y,
                            window->width,
                            ATK_WINDOW_TITLE_HEIGHT,
                            theme->window_border);

    video_draw_text(window->x + ATK_WINDOW_TITLE_PADDING_X,
                    window->y + ATK_WINDOW_TITLE_TEXT_Y_OFFSET,
                    priv->title,
                    theme->window_title_text,
                    theme->window_title);

    video_draw_rect_outline(window->x,
                            window->y,
                            window->width,
                            window->height,
                            theme->window_border);

    ATK_LIST_FOR_EACH(node, &priv->children)
    {
        atk_widget_t *child = (atk_widget_t *)node->value;
        if (!child || !child->used)
        {
            continue;
        }

        if (atk_widget_is_a(child, &ATK_BUTTON_CLASS))
        {
            atk_button_draw(state, child, window->x, window->y);
        }
        else if (atk_widget_is_a(child, &ATK_LABEL_CLASS))
        {
            atk_label_draw(state, child);
        }
        else if (atk_widget_is_a(child, &ATK_TEXT_INPUT_CLASS))
        {
            atk_text_input_draw(state, child);
        }
    }
}

static void format_window_title(char *buffer, size_t capacity, int id)
{
    if (!buffer || capacity == 0)
    {
        return;
    }
    const char prefix[] = "Window ";
    size_t pos = 0;
    for (size_t i = 0; i < sizeof(prefix) - 1 && pos < capacity - 1; ++i)
    {
        buffer[pos++] = prefix[i];
    }

    char digits[16];
    size_t digit_count = 0;
    int value = id;
    if (value <= 0)
    {
        digits[digit_count++] = '0';
    }
    else
    {
        while (value > 0 && digit_count < sizeof(digits))
        {
            digits[digit_count++] = (char)('0' + (value % 10));
            value /= 10;
        }
    }

    while (digit_count > 0 && pos < capacity - 1)
    {
        buffer[pos++] = digits[--digit_count];
    }
    buffer[pos] = '\0';
}

static void window_get_bounds(const atk_widget_t *window, int *x, int *y, int *width, int *height)
{
    if (!window || !window->used)
    {
        if (x) *x = 0;
        if (y) *y = 0;
        if (width) *width = 0;
        if (height) *height = 0;
        return;
    }

    int bx = window->x - ATK_WINDOW_BORDER;
    int by = window->y - ATK_WINDOW_BORDER;
    int bw = window->width + ATK_WINDOW_BORDER * 2;
    int bh = window->height + ATK_WINDOW_BORDER * 2;

    if (x) *x = bx;
    if (y) *y = by;
    if (width) *width = bw;
    if (height) *height = bh;
}

static atk_widget_t *window_add_button(atk_widget_t *window,
                                       const char *title,
                                       int rel_x,
                                       int rel_y,
                                       int width,
                                       int height,
                                       atk_button_style_t style,
                                       bool draggable,
                                       atk_button_action_t action,
                                       void *context)
{
    if (!window)
    {
        return 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return 0;
    }

    atk_widget_t *btn = atk_widget_create(&ATK_BUTTON_CLASS);
    if (!btn)
    {
        return 0;
    }

    btn->x = rel_x;
    btn->y = rel_y;
    btn->width = width;
    btn->height = height;
    btn->parent = window;

    atk_button_configure(btn,
                         title,
                         style,
                         draggable,
                         false,
                         action,
                         context);
    atk_list_node_t *child_node = atk_list_push_back(&priv->children, btn);
    if (!child_node)
    {
        atk_widget_destroy(btn);
        return 0;
    }

    atk_list_node_t *button_node = atk_list_push_back(&priv->buttons, btn);
    if (!button_node)
    {
        atk_list_remove(&priv->children, child_node);
        atk_widget_destroy(btn);
        return 0;
    }

    atk_button_priv_t *btn_priv = (atk_button_priv_t *)atk_widget_priv(btn, &ATK_BUTTON_CLASS);
    if (btn_priv)
    {
        btn_priv->list_node = button_node;
    }

    return btn;
}

static void action_window_close(atk_widget_t *button, void *context)
{
    (void)button;
    atk_widget_t *window = (atk_widget_t *)context;
    atk_state_t *state = atk_state_get();
    atk_window_close(state, window);
}

static atk_window_priv_t *window_priv_mut(atk_widget_t *window)
{
    if (!window)
    {
        return 0;
    }
    return (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
}

static const atk_window_priv_t *window_priv(const atk_widget_t *window)
{
    if (!window)
    {
        return 0;
    }
    return (const atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
}

static void button_destroy_value(void *value)
{
    atk_widget_t *widget = (atk_widget_t *)value;
    if (!widget)
    {
        return;
    }

    atk_button_priv_t *priv = (atk_button_priv_t *)atk_widget_priv(widget, &ATK_BUTTON_CLASS);
    if (priv)
    {
        priv->list_node = 0;
    }

    atk_widget_destroy(widget);
}

static void window_child_destroy(void *value)
{
    atk_widget_t *widget = (atk_widget_t *)value;
    if (!widget)
    {
        return;
    }

    if (atk_widget_is_a(widget, &ATK_BUTTON_CLASS))
    {
        button_destroy_value(widget);
    }
    else if (atk_widget_is_a(widget, &ATK_LABEL_CLASS))
    {
        atk_label_destroy(widget);
        atk_widget_destroy(widget);
    }
    else if (atk_widget_is_a(widget, &ATK_TEXT_INPUT_CLASS))
    {
        atk_text_input_destroy(widget);
        atk_widget_destroy(widget);
    }
    else
    {
        atk_widget_destroy(widget);
    }
}

static void window_destroy(atk_widget_t *window)
{
    if (!window)
    {
        return;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (priv)
    {
        atk_list_clear(&priv->children, window_child_destroy);
        atk_list_clear(&priv->buttons, NULL);
        atk_list_clear(&priv->text_inputs, NULL);
        priv->list_node = 0;
        priv->user_context = NULL;
        priv->on_destroy = NULL;
    }

    atk_widget_destroy(window);
}

static void window_destroy_value(void *value)
{
    window_destroy((atk_widget_t *)value);
}
