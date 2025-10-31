#include "atk_window.h"

#include "libc.h"
#include "serial.h"
#include "video.h"

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
static atk_widget_t *window_allocate_slot(atk_state_t *state);
static void window_release_slot(atk_widget_t *window);

extern const atk_class_t ATK_BUTTON_CLASS;
static const atk_widget_vtable_t window_vtable = { 0 };
const atk_class_t ATK_WINDOW_CLASS = { "Window", &ATK_WIDGET_CLASS, &window_vtable, sizeof(atk_window_priv_t) };

void atk_window_reset_all(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    for (int i = 0; i < ATK_MAX_WINDOWS; ++i)
    {
        atk_widget_init(state->window_storage[i], &ATK_WINDOW_CLASS);
        state->windows[i] = 0;
    }

    state->window_count = 0;
    state->next_window_id = 1;
    state->dragging_window = -1;
    state->drag_offset_x = 0;
    state->drag_offset_y = 0;
    state->pressed_window_button_window = -1;
    state->pressed_window_button_index = -1;
}

void atk_window_draw_all(const atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    for (int i = 0; i < state->window_count; ++i)
    {
        atk_widget_t *window = state->windows[i];
        if (window && window->used)
        {
            window_draw(state, window);
        }
    }
}

int atk_window_bring_to_front(atk_state_t *state, int index)
{
    if (!state || index < 0 || index >= state->window_count)
    {
        return -1;
    }
    if (index == state->window_count - 1)
    {
        return index;
    }

    atk_widget_t *temp = state->windows[index];
    for (int i = index; i < state->window_count - 1; ++i)
    {
        state->windows[i] = state->windows[i + 1];

        if (state->dragging_window == i + 1)
        {
            state->dragging_window = i;
        }
        if (state->pressed_window_button_window == i + 1)
        {
            state->pressed_window_button_window = i;
        }
    }
    state->windows[state->window_count - 1] = temp;

    int new_index = state->window_count - 1;

    if (state->dragging_window == index)
    {
        state->dragging_window = new_index;
    }
    else if (state->dragging_window > index)
    {
        state->dragging_window--;
    }

    if (state->pressed_window_button_window == index)
    {
        state->pressed_window_button_window = new_index;
    }
    else if (state->pressed_window_button_window > index)
    {
        state->pressed_window_button_window--;
    }

    return new_index;
}

int atk_window_hit_test(const atk_state_t *state, int x, int y)
{
    if (!state)
    {
        return -1;
    }

    for (int i = state->window_count - 1; i >= 0; --i)
    {
        atk_widget_t *window = state->windows[i];
        if (!window || !window->used)
        {
            continue;
        }
        if (x >= window->x && x < window->x + window->width &&
            y >= window->y && y < window->y + window->height)
        {
            return i;
        }
    }
    return -1;
}

int atk_window_title_hit_test(const atk_state_t *state, int x, int y)
{
    if (!state)
    {
        return -1;
    }

    for (int i = state->window_count - 1; i >= 0; --i)
    {
        atk_widget_t *window = state->windows[i];
        if (!window || !window->used)
        {
            continue;
        }
        if (x >= window->x && x < window->x + window->width &&
            y >= window->y && y < window->y + ATK_WINDOW_TITLE_HEIGHT)
        {
            return i;
        }
    }
    return -1;
}

atk_widget_t *atk_window_get_button_at(atk_widget_t *window, int px, int py, int *out_index)
{
    if (!window || !window->used)
    {
        return 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    for (int i = priv->button_count - 1; i >= 0; --i)
    {
        atk_widget_t *btn = priv->buttons[i];
        if (!btn || !btn->used)
        {
            continue;
        }
        if (atk_button_hit_test(btn, window->x, window->y, px, py))
        {
            if (out_index)
            {
                *out_index = i;
            }
            return btn;
        }
    }
    return 0;
}

atk_widget_t *atk_window_button_at_index(atk_widget_t *window, int index)
{
    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv || index < 0 || index >= priv->button_count)
    {
        return 0;
    }
    return priv->buttons[index];
}

int atk_window_button_count(const atk_widget_t *window)
{
    const atk_window_priv_t *priv = window_priv(window);
    if (!priv)
    {
        return 0;
    }
    return priv->button_count;
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

    if (state->window_count >= ATK_MAX_WINDOWS)
    {
        atk_log("window_create_at: max windows reached");
        return 0;
    }

    atk_widget_t *window = window_allocate_slot(state);
    if (!window)
    {
        atk_log("window_create_at: no storage available");
        return 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    window->used = true;
    window->width = 600;
    window->height = 400;
    window->x = x - window->width / 2;
    window->y = y - ATK_WINDOW_TITLE_HEIGHT / 2;
    window->parent = 0;

    priv->button_count = 0;
    format_window_title(priv->title, sizeof(priv->title), state->next_window_id++);

    atk_window_ensure_inside(window);

    int btn_margin = 4;
    int btn_width = ATK_WINDOW_TITLE_HEIGHT - btn_margin * 2;
    if (btn_width < ATK_FONT_WIDTH + 4)
    {
        btn_width = ATK_FONT_WIDTH + 4;
    }
    int btn_height = ATK_WINDOW_TITLE_HEIGHT - btn_margin * 2;

    window_add_button(window,
                      "X",
                      window->width - btn_width - btn_margin,
                      btn_margin,
                      btn_width,
                      btn_height,
                      ATK_BUTTON_STYLE_TITLE_INSIDE,
                      false,
                      action_window_close,
                      window);

    state->windows[state->window_count++] = window;
    return window;
}

void atk_window_close(atk_state_t *state, atk_widget_t *window)
{
    if (!state || !window)
    {
        return;
    }

    int index = -1;
    for (int i = 0; i < state->window_count; ++i)
    {
        if (state->windows[i] == window)
        {
            index = i;
            break;
        }
    }

    if (index < 0)
    {
        return;
    }

    if (state->dragging_window == index)
    {
        state->dragging_window = -1;
    }
    else if (state->dragging_window > index)
    {
        state->dragging_window--;
    }

    if (state->pressed_window_button_window == index)
    {
        state->pressed_window_button_window = -1;
        state->pressed_window_button_index = -1;
    }
    else if (state->pressed_window_button_window > index)
    {
        state->pressed_window_button_window--;
    }

    for (int i = index; i < state->window_count - 1; ++i)
    {
        state->windows[i] = state->windows[i + 1];
    }

    state->window_count--;
    state->windows[state->window_count] = 0;

    window_release_slot(window);
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

    for (int i = 0; i < priv->button_count; ++i)
    {
        atk_widget_t *btn = priv->buttons[i];
        if (btn && btn->used)
        {
            atk_button_draw(state, btn, window->x, window->y);
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
    if (!priv || priv->button_count >= ATK_MAX_WINDOW_BUTTONS)
    {
        return 0;
    }

    int slot = priv->button_count++;
    void *storage = priv->button_storage[slot];
    atk_widget_t *btn = atk_widget_init(storage, &ATK_BUTTON_CLASS);
    priv->buttons[slot] = btn;

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

static atk_widget_t *window_allocate_slot(atk_state_t *state)
{
    for (int i = 0; i < ATK_MAX_WINDOWS; ++i)
    {
        atk_widget_t *slot = (atk_widget_t *)state->window_storage[i];
        if (!slot->cls)
        {
            atk_widget_init(slot, &ATK_WINDOW_CLASS);
        }
        if (!slot->used)
        {
            atk_widget_init(slot, &ATK_WINDOW_CLASS);
            return slot;
        }
    }
    return 0;
}

static void window_release_slot(atk_widget_t *window)
{
    if (!window)
    {
        return;
    }
    atk_widget_init(window, &ATK_WINDOW_CLASS);
}
