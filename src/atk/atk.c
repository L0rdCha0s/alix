#include "atk.h"
#include "video.h"
#include "libc.h"
#include "serial.h"

#define MAX_WINDOWS 16
#define WINDOW_TITLE_HEIGHT 28
#define WINDOW_BORDER 2
#define WINDOW_TITLE_PADDING_X 8
#define WINDOW_TITLE_TEXT_Y_OFFSET 6
#define FONT_WIDTH 8
#define FONT_HEIGHT 16
#define BUTTON_TITLE_MAX 32
#define MAX_WINDOW_BUTTONS 8
#define MAX_DESKTOP_BUTTONS 16

typedef enum
{
    BUTTON_STYLE_TITLE_INSIDE = 0,
    BUTTON_STYLE_TITLE_BELOW = 1
} button_style_t;

typedef struct button button_t;
typedef void (*button_action_t)(button_t *button, void *context);

struct button
{
    bool used;
    int x;
    int y;
    int width;
    int height;
    button_style_t style;
    bool draggable;
    bool absolute;
    char title[BUTTON_TITLE_MAX];
    button_action_t action;
    void *action_context;
};

typedef struct
{
    bool used;
    int x;
    int y;
    int width;
    int height;
    char title[32];
    button_t buttons[MAX_WINDOW_BUTTONS];
    int button_count;
} window_t;

static window_t windows[MAX_WINDOWS];
static int window_count = 0;
static int next_window_id = 1;
static int dragging_window = -1;
static int drag_offset_x = 0;
static int drag_offset_y = 0;

static button_t desktop_buttons[MAX_DESKTOP_BUTTONS];
static int desktop_button_count = 0;

static int pressed_window_button_window = -1;
static int pressed_window_button_index = -1;
static int pressed_desktop_button = -1;
static int dragging_desktop_button = -1;
static int desktop_drag_offset_x = 0;
static int desktop_drag_offset_y = 0;
static bool desktop_drag_moved = false;

static uint16_t color_background = 0;
static uint16_t color_window_border = 0;
static uint16_t color_window_title = 0;
static uint16_t color_window_title_text = 0;
static uint16_t color_window_body = 0;
static uint16_t color_button_face = 0;
static uint16_t color_button_border = 0;
static uint16_t color_button_text = 0;
static uint16_t color_desktop_icon_face = 0;
static uint16_t color_desktop_icon_text = 0;

static bool atk_exit_requested = false;

static void atk_log(const char *msg);
static void windows_reset(void);
static void desktop_reset(void);
static void button_set_title(button_t *btn, const char *title);
static int button_effective_height(const button_t *btn);
static void button_draw(const button_t *btn, int origin_x, int origin_y);
static bool button_hit_test(const button_t *btn, int origin_x, int origin_y, int px, int py);
static void window_draw(const window_t *win);
static void windows_draw_all(void);
static void desktop_draw_buttons(void);
static int window_bring_to_front(int index);
static int window_hit_test(int x, int y);
static int window_title_hit_test(int x, int y);
static button_t *window_get_button_at(window_t *win, int px, int py, int *out_index);
static int desktop_button_hit_test(int px, int py);
static void window_ensure_inside(window_t *win);
static void window_get_bounds(const window_t *win, int *x, int *y, int *width, int *height);
static void window_mark_dirty(const window_t *win);
static button_t *window_add_button(window_t *win, const char *title, int rel_x, int rel_y, int width, int height, button_style_t style, bool draggable, button_action_t action, void *context);
static button_t *desktop_add_button(int x, int y, int width, int height, const char *title, button_style_t style, bool draggable, button_action_t action, void *context);
static void window_close(window_t *win);
static void action_window_close(button_t *button, void *context);
static void action_exit_to_text(button_t *button, void *context);
static window_t *window_create_at(int x, int y);
static void format_window_title(char *buffer, size_t capacity, int id);

void atk_init(void)
{
    windows_reset();
    desktop_reset();
    atk_exit_requested = false;
}

void atk_enter_mode(void)
{
    color_background = video_make_color(0xFF, 0x80, 0x20);
    color_window_border = video_make_color(0x20, 0x20, 0x20);
    color_window_title = video_make_color(0x30, 0x60, 0xA0);
    color_window_title_text = video_make_color(0xFF, 0xFF, 0xFF);
    color_window_body = video_make_color(0xF0, 0xF0, 0xF0);
    color_button_face = video_make_color(0xE0, 0xE0, 0xE0);
    color_button_border = video_make_color(0x40, 0x40, 0x40);
    color_button_text = video_make_color(0x10, 0x10, 0x10);
    color_desktop_icon_face = video_make_color(0x50, 0x90, 0xD0);
    color_desktop_icon_text = color_window_title_text;

    windows_reset();
    desktop_reset();

    desktop_add_button(40,
                       40,
                       88,
                       88,
                       "Exit",
                       BUTTON_STYLE_TITLE_BELOW,
                       true,
                       action_exit_to_text,
                       0);
}

void atk_render(void)
{
    video_invalidate_all();
    video_fill(color_background);
    desktop_draw_buttons();
    windows_draw_all();
}

atk_mouse_event_result_t atk_handle_mouse_event(int cursor_x, int cursor_y, bool pressed_edge, bool released_edge, bool left_pressed)
{
    atk_mouse_event_result_t result = { .redraw = false, .exit_video = false };

    if (pressed_edge)
    {
        dragging_window = -1;
        dragging_desktop_button = -1;
        desktop_drag_moved = false;
        pressed_window_button_window = -1;
        pressed_window_button_index = -1;
        pressed_desktop_button = -1;

        bool handled = false;

        for (int i = window_count - 1; i >= 0 && !handled; --i)
        {
            int button_index = -1;
            button_t *btn = window_get_button_at(&windows[i], cursor_x, cursor_y, &button_index);
            if (btn)
            {
                window_t before = windows[i];
                int front_index = window_bring_to_front(i);
                if (front_index >= 0)
                {
                    if (front_index != i)
                    {
                        window_mark_dirty(&before);
                        window_mark_dirty(&windows[front_index]);
                        result.redraw = true;
                    }
                    pressed_window_button_window = front_index;
                    pressed_window_button_index = button_index;
                    handled = true;
                }
            }
        }

        if (!handled)
        {
            int title_index = window_title_hit_test(cursor_x, cursor_y);
            if (title_index >= 0)
            {
                window_t before = windows[title_index];
                int front_index = window_bring_to_front(title_index);
                if (front_index >= 0)
                {
                    if (front_index != title_index)
                    {
                        window_mark_dirty(&before);
                        window_mark_dirty(&windows[front_index]);
                        result.redraw = true;
                    }
                    dragging_window = front_index;
                    drag_offset_x = cursor_x - windows[front_index].x;
                    drag_offset_y = cursor_y - windows[front_index].y;
                    handled = true;
                }
            }
        }

        if (!handled)
        {
            int body_index = window_hit_test(cursor_x, cursor_y);
            if (body_index >= 0)
            {
                window_t before = windows[body_index];
                int front_index = window_bring_to_front(body_index);
                if (front_index >= 0 && front_index != body_index)
                {
                    window_mark_dirty(&before);
                    window_mark_dirty(&windows[front_index]);
                    result.redraw = true;
                }
                handled = true;
            }
        }

        if (!handled)
        {
            int desktop_index = desktop_button_hit_test(cursor_x, cursor_y);
            if (desktop_index >= 0)
            {
                pressed_desktop_button = desktop_index;
                button_t *btn = &desktop_buttons[desktop_index];
                if (btn->draggable)
                {
                    dragging_desktop_button = desktop_index;
                    desktop_drag_offset_x = cursor_x - btn->x;
                    desktop_drag_offset_y = cursor_y - btn->y;
                    desktop_drag_moved = false;
                }
                handled = true;
            }
        }

        if (!handled)
        {
            window_t *created = window_create_at(cursor_x, cursor_y);
            if (created)
            {
                window_mark_dirty(created);
                result.redraw = true;
            }
        }
    }
    else if (released_edge)
    {
        dragging_window = -1;

        if (dragging_desktop_button >= 0)
        {
            dragging_desktop_button = -1;
        }

        if (pressed_window_button_window >= 0 &&
            pressed_window_button_window < window_count)
        {
            window_t *win = &windows[pressed_window_button_window];
            if (pressed_window_button_index >= 0 &&
                pressed_window_button_index < win->button_count)
            {
                button_t *btn = &win->buttons[pressed_window_button_index];
                if (btn->used && button_hit_test(btn, win->x, win->y, cursor_x, cursor_y))
                {
                    if (btn->action)
                    {
                        btn->action(btn, btn->action_context);
                        result.redraw = true;
                    }
                }
            }
        }
        pressed_window_button_window = -1;
        pressed_window_button_index = -1;

        if (pressed_desktop_button >= 0 &&
            pressed_desktop_button < desktop_button_count)
        {
            button_t *btn = &desktop_buttons[pressed_desktop_button];
            if (btn->used)
            {
                bool inside = button_hit_test(btn, 0, 0, cursor_x, cursor_y);
                if (!desktop_drag_moved && inside && btn->action)
                {
                    btn->action(btn, btn->action_context);
                }
            }
        }
        pressed_desktop_button = -1;
        desktop_drag_moved = false;
    }

    if (left_pressed && dragging_window >= 0 && dragging_window < window_count)
    {
        window_t *win = &windows[dragging_window];
        window_t old_pos = *win;
        int new_x = cursor_x - drag_offset_x;
        int new_y = cursor_y - drag_offset_y;
        win->x = new_x;
        win->y = new_y;
        window_ensure_inside(win);
        if (win->x != old_pos.x || win->y != old_pos.y)
        {
            window_mark_dirty(&old_pos);
            window_mark_dirty(win);
            result.redraw = true;
        }
    }

    if (left_pressed && dragging_desktop_button >= 0 &&
        dragging_desktop_button < desktop_button_count)
    {
        button_t *btn = &desktop_buttons[dragging_desktop_button];
        button_t old_btn = *btn;

        int new_x = cursor_x - desktop_drag_offset_x;
        int new_y = cursor_y - desktop_drag_offset_y;

        if (new_x < 0) new_x = 0;
        if (new_y < 0) new_y = 0;
        int max_x = VIDEO_WIDTH - btn->width;
        int max_y = VIDEO_HEIGHT - button_effective_height(btn);
        if (max_x < 0) max_x = 0;
        if (max_y < 0) max_y = 0;
        if (new_x > max_x) new_x = max_x;
        if (new_y > max_y) new_y = max_y;

        btn->x = new_x;
        btn->y = new_y;

        if (btn->x != old_btn.x || btn->y != old_btn.y)
        {
            desktop_drag_moved = true;
            video_invalidate_rect(old_btn.x, old_btn.y, old_btn.width, button_effective_height(&old_btn));
            video_invalidate_rect(btn->x, btn->y, btn->width, button_effective_height(btn));
            result.redraw = true;
        }
    }

    if (atk_exit_requested)
    {
        result.exit_video = true;
        atk_exit_requested = false;
    }

    return result;
}

static void atk_log(const char *msg)
{
    serial_write_string(msg);
    serial_write_string("\r\n");
}

static void windows_reset(void)
{
    memset(windows, 0, sizeof(windows));
    window_count = 0;
    next_window_id = 1;
    dragging_window = -1;
    drag_offset_x = 0;
    drag_offset_y = 0;
}

static void desktop_reset(void)
{
    memset(desktop_buttons, 0, sizeof(desktop_buttons));
    desktop_button_count = 0;
    pressed_desktop_button = -1;
    dragging_desktop_button = -1;
    desktop_drag_offset_x = 0;
    desktop_drag_offset_y = 0;
    desktop_drag_moved = false;
}

static void button_set_title(button_t *btn, const char *title)
{
    if (!btn || !title)
    {
        return;
    }
    size_t i = 0;
    for (; title[i] != '\0' && i < BUTTON_TITLE_MAX - 1; ++i)
    {
        btn->title[i] = title[i];
    }
    btn->title[i] = '\0';
}

static int button_effective_height(const button_t *btn)
{
    if (!btn)
    {
        return 0;
    }
    int height = btn->height;
    if (btn->style == BUTTON_STYLE_TITLE_BELOW)
    {
        height += FONT_HEIGHT + 4;
    }
    return height;
}

static void button_draw(const button_t *btn, int origin_x, int origin_y)
{
    if (!btn || !btn->used)
    {
        return;
    }
    int bx = origin_x + btn->x;
    int by = origin_y + btn->y;

    uint16_t border_color = btn->absolute ? color_button_border : color_window_border;
    uint16_t face_color = btn->absolute ? color_desktop_icon_face : color_button_face;
    uint16_t text_color = btn->absolute ? color_desktop_icon_text : color_button_text;

    if (!btn->absolute && btn->style == BUTTON_STYLE_TITLE_INSIDE)
    {
        face_color = color_window_title;
        text_color = color_window_title_text;
    }

    video_draw_rect(bx, by, btn->width, btn->height, face_color);
    video_draw_rect_outline(bx, by, btn->width, btn->height, border_color);

    int text_x = bx + 4;
    int text_y = by + 4;

    size_t title_len = strlen(btn->title);
    int title_px_width = (int)(title_len * FONT_WIDTH);

    if (btn->style == BUTTON_STYLE_TITLE_INSIDE)
    {
        if (title_px_width < btn->width)
        {
            text_x = bx + (btn->width - title_px_width) / 2;
        }
        if (btn->height > FONT_HEIGHT)
        {
            text_y = by + (btn->height - FONT_HEIGHT) / 2;
        }
        video_draw_text(text_x, text_y, btn->title, text_color, face_color);
    }
    else
    {
        int label_y = by + btn->height + 2;
        if (title_px_width < btn->width)
        {
            text_x = bx + (btn->width - title_px_width) / 2;
        }
        else
        {
            text_x = bx;
        }
        video_draw_text(text_x, label_y, btn->title, text_color, color_background);
    }
}

static bool button_hit_test(const button_t *btn, int origin_x, int origin_y, int px, int py)
{
    if (!btn || !btn->used)
    {
        return false;
    }
    int x0 = origin_x + btn->x;
    int y0 = origin_y + btn->y;
    int x1 = x0 + btn->width;
    int y1 = y0 + button_effective_height(btn);
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

static void window_draw(const window_t *win)
{
    if (!win || !win->used)
    {
        return;
    }

    video_draw_rect(win->x - WINDOW_BORDER,
                    win->y - WINDOW_BORDER,
                    win->width + WINDOW_BORDER * 2,
                    win->height + WINDOW_BORDER * 2,
                    color_window_border);

    video_draw_rect(win->x,
                    win->y,
                    win->width,
                    win->height,
                    color_window_body);

    video_draw_rect(win->x,
                    win->y,
                    win->width,
                    WINDOW_TITLE_HEIGHT,
                    color_window_title);

    video_draw_rect_outline(win->x,
                            win->y,
                            win->width,
                            WINDOW_TITLE_HEIGHT,
                            color_window_border);

    video_draw_text(win->x + WINDOW_TITLE_PADDING_X,
                    win->y + WINDOW_TITLE_TEXT_Y_OFFSET,
                    win->title,
                    color_window_title_text,
                    color_window_title);

    video_draw_rect_outline(win->x,
                            win->y,
                            win->width,
                            win->height,
                            color_window_border);

    for (int i = 0; i < win->button_count; ++i)
    {
        if (win->buttons[i].used)
        {
            button_draw(&win->buttons[i], win->x, win->y);
        }
    }
}

static void windows_draw_all(void)
{
    for (int i = 0; i < window_count; ++i)
    {
        if (windows[i].used)
        {
            window_draw(&windows[i]);
        }
    }
}

static void desktop_draw_buttons(void)
{
    for (int i = 0; i < desktop_button_count; ++i)
    {
        if (desktop_buttons[i].used)
        {
            button_draw(&desktop_buttons[i], 0, 0);
        }
    }
}

static int window_bring_to_front(int index)
{
    if (index < 0 || index >= window_count)
    {
        return -1;
    }
    if (index == window_count - 1)
    {
        return index;
    }

    window_t temp = windows[index];
    for (int i = index; i < window_count - 1; ++i)
    {
        windows[i] = windows[i + 1];

        if (dragging_window == i + 1)
        {
            dragging_window = i;
        }
        if (pressed_window_button_window == i + 1)
        {
            pressed_window_button_window = i;
        }
    }
    windows[window_count - 1] = temp;

    int new_index = window_count - 1;

    if (dragging_window == index)
    {
        dragging_window = new_index;
    }
    else if (dragging_window > index)
    {
        dragging_window--;
    }

    if (pressed_window_button_window == index)
    {
        pressed_window_button_window = new_index;
    }
    else if (pressed_window_button_window > index)
    {
        pressed_window_button_window--;
    }

    return new_index;
}

static int window_hit_test(int x, int y)
{
    for (int i = window_count - 1; i >= 0; --i)
    {
        window_t *win = &windows[i];
        if (!win->used)
        {
            continue;
        }
        if (x >= win->x && x < win->x + win->width &&
            y >= win->y && y < win->y + win->height)
        {
            return i;
        }
    }
    return -1;
}

static int window_title_hit_test(int x, int y)
{
    for (int i = window_count - 1; i >= 0; --i)
    {
        window_t *win = &windows[i];
        if (!win->used)
        {
            continue;
        }
        if (x >= win->x && x < win->x + win->width &&
            y >= win->y && y < win->y + WINDOW_TITLE_HEIGHT)
        {
            return i;
        }
    }
    return -1;
}

static button_t *window_get_button_at(window_t *win, int px, int py, int *out_index)
{
    if (!win)
    {
        return 0;
    }
    for (int i = win->button_count - 1; i >= 0; --i)
    {
        button_t *btn = &win->buttons[i];
        if (!btn->used)
        {
            continue;
        }
        if (button_hit_test(btn, win->x, win->y, px, py))
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

static int desktop_button_hit_test(int px, int py)
{
    for (int i = desktop_button_count - 1; i >= 0; --i)
    {
        if (!desktop_buttons[i].used)
        {
            continue;
        }
        if (button_hit_test(&desktop_buttons[i], 0, 0, px, py))
        {
            return i;
        }
    }
    return -1;
}

static void window_ensure_inside(window_t *win)
{
    if (!win)
    {
        return;
    }

    if (win->width > VIDEO_WIDTH)
    {
        win->width = VIDEO_WIDTH;
    }
    if (win->height > VIDEO_HEIGHT)
    {
        win->height = VIDEO_HEIGHT;
    }

    int max_x = VIDEO_WIDTH - win->width;
    int max_y = VIDEO_HEIGHT - win->height;

    if (win->x < 0) win->x = 0;
    if (win->y < 0) win->y = 0;
    if (win->x > max_x) win->x = max_x;
    if (win->y > max_y) win->y = max_y;
}

static void window_get_bounds(const window_t *win, int *x, int *y, int *width, int *height)
{
    if (!win || !win->used)
    {
        if (x) *x = 0;
        if (y) *y = 0;
        if (width) *width = 0;
        if (height) *height = 0;
        return;
    }

    int bx = win->x - WINDOW_BORDER;
    int by = win->y - WINDOW_BORDER;
    int bw = win->width + WINDOW_BORDER * 2;
    int bh = win->height + WINDOW_BORDER * 2;

    if (x) *x = bx;
    if (y) *y = by;
    if (width) *width = bw;
    if (height) *height = bh;
}

static void window_mark_dirty(const window_t *win)
{
    int x, y, w, h;
    window_get_bounds(win, &x, &y, &w, &h);
    if (w <= 0 || h <= 0)
    {
        return;
    }
    video_invalidate_rect(x, y, w, h);
}

static button_t *window_add_button(window_t *win,
                                   const char *title,
                                   int rel_x,
                                   int rel_y,
                                   int width,
                                   int height,
                                   button_style_t style,
                                   bool draggable,
                                   button_action_t action,
                                   void *context)
{
    if (!win || win->button_count >= MAX_WINDOW_BUTTONS)
    {
        return 0;
    }
    button_t *btn = &win->buttons[win->button_count++];
    memset(btn, 0, sizeof(*btn));
    btn->used = true;
    btn->absolute = false;
    btn->x = rel_x;
    btn->y = rel_y;
    btn->width = width;
    btn->height = height;
    btn->style = style;
    btn->draggable = draggable;
    btn->action = action;
    btn->action_context = context;
    button_set_title(btn, title ? title : "");
    return btn;
}

static button_t *desktop_add_button(int x,
                                    int y,
                                    int width,
                                    int height,
                                    const char *title,
                                    button_style_t style,
                                    bool draggable,
                                    button_action_t action,
                                    void *context)
{
    if (desktop_button_count >= MAX_DESKTOP_BUTTONS)
    {
        return 0;
    }
    button_t *btn = &desktop_buttons[desktop_button_count++];
    memset(btn, 0, sizeof(*btn));
    btn->used = true;
    btn->absolute = true;
    btn->x = x;
    btn->y = y;
    btn->width = width;
    btn->height = height;
    btn->style = style;
    btn->draggable = draggable;
    btn->action = action;
    btn->action_context = context;
    button_set_title(btn, title ? title : "");
    return btn;
}

static void window_close(window_t *win)
{
    if (!win || !win->used)
    {
        return;
    }
    window_mark_dirty(win);

    int index = -1;
    for (int i = 0; i < window_count; ++i)
    {
        if (&windows[i] == win)
        {
            index = i;
            break;
        }
    }
    if (index < 0)
    {
        return;
    }

    if (dragging_window == index)
    {
        dragging_window = -1;
    }
    else if (dragging_window > index)
    {
        dragging_window--;
    }

    if (pressed_window_button_window == index)
    {
        pressed_window_button_window = -1;
        pressed_window_button_index = -1;
    }
    else if (pressed_window_button_window > index)
    {
        pressed_window_button_window--;
    }

    for (int i = index; i < window_count - 1; ++i)
    {
        windows[i] = windows[i + 1];
    }
    if (window_count > 0)
    {
        memset(&windows[window_count - 1], 0, sizeof(window_t));
    }
    window_count--;
}

static void action_window_close(button_t *button, void *context)
{
    (void)button;
    window_close((window_t *)context);
}

static void action_exit_to_text(button_t *button, void *context)
{
    (void)button;
    (void)context;
    atk_exit_requested = true;
}

static window_t *window_create_at(int x, int y)
{
    if (window_count >= MAX_WINDOWS)
    {
        atk_log("window_create_at: max windows reached");
        return 0;
    }

    window_t *win = &windows[window_count++];
    memset(win, 0, sizeof(*win));
    win->used = true;
    win->width = 600;
    win->height = 400;
    win->x = x - win->width / 2;
    win->y = y - WINDOW_TITLE_HEIGHT / 2;
    format_window_title(win->title, sizeof(win->title), next_window_id++);

    window_ensure_inside(win);

    int btn_margin = 4;
    int btn_width = WINDOW_TITLE_HEIGHT - btn_margin * 2;
    if (btn_width < FONT_WIDTH + 4)
    {
        btn_width = FONT_WIDTH + 4;
    }
    int btn_height = WINDOW_TITLE_HEIGHT - btn_margin * 2;
    window_add_button(win,
                      "X",
                      win->width - btn_width - btn_margin,
                      btn_margin,
                      btn_width,
                      btn_height,
                      BUTTON_STYLE_TITLE_INSIDE,
                      false,
                      action_window_close,
                      win);

    return win;
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
