#include "video.h"
#include "io.h"
#include "timer.h"
#include "serial.h"
#include "mouse.h"
#include "libc.h"

#define BGA_INDEX_PORT 0x1CE
#define BGA_DATA_PORT  0x1CF
#define BGA_REG_ID     0x0
#define BGA_REG_XRES   0x1
#define BGA_REG_YRES   0x2
#define BGA_REG_BPP    0x3
#define BGA_REG_ENABLE 0x4
#define BGA_REG_BANK   0x5
#define BGA_REG_VIRT_WIDTH  0x6
#define BGA_REG_VIRT_HEIGHT 0x7
#define BGA_REG_X_OFFSET    0x8
#define BGA_REG_Y_OFFSET    0x9

#define VIDEO_WIDTH  1280
#define VIDEO_HEIGHT 1024
#define VIDEO_BPP    16

#define CURSOR_W 16
#define CURSOR_H 16
#define DOUBLE_CLICK_TICKS 400

static volatile uint16_t *framebuffer = 0;
static uint64_t framebuffer_phys = 0;
static bool framebuffer_detected = false;
static bool vga_state_saved = false;
static uint8_t saved_regs[1 + 5 + 25 + 9 + 21];
static int video_mouse_log_count = 0;

static bool video_active = false;
static bool exit_requested = false;
static int cursor_x = 0;
static int cursor_y = 0;
static bool cursor_has_backup = false;
static int cursor_backup_x = 0;
static int cursor_backup_y = 0;
static uint16_t cursor_backup[CURSOR_W * CURSOR_H];
static bool last_left_down = false;
static uint64_t last_click_tick = 0;
static bool logged_first_mouse = false;

#define VGA_FONT_BYTES 8192

static bool vga_font_saved = false;
static uint8_t saved_font[VGA_FONT_BYTES];

typedef struct
{
    uint8_t seq2;
    uint8_t seq4;
    uint8_t gc4;
    uint8_t gc5;
    uint8_t gc6;
} vga_font_regs_t;

#define MAX_WINDOWS 16
#define WINDOW_TITLE_HEIGHT 28
#define WINDOW_BORDER 2
#define WINDOW_TITLE_PADDING_X 8
#define WINDOW_TITLE_TEXT_Y_OFFSET 6
#define FONT_WIDTH 8
#define FONT_HEIGHT 16

typedef struct
{
    bool used;
    int x;
    int y;
    int width;
    int height;
    char title[32];
} window_t;

static window_t windows[MAX_WINDOWS];
static int window_count = 0;
static int next_window_id = 1;
static int dragging_window = -1;
static int drag_offset_x = 0;
static int drag_offset_y = 0;

static uint16_t color_background = 0;
static uint16_t color_window_border = 0;
static uint16_t color_window_title = 0;
static uint16_t color_window_title_text = 0;
static uint16_t color_window_body = 0;

static void video_log(const char *msg);
static void video_log_hex(const char *prefix, uint64_t value);
static uint32_t pci_config_read(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset);
static void detect_framebuffer(void);
static void video_log_mouse_event(int dx, int dy, bool left_pressed);
static void vga_enter_text_mode(void);
static void vga_write_regs(const uint8_t *regs);
static void vga_capture_state(void);
static bool vga_restore_state(void);
static void vga_capture_font(void);
static void vga_restore_font(void);
static void vga_font_access_begin(vga_font_regs_t *state);
static void vga_font_access_end(const vga_font_regs_t *state);
static uint8_t vga_seq_read(uint8_t index);
static void vga_seq_write(uint8_t index, uint8_t value);
static uint8_t vga_gc_read(uint8_t index);
static void vga_gc_write(uint8_t index, uint8_t value);
static void windows_reset(void);
static void window_draw(const window_t *win);
static void windows_draw_all(void);
static int window_bring_to_front(int index);
static int window_hit_test(int x, int y);
static int window_title_hit_test(int x, int y);
static void window_ensure_inside(window_t *win);
static void draw_rect(int x, int y, int width, int height, uint16_t color);
static void draw_rect_outline(int x, int y, int width, int height, uint16_t color);
static void draw_text(int x, int y, const char *text, uint16_t fg, uint16_t bg);
static void draw_char(int x, int y, char c, uint16_t fg, uint16_t bg);
static void video_draw_scene(void);
static void window_create_at(int x, int y);
static void format_window_title(char *buffer, size_t capacity, int id);

void video_init(void)
{
    vga_capture_state();
    vga_capture_font();
}

static const char *cursor_shape[CURSOR_H] = {
    "X...............",
    "XX..............",
    "XOX.............",
    "XOOX............",
    "XOOOX...........",
    "XOOOOX..........",
    "XOOOOOX.........",
    "XOOOOOOX........",
    "XOOOOOOOOX......",
    "XOOOOOOX........",
    "XOOOX...........",
    "XOOX............",
    "XOX.............",
    "XX..............",
    "X...............",
    "................"
};

static uint16_t cursor_color_primary(void)
{
    return (uint16_t)(((0xFF & 0xF8) << 8) | ((0xFF & 0xFC) << 3) | (0xFF >> 3));
}

static uint16_t cursor_color_shadow(void)
{
    uint8_t r = 0x40, g = 0x40, b = 0x40;
    return (uint16_t)(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

static uint16_t make_color(uint8_t r, uint8_t g, uint8_t b)
{
    return (uint16_t)(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

static void bga_write(uint16_t index, uint16_t value)
{
    outw(BGA_INDEX_PORT, index);
    outw(BGA_DATA_PORT, value);
}

static uint16_t bga_read(uint16_t index)
{
    outw(BGA_INDEX_PORT, index);
    return inw(BGA_DATA_PORT);
}

static bool bga_available(void)
{
    uint16_t id = bga_read(BGA_REG_ID);
    return id >= 0xB0C0 && id <= 0xB0C6;
}

static bool video_hw_enable(void)
{
    detect_framebuffer();
    if (framebuffer_phys == 0)
    {
        video_log("framebuffer phys is zero");
        return false;
    }
    framebuffer = (volatile uint16_t *)(uintptr_t)framebuffer_phys;
    video_log_hex("Framebuffer phys base: 0x", framebuffer_phys);

    if (!bga_available())
    {
        video_log("BGA controller not detected");
        return false;
    }

    video_log("BGA detected, configuring mode");

    bga_write(BGA_REG_ENABLE, 0x00);
    bga_write(BGA_REG_XRES, VIDEO_WIDTH);
    bga_write(BGA_REG_YRES, VIDEO_HEIGHT);
    bga_write(BGA_REG_BPP, VIDEO_BPP);
    bga_write(BGA_REG_VIRT_WIDTH, VIDEO_WIDTH);
    bga_write(BGA_REG_VIRT_HEIGHT, VIDEO_HEIGHT);
    bga_write(BGA_REG_X_OFFSET, 0);
    bga_write(BGA_REG_Y_OFFSET, 0);
    bga_write(BGA_REG_BANK, 0);
    bga_write(BGA_REG_ENABLE, 0x41); /* enable + LFB */

    video_log_hex("BGA XRES readback: 0x", bga_read(BGA_REG_XRES));
    video_log_hex("BGA YRES readback: 0x", bga_read(BGA_REG_YRES));
    video_log_hex("BGA BPP readback: 0x", bga_read(BGA_REG_BPP));
    return true;
}

static void video_hw_disable(void)
{
    bga_write(BGA_REG_ENABLE, 0x00);
}

static void video_clear_background(void)
{
    if (!framebuffer)
    {
        return;
    }
    uint16_t color = color_background ? color_background : make_color(0xFF, 0x80, 0x20);
    for (int y = 0; y < VIDEO_HEIGHT; ++y)
    {
        int offset = y * VIDEO_WIDTH;
        for (int x = 0; x < VIDEO_WIDTH; ++x)
        {
            framebuffer[offset + x] = color;
        }
    }
}

static void cursor_restore(void)
{
    if (!cursor_has_backup)
    {
        return;
    }
    for (int row = 0; row < CURSOR_H; ++row)
    {
        for (int col = 0; col < CURSOR_W; ++col)
        {
            int dst_x = cursor_backup_x + col;
            int dst_y = cursor_backup_y + row;
            if (dst_x < 0 || dst_x >= VIDEO_WIDTH || dst_y < 0 || dst_y >= VIDEO_HEIGHT)
            {
                continue;
            }
            framebuffer[dst_y * VIDEO_WIDTH + dst_x] = cursor_backup[row * CURSOR_W + col];
        }
    }
    cursor_has_backup = false;
}

static void cursor_draw(void)
{
    cursor_restore();

    if (cursor_x < 0)
    {
        cursor_x = 0;
    }
    if (cursor_y < 0)
    {
        cursor_y = 0;
    }
    if (cursor_x > VIDEO_WIDTH - CURSOR_W)
    {
        cursor_x = VIDEO_WIDTH - CURSOR_W;
    }
    if (cursor_y > VIDEO_HEIGHT - CURSOR_H)
    {
        cursor_y = VIDEO_HEIGHT - CURSOR_H;
    }

    cursor_backup_x = cursor_x;
    cursor_backup_y = cursor_y;

    for (int row = 0; row < CURSOR_H; ++row)
    {
        for (int col = 0; col < CURSOR_W; ++col)
        {
            int dst_x = cursor_x + col;
            int dst_y = cursor_y + row;
            if (dst_x < 0 || dst_x >= VIDEO_WIDTH || dst_y < 0 || dst_y >= VIDEO_HEIGHT)
            {
                cursor_backup[row * CURSOR_W + col] = 0;
                continue;
            }

            uint16_t *dest = (uint16_t *)&framebuffer[dst_y * VIDEO_WIDTH + dst_x];
            cursor_backup[row * CURSOR_W + col] = *dest;

            char pixel = cursor_shape[row][col];
            if (pixel == 'X')
            {
                *dest = cursor_color_primary();
            }
            else if (pixel == 'O')
            {
                *dest = cursor_color_shadow();
            }
        }
    }
    cursor_has_backup = true;
}

static void draw_rect(int x, int y, int width, int height, uint16_t color)
{
    if (!framebuffer || width <= 0 || height <= 0)
    {
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + width;
    int y1 = y + height;

    if (x1 <= 0 || y1 <= 0 || x0 >= VIDEO_WIDTH || y0 >= VIDEO_HEIGHT)
    {
        return;
    }

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > VIDEO_WIDTH) x1 = VIDEO_WIDTH;
    if (y1 > VIDEO_HEIGHT) y1 = VIDEO_HEIGHT;

    for (int row = y0; row < y1; ++row)
    {
        int offset = row * VIDEO_WIDTH + x0;
        for (int col = x0; col < x1; ++col)
        {
            framebuffer[offset++] = color;
        }
    }
}

static void draw_rect_outline(int x, int y, int width, int height, uint16_t color)
{
    if (!framebuffer || width <= 0 || height <= 0)
    {
        return;
    }

    draw_rect(x, y, width, 1, color);
    draw_rect(x, y + height - 1, width, 1, color);
    draw_rect(x, y, 1, height, color);
    draw_rect(x + width - 1, y, 1, height, color);
}

static void draw_char(int x, int y, char c, uint16_t fg, uint16_t bg)
{
    if (!framebuffer)
    {
        return;
    }

    unsigned char ch = (unsigned char)c;
    size_t glyph_offset = (size_t)ch * 32;
    if (glyph_offset + FONT_HEIGHT > VGA_FONT_BYTES)
    {
        return;
    }

    const uint8_t *glyph = &saved_font[glyph_offset];
    for (int row = 0; row < FONT_HEIGHT; ++row)
    {
        int dst_y = y + row;
        if (dst_y < 0 || dst_y >= VIDEO_HEIGHT)
        {
            continue;
        }
        uint8_t bits = glyph[row];
        int dst_x = x;
        for (int col = 0; col < FONT_WIDTH; ++col, ++dst_x)
        {
            if (dst_x < 0 || dst_x >= VIDEO_WIDTH)
            {
                continue;
            }
            uint16_t color = (bits & (0x80 >> col)) ? fg : bg;
            framebuffer[dst_y * VIDEO_WIDTH + dst_x] = color;
        }
    }
}

static void draw_text(int x, int y, const char *text, uint16_t fg, uint16_t bg)
{
    if (!text)
    {
        return;
    }
    for (size_t i = 0; text[i] != '\0'; ++i)
    {
        draw_char(x + (int)(i * FONT_WIDTH), y, text[i], fg, bg);
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

static void video_draw_scene(void)
{
    video_clear_background();
    windows_draw_all();
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

static void window_draw(const window_t *win)
{
    if (!win || !win->used)
    {
        return;
    }

    draw_rect(win->x - WINDOW_BORDER,
              win->y - WINDOW_BORDER,
              win->width + WINDOW_BORDER * 2,
              win->height + WINDOW_BORDER * 2,
              color_window_border);

    draw_rect(win->x,
              win->y,
              win->width,
              win->height,
              color_window_body);

    draw_rect(win->x,
              win->y,
              win->width,
              WINDOW_TITLE_HEIGHT,
              color_window_title);

    draw_rect(win->x,
              win->y + WINDOW_TITLE_HEIGHT - 1,
              win->width,
              1,
              color_window_border);

    draw_text(win->x + WINDOW_TITLE_PADDING_X,
              win->y + WINDOW_TITLE_TEXT_Y_OFFSET,
              win->title,
              color_window_title_text,
              color_window_title);

    draw_rect_outline(win->x,
                      win->y,
                      win->width,
                      win->height,
                      color_window_border);
}

static void window_create_at(int x, int y)
{
    if (window_count >= MAX_WINDOWS)
    {
        video_log("window_create_at: max windows reached");
        return;
    }

    window_t *win = &windows[window_count];
    win->used = true;
    win->width = 600;
    win->height = 400;
    win->x = x - win->width / 2;
    win->y = y - WINDOW_TITLE_HEIGHT / 2;
    format_window_title(win->title, sizeof(win->title), next_window_id++);

    window_ensure_inside(win);

    window_count++;
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
    }
    windows[window_count - 1] = temp;
    return window_count - 1;
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


bool video_enter_mode(void)
{
    if (!video_hw_enable())
    {
        video_log("video_hw_enable failed");
        return false;
    }
    video_mouse_log_count = 0;
    mouse_reset_debug_counter();
    video_log("video mode enabled, preparing scene");

    color_background = make_color(0xFF, 0x80, 0x20);
    color_window_border = make_color(0x20, 0x20, 0x20);
    color_window_title = make_color(0x30, 0x60, 0xA0);
    color_window_title_text = make_color(0xFF, 0xFF, 0xFF);
    color_window_body = make_color(0xF0, 0xF0, 0xF0);

    windows_reset();
    video_draw_scene();

    uint16_t sample = framebuffer ? framebuffer[(VIDEO_WIDTH * VIDEO_HEIGHT) / 2] : 0;
    video_log_hex("Sample pixel mid-screen: 0x", sample);
    cursor_x = VIDEO_WIDTH / 2;
    cursor_y = VIDEO_HEIGHT / 2;
    cursor_has_backup = false;
    last_left_down = false;
    last_click_tick = 0;
    exit_requested = false;
    video_active = true;
    logged_first_mouse = false;
    cursor_draw();
    video_log("cursor drawn, entering loop");
    return true;
}

void video_run_loop(void)
{
    video_log("video_run_loop start");
    while (video_active && !exit_requested)
    {
        mouse_poll();
        __asm__ volatile ("hlt");
        mouse_poll();
    }
    video_log("video_run_loop end");
}

void video_exit_mode(void)
{
    cursor_restore();
    video_hw_disable();
    vga_enter_text_mode();
    video_active = false;
    exit_requested = false;
    cursor_has_backup = false;
    video_log("video mode exited");
}

void video_on_mouse_event(int dx, int dy, bool left_pressed)
{
    if (!video_active)
    {
        if (dx != 0 || dy != 0 || left_pressed)
        {
            video_log("mouse event ignored (video inactive)");
        }
        return;
    }

    cursor_restore();

    cursor_x += dx;
    cursor_y += dy;

    if (cursor_x < 0) cursor_x = 0;
    if (cursor_y < 0) cursor_y = 0;
    if (cursor_x > VIDEO_WIDTH - 1) cursor_x = VIDEO_WIDTH - 1;
    if (cursor_y > VIDEO_HEIGHT - 1) cursor_y = VIDEO_HEIGHT - 1;

    bool needs_redraw = false;

    bool pressed_edge = left_pressed && !last_left_down;
    bool released_edge = !left_pressed && last_left_down;

    if (pressed_edge)
    {
        uint64_t now = timer_ticks();
        video_log("mouse click");
        if (last_click_tick != 0 && (now - last_click_tick) <= DOUBLE_CLICK_TICKS)
        {
            exit_requested = true;
            video_log("double click detected, exiting video");
        }
        last_click_tick = now;

        if (!exit_requested)
        {
            int title_index = window_title_hit_test(cursor_x, cursor_y);
            if (title_index >= 0)
            {
                int front_index = window_bring_to_front(title_index);
                dragging_window = front_index;
                drag_offset_x = cursor_x - windows[front_index].x;
                drag_offset_y = cursor_y - windows[front_index].y;
                needs_redraw = (front_index != title_index);
            }
            else
            {
                int body_index = window_hit_test(cursor_x, cursor_y);
                if (body_index >= 0)
                {
                    int front_index = window_bring_to_front(body_index);
                    dragging_window = -1;
                    needs_redraw = (front_index != body_index);
                }
                else
                {
                    window_create_at(cursor_x, cursor_y);
                    needs_redraw = true;
                }
            }
        }
    }
    else if (released_edge)
    {
        dragging_window = -1;
    }

    if (left_pressed && dragging_window >= 0 && dragging_window < window_count)
    {
        window_t *win = &windows[dragging_window];
        int new_x = cursor_x - drag_offset_x;
        int new_y = cursor_y - drag_offset_y;
        int old_x = win->x;
        int old_y = win->y;
        win->x = new_x;
        win->y = new_y;
        window_ensure_inside(win);
        if (win->x != old_x || win->y != old_y)
        {
            needs_redraw = true;
        }
    }

    if (needs_redraw)
    {
        video_draw_scene();
    }

    cursor_draw();

    if (!logged_first_mouse)
    {
        video_log("mouse movement detected in video");
        logged_first_mouse = true;
    }
    video_log_mouse_event(dx, dy, left_pressed);

    last_left_down = left_pressed;
}
static void video_log(const char *msg)
{
    serial_write_string(msg);
    serial_write_string("\r\n");
}

static void video_log_hex(const char *prefix, uint64_t value)
{
    static const char hex[] = "0123456789ABCDEF";
    char buf[17];
    buf[16] = '\0';
    for (int i = 15; i >= 0; --i)
    {
        buf[i] = hex[value & 0xF];
        value >>= 4;
    }
    serial_write_string(prefix);
    serial_write_string(buf);
    serial_write_string("\r\n");
}

static uint32_t pci_config_read(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset)
{
    uint32_t address = 0x80000000U
        | ((uint32_t)bus << 16)
        | ((uint32_t)device << 11)
        | ((uint32_t)function << 8)
        | (offset & 0xFC);
    outl(0xCF8, address);
    return inl(0xCFC);
}

static void detect_framebuffer(void)
{
    if (framebuffer_detected)
    {
        return;
    }
    framebuffer_detected = true;
    framebuffer_phys = 0x00000000E0000000ULL;

    for (uint8_t bus = 0; bus < 0x20; ++bus)
    {
        for (uint8_t device = 0; device < 32; ++device)
        {
            for (uint8_t function = 0; function < 8; ++function)
            {
                uint32_t id = pci_config_read(bus, device, function, 0x00);
                uint16_t vendor = (uint16_t)(id & 0xFFFF);
                if (vendor == 0xFFFF)
                {
                    if (function == 0)
                    {
                        break; /* no device */
                    }
                    continue;
                }
                uint16_t device_id = (uint16_t)((id >> 16) & 0xFFFF);
                if (vendor == 0x1234 && device_id == 0x1111)
                {
                    uint32_t bar0 = pci_config_read(bus, device, function, 0x10);
                    framebuffer_phys = (uint64_t)(bar0 & ~0xF);
                    video_log_hex("Detected BGA framebuffer BAR: 0x", framebuffer_phys);
                    return;
                }
            }
        }
    }

    video_log("BGA device not found on PCI bus; using default framebuffer address");
}

static void video_log_mouse_event(int dx, int dy, bool left_pressed)
{
    if (video_mouse_log_count >= 16)
    {
        return;
    }
    ++video_mouse_log_count;
    serial_write_string("mouse event dx=");
    serial_write_char((dx >= 0) ? '+' : '-');
    int abs_dx = dx >= 0 ? dx : -dx;
    serial_write_char('0' + (abs_dx / 10));
    serial_write_char('0' + (abs_dx % 10));
    serial_write_string(" dy=");
    serial_write_char((dy >= 0) ? '+' : '-');
    int abs_dy = dy >= 0 ? dy : -dy;
    serial_write_char('0' + (abs_dy / 10));
    serial_write_char('0' + (abs_dy % 10));
    serial_write_string(left_pressed ? " left=1\r\n" : " left=0\r\n");
}

static uint8_t vga_seq_read(uint8_t index)
{
    outb(0x3C4, index);
    return inb(0x3C5);
}

static void vga_seq_write(uint8_t index, uint8_t value)
{
    outb(0x3C4, index);
    outb(0x3C5, value);
}

static uint8_t vga_gc_read(uint8_t index)
{
    outb(0x3CE, index);
    return inb(0x3CF);
}

static void vga_gc_write(uint8_t index, uint8_t value)
{
    outb(0x3CE, index);
    outb(0x3CF, value);
}

static void vga_font_access_begin(vga_font_regs_t *state)
{
    if (!state)
    {
        return;
    }

    state->seq2 = vga_seq_read(0x02);
    state->seq4 = vga_seq_read(0x04);
    state->gc4 = vga_gc_read(0x04);
    state->gc5 = vga_gc_read(0x05);
    state->gc6 = vga_gc_read(0x06);

    vga_seq_write(0x00, 0x01);
    vga_seq_write(0x02, 0x04);
    vga_seq_write(0x04, 0x07);
    vga_seq_write(0x00, 0x03);

    vga_gc_write(0x04, 0x02);
    vga_gc_write(0x05, 0x00);
    vga_gc_write(0x06, 0x04);
}

static void vga_font_access_end(const vga_font_regs_t *state)
{
    if (!state)
    {
        return;
    }

    vga_seq_write(0x00, 0x01);
    vga_seq_write(0x02, state->seq2);
    vga_seq_write(0x04, state->seq4);
    vga_seq_write(0x00, 0x03);

    vga_gc_write(0x04, state->gc4);
    vga_gc_write(0x05, state->gc5);
    vga_gc_write(0x06, state->gc6);
}

static void vga_write_regs(const uint8_t *regs)
{
    outb(0x3C2, *regs++);

    for (uint8_t i = 0; i < 5; ++i)
    {
        outb(0x3C4, i);
        outb(0x3C5, regs[i]);
    }
    regs += 5;

    outb(0x3D4, 0x11);
    uint8_t unlock = inb(0x3D5);
    outb(0x3D4, 0x11);
    outb(0x3D5, unlock & ~0x80);

    for (uint8_t i = 0; i < 25; ++i)
    {
        outb(0x3D4, i);
        outb(0x3D5, regs[i]);
    }
    regs += 25;

    for (uint8_t i = 0; i < 9; ++i)
    {
        outb(0x3CE, i);
        outb(0x3CF, regs[i]);
    }
    regs += 9;

    for (uint8_t i = 0; i < 21; ++i)
    {
        (void)inb(0x3DA);
        outb(0x3C0, i);
        outb(0x3C0, regs[i]);
    }

    (void)inb(0x3DA);
    outb(0x3C0, 0x20);
}

static void vga_capture_state(void)
{
    if (vga_state_saved)
    {
        return;
    }
    uint8_t *ptr = saved_regs;
    *ptr++ = inb(0x3CC);

    for (uint8_t i = 0; i < 5; ++i)
    {
        outb(0x3C4, i);
        *ptr++ = inb(0x3C5);
    }

    outb(0x3D4, 0x11);
    uint8_t unlock = inb(0x3D5);
    outb(0x3D4, 0x11);
    outb(0x3D5, unlock & ~0x80);

    for (uint8_t i = 0; i < 25; ++i)
    {
        outb(0x3D4, i);
        *ptr++ = inb(0x3D5);
    }

    for (uint8_t i = 0; i < 9; ++i)
    {
        outb(0x3CE, i);
        *ptr++ = inb(0x3CF);
    }

    for (uint8_t i = 0; i < 21; ++i)
    {
        (void)inb(0x3DA);
        outb(0x3C0, i);
        *ptr++ = inb(0x3C1);
    }
    (void)inb(0x3DA);
    outb(0x3C0, 0x20);
    vga_state_saved = true;
    video_log("VGA state captured");
}

static bool vga_restore_state(void)
{
    if (!vga_state_saved)
    {
        video_log("VGA state not captured; cannot restore");
        return false;
    }
    vga_write_regs(saved_regs);
    video_log("VGA state restored");
    return true;
}

static void vga_capture_font(void)
{
    if (vga_font_saved)
    {
        return;
    }
    if (!vga_state_saved)
    {
        video_log("Cannot capture VGA font before state capture");
        return;
    }

    vga_font_regs_t regs;
    vga_font_access_begin(&regs);

    volatile uint8_t *font_mem = (volatile uint8_t *)(uintptr_t)0x00000000000A0000ULL;
    for (size_t i = 0; i < VGA_FONT_BYTES; ++i)
    {
        saved_font[i] = font_mem[i];
    }

    vga_font_access_end(&regs);

    vga_font_saved = true;
    video_log("VGA font captured");
}

static void vga_restore_font(void)
{
    if (!vga_font_saved)
    {
        video_log("Skipping VGA font restore (not captured)");
        return;
    }

    vga_font_regs_t regs;
    vga_font_access_begin(&regs);

    volatile uint8_t *font_mem = (volatile uint8_t *)(uintptr_t)0x00000000000A0000ULL;
    for (size_t i = 0; i < VGA_FONT_BYTES; ++i)
    {
        font_mem[i] = saved_font[i];
    }

    vga_font_access_end(&regs);
    video_log("VGA font restored");
}

static void vga_enter_text_mode(void)
{
    if (!vga_restore_state())
    {
        video_log("Falling back to BIOS text mode call");
        __asm__ volatile (
            "mov $0x0003, %%ax\n\t"
            "int $0x10\n\t"
            :
            :
            : "ax", "memory");
        return;
    }
    vga_restore_font();
}
