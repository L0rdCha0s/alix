#include "video.h"
#include "io.h"
#include "serial.h"
#include "mouse.h"
#include "atk.h"
#include "atk/atk_list.h"
#include "pci.h"
#include "keyboard.h"
#include "libc.h"
#include "font.h"
#include "console.h"

typedef struct atk_state atk_state_t;
typedef struct atk_widget atk_widget_t;

atk_state_t *atk_state_get(void);
void atk_window_draw(atk_state_t *state, atk_widget_t *window);
void atk_window_draw_from(atk_state_t *state, atk_widget_t *start_window);
void atk_window_mark_dirty(const atk_widget_t *window);
bool atk_window_contains(const atk_state_t *state, const atk_widget_t *window);
bool atk_window_is_topmost(const atk_state_t *state, const atk_widget_t *window);
typedef struct atk_state atk_state_t;
typedef struct atk_widget atk_widget_t;

atk_state_t *atk_state_get(void);
void atk_window_draw(atk_state_t *state, atk_widget_t *window);
void atk_window_mark_dirty(const atk_widget_t *window);

static inline uint64_t video_irq_save(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    __asm__ volatile ("cli" ::: "memory");
    return flags;
}

static inline void video_irq_restore(uint64_t flags)
{
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc");
}

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

#define VIDEO_BPP    16

#define CURSOR_W 16
#define CURSOR_H 16
#define FONT_WIDTH 8
#define FONT_HEIGHT 16

#define VGA_FONT_BYTES 8192
#define VIDEO_FONT_CHAR_COUNT 256
#define VIDEO_FONT_BYTES      (VIDEO_FONT_CHAR_COUNT * FONT_HEIGHT)

#define BACKBUFFER_ADDR 0x0000000000E00000ULL  /* 14 MiB: above kernel stack, below VFS pool */
static uint16_t *backbuffer = (uint16_t *)(uintptr_t)BACKBUFFER_ADDR;

static volatile uint16_t *framebuffer = 0;
static uint64_t framebuffer_phys = 0;
static bool framebuffer_detected = false;

static bool vga_state_saved = false;
static uint8_t saved_regs[1 + 5 + 25 + 9 + 21];

static bool vga_font_saved = false;
static uint8_t saved_font[VGA_FONT_BYTES];
static uint8_t video_font[VIDEO_FONT_BYTES];

static bool video_active = false;
static bool exit_requested = false;
static int cursor_x = 0;
static int cursor_y = 0;
static int prev_cursor_x = 0;
static int prev_cursor_y = 0;
static bool last_left_down = false;
static bool logged_first_mouse = false;

static int video_mouse_log_count = 0;
#define VIDEO_MOUSE_LOG 0

static volatile bool refresh_requested = false;
static bool refresh_requested_full = false;
static atk_widget_t *refresh_window = NULL;

typedef struct
{
    uint8_t seq2;
    uint8_t seq4;
    uint8_t gc4;
    uint8_t gc5;
    uint8_t gc6;
} vga_font_regs_t;

/* --------- MSR / MTRR helpers (write-combining for LFB) --------- */
static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}
static inline void wrmsr(uint32_t msr, uint64_t v)
{
    uint32_t lo = (uint32_t)v, hi = (uint32_t)(v >> 32);
    __asm__ volatile ("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

#define IA32_MTRR_DEF_TYPE   0x2FF
#define IA32_MTRR_PHYSBASE0  0x200
#define IA32_MTRR_PHYSMASK0  0x201
#define MTRR_TYPE_WC         0x01
#define MTRR_DEF_ENABLE      (1ULL<<11)
#define MTRR_VALID           (1ULL<<11)

/* Align/size must be power of two; aperture is typically 16 MiB for Bochs/QEMU BGA. */
static void video_enable_wc(uint64_t phys, uint64_t size)
{
    uint64_t def = rdmsr(IA32_MTRR_DEF_TYPE);

    /* disable MTRRs while programming */
    wrmsr(IA32_MTRR_DEF_TYPE, def & ~MTRR_DEF_ENABLE);

    /* PhysBase: low 8 bits type, address in bits 12.. */
    wrmsr(IA32_MTRR_PHYSBASE0, (phys & 0xFFFFFF000ULL) | MTRR_TYPE_WC);
    /* PhysMask: valid bit + address mask in bits 12.. */
    wrmsr(IA32_MTRR_PHYSMASK0, ((~(size - 1)) & 0xFFFFFF000ULL) | MTRR_VALID);

    /* re-enable */
    wrmsr(IA32_MTRR_DEF_TYPE, def | MTRR_DEF_ENABLE);
    __asm__ volatile ("wbinvd"); /* be conservative */
}

/* --------- Prototypes --------- */
static void video_log(const char *msg);
static void video_log_hex(const char *prefix, uint64_t value);
static void detect_framebuffer(void);
static void video_log_mouse_event(int dx, int dy, bool left_pressed);
static void video_poll_keyboard(void);
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
static void video_dirty_reset(void);
static void video_flush_dirty(void);
static void video_perform_refresh(void);
static void cursor_draw_overlay(void);
static void cursor_restore_background(void);
static void video_prepare_font(void);
static void video_draw_char(int x, int y, char c, uint16_t fg, uint16_t bg);
static void video_blit_clipped(int dst_x0, int dst_y0, int copy_w, int copy_h,
                               const uint8_t *src, int stride_bytes, int src_x0, int src_y0);

/* --------- Cursor shape --------- */
static const char *const cursor_shape_arrow[CURSOR_H] = {
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

static const char *const cursor_shape_resize_h[CURSOR_H] = {
    "................",
    "................",
    "..X..........X..",
    "..XX........XX..",
    "..XOX......XOX..",
    "..XOOX....XOOX..",
    "..XOOOX..XOOOX..",
    "..XOOOX..XOOOX..",
    "..XOOX....XOOX..",
    "..XOX......XOX..",
    "..XX........XX..",
    "..X..........X..",
    "................",
    "................",
    "................",
    "................"
};

static const char *const cursor_shape_resize_v[CURSOR_H] = {
    ".......XX.......",
    "......XOOX......",
    ".....XOOOOX.....",
    "....XOOOOOOX....",
    "...XOOOOOOOOX...",
    "..XOOOOOOOOOOX..",
    ".XOOOOOOOOOOOOX.",
    "..XOOOOOOOOOOX..",
    "...XOOOOOOOOX...",
    "....XOOOOOOX....",
    ".....XOOOOX.....",
    "......XOOX......",
    ".......XX.......",
    ".......XX.......",
    ".......XX.......",
    ".......XX......."
};

static const char *const cursor_shape_resize_ne_sw[CURSOR_H] = {
    "..............X.",
    ".............XOX",
    "............XOOX",
    "...........XOOX.",
    "..........XOOX..",
    ".........XOOX...",
    "........XOOX....",
    ".......XOOX.....",
    "......XOOX......",
    ".....XOOX.......",
    "....XOOX........",
    "...XOOX.........",
    "..XOOX..........",
    ".XOOX...........",
    "XOX.............",
    ".X.............."
};

static const char *const cursor_shape_resize_nw_se[CURSOR_H] = {
    ".X..............",
    "XOX.............",
    ".XOOX...........",
    "..XOOX..........",
    "...XOOX.........",
    "....XOOX........",
    ".....XOOX.......",
    "......XOOX......",
    ".......XOOX.....",
    "........XOOX....",
    ".........XOOX...",
    "..........XOOX..",
    "...........XOOX.",
    "............XOOX",
    ".............XOX",
    "..............X."
};

static const char *const *cursor_shape_active = cursor_shape_arrow;
static video_cursor_shape_t cursor_shape_kind = VIDEO_CURSOR_ARROW;

static uint16_t cursor_color_primary(void)
{
    return (uint16_t)(((0xFF & 0xF8) << 8) | ((0xFF & 0xFC) << 3) | (0xFF >> 3));
}
static uint16_t cursor_color_shadow(void)
{
    uint8_t r = 0x40, g = 0x40, b = 0x40;
    return (uint16_t)(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

uint16_t video_make_color(uint8_t r, uint8_t g, uint8_t b)
{
    return (uint16_t)(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

/* --------- BGA helpers --------- */
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

/* --------- Public API --------- */
void video_init(void)
{
    vga_capture_state();
    vga_capture_font();
    video_prepare_font();
    atk_init();
}

static bool video_hw_enable(void)
{
    detect_framebuffer();
    if (framebuffer_phys == 0)
    {
        video_log("framebuffer phys is zero");
        return false;
    }

    /* Enable write-combining over the LFB aperture (16 MiB typical) */
    video_enable_wc(framebuffer_phys, 16ULL * 1024 * 1024ULL);

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

void video_fill(uint16_t color)
{
    //video_log_hex("fill color=", color);
    //video_log_hex("fill backbuffer=", (uint64_t)(uintptr_t)backbuffer);
    for (int y = 0; y < VIDEO_HEIGHT; ++y)
    {
        uint16_t *row = &backbuffer[y * VIDEO_WIDTH];
        for (int x = 0; x < VIDEO_WIDTH; ++x)
        {
            row[x] = color;
        }
    }
}

/* Draw cursor only to the LFB (overlay), no readbacks */
static void cursor_draw_overlay(void)
{
    /* clamp */
    if (cursor_x < 0) cursor_x = 0;
    if (cursor_y < 0) cursor_y = 0;
    if (cursor_x > VIDEO_WIDTH  - CURSOR_W)  cursor_x = VIDEO_WIDTH  - CURSOR_W;
    if (cursor_y > VIDEO_HEIGHT - CURSOR_H)  cursor_y = VIDEO_HEIGHT - CURSOR_H;

    for (int row = 0; row < CURSOR_H; ++row)
    {
        int dst_y = cursor_y + row;
        if ((unsigned)dst_y >= VIDEO_HEIGHT) continue;

        for (int col = 0; col < CURSOR_W; ++col)
        {
            int dst_x = cursor_x + col;
            if ((unsigned)dst_x >= VIDEO_WIDTH) continue;

            const char *shape_row = cursor_shape_active ? cursor_shape_active[row] : cursor_shape_arrow[row];
            char pixel = shape_row[col];
            if (pixel == '.') continue; /* leave background as last flushed */

            uint16_t *p = (uint16_t *)&framebuffer[dst_y * VIDEO_WIDTH + dst_x];
            *p = (pixel == 'X') ? cursor_color_primary() : cursor_color_shadow();
        }
    }

    prev_cursor_x = cursor_x;
    prev_cursor_y = cursor_y;
}

static void cursor_restore_background(void)
{
    if (!framebuffer)
    {
        return;
    }

    int x0 = prev_cursor_x;
    int y0 = prev_cursor_y;
    for (int row = 0; row < CURSOR_H; ++row)
    {
        int dst_y = y0 + row;
        if ((unsigned)dst_y >= VIDEO_HEIGHT)
        {
            continue;
        }

        for (int col = 0; col < CURSOR_W; ++col)
        {
            int dst_x = x0 + col;
            if ((unsigned)dst_x >= VIDEO_WIDTH)
            {
                continue;
            }

            size_t index = (size_t)dst_y * VIDEO_WIDTH + dst_x;
            framebuffer[index] = backbuffer[index];
        }
    }
}

/* --------- Text & blits to backbuffer --------- */
static void video_prepare_font(void)
{
    uint8_t rows[FONT_HEIGHT];
    for (int ch = 0; ch < VIDEO_FONT_CHAR_COUNT; ++ch)
    {
        font_basic_copy_glyph8x16((uint8_t)ch, rows);
        size_t offset = (size_t)ch * FONT_HEIGHT;
        memcpy(&video_font[offset], rows, FONT_HEIGHT);
    }
}

static void video_draw_char(int x, int y, char c, uint16_t fg, uint16_t bg)
{
    unsigned char ch = (unsigned char)c;
    size_t glyph_offset = (size_t)ch * FONT_HEIGHT;
    if (glyph_offset + FONT_HEIGHT > VIDEO_FONT_BYTES)
    {
        return;
    }

    const uint8_t *glyph = &video_font[glyph_offset];
    for (int row = 0; row < FONT_HEIGHT; ++row)
    {
        int dst_y = y + row;
        if ((unsigned)dst_y >= VIDEO_HEIGHT) continue;

        uint8_t bits = glyph[row];
        int dst_x = x;
        for (int col = 0; col < FONT_WIDTH; ++col, ++dst_x)
        {
            if ((unsigned)dst_x >= VIDEO_WIDTH) continue;
            uint16_t color = (bits & (0x80 >> col)) ? fg : bg;
            backbuffer[dst_y * VIDEO_WIDTH + dst_x] = color;
        }
    }
}

void video_draw_text(int x, int y, const char *text, uint16_t fg, uint16_t bg)
{
    if (!text) return;
    for (size_t i = 0; text[i] != '\0'; ++i)
    {
        video_draw_char(x + (int)(i * FONT_WIDTH), y, text[i], fg, bg);
    }
}

void video_draw_text_clipped(int x, int y, int width, int height,
                             const char *text, uint16_t fg, uint16_t bg)
{
    if (!text || width <= 0 || height <= 0) return;

    int max_chars_per_line = width / FONT_WIDTH;
    if (max_chars_per_line <= 0) return;

    int line_height = FONT_HEIGHT + 2;
    int max_lines = height / line_height;
    if (max_lines <= 0) return;

    const char *cursor = text;
    int drawn_lines = 0;
    char buffer[512];
    int buffer_limit = (int)sizeof(buffer) - 1;

    while (drawn_lines < max_lines && *cursor != '\0')
    {
        int chars_in_line = 0;
        const char *line_start = cursor;

        while (*cursor != '\0' && *cursor != '\n' && chars_in_line < max_chars_per_line)
        {
            ++cursor;
            ++chars_in_line;
        }

        int copy_len = chars_in_line;
        if (copy_len > buffer_limit) copy_len = buffer_limit;

        for (int i = 0; i < copy_len; ++i) buffer[i] = line_start[i];
        buffer[copy_len] = '\0';

        video_draw_text(x, y + drawn_lines * line_height, buffer, fg, bg);
        ++drawn_lines;

        if (copy_len < chars_in_line)
        {
            cursor = line_start + copy_len;
            continue;
        }
        if (*cursor == '\n') ++cursor;
    }
}

static void video_blit_clipped(int dst_x0, int dst_y0, int copy_w, int copy_h,
                               const uint8_t *src, int stride_bytes, int src_x0, int src_y0)
{
    const uint8_t *row_ptr = src + (size_t)src_y0 * (size_t)stride_bytes + (size_t)src_x0 * 2U;
    for (int row = 0; row < copy_h; ++row)
    {
        uint16_t *dst = &backbuffer[(dst_y0 + row) * VIDEO_WIDTH + dst_x0];
        memcpy(dst, row_ptr, (size_t)copy_w * 2U);
        row_ptr += stride_bytes;
    }
}

void video_blit_rgb565(int x, int y, int width, int height, const uint16_t *pixels, int stride_bytes)
{

    if (!pixels || width <= 0 || height <= 0) return;
    if (stride_bytes <= 0) stride_bytes = width * 2;

    int x0 = x, y0 = y;
    int x1 = x + width, y1 = y + height;
    int src_x = 0, src_y = 0;

    if (x0 < 0) { src_x = -x0; x0 = 0; }
    if (y0 < 0) { src_y = -y0; y0 = 0; }
    if (x1 > VIDEO_WIDTH)  x1 = VIDEO_WIDTH;
    if (y1 > VIDEO_HEIGHT) y1 = VIDEO_HEIGHT;

    int copy_w = x1 - x0;
    int copy_h = y1 - y0;
    if (copy_w <= 0 || copy_h <= 0) return;

    int max_copy_w = width  - src_x;
    int max_copy_h = height - src_y;
    if (copy_w > max_copy_w) copy_w = max_copy_w;
    if (copy_h > max_copy_h) copy_h = max_copy_h;
    if (copy_w <= 0 || copy_h <= 0) return;

    video_blit_clipped(x0, y0, copy_w, copy_h, (const uint8_t *)pixels, stride_bytes, src_x, src_y);
    video_invalidate_rect(x0, y0, copy_w, copy_h);
}

/* --------- Dirty tracking & flush --------- */
static bool dirty_active = false;
static int dirty_x0 = 0, dirty_y0 = 0, dirty_x1 = 0, dirty_y1 = 0;

static void video_dirty_reset(void)
{
    dirty_active = false;
    dirty_x0 = dirty_y0 = 0;
    dirty_x1 = dirty_y1 = 0;
}

void video_invalidate_rect(int x, int y, int width, int height)
{
    //video_log_hex("invalidate x=", (uint64_t)x);
    //video_log_hex("invalidate y=", (uint64_t)y);
    //video_log_hex("invalidate w=", (uint64_t)width);
    //video_log_hex("invalidate h=", (uint64_t)height);
    int x0 = x, y0 = y, x1 = x + width, y1 = y + height;

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > VIDEO_WIDTH)  x1 = VIDEO_WIDTH;
    if (y1 > VIDEO_HEIGHT) y1 = VIDEO_HEIGHT;

    if (x0 >= x1 || y0 >= y1) return;

    if (!dirty_active)
    {
        dirty_active = true;
        dirty_x0 = x0; dirty_y0 = y0;
        dirty_x1 = x1; dirty_y1 = y1;
        return;
    }
    if (x0 < dirty_x0) dirty_x0 = x0;
    if (y0 < dirty_y0) dirty_y0 = y0;
    if (x1 > dirty_x1) dirty_x1 = x1;
    if (y1 > dirty_y1) dirty_y1 = y1;
}

void video_invalidate_all(void)
{
    video_invalidate_rect(0, 0, VIDEO_WIDTH, VIDEO_HEIGHT);
}

/* Copy with wide stores; helps WC coalesce */
static inline void fb_memcpy_wc(volatile void *dst_mmio, const void *src, size_t bytes)
{
    const uint8_t *s = (const uint8_t *)src;
    volatile uint8_t *d = (volatile uint8_t *)dst_mmio;

    size_t i = 0;
    /* align to 8 */
    for (; ((uintptr_t)(d + i) & 7) && i < bytes; ++i) d[i] = s[i];
    for (; i + 8 <= bytes; i += 8)
    {
        *(volatile uint64_t *)(d + i) = *(const uint64_t *)(s + i);
    }
    for (; i < bytes; ++i) d[i] = s[i];
}

static void video_flush_dirty(void)
{
    if (!dirty_active || !framebuffer) return;

    int w = dirty_x1 - dirty_x0;
    size_t row_bytes = (size_t)w * 2U;
#ifdef ENABLE_MEM_DEBUG_LOGS
    video_log_hex("flush x0=", dirty_x0);
    video_log_hex("flush y0=", dirty_y0);
    video_log_hex("flush x1=", dirty_x1);
    video_log_hex("flush y1=", dirty_y1);
    video_log_hex("flush bytes=", row_bytes);
#endif

    for (int y = dirty_y0; y < dirty_y1; ++y)
    {
        volatile uint16_t *dst = &framebuffer[y * VIDEO_WIDTH + dirty_x0];
        uint16_t *src = &backbuffer[y * VIDEO_WIDTH + dirty_x0];
#ifdef ENABLE_MEM_DEBUG_LOGS
        video_log_hex("flush dst=", (uint64_t)(uintptr_t)dst);
        video_log_hex("flush src=", (uint64_t)(uintptr_t)src);
#endif
        fb_memcpy_wc((void *)dst, src, row_bytes);
    }

    video_dirty_reset();
}

static void video_perform_refresh(void)
{
    uint64_t irq_state = video_irq_save();

    if (!video_active)
    {
        goto out;
    }

    if (dirty_active)
    {
        video_flush_dirty();
    }

    atk_state_t *state = atk_state_get();

    if (refresh_window)
    {
        atk_widget_t *target = refresh_window;
        refresh_window = NULL;

        if (target)
        {
            video_dirty_reset();
            atk_window_draw_from(state, target);
            if (dirty_active)
            {
                video_flush_dirty();
            }
            cursor_draw_overlay();
            refresh_requested = refresh_requested_full || (refresh_window != NULL);
            goto out;
        }

        refresh_requested_full = true;
    }

    if (refresh_requested_full)
    {
        refresh_requested_full = false;
        video_dirty_reset();
        atk_render();
        if (dirty_active)
        {
            video_flush_dirty();
        }
        cursor_draw_overlay();
    }

    refresh_requested = refresh_requested_full || (refresh_window != NULL);

out:
    video_irq_restore(irq_state);
}

void video_cursor_set_shape(video_cursor_shape_t shape)
{
    if (shape == cursor_shape_kind)
    {
        return;
    }

    cursor_shape_kind = shape;
    switch (shape)
    {
        case VIDEO_CURSOR_RESIZE_H:
            cursor_shape_active = cursor_shape_resize_h;
            break;
        case VIDEO_CURSOR_RESIZE_V:
            cursor_shape_active = cursor_shape_resize_v;
            break;
        case VIDEO_CURSOR_RESIZE_DIAG_NE_SW:
            cursor_shape_active = cursor_shape_resize_ne_sw;
            break;
        case VIDEO_CURSOR_RESIZE_DIAG_NW_SE:
            cursor_shape_active = cursor_shape_resize_nw_se;
            break;
        case VIDEO_CURSOR_ARROW:
        default:
            cursor_shape_active = cursor_shape_arrow;
            cursor_shape_kind = VIDEO_CURSOR_ARROW;
            break;
    }
}

/* --------- Mode entry/exit & loop --------- */
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
    console_set_vga_enabled(false);

    video_dirty_reset();
    atk_enter_mode();
    atk_render();
    video_flush_dirty();

    uint16_t sample = backbuffer[(VIDEO_WIDTH * VIDEO_HEIGHT) / 2];
    video_log_hex("Sample pixel mid-screen: 0x", sample);

    cursor_x = VIDEO_WIDTH / 2;
    cursor_y = VIDEO_HEIGHT / 2;
    prev_cursor_x = cursor_x;
    prev_cursor_y = cursor_y;
    last_left_down = false;
    exit_requested = false;
    video_active = true;
    logged_first_mouse = false;

    cursor_draw_overlay();
    video_log("cursor drawn, entering loop");
    return true;
}

void video_run_loop(void)
{
    video_log("video_run_loop start");
    while (video_active && !exit_requested)
    {
        mouse_poll();
        video_poll_keyboard();
        if (refresh_requested)
        {
            refresh_requested = false;
            video_perform_refresh();
        }
        __asm__ volatile ("hlt");
    }
    video_log("video_run_loop end");
}

void video_pump_events(void)
{
    if (!video_active)
    {
        return;
    }

    mouse_poll();
    video_poll_keyboard();
    if (refresh_requested)
    {
        refresh_requested = false;
        video_perform_refresh();
    }
}

void video_request_refresh(void)
{
    if (!video_active)
    {
        return;
    }
    refresh_requested_full = true;
    refresh_requested = true;
}

void video_request_refresh_window(atk_widget_t *window)
{
    if (!video_active || !window)
    {
        return;
    }
    atk_state_t *state = atk_state_get();
    if (!state || !atk_window_contains(state, window))
    {
        refresh_requested_full = true;
        refresh_requested = true;
        return;
    }

    if (!atk_window_is_topmost(state, window))
    {
        refresh_requested_full = true;
        refresh_requested = true;
        return;
    }

    refresh_window = window;
    refresh_requested = true;
}

void video_exit_mode(void)
{
    video_hw_disable();
    console_set_vga_enabled(true);
    vga_enter_text_mode();
    video_active = false;
    exit_requested = false;
    video_dirty_reset();
    video_log("video mode exited");
}

/* --------- Input paths --------- */
static void video_poll_keyboard(void)
{
    if (!video_active) return;

    char ch = 0;
    bool have_input = false;
    bool redraw_needed = false;

    while (keyboard_try_read(&ch))
    {
        have_input = true;
        atk_key_event_result_t result = atk_handle_key_char(ch);
        if (result.redraw) redraw_needed = true;
        if (result.exit_video) exit_requested = true;
    }

    if (!have_input || !redraw_needed) return;

    video_request_refresh();
    video_perform_refresh();
}

void video_on_mouse_event(int dx, int dy, bool left_pressed)
{
    uint64_t irq_state = video_irq_save();

    if (!video_active)
    {
        /* Do not log inside IRQ handlers; serial output here has triggered faults. */
        goto out;
    }

    if (refresh_window)
    {
        refresh_requested_full = true;
        refresh_window = NULL;
        refresh_requested = true;
    }

    /* restore previous cursor region before drawing new one */
    cursor_restore_background();

    /* update cursor */
    cursor_x += dx;
    cursor_y += dy;
    if (cursor_x < 0) cursor_x = 0;
    if (cursor_y < 0) cursor_y = 0;
    if (cursor_x > VIDEO_WIDTH - 1) cursor_x = VIDEO_WIDTH - 1;
    if (cursor_y > VIDEO_HEIGHT - 1) cursor_y = VIDEO_HEIGHT - 1;

    bool pressed_edge  = (left_pressed && !last_left_down);
    bool released_edge = (!left_pressed && last_left_down);

    atk_mouse_event_result_t result = atk_handle_mouse_event(cursor_x, cursor_y, pressed_edge, released_edge, left_pressed);

    if (result.redraw)
    {
        /* let renderer choose dirties; do not pre-clear here */
        atk_render();
    }

    if (dirty_active && !refresh_requested)
    {
        video_flush_dirty();
    }

    if (refresh_requested)
    {
        video_perform_refresh();
        goto out;
    }

    cursor_draw_overlay();

    /* Mouse IRQ logging disabled; avoid serial I/O in interrupt context. */

    if (result.exit_video)
    {
        exit_requested = true;
    }

    last_left_down = left_pressed;

out:
    video_irq_restore(irq_state);
}

/* --------- Logging & detection --------- */
static void video_log(const char *msg)
{
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
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
    serial_printf("%s", prefix);
    serial_printf("%s", buf);
    serial_printf("%s", "\r\n");
}

static void detect_framebuffer(void)
{
    if (framebuffer_detected)
    {
        return;
    }
    framebuffer_detected = true;
    framebuffer_phys = 0x00000000E0000000ULL;

    pci_device_t bga_device;
    if (pci_find_device(0x1234, 0x1111, &bga_device))
    {
        uint32_t bar0 = pci_config_read32(bga_device, 0x10);
        framebuffer_phys = (uint64_t)(bar0 & ~0xFU);
        video_log_hex("Detected BGA framebuffer BAR: 0x", framebuffer_phys);
        return;
    }

    video_log("BGA device not found on PCI bus; using default framebuffer address");
}

static void video_log_mouse_event(int dx, int dy, bool left_pressed)
{
#if VIDEO_MOUSE_LOG
    if (video_mouse_log_count >= 16) return;
    ++video_mouse_log_count;
    serial_printf("%s", "mouse event dx=");
    serial_printf("%c", (dx >= 0) ? '+' : '-');
    int abs_dx = dx >= 0 ? dx : -dx;
    serial_printf("%c", '0' + (abs_dx / 10));
    serial_printf("%c", '0' + (abs_dx % 10));
    serial_printf("%s", " dy=");
    serial_printf("%c", (dy >= 0) ? '+' : '-');
    int abs_dy = dy >= 0 ? dy : -dy;
    serial_printf("%c", '0' + (abs_dy / 10));
    serial_printf("%c", '0' + (abs_dy % 10));
    serial_printf("%s", left_pressed ? " left=1\r\n" : " left=0\r\n");
#else
    (void)dx; (void)dy; (void)left_pressed;
#endif
}

/* --------- VGA state/font save/restore --------- */
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
    if (!state) return;

    state->seq2 = vga_seq_read(0x02);
    state->seq4 = vga_seq_read(0x04);
    state->gc4  = vga_gc_read(0x04);
    state->gc5  = vga_gc_read(0x05);
    state->gc6  = vga_gc_read(0x06);

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
    if (!state) return;

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
    if (vga_state_saved) return;

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
    if (vga_font_saved) return;
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
        video_log("Unable to restore VGA state (UEFI build has no BIOS fallback)");
        return;
    }
    vga_restore_font();
}

void video_draw_rect(int x, int y, int width, int height, uint16_t color)
{
    if (width <= 0 || height <= 0) return;

    int x0 = x, y0 = y;
    int x1 = x + width, y1 = y + height;

    // trivial reject
    if (x1 <= 0 || y1 <= 0 || x0 >= VIDEO_WIDTH || y0 >= VIDEO_HEIGHT) return;

    // clip to screen
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > VIDEO_WIDTH)  x1 = VIDEO_WIDTH;
    if (y1 > VIDEO_HEIGHT) y1 = VIDEO_HEIGHT;

    for (int row = y0; row < y1; ++row)
    {
        uint16_t *dst = &backbuffer[row * VIDEO_WIDTH + x0];
        for (int col = x0; col < x1; ++col)
        {
            *dst++ = color;
        }
    }

    // NOTE: No video_invalidate_rect() here — callers mark dirty as needed.
}

void video_draw_rect_outline(int x, int y, int width, int height, uint16_t color)
{
    if (width <= 0 || height <= 0) return;

    // top & bottom
    video_draw_rect(x, y, width, 1, color);
    video_draw_rect(x, y + height - 1, width, 1, color);

    // left & right
    video_draw_rect(x, y, 1, height, color);
    video_draw_rect(x + width - 1, y, 1, height, color);
}

bool video_is_active(void)
{
    return video_active;
}
#include "atk/atk_label.h" /* for forward decls? maybe not needed but safe? */
