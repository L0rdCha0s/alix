#include "console.h"
#include "bootinfo.h"
#include "io.h"
#include "libc.h"
#include "font.h"

#define VGA_REG_COUNT_MISC 1
#define VGA_COLUMNS 80
#define VGA_ROWS    25
#define VGA_MEMORY  ((volatile uint16_t *)0x00000000000B8000ULL)
#define VGA_COLOR   0x0F
#define GLYPH_WIDTH  8
#define GLYPH_HEIGHT 8

static size_t cursor_row = 0;
static size_t cursor_col = 0;
static char console_chars[VGA_ROWS][VGA_COLUMNS];
static bool fb_console_enabled = false;
static uint32_t fb_width = 0;
static uint32_t fb_height = 0;
static uint32_t fb_pitch = 0;
static uint32_t fb_cell_w = GLYPH_WIDTH;
static uint32_t fb_cell_h = GLYPH_HEIGHT;
static volatile uint32_t *fb_ptr = NULL;
static void fb_draw_cell(size_t row, size_t col);
static void fb_redraw_all(void);
static void fb_init_from_bootinfo(void);

static void vga_write_regs(const uint8_t *regs)
{
    uint8_t misc = *regs++;
    outb(0x3C2, misc);

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

static void console_force_text_mode(const uint8_t *regs)
{
    if (regs)
    {
        vga_write_regs(regs);
    }
}

static void console_update_cursor(void)
{
    uint16_t pos = (uint16_t)(cursor_row * VGA_COLUMNS + cursor_col);
    outb(0x3D4, 0x0F);
    outb(0x3D5, (uint8_t)(pos & 0xFF));
    outb(0x3D4, 0x0E);
    outb(0x3D5, (uint8_t)(pos >> 8));
}

static void console_scroll(void)
{
    const size_t line_bytes = VGA_COLUMNS * sizeof(uint16_t);
    memmove((void *)VGA_MEMORY,
            (const void *)(VGA_MEMORY + VGA_COLUMNS),
            line_bytes * (VGA_ROWS - 1));
    uint16_t *last_line = (uint16_t *)(VGA_MEMORY + VGA_COLUMNS * (VGA_ROWS - 1));
    for (size_t col = 0; col < VGA_COLUMNS; ++col)
    {
        last_line[col] = ((uint16_t)VGA_COLOR << 8) | ' ';
    }
    cursor_row = VGA_ROWS - 1;

    memmove(console_chars,
            console_chars + 1,
            sizeof(console_chars[0]) * (VGA_ROWS - 1));
    memset(console_chars[VGA_ROWS - 1], ' ', VGA_COLUMNS);
    fb_redraw_all();
}

void console_init(void)
{
    memset(console_chars, ' ', sizeof(console_chars));
    static const uint8_t text_mode_80x25[] = {
        /* MISC */
        0x67,
        /* SEQ */
        0x03, 0x01, 0x0F, 0x00, 0x06,
        /* CRTC */
        0x5F, 0x4F, 0x50, 0x82, 0x55, 0x81, 0xBF, 0x1F,
        0x00, 0x4F, 0x0D, 0x0E, 0x00, 0x0B, 0x0C, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x9C, 0x0E, 0x8F, 0x28, 0x1F,
        /* GC */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0E, 0x00, 0xFF,
        /* AC */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x0C, 0x00, 0x0F, 0x08, 0x00
    };
    console_force_text_mode(text_mode_80x25);
    cursor_row = cursor_col = 0;
    console_update_cursor();
    fb_init_from_bootinfo();
    fb_redraw_all();
}

void console_clear(void)
{
    uint16_t blank = ((uint16_t)VGA_COLOR << 8) | ' ';
    volatile uint16_t *ptr = VGA_MEMORY;
    for (size_t i = 0; i < VGA_COLUMNS * VGA_ROWS; ++i)
    {
        ptr[i] = blank;
    }
    cursor_row = 0;
    cursor_col = 0;
    console_update_cursor();
    memset(console_chars, ' ', sizeof(console_chars));
    fb_redraw_all();
}

static void console_newline(void)
{
    cursor_col = 0;
    if (++cursor_row >= VGA_ROWS)
    {
        console_scroll();
    }
    console_update_cursor();
}

void console_putc(char c)
{
    if (c == '\n')
    {
        console_newline();
        return;
    }
    if (c == '\r')
    {
        cursor_col = 0;
        console_update_cursor();
        return;
    }
    if (c == '\t')
    {
        size_t next_tab = (cursor_col + 8) & ~(size_t)7;
        while (cursor_col < next_tab)
        {
            console_putc(' ');
        }
        return;
    }

    if (cursor_col >= VGA_COLUMNS)
    {
        console_newline();
    }

    size_t row = cursor_row;
    size_t col = cursor_col;
    volatile uint16_t *cell = VGA_MEMORY + row * VGA_COLUMNS + col;
    *cell = ((uint16_t)VGA_COLOR << 8) | (uint8_t)c;
    console_chars[row][col] = c;
    fb_draw_cell(row, col);
    cursor_col++;

    if (cursor_col >= VGA_COLUMNS)
    {
        console_newline();
    }
    else
    {
        console_update_cursor();
    }
}

void console_write(const char *s)
{
    size_t len = strlen(s);
    for (size_t i = 0; i < len; ++i)
    {
        console_putc(s[i]);
    }
}

void console_backspace(void)
{
    if (cursor_col == 0)
    {
        if (cursor_row == 0)
        {
            return;
        }
        cursor_row--;
        cursor_col = VGA_COLUMNS - 1;
    }
    else
    {
        cursor_col--;
    }

    volatile uint16_t *cell = VGA_MEMORY + cursor_row * VGA_COLUMNS + cursor_col;
    *cell = ((uint16_t)VGA_COLOR << 8) | ' ';
    console_update_cursor();
    console_chars[cursor_row][cursor_col] = ' ';
    fb_draw_cell(cursor_row, cursor_col);
}

static void fb_init_from_bootinfo(void)
{
    fb_console_enabled = false;
    fb_ptr = NULL;
    if (!boot_info.framebuffer_enabled)
    {
        return;
    }
    if (boot_info.framebuffer_bpp != 32)
    {
        return;
    }

    fb_width = boot_info.framebuffer_width;
    fb_height = boot_info.framebuffer_height;
    fb_pitch = boot_info.framebuffer_pitch ? (boot_info.framebuffer_pitch * 4U) : (fb_width * 4U);
    fb_ptr = (uint32_t *)(uintptr_t)boot_info.framebuffer_base;
    if (!fb_ptr)
    {
        return;
    }
    fb_cell_w = fb_width / VGA_COLUMNS;
    fb_cell_h = fb_height / VGA_ROWS;
    if (fb_cell_w == 0) fb_cell_w = 1;
    if (fb_cell_h == 0) fb_cell_h = 1;
    fb_console_enabled = true;
}

static void fb_draw_cell(size_t row, size_t col)
{
    if (!fb_console_enabled || !fb_ptr)
    {
        return;
    }
    if (row >= VGA_ROWS || col >= VGA_COLUMNS)
    {
        return;
    }

    uint32_t cell_w = fb_cell_w;
    uint32_t cell_h = fb_cell_h;
    uint32_t x0 = (uint32_t)col * cell_w;
    uint32_t y0 = (uint32_t)row * cell_h;
    if (x0 + cell_w > fb_width || y0 + cell_h > fb_height)
    {
        return;
    }

    unsigned char ch = (unsigned char)console_chars[row][col];
    const uint8_t *glyph = font_basic_get_glyph8x8(ch);
    if (!glyph)
    {
        glyph = font_basic_get_glyph8x8(' ');
    }
    const uint32_t fg = 0xFFFFFFFFU;
    const uint32_t bg = 0xFF000000U;

    for (uint32_t y = 0; y < cell_h; ++y)
    {
        uint32_t glyph_row = (y * GLYPH_HEIGHT) / cell_h;
        uint8_t bits = glyph ? glyph[glyph_row] : 0;
        volatile uint32_t *dst = (volatile uint32_t *)((uintptr_t)fb_ptr + (y0 + y) * fb_pitch) + x0;
        for (uint32_t x = 0; x < cell_w; ++x)
        {
            uint32_t glyph_col = (x * GLYPH_WIDTH) / cell_w;
            dst[x] = (bits & (0x80 >> glyph_col)) ? fg : bg;
        }
    }
}

static void fb_redraw_all(void)
{
    if (!fb_console_enabled || !fb_ptr)
    {
        return;
    }
    for (size_t row = 0; row < VGA_ROWS; ++row)
    {
        for (size_t col = 0; col < VGA_COLUMNS; ++col)
        {
            fb_draw_cell(row, col);
        }
    }
}
