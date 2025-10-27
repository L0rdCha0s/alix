#include "console.h"
#include "io.h"
#include "libc.h"

#define VGA_COLUMNS 80
#define VGA_ROWS    25
#define VGA_MEMORY  ((volatile uint16_t *)0x00000000000B8000)
#define VGA_COLOR   0x0F

static size_t cursor_row = 0;
static size_t cursor_col = 0;

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
}

void console_init(void)
{
    cursor_row = cursor_col = 0;
    console_update_cursor();
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

    volatile uint16_t *cell = VGA_MEMORY + cursor_row * VGA_COLUMNS + cursor_col;
    *cell = ((uint16_t)VGA_COLOR << 8) | (uint8_t)c;
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
}
