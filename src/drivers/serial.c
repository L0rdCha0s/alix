#include "serial.h"
#include "io.h"
#include "libc.h"

#define COM1 0x3F8

static const uint64_t CANONICAL_MASK = 0xFFFF800000000000ULL;

static int serial_transmit_ready(void)
{
    return (inb(COM1 + 5) & 0x20) != 0;
}

static int serial_receive_ready(void)
{
    return (inb(COM1 + 5) & 0x01) != 0;
}

void serial_init(void)
{
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x01);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

void serial_write_char(char c)
{
    while (!serial_transmit_ready())
    {
    }
    outb(COM1, (uint8_t)c);
}

void serial_write_hex64(uint64_t v)
{
    static const char hex[] = "0123456789ABCDEF";
    for (int shift = 60; shift >= 0; shift -= 4)
    {
        serial_write_char(hex[(v >> shift) & 0xF]);
    }
}

void serial_write_hex8(uint8_t v)
{
    static const char hex[] = "0123456789ABCDEF";
    serial_write_char(hex[(v >> 4) & 0xF]);
    serial_write_char(hex[v & 0xF]);
}

static bool is_canonical(uint64_t addr)
{
    uint64_t mask = addr & CANONICAL_MASK;
    return mask == 0 || mask == CANONICAL_MASK;
}

void serial_write_string(const char *s)
{
    if (!s)
    {
        return;
    }

    uint64_t addr = (uint64_t)s;
    if (!is_canonical(addr))
    {
        serial_write_char('!');
        serial_write_hex64(addr);
        serial_write_char('@');
        uint64_t ret = (uint64_t)__builtin_return_address(0);
        serial_write_hex64(ret);
        serial_write_char('\n');
        for (;;)
        {
            __asm__ volatile ("hlt");
        }
    }

    size_t len = strlen(s);
    for (size_t i = 0; i < len; ++i)
    {
        if (s[i] == '\n')
        {
            serial_write_char('\r');
        }
        serial_write_char(s[i]);
    }
}

char serial_read_char(void)
{
    while (!serial_receive_ready())
    {
    }
    return (char)inb(COM1);
}

bool serial_has_char(void)
{
    return serial_receive_ready() != 0;
}
