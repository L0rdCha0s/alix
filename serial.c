#include "serial.h"
#include "io.h"
#include "libc.h"

#define COM1 0x3F8

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

void serial_write_string(const char *s)
{
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
