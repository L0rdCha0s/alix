#include "serial.h"
#include "libc.h"
#include "usyscall.h"

static void serial_sys_write(const char *buffer, size_t length)
{
    if (!buffer || length == 0)
    {
        return;
    }
    sys_serial_write(buffer, length);
}

void serial_init(void) {}

void serial_write_char(char c)
{
    char tmp = c;
    serial_sys_write(&tmp, 1);
}

void serial_write_string(const char *s)
{
    if (!s)
    {
        return;
    }
    size_t len = strlen(s);
    if (len == 0)
    {
        return;
    }
    serial_sys_write(s, len);
}

void serial_write_hex64(uint64_t value)
{
    char buffer[17];
    buffer[16] = '\0';
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 15; i >= 0; --i)
    {
        buffer[i] = hex[value & 0xF];
        value >>= 4;
    }
    serial_sys_write(buffer, 16);
}

char serial_read_char(void)
{
    return 0;
}

bool serial_has_char(void)
{
    return false;
}

bool serial_is_ready(void)
{
    return true;
}
