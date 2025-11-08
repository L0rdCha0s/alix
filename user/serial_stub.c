#include "serial.h"

void serial_init(void) {}
void serial_write_char(char c)
{
    (void)c;
}

void serial_write_string(const char *s)
{
    (void)s;
}

void serial_write_hex64(uint64_t value)
{
    (void)value;
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
