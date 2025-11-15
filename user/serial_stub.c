#include "serial.h"
#include "serial_format.h"
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

static void serial_stub_putc(void *ctx, char c)
{
    (void)ctx;
    if (c == '\n')
    {
        char seq[2] = {'\r', '\n'};
        serial_sys_write(seq, 2);
        return;
    }
    serial_sys_write(&c, 1);
}

void serial_printf(const char *format, ...)
{
    if (!format)
    {
        return;
    }
    serial_format_ctx_t ctx = {
        .putc = serial_stub_putc,
        .validate = NULL,
        .ctx = NULL,
        .count = 0,
        .error = false
    };
    va_list args;
    va_start(args, format);
    serial_format_vprintf(&ctx, format, args);
    va_end(args);
}

void serial_output_bytes(const char *data, size_t length)
{
    if (!data || length == 0)
    {
        return;
    }
    serial_sys_write(data, length);
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
