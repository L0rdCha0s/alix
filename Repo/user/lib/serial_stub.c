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

typedef struct
{
    char buffer[1024];
    size_t length;
} serial_stub_buffer_t;

static void serial_stub_flush(serial_stub_buffer_t *ctx)
{
    if (!ctx || ctx->length == 0)
    {
        return;
    }
    serial_sys_write(ctx->buffer, ctx->length);
    ctx->length = 0;
}

static void serial_stub_putc_buffered(void *ctx, char c)
{
    serial_stub_buffer_t *buffer = (serial_stub_buffer_t *)ctx;
    if (!buffer)
    {
        return;
    }
    if (c == '\n')
    {
        if (buffer->length + 2 > sizeof(buffer->buffer))
        {
            serial_stub_flush(buffer);
        }
        buffer->buffer[buffer->length++] = '\r';
        buffer->buffer[buffer->length++] = '\n';
        return;
    }
    if (buffer->length + 1 > sizeof(buffer->buffer))
    {
        serial_stub_flush(buffer);
    }
    buffer->buffer[buffer->length++] = c;
}

void serial_printf(const char *format, ...)
{
    if (!format)
    {
        return;
    }
    serial_stub_buffer_t buffer = {0};
    serial_format_ctx_t ctx = {
        .putc = serial_stub_putc_buffered,
        .validate = NULL,
        .ctx = &buffer,
        .count = 0,
        .error = false
    };
    va_list args;
    va_start(args, format);
    serial_format_vprintf(&ctx, format, args);
    va_end(args);
    serial_stub_flush(&buffer);
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
