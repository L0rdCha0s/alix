#ifndef SERIAL_FORMAT_H
#define SERIAL_FORMAT_H

#include "types.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

typedef void (*serial_format_putc_fn)(void *ctx, char c);
typedef bool (*serial_format_validate_fn)(void *ctx, const void *ptr);

typedef struct serial_format_ctx
{
    serial_format_putc_fn putc;
    serial_format_validate_fn validate;
    void *ctx;
    int count;
    bool error;
} serial_format_ctx_t;

static inline size_t serial_format_strlen(const char *str)
{
    size_t len = 0;
    if (!str)
    {
        return 0;
    }
    while (str[len] != '\0')
    {
        ++len;
    }
    return len;
}

static inline void serial_format_emit(serial_format_ctx_t *ctx, char c)
{
    if (!ctx || ctx->error || !ctx->putc)
    {
        return;
    }
    ctx->putc(ctx->ctx, c);
    ctx->count++;
}

static inline void serial_format_emit_range(serial_format_ctx_t *ctx,
                                            const char *data,
                                            size_t len)
{
    if (!ctx || ctx->error || !ctx->putc || !data)
    {
        return;
    }
    for (size_t i = 0; i < len; ++i)
    {
        serial_format_emit(ctx, data[i]);
        if (ctx->error)
        {
            return;
        }
    }
}

static inline void serial_format_emit_string(serial_format_ctx_t *ctx, const char *text)
{
    if (!ctx || ctx->error)
    {
        return;
    }
    if (!text)
    {
        text = "(null)";
    }
    serial_format_emit_range(ctx, text, serial_format_strlen(text));
}

static inline void serial_format_print_unsigned(serial_format_ctx_t *ctx,
                                                uint64_t value,
                                                unsigned int base,
                                                bool uppercase,
                                                int width,
                                                bool zero_pad)
{
    if (!ctx || ctx->error || base < 2 || base > 16)
    {
        return;
    }

    char buffer[32];
    size_t index = 0;
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";

    do
    {
        buffer[index++] = digits[value % base];
        value /= base;
    } while (value != 0 && index < sizeof(buffer));

    if (!zero_pad)
    {
        width = 0;
    }
    int pad = 0;
    if (width > 0 && (int)index < width)
    {
        pad = width - (int)index;
    }
    while (pad-- > 0)
    {
        serial_format_emit(ctx, '0');
    }

    while (index > 0)
    {
        serial_format_emit(ctx, buffer[--index]);
    }
}

static inline void serial_format_print_signed(serial_format_ctx_t *ctx,
                                              int64_t value,
                                              int width,
                                              bool zero_pad)
{
    if (!ctx || ctx->error)
    {
        return;
    }
    if (value < 0)
    {
        serial_format_emit(ctx, '-');
        if (zero_pad && width > 0)
        {
            width--;
        }
        uint64_t magnitude = (uint64_t)(-(value + 1)) + 1;
        serial_format_print_unsigned(ctx, magnitude, 10, false, width, zero_pad);
        return;
    }
    serial_format_print_unsigned(ctx, (uint64_t)value, 10, false, width, zero_pad);
}

static inline void serial_format_vprintf(serial_format_ctx_t *ctx,
                                         const char *format,
                                         va_list args)
{
    if (!ctx || !format)
    {
        return;
    }
    while (!ctx->error && *format)
    {
        if (*format != '%')
        {
            const char *start = format;
            while (*format && *format != '%')
            {
                ++format;
            }
            serial_format_emit_range(ctx, start, (size_t)(format - start));
            continue;
        }
        ++format;
        bool zero_pad = false;
        if (*format == '0')
        {
            zero_pad = true;
            ++format;
        }
        int width = 0;
        while (*format >= '0' && *format <= '9')
        {
            width = (width * 10) + (*format - '0');
            ++format;
        }
        bool length_z = false;
        bool length_l = false;
        bool length_ll = false;
        if (*format == 'z')
        {
            length_z = true;
            ++format;
        }
        else if (*format == 'l')
        {
            length_l = true;
            ++format;
            if (*format == 'l')
            {
                length_ll = true;
                ++format;
            }
        }

        char specifier = *format;
        if (specifier != '\0')
        {
            ++format;
        }

        switch (specifier)
        {
            case '%':
            {
                serial_format_emit(ctx, '%');
                break;
            }
            case 'c':
            {
                int value = va_arg(args, int);
                serial_format_emit(ctx, (char)value);
                break;
            }
            case 's':
            {
                const char *text = va_arg(args, const char *);
                if (ctx->validate && text && !ctx->validate(ctx->ctx, text))
                {
                    ctx->error = true;
                    return;
                }
                serial_format_emit_string(ctx, text);
                break;
            }
            case 'd':
            case 'i':
            {
                int64_t value;
                if (length_z)
                {
                    value = (int64_t)va_arg(args, ssize_t);
                }
                else if (length_ll)
                {
                    value = va_arg(args, long long);
                }
                else if (length_l)
                {
                    value = va_arg(args, long);
                }
                else
                {
                    value = va_arg(args, int);
                }
                serial_format_print_signed(ctx, value, width, zero_pad);
                break;
            }
            case 'u':
            case 'x':
            case 'X':
            {
                uint64_t value;
                if (length_z)
                {
                    value = (uint64_t)va_arg(args, size_t);
                }
                else if (length_ll)
                {
                    value = va_arg(args, unsigned long long);
                }
                else if (length_l)
                {
                    value = va_arg(args, unsigned long);
                }
                else
                {
                    value = (uint64_t)va_arg(args, unsigned int);
                }
                unsigned base = (specifier == 'u') ? 10u : 16u;
                bool uppercase = (specifier == 'X');
                serial_format_print_unsigned(ctx, value, base, uppercase, width, zero_pad);
                break;
            }
            case 'p':
            {
                uintptr_t ptr = (uintptr_t)va_arg(args, void *);
                serial_format_emit_range(ctx, "0x", 2);
                serial_format_print_unsigned(ctx, ptr, 16, false, 0, false);
                break;
            }
            case '\0':
            {
                serial_format_emit(ctx, '%');
                if (length_z)
                {
                    serial_format_emit(ctx, 'z');
                }
                if (length_l)
                {
                    serial_format_emit(ctx, 'l');
                    if (length_ll)
                    {
                        serial_format_emit(ctx, 'l');
                    }
                }
                return;
            }
            default:
            {
                serial_format_emit(ctx, '%');
                if (length_z)
                {
                    serial_format_emit(ctx, 'z');
                }
                if (length_l)
                {
                    serial_format_emit(ctx, 'l');
                    if (length_ll)
                    {
                        serial_format_emit(ctx, 'l');
                    }
                }
                serial_format_emit(ctx, specifier);
                break;
            }
        }
    }
}

#endif
