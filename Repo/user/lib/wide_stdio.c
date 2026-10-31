#include "stdio.h"
#include "stdio_internal.h"
#include "wchar.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include <stdarg.h>
#include <stdint.h>
#include <limits.h>

/* C/POSIX is a stateless ASCII encoding. Wide memory strings still preserve
 * every native wchar_t unit; conversion to/from a byte stream is explicit. */
int fwide(FILE *stream, int mode)
{
    if (!stream) { errno = EBADF; return 0; }
    alix_mutex_lock(&stream->mutex);
    if (stream->fd < 0) errno = EBADF;
    else if (!stream->orientation && mode) stream->orientation = mode > 0 ? 1 : -1;
    int result = stream->orientation;
    alix_mutex_unlock(&stream->mutex);
    return result;
}

static wint_t wide_get_unlocked(FILE *stream, bool *failed)
{
    unsigned char byte = 0;
    if (__alix_stdio_read_unlocked(stream, &byte, 1, failed) != 1) return WEOF;
    wint_t result = btowc(byte);
    if (result == WEOF)
    {
        errno = EILSEQ;
        stream->error = 1;
        *failed = true;
    }
    return result;
}

wint_t fgetwc(FILE *stream)
{
    if (!stream) { errno = EBADF; return WEOF; }
    alix_mutex_lock(&stream->mutex);
    bool failed = false;
    wint_t result = __alix_stdio_orient_unlocked(stream, 1) ? wide_get_unlocked(stream, &failed) : WEOF;
    alix_mutex_unlock(&stream->mutex);
    return result;
}

wint_t getwc(FILE *stream) { return fgetwc(stream); }
wint_t getwchar(void) { return fgetwc(stdin); }

static wint_t wide_put_unlocked(wchar_t value, FILE *stream)
{
    int converted = wctob((wint_t)value);
    if (converted == EOF) { errno = EILSEQ; stream->error = 1; return WEOF; }
    unsigned char byte = (unsigned char)converted;
    return __alix_stdio_write_unlocked(stream, &byte, 1) == 1 ? (wint_t)value : WEOF;
}

wint_t fputwc(wchar_t value, FILE *stream)
{
    if (!stream) { errno = EBADF; return WEOF; }
    alix_mutex_lock(&stream->mutex);
    wint_t result = __alix_stdio_orient_unlocked(stream, 1) ? wide_put_unlocked(value, stream) : WEOF;
    alix_mutex_unlock(&stream->mutex);
    return result;
}

wint_t putwc(wchar_t value, FILE *stream) { return fputwc(value, stream); }
wint_t putwchar(wchar_t value) { return fputwc(value, stdout); }

wint_t ungetwc(wint_t value, FILE *stream)
{
    if (value == WEOF) return WEOF;
    if (!stream) { errno = EBADF; return WEOF; }
    alix_mutex_lock(&stream->mutex);
    wint_t result = WEOF;
    if (__alix_stdio_orient_unlocked(stream, 1))
    {
        int byte = wctob(value);
        if (byte == EOF) { errno = EILSEQ; stream->error = 1; }
        else if (__alix_stdio_pushback_unlocked(stream, (unsigned char)byte) != EOF) result = value;
    }
    alix_mutex_unlock(&stream->mutex);
    return result;
}

wchar_t *fgetws(wchar_t *buffer, int count, FILE *stream)
{
    if (!buffer || count <= 0 || !stream) { errno = !stream ? EBADF : EINVAL; return NULL; }
    alix_mutex_lock(&stream->mutex);
    if (!__alix_stdio_orient_unlocked(stream, 1)) { alix_mutex_unlock(&stream->mutex); return NULL; }
    if (count == 1) { buffer[0] = 0; alix_mutex_unlock(&stream->mutex); return buffer; }
    int written = 0;
    bool failed = false;
    while (written < count - 1)
    {
        wint_t value = wide_get_unlocked(stream, &failed);
        if (value == WEOF) break;
        buffer[written++] = (wchar_t)value;
        if (value == '\n') break;
    }
    wchar_t *result = NULL;
    if (written && !failed) { buffer[written] = 0; result = buffer; }
    alix_mutex_unlock(&stream->mutex);
    return result;
}

int fputws(const wchar_t *text, FILE *stream)
{
    if (!text || !stream) { errno = !stream ? EBADF : EINVAL; return EOF; }
    alix_mutex_lock(&stream->mutex);
    if (!__alix_stdio_orient_unlocked(stream, 1)) { alix_mutex_unlock(&stream->mutex); return EOF; }
    char *bytes = malloc(256);
    if (!bytes) { errno = ENOMEM; stream->error = 1; alix_mutex_unlock(&stream->mutex); return EOF; }
    int result = 0;
    while (*text)
    {
        size_t count = 0;
        bool invalid = false;
        while (count < 256 && *text)
        {
            int byte = wctob((wint_t)*text);
            if (byte == EOF) { invalid = true; break; }
            bytes[count++] = (char)byte;
            ++text;
        }
        if (count && __alix_stdio_write_unlocked(stream, bytes, count) != count) { result = EOF; break; }
        if (invalid) { errno = EILSEQ; stream->error = 1; result = EOF; break; }
    }
    free(bytes);
    alix_mutex_unlock(&stream->mutex);
    return result;
}

typedef struct
{
    FILE *stream;
    wchar_t *buffer;
    size_t capacity, length;
    bool error;
    char specification[64];
    char bytes[256];
    wchar_t units[256];
} wide_sink_t;

static void wide_error(wide_sink_t *sink, int error)
{
    errno = error;
    sink->error = true;
    if (sink->stream) sink->stream->error = 1;
}

static void wide_write(wide_sink_t *sink, const wchar_t *text, size_t count)
{
    if (sink->error || !count) return;
    if (count > (size_t)INT_MAX - sink->length) { wide_error(sink, EOVERFLOW); return; }
    if (!sink->stream)
    {
        size_t available = sink->capacity - 1 - sink->length;
        size_t copied = count < available ? count : available;
        if (copied) memcpy(sink->buffer + sink->length, text, copied * sizeof(wchar_t));
        sink->length += copied;
        if (copied != count) wide_error(sink, EOVERFLOW);
        return;
    }
    while (count && !sink->error)
    {
        size_t chunk = count < sizeof(sink->bytes) ? count : sizeof(sink->bytes);
        size_t converted = 0;
        for (; converted < chunk; ++converted)
        {
            int byte = wctob((wint_t)text[converted]);
            if (byte == EOF) break;
            sink->bytes[converted] = (char)byte;
        }
        size_t written = converted ? __alix_stdio_write_unlocked(sink->stream, sink->bytes, converted) : 0;
        sink->length += written;
        if (written != converted) { sink->error = true; return; }
        if (converted != chunk) { wide_error(sink, EILSEQ); return; }
        text += chunk;
        count -= chunk;
    }
}

static void wide_ascii(wide_sink_t *sink, const char *text, size_t count)
{
    while (count && !sink->error)
    {
        size_t chunk = count < 256 ? count : 256;
        for (size_t index = 0; index < chunk; ++index)
        {
            wint_t unit = btowc((unsigned char)text[index]);
            if (unit == WEOF) { wide_error(sink, EILSEQ); return; }
            sink->units[index] = (wchar_t)unit;
        }
        wide_write(sink, sink->units, chunk);
        text += chunk;
        count -= chunk;
    }
}

static void wide_pad(wide_sink_t *sink, size_t count)
{
    if (sink->error || !count) return;
    if (count > (size_t)INT_MAX - sink->length) { wide_error(sink, EOVERFLOW); return; }
    if (!sink->stream)
    {
        size_t available = sink->capacity - 1 - sink->length;
        size_t copied = count < available ? count : available;
        for (size_t index = 0; index < copied; ++index) sink->buffer[sink->length + index] = ' ';
        sink->length += copied;
        if (copied != count) wide_error(sink, EOVERFLOW);
        return;
    }
    for (size_t index = 0; index < 256; ++index) sink->units[index] = ' ';
    while (count && !sink->error)
    {
        size_t chunk = count < 256 ? count : 256;
        wide_write(sink, sink->units, chunk);
        count -= chunk;
    }
}

/* A numeric conversion has no %n or string side effects. Its value is fetched
 * once by the wide parser, then the proven native byte formatter supplies the
 * exact ASCII spelling, including long-double rounding. Buffer truncation
 * allocates only the prefix that can actually fit, even for INT_MAX width. */
static void wide_number(wide_sink_t *sink, const char *format, ...)
{
    va_list arguments, copy;
    va_start(arguments, format);
    va_copy(copy, arguments);
    int needed = vsnprintf(NULL, 0, format, arguments);
    va_end(arguments);
    if (needed < 0) { sink->error = true; if (sink->stream) sink->stream->error = 1; va_end(copy); return; }
    if ((size_t)needed > (size_t)INT_MAX - sink->length)
    {
        wide_error(sink, EOVERFLOW); va_end(copy); return;
    }
    size_t copied = (size_t)needed;
    if (!sink->stream)
    {
        size_t available = sink->capacity - 1 - sink->length;
        if (copied > available) copied = available;
    }
    if (needed == 0) { va_end(copy); return; }
    char *bytes = malloc(copied + 1);
    if (!bytes) { wide_error(sink, ENOMEM); va_end(copy); return; }
    int produced = vsnprintf(bytes, copied + 1, format, copy);
    va_end(copy);
    if (produced != needed)
    {
        if (produced >= 0) errno = EIO;
        sink->error = true;
        if (sink->stream) sink->stream->error = 1;
    }
    else
    {
        wide_ascii(sink, bytes, copied);
        if (!sink->error && copied != (size_t)needed) wide_error(sink, EOVERFLOW);
    }
    free(bytes);
}

enum wide_length { W_NORMAL, W_LONG, W_LLONG, W_SHORT, W_CHAR, W_SIZE, W_PTRDIFF, W_INTMAX, W_LDOUBLE };
enum { W_LEFT = 1, W_PLUS = 2, W_SPACE = 4, W_ALT = 8, W_ZERO = 16, W_GROUP = 32 };

static char *wide_decimal(char *output, unsigned value)
{
    unsigned divisor = 1;
    while (value / divisor >= 10) divisor *= 10;
    do { *output++ = (char)('0' + value / divisor); value %= divisor; divisor /= 10; } while (divisor);
    return output;
}

static void wide_specification(wide_sink_t *sink, unsigned flags, int width, int precision,
                               char length, char conversion)
{
    char *output = sink->specification;
    *output++ = '%';
    if (flags & W_LEFT) *output++ = '-';
    if (flags & W_PLUS) *output++ = '+';
    if (flags & W_SPACE) *output++ = ' ';
    if (flags & W_ALT) *output++ = '#';
    if (flags & W_ZERO) *output++ = '0';
    if (flags & W_GROUP) *output++ = '\'';
    if (width) output = wide_decimal(output, (unsigned)width);
    if (precision >= 0) { *output++ = '.'; output = wide_decimal(output, (unsigned)precision); }
    if (length) *output++ = length;
    *output++ = conversion;
    *output = 0;
}

static void wide_format(wide_sink_t *sink, const wchar_t *format, va_list arguments)
{
    static const wchar_t null_text[] = {'(', 'n', 'u', 'l', 'l', ')', 0};
    while (*format && !sink->error)
    {
        if (*format != '%') { wide_write(sink, format++, 1); continue; }
        ++format;
        unsigned flags = 0;
        for (;; ++format)
        {
            if (*format == '-') flags |= W_LEFT;
            else if (*format == '+') flags |= W_PLUS;
            else if (*format == ' ') flags |= W_SPACE;
            else if (*format == '#') flags |= W_ALT;
            else if (*format == '0') flags |= W_ZERO;
            else if (*format == '\'') flags |= W_GROUP;
            else break;
        }
        int width = 0, precision = -1;
        if (*format == '*')
        {
            width = va_arg(arguments, int); ++format;
            if (width == INT_MIN) { wide_error(sink, EOVERFLOW); return; }
            if (width < 0) { width = -width; flags |= W_LEFT; }
        }
        else while (*format >= '0' && *format <= '9')
        {
            int digit = *format++ - '0';
            if (width > (INT_MAX - digit) / 10) { wide_error(sink, EOVERFLOW); return; }
            width = width * 10 + digit;
        }
        if (*format == '.')
        {
            ++format; precision = 0;
            if (*format == '*') { precision = va_arg(arguments, int); ++format; if (precision < 0) precision = -1; }
            else while (*format >= '0' && *format <= '9')
            {
                int digit = *format++ - '0';
                if (precision > (INT_MAX - digit) / 10) { wide_error(sink, EOVERFLOW); return; }
                precision = precision * 10 + digit;
            }
        }
        enum wide_length length = W_NORMAL;
        if (*format == 'l') { ++format; length = W_LONG; if (*format == 'l') { ++format; length = W_LLONG; } }
        else if (*format == 'h') { ++format; length = W_SHORT; if (*format == 'h') { ++format; length = W_CHAR; } }
        else if (*format == 'j') { ++format; length = W_INTMAX; }
        else if (*format == 'z') { ++format; length = W_SIZE; }
        else if (*format == 't') { ++format; length = W_PTRDIFF; }
        else if (*format == 'L') { ++format; length = W_LDOUBLE; }
        wchar_t conversion = *format;
        if (!conversion) { wide_error(sink, EINVAL); return; }
        ++format;
        if (conversion == '%')
        {
            wchar_t percent = '%'; wide_write(sink, &percent, 1);
        }
        else if (conversion == 's')
        {
            const wchar_t *wide = NULL;
            const char *bytes = NULL;
            if (length == W_LONG) { wide = va_arg(arguments, const wchar_t *); if (!wide) wide = null_text; }
            else if (length == W_NORMAL) { bytes = va_arg(arguments, const char *); if (!bytes) bytes = "(null)"; }
            else { wide_error(sink, EINVAL); return; }
            size_t count = 0;
            while (precision < 0 || count < (size_t)precision)
            {
                if (wide ? wide[count] == 0 : bytes[count] == 0) break;
                if (count == INT_MAX) { wide_error(sink, EOVERFLOW); return; }
                if (bytes && btowc((unsigned char)bytes[count]) == WEOF) { wide_error(sink, EILSEQ); return; }
                ++count;
            }
            size_t padding = (size_t)width > count ? (size_t)width - count : 0;
            if (!(flags & W_LEFT)) wide_pad(sink, padding);
            if (wide) wide_write(sink, wide, count); else wide_ascii(sink, bytes, count);
            if (flags & W_LEFT) wide_pad(sink, padding);
        }
        else if (conversion == 'c')
        {
            wint_t value;
            if (length == W_LONG) value = va_arg(arguments, wint_t);
            else if (length == W_NORMAL) value = btowc(va_arg(arguments, int));
            else { wide_error(sink, EINVAL); return; }
            if (value == WEOF || value > 0xffffu) { wide_error(sink, EILSEQ); return; }
            wchar_t unit = (wchar_t)value;
            if (!(flags & W_LEFT) && width > 1) wide_pad(sink, (size_t)width - 1);
            wide_write(sink, &unit, 1);
            if ((flags & W_LEFT) && width > 1) wide_pad(sink, (size_t)width - 1);
        }
        else if (conversion == 'd' || conversion == 'i')
        {
            intmax_t value;
            if (length == W_LONG) value = va_arg(arguments, long);
            else if (length == W_LLONG) value = va_arg(arguments, long long);
            else if (length == W_INTMAX) value = va_arg(arguments, intmax_t);
            else if (length == W_SIZE) value = va_arg(arguments, ssize_t);
            else if (length == W_PTRDIFF) value = va_arg(arguments, ptrdiff_t);
            else if (length == W_LDOUBLE) { wide_error(sink, EINVAL); return; }
            else { int promoted = va_arg(arguments, int); value = length == W_CHAR ? (signed char)promoted : length == W_SHORT ? (short)promoted : promoted; }
            wide_specification(sink, flags, width, precision, 'j', (char)conversion);
            wide_number(sink, sink->specification, value);
        }
        else if (conversion == 'u' || conversion == 'o' || conversion == 'x' || conversion == 'X')
        {
            uintmax_t value;
            if (length == W_LONG) value = va_arg(arguments, unsigned long);
            else if (length == W_LLONG) value = va_arg(arguments, unsigned long long);
            else if (length == W_INTMAX) value = va_arg(arguments, uintmax_t);
            else if (length == W_SIZE) value = va_arg(arguments, size_t);
            else if (length == W_PTRDIFF) value = va_arg(arguments, uintptr_t);
            else if (length == W_LDOUBLE) { wide_error(sink, EINVAL); return; }
            else { unsigned promoted = va_arg(arguments, unsigned); value = length == W_CHAR ? (unsigned char)promoted : length == W_SHORT ? (unsigned short)promoted : promoted; }
            wide_specification(sink, flags, width, precision, 'j', (char)conversion);
            wide_number(sink, sink->specification, value);
        }
        else if (conversion == 'f' || conversion == 'F' || conversion == 'e' || conversion == 'E' ||
                 conversion == 'g' || conversion == 'G' || conversion == 'a' || conversion == 'A')
        {
            if (length != W_NORMAL && length != W_LONG && length != W_LDOUBLE) { wide_error(sink, EINVAL); return; }
            wide_specification(sink, flags, width, precision, length == W_LDOUBLE ? 'L' : 0, (char)conversion);
            if (length == W_LDOUBLE) wide_number(sink, sink->specification, va_arg(arguments, long double));
            else wide_number(sink, sink->specification, va_arg(arguments, double));
        }
        else if (conversion == 'p')
        {
            if (length != W_NORMAL) { wide_error(sink, EINVAL); return; }
            wide_specification(sink, flags, width, precision, 0, 'p');
            wide_number(sink, sink->specification, va_arg(arguments, void *));
        }
        else if (conversion == 'n')
        {
            if (length == W_LONG) *va_arg(arguments, long *) = (long)sink->length;
            else if (length == W_LLONG) *va_arg(arguments, long long *) = (long long)sink->length;
            else if (length == W_SHORT) *va_arg(arguments, short *) = (short)sink->length;
            else if (length == W_CHAR) *va_arg(arguments, signed char *) = (signed char)sink->length;
            else if (length == W_SIZE) *va_arg(arguments, ssize_t *) = (ssize_t)sink->length;
            else if (length == W_PTRDIFF) *va_arg(arguments, ptrdiff_t *) = (ptrdiff_t)sink->length;
            else if (length == W_INTMAX) *va_arg(arguments, intmax_t *) = (intmax_t)sink->length;
            else if (length == W_NORMAL) *va_arg(arguments, int *) = (int)sink->length;
            else { wide_error(sink, EINVAL); return; }
        }
        else { wide_error(sink, EINVAL); return; }
    }
}

int vswprintf(wchar_t *buffer, size_t capacity, const wchar_t *format, va_list arguments)
{
    if (!format || (capacity && !buffer)) { errno = EINVAL; return -1; }
    if (!capacity || capacity > (size_t)-1 / sizeof(wchar_t)) { errno = EOVERFLOW; return -1; }
    buffer[0] = 0;
    wide_sink_t *sink = calloc(1, sizeof(*sink));
    if (!sink) { errno = ENOMEM; return -1; }
    sink->buffer = buffer;
    sink->capacity = capacity;
    wide_format(sink, format, arguments);
    buffer[sink->length] = 0;
    int result = sink->error ? -1 : (int)sink->length;
    free(sink);
    return result;
}

int swprintf(wchar_t *buffer, size_t capacity, const wchar_t *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = vswprintf(buffer, capacity, format, arguments);
    va_end(arguments);
    return result;
}

int vfwprintf(FILE *stream, const wchar_t *format, va_list arguments)
{
    if (!stream || !format) { errno = !stream ? EBADF : EINVAL; return -1; }
    alix_mutex_lock(&stream->mutex);
    if (!__alix_stdio_orient_unlocked(stream, 1)) { alix_mutex_unlock(&stream->mutex); return -1; }
    wide_sink_t *sink = calloc(1, sizeof(*sink));
    if (!sink) { errno = ENOMEM; stream->error = 1; alix_mutex_unlock(&stream->mutex); return -1; }
    sink->stream = stream;
    wide_format(sink, format, arguments);
    int result = sink->error ? -1 : (int)sink->length;
    free(sink);
    alix_mutex_unlock(&stream->mutex);
    return result;
}

int fwprintf(FILE *stream, const wchar_t *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = vfwprintf(stream, format, arguments);
    va_end(arguments);
    return result;
}

int vwprintf(const wchar_t *format, va_list arguments) { return vfwprintf(stdout, format, arguments); }

int wprintf(const wchar_t *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = vfwprintf(stdout, format, arguments);
    va_end(arguments);
    return result;
}
