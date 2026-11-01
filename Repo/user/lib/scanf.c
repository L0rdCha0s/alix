#include "vendor/musl/scan/stdio_impl.h"
#include "vendor/musl/scan/shgetc.h"
#include "vendor/musl/scan/floatscan.h"
#include "stdio_internal.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"

void __alix_scan_init(alix_scan_stream *scan)
{
    memset(scan, 0, sizeof(*scan));
    scan->buf = scan->storage + 8;
    scan->rpos = scan->rend = scan->buf;
}

/* Refill retains eight units for the numeric parser's bounded lookbehind.
 * The state is private heap storage, never a public FILE or a shared stack. */
int __uflow(alix_scan_stream *scan)
{
    if (scan->rpos < scan->rend) return *scan->rpos++;
    if (scan->text && scan->buf != scan->storage + 8)
    { scan->flags |= F_EOF; return EOF; }
    uint32_t unit;
    if (scan->text)
    {
        unit = (unsigned char)scan->text[scan->position];
        if (!unit) { scan->flags |= F_EOF; return EOF; }
    }
    else if (scan->wide)
    {
        unit = scan->wide[scan->position];
        if (!unit) { scan->flags |= F_EOF; return EOF; }
    }
    else
    {
        unsigned char byte;
        bool failed = false;
        if (__alix_stdio_read_unlocked(scan->stream, &byte, 1, &failed) != 1)
        {
            scan->flags |= failed ? F_ERR : F_EOF;
            return EOF;
        }
        unit = byte;
    }
    ++scan->position;
    memmove(scan->storage, scan->storage + 1, 8);
    memmove(scan->units, scan->units + 1, 8 * sizeof(*scan->units));
    scan->units[8] = unit;
    scan->storage[8] = unit < 128 || !scan->wide ? (unsigned char)unit : 128;
    scan->rpos = scan->buf + 1;
    scan->rend = scan->rpos;
    return scan->storage[8];
}
int __toread(alix_scan_stream *scan) { (void)scan; return 0; }
int __alix_scan_getwc(alix_scan_stream *scan)
{
    int byte;
    if (scan->rpos < scan->rend)
    {
        size_t index = (size_t)(scan->rpos - scan->storage);
        ++scan->rpos;
        return (int)scan->units[index];
    }
    byte = __uflow(scan);
    if (byte < 0) return EOF;
    if (scan->stream && byte >= 128)
    {
        scan->flags |= F_ERR;
        scan->stream->error = 1;
        errno = EILSEQ;
        return EOF;
    }
    return (int)scan->units[8];
}
int __alix_scan_ungetwc(int unit, alix_scan_stream *scan)
{
    if (unit < 0 || scan->rpos == scan->storage) return EOF;
    --scan->rpos;
    scan->flags &= ~F_EOF;
    return unit;
}
int __alix_scan_fscanf(alix_scan_stream *scan, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = __alix_scan_bytes(scan, format, arguments);
    va_end(arguments);
    return result;
}

static int scan_stream(FILE *stream, const void *format, va_list arguments, bool wide)
{
    alix_scan_stream *scan = malloc(sizeof(*scan));
    if (!scan) { errno = ENOMEM; return EOF; }
    __alix_scan_init(scan);
    scan->stream = stream;
    __alix_stdio_before_read(stream);
    alix_mutex_lock(&stream->mutex);
    int result = EOF;
    if (__alix_stdio_orient_unlocked(stream, wide ? 1 : -1))
    {
        result = wide ? __alix_scan_wide(scan, format, arguments) : __alix_scan_bytes(scan, format, arguments);
        if (scan->rpos < scan->rend)
            (void)__alix_stdio_pushback_unlocked(stream, *scan->rpos);
    }
    alix_mutex_unlock(&stream->mutex);
    free(scan);
    return result;
}
static int scan_string(const void *text, const void *format, va_list arguments, bool wide)
{
    alix_scan_stream *scan = malloc(sizeof(*scan));
    if (!scan) { errno = ENOMEM; return EOF; }
    __alix_scan_init(scan);
    if (wide) scan->wide = text; else scan->text = text;
    int result = wide ? __alix_scan_wide(scan, format, arguments) : __alix_scan_bytes(scan, format, arguments);
    free(scan);
    return result;
}

int vfscanf(FILE *stream, const char *format, va_list args) { return scan_stream(stream, format, args, false); }
int vscanf(const char *format, va_list args) { return vfscanf(stdin, format, args); }
int vsscanf(const char *text, const char *format, va_list args) { return scan_string(text, format, args, false); }
int vfwscanf(FILE *stream, const wchar_t *format, va_list args) { return scan_stream(stream, format, args, true); }
int vwscanf(const wchar_t *format, va_list args) { return vfwscanf(stdin, format, args); }
int vswscanf(const wchar_t *text, const wchar_t *format, va_list args) { return scan_string(text, format, args, true); }

#define SCAN_WRAPPER(name, vname, type, declaration, first) \
int name declaration { va_list args; va_start(args, format); int result = vname first; va_end(args); return result; }
SCAN_WRAPPER(fscanf, vfscanf, char, (FILE *stream, const char *format, ...), (stream, format, args))
SCAN_WRAPPER(scanf, vscanf, char, (const char *format, ...), (format, args))
SCAN_WRAPPER(sscanf, vsscanf, char, (const char *text, const char *format, ...), (text, format, args))
SCAN_WRAPPER(fwscanf, vfwscanf, wchar_t, (FILE *stream, const wchar_t *format, ...), (stream, format, args))
SCAN_WRAPPER(wscanf, vwscanf, wchar_t, (const wchar_t *format, ...), (format, args))
SCAN_WRAPPER(swscanf, vswscanf, wchar_t, (const wchar_t *text, const wchar_t *format, ...), (text, format, args))
#undef SCAN_WRAPPER

static long double scan_float(const char *text, char **end, int precision)
{
    if (end) *end = (char *)text;
    alix_scan_stream *scan = malloc(sizeof(*scan));
    if (!scan) { errno = ENOMEM; return 0; }
    __alix_scan_init(scan);
    scan->text = text;
    /* strto* may rewind an arbitrarily long malformed NaN payload. Its
     * synchronous memory reader can safely use the original string directly. */
    scan->buf = scan->rpos = (unsigned char *)text;
    scan->rend = scan->rpos + strlen(text);
    shlim(scan, 0);
    long double result = __floatscan(scan, precision, 1);
    off_t count = shcnt(scan);
    if (end && count > 0) *end = (char *)text + count;
    free(scan);
    return result;
}
float strtof(const char *text, char **end) { return (float)scan_float(text, end, 0); }
double strtod(const char *text, char **end) { return (double)scan_float(text, end, 1); }
long double strtold(const char *text, char **end) { return scan_float(text, end, 2); }
