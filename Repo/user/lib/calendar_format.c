#include "time.h"
#include "errno.h"
#include "stdint.h"
#include "string.h"

typedef struct { char *output; size_t capacity, used; } calendar_writer_t;

static int calendar_text(calendar_writer_t *writer, const char *text, size_t length)
{
    if (length >= writer->capacity - writer->used) return 0;
    memcpy(writer->output + writer->used, text, length);
    writer->used += length;
    return 1;
}

static int calendar_number(calendar_writer_t *writer, int64_t number, unsigned width, char padding)
{
    char digits[32];
    unsigned count = 0;
    int negative = number < 0;
    uint64_t magnitude = negative ? 0 - (uint64_t)number : (uint64_t)number;
    do { digits[count++] = (char)('0' + magnitude % 10); magnitude /= 10; } while (magnitude);
    if (negative && !calendar_text(writer, "-", 1)) return 0;
    for (unsigned i = count + (unsigned)negative; i < width; ++i)
        if (!calendar_text(writer, &padding, 1)) return 0;
    while (count) if (!calendar_text(writer, &digits[--count], 1)) return 0;
    return 1;
}

static int calendar_format(calendar_writer_t *writer, const char *format, const struct tm *date,
                            unsigned depth)
{
    static const char *const weekdays[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
    static const char *const months[] = {"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"};
    if (depth > 3) { errno = EINVAL; return 0; }
    while (*format)
    {
        if (*format != '%') { if (!calendar_text(writer, format++, 1)) return 0; continue; }
        ++format;
        if (*format == 'E' || *format == 'O') ++format; /* C locale has no alternate forms. */
        char code = *format++;
        const char *replacement = NULL;
        int64_t number = 0;
        unsigned width = 0;
        char padding = '0';
        int numeric = 0;
        switch (code)
        {
            case '%': replacement = "%"; break;
            case 'n': replacement = "\n"; break;
            case 't': replacement = "\t"; break;
            case 'a': case 'A':
                if (date->tm_wday < 0 || date->tm_wday > 6) goto invalid;
                replacement = weekdays[date->tm_wday];
                if (code == 'a') { if (!calendar_text(writer, replacement, 3)) return 0; continue; }
                break;
            case 'b': case 'B': case 'h':
                if (date->tm_mon < 0 || date->tm_mon > 11) goto invalid;
                replacement = months[date->tm_mon];
                if (code != 'B') { if (!calendar_text(writer, replacement, 3)) return 0; continue; }
                break;
            case 'c': replacement = "%a %b %e %T %Y"; break;
            case 'D': case 'x': replacement = "%m/%d/%y"; break;
            case 'F': replacement = "%Y-%m-%d"; break;
            case 'r': replacement = "%I:%M:%S %p"; break;
            case 'R': replacement = "%H:%M"; break;
            case 'T': case 'X': replacement = "%H:%M:%S"; break;
            case 'p':
                if (date->tm_hour < 0 || date->tm_hour > 23) goto invalid;
                replacement = date->tm_hour < 12 ? "AM" : "PM"; break;
            case 'Z': replacement = date->tm_isdst < 0 || !date->tm_zone ? "" : date->tm_zone; break;
            case 'z':
            {
                if (date->tm_isdst < 0) continue;
                int64_t offset = date->tm_gmtoff;
                if (offset < -89999 || offset > 93599) goto invalid;
                if (!calendar_text(writer, offset < 0 ? "-" : "+", 1)) return 0;
                if (offset < 0) offset = -offset;
                if (!calendar_number(writer, offset / 3600, 2, '0') ||
                    !calendar_number(writer, offset / 60 % 60, 2, '0')) return 0;
                continue;
            }
            case 'C': case 'y': case 'Y':
            {
                int64_t year = (int64_t)date->tm_year + 1900;
                if (code == 'Y') { number = year; width = 4; }
                else if (code == 'C') { number = year / 100 - (year % 100 < 0); width = 2; }
                else { number = (year % 100 + 100) % 100; width = 2; }
                numeric = 1; break;
            }
            case 'd': case 'e':
                if (date->tm_mday < 1 || date->tm_mday > 31) goto invalid;
                number = date->tm_mday; width = 2; padding = code == 'e' ? ' ' : '0'; numeric = 1; break;
            case 'H': case 'I':
                if (date->tm_hour < 0 || date->tm_hour > 23) goto invalid;
                number = code == 'H' ? date->tm_hour : (date->tm_hour + 11) % 12 + 1;
                width = 2; numeric = 1; break;
            case 'j':
                if (date->tm_yday < 0 || date->tm_yday > 365) goto invalid;
                number = date->tm_yday + 1; width = 3; numeric = 1; break;
            case 'm':
                if (date->tm_mon < 0 || date->tm_mon > 11) goto invalid;
                number = date->tm_mon + 1; width = 2; numeric = 1; break;
            case 'M': case 'S':
                number = code == 'M' ? date->tm_min : date->tm_sec;
                if (number < 0 || number > (code == 'M' ? 59 : 60)) goto invalid;
                width = 2; numeric = 1; break;
            case 'u': case 'w':
                if (date->tm_wday < 0 || date->tm_wday > 6) goto invalid;
                number = code == 'u' && date->tm_wday == 0 ? 7 : date->tm_wday;
                numeric = 1; break;
            case 'U': case 'W':
                if (date->tm_wday < 0 || date->tm_wday > 6 || date->tm_yday < 0 || date->tm_yday > 365) goto invalid;
                number = (date->tm_yday + 7 - (code == 'U' ? date->tm_wday : (date->tm_wday + 6) % 7)) / 7;
                width = 2; numeric = 1; break;
            case 'g': case 'G': case 'V':
            {
                if (date->tm_wday < 0 || date->tm_wday > 6 || date->tm_yday < 0 || date->tm_yday > 365) goto invalid;
                int64_t year = (int64_t)date->tm_year + 1900;
                int monday_day = (date->tm_wday + 6) % 7;
                int thursday = date->tm_yday + 3 - monday_day;
                int leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
                if (thursday < 0)
                {
                    --year;
                    thursday += 365 + (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
                }
                else if (thursday >= 365 + leap) { thursday -= 365 + leap; ++year; }
                number = code == 'V' ? thursday / 7 + 1 : code == 'g' ? (year % 100 + 100) % 100 : year;
                width = code == 'G' ? 4 : 2; numeric = 1; break;
            }
            default: goto invalid;
        }
        if (numeric) { if (!calendar_number(writer, number, width, padding)) return 0; }
        else if (code == 'c' || code == 'D' || code == 'x' || code == 'F' || code == 'r' ||
                 code == 'R' || code == 'T' || code == 'X')
        { if (!calendar_format(writer, replacement, date, depth + 1)) return 0; }
        else if (!calendar_text(writer, replacement, strlen(replacement))) return 0;
    }
    return 1;
invalid:
    errno = EINVAL; return 0;
}

size_t strftime(char *output, size_t size, const char *format, const struct tm *value)
{
    if (!size) return 0;
    if (!output || !format || !value) { errno = EINVAL; return 0; }
    calendar_writer_t writer = {output, size, 0};
    int saved = errno;
    if (!calendar_format(&writer, format, value, 0)) { output[0] = 0; return 0; }
    output[writer.used] = 0; errno = saved; return writer.used;
}
