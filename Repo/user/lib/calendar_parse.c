#include "time.h"
#include "ctype.h"
#include "errno.h"
#include "stdint.h"
#include "string.h"
#include "strings.h"

/* The installed LC_TIME selections are C and POSIX. State belongs to a single
 * parse, including across composite directives and concurrent callers. */
typedef struct
{
    struct tm date;
    unsigned fields;
    int century, relative, iso_year, iso_week, week, week_start, ampm, hour12;
} calendar_parser_t;

enum { YEAR = 1, MONTH = 2, MDAY = 4, YDAY = 8, WDAY = 16 };
extern size_t __alix_timezone_parse_name(const char *, struct tm *);

static const char *calendar_digits(const char *input, int *value, unsigned count, int low, int high)
{
    int number = 0;
    unsigned digits = 0;
    while (digits < count && *input >= '0' && *input <= '9')
    {
        number = number * 10 + *input++ - '0';
        ++digits;
    }
    if (!digits || number < low || number > high) return NULL;
    *value = number;
    return input;
}

static const char *calendar_name(const char *input, int *value, const char *const *names, unsigned count)
{
    for (unsigned i = 0; i < count; ++i)
    {
        size_t length = strlen(names[i]);
        if (!strncasecmp(input, names[i], length)) { *value = (int)i; return input + length; }
        if (!strncasecmp(input, names[i], 3)) { *value = (int)i; return input + 3; }
    }
    return NULL;
}

static const char *calendar_parse(calendar_parser_t *state, const char *input, const char *format,
                                   unsigned depth)
{
    static const char *const days[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
    static const char *const months[] = {"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"};
    if (depth > 3) return NULL;
    while (*format)
    {
        unsigned char code = (unsigned char)*format++;
        if (isspace(code)) { while (isspace((unsigned char)*input)) ++input; continue; }
        if (code != '%') { if (*input != code) return NULL; ++input; continue; }
        code = (unsigned char)*format++;
        if (!code) return NULL;
        if (code == 'E' || code == 'O')
        {
            unsigned char modifier = code;
            code = (unsigned char)*format++;
            if (!code || !strchr(modifier == 'E' ? "cCxXyY" : "deHImMSuUVwWy", code)) return NULL;
        }
        const char *composite = NULL;
        int number = 0;
        switch (code)
        {
            case '%': if (*input++ != '%') return NULL; break;
            case 'n': case 't': while (isspace((unsigned char)*input)) ++input; break;
            case 'c': composite = "%a %b %e %T %Y"; break;
            case 'D': case 'x': composite = "%m/%d/%y"; break;
            case 'F': composite = "%Y-%m-%d"; break;
            case 'r': composite = "%I:%M:%S %p"; break;
            case 'R': composite = "%H:%M"; break;
            case 'T': case 'X': composite = "%H:%M:%S"; break;
            case 'v': composite = "%e-%b-%Y"; break;
            case 'a': case 'A':
                input = calendar_name(input, &state->date.tm_wday, days, 7);
                state->fields |= WDAY; break;
            case 'b': case 'B': case 'h':
                input = calendar_name(input, &state->date.tm_mon, months, 12);
                state->fields |= MONTH; break;
            case 'C': input = calendar_digits(input, &state->century, 2, 0, 99); break;
            case 'y': input = calendar_digits(input, &state->relative, 2, 0, 99); break;
            case 'Y':
                input = calendar_digits(input, &number, 4, 0, 9999);
                state->date.tm_year = number - 1900; state->fields |= YEAR; break;
            case 'd': case 'e':
                while (*input == ' ') ++input;
                input = calendar_digits(input, &state->date.tm_mday, 2, 1, 31);
                state->fields |= MDAY; break;
            case 'm':
                input = calendar_digits(input, &number, 2, 1, 12);
                state->date.tm_mon = number - 1; state->fields |= MONTH; break;
            case 'j':
                input = calendar_digits(input, &number, 3, 1, 366);
                state->date.tm_yday = number - 1; state->fields |= YDAY; break;
            case 'w': input = calendar_digits(input, &state->date.tm_wday, 1, 0, 6); state->fields |= WDAY; break;
            case 'u':
                input = calendar_digits(input, &number, 1, 1, 7);
                state->date.tm_wday = number % 7; state->fields |= WDAY; break;
            case 'H': case 'k':
                while (*input == ' ') ++input;
                input = calendar_digits(input, &state->date.tm_hour, 2, 0, 23); state->hour12 = 0; break;
            case 'I': case 'l':
                while (*input == ' ') ++input;
                input = calendar_digits(input, &number, 2, 1, 12);
                state->date.tm_hour = number % 12; state->hour12 = 1; break;
            case 'M': input = calendar_digits(input, &state->date.tm_min, 2, 0, 59); break;
            case 'S': input = calendar_digits(input, &state->date.tm_sec, 2, 0, 60); break;
            case 'p':
                if (!strncasecmp(input, "AM", 2)) state->ampm = 0;
                else if (!strncasecmp(input, "PM", 2)) state->ampm = 1;
                else return NULL;
                input += 2; break;
            case 'U': case 'W':
                input = calendar_digits(input, &state->week, 2, 0, 53);
                state->week_start = code == 'W'; break;
            case 'G': input = calendar_digits(input, &state->iso_year, 4, 0, 9999); break;
            case 'g':
                input = calendar_digits(input, &number, 2, 0, 99);
                state->iso_year = number + (number <= 68 ? 2000 : 1900); break;
            case 'V': input = calendar_digits(input, &state->iso_week, 2, 1, 53); break;
            case 'z':
            {
                if (*input == 'Z') { state->date.tm_gmtoff = 0; state->date.tm_zone = "UTC"; ++input; }
                else
                {
                    int sign = *input == '-' ? -1 : 1, hour, minute = 0, second = 0;
                    if (*input != '+' && *input != '-') return NULL;
                    ++input;
                    if (!input[0] || !input[1]) return NULL;
                    const char *next = calendar_digits(input, &hour, 2, 0, 23);
                    if (!next || next - input != 2) return NULL;
                    input = next;
                    int colon = *input == ':';
                    if (colon) ++input;
                    if (colon || isdigit((unsigned char)*input))
                    {
                        next = calendar_digits(input, &minute, 2, 0, 59);
                        if (!next || next - input != 2) return NULL;
                        input = next;
                    }
                    if (colon && *input == ':')
                    {
                        next = calendar_digits(input + 1, &second, 2, 0, 59);
                        if (!next || next - input != 3) return NULL;
                        input = next;
                    }
                    if (isdigit((unsigned char)*input)) return NULL;
                    state->date.tm_gmtoff = sign * (hour * 3600 + minute * 60 + second);
                    state->date.tm_zone = NULL;
                }
                state->date.tm_isdst = 0; break;
            }
            case 'Z':
            {
                size_t length = __alix_timezone_parse_name(input, &state->date);
                if (!length) return NULL;
                input += length; break;
            }
            case 's':
            {
                int negative = *input == '-';
                if (*input == '-' || *input == '+') ++input;
                if (!isdigit((unsigned char)*input)) return NULL;
                uint64_t magnitude = 0, limit = (uint64_t)INT64_MAX + (unsigned)negative;
                while (isdigit((unsigned char)*input))
                {
                    unsigned digit = (unsigned)(*input++ - '0');
                    if (magnitude > (limit - digit) / 10) return NULL;
                    magnitude = magnitude * 10 + digit;
                }
                time_t epoch = negative ? (time_t)(0 - magnitude) : (time_t)magnitude;
                if (!localtime_r(&epoch, &state->date)) return NULL;
                state->fields = YEAR | MONTH | MDAY | YDAY | WDAY;
                break;
            }
            default: return NULL;
        }
        if (!input) return NULL;
        if (composite && !(input = calendar_parse(state, input, composite, depth + 1))) return NULL;
    }
    return input;
}

static int calendar_finish(calendar_parser_t *state)
{
    struct tm *date = &state->date;
    if (state->relative >= 0 || state->century >= 0)
    {
        int year = state->relative >= 0 ? state->relative : 0;
        year += state->century >= 0 ? state->century * 100 : year <= 68 ? 2000 : 1900;
        date->tm_year = year - 1900; state->fields |= YEAR;
    }
    if (state->ampm >= 0 && state->hour12) date->tm_hour += state->ampm * 12;
    struct tm derived = {.tm_year = date->tm_year, .tm_mon = 0, .tm_mday = 1};
    int calculate = 0;
    if (state->iso_year >= 0 && state->iso_week >= 0 && (state->fields & WDAY))
    {
        derived.tm_year = state->iso_year - 1900; derived.tm_mday = 4;
        time_t first = timegm(&derived);
        int days = (state->iso_week - 1) * 7 - (derived.tm_wday + 6) % 7 + (date->tm_wday + 6) % 7;
        time_t thursday = first + (time_t)(days + 3 - (date->tm_wday + 6) % 7) * 86400;
        struct tm check;
        if (!gmtime_r(&thursday, &check) || check.tm_year != state->iso_year - 1900) return 0;
        first += (time_t)days * 86400;
        if (!gmtime_r(&first, &derived)) return 0;
        calculate = 1;
    }
    else if ((state->fields & YEAR) && !(state->fields & YDAY) && state->week >= 0 && (state->fields & WDAY))
    {
        timegm(&derived);
        int first = (7 - (derived.tm_wday - state->week_start + 7) % 7) % 7;
        derived.tm_mday = 1 + first + (state->week - 1) * 7 + (date->tm_wday - state->week_start + 7) % 7;
        timegm(&derived); calculate = 1;
    }
    else if ((state->fields & (YEAR | YDAY)) == (YEAR | YDAY))
    {
        derived.tm_mday += date->tm_yday;
        timegm(&derived);
        if (derived.tm_year != date->tm_year) return 0;
        calculate = 1;
    }
    else if ((state->fields & (YEAR | MONTH | MDAY)) == (YEAR | MONTH | MDAY))
    {
        derived.tm_mon = date->tm_mon; derived.tm_mday = date->tm_mday;
        timegm(&derived);
        if (derived.tm_mon != date->tm_mon || derived.tm_mday != date->tm_mday) return 0;
        calculate = 1;
    }
    if (calculate)
    {
        if (!(state->fields & MONTH)) date->tm_mon = derived.tm_mon;
        if (!(state->fields & MDAY)) date->tm_mday = derived.tm_mday;
        if (!(state->fields & YDAY)) date->tm_yday = derived.tm_yday;
        if (!(state->fields & WDAY)) date->tm_wday = derived.tm_wday;
        date->tm_year = derived.tm_year;
    }
    return 1;
}

char *strptime(const char *input, const char *format, struct tm *date)
{
    if (!input || !format || !date) { errno = EINVAL; return NULL; }
    int saved = errno;
    calendar_parser_t state = {.date = *date, .century = -1, .relative = -1, .iso_year = -1,
                              .iso_week = -1, .week = -1, .ampm = -1};
    const char *end = calendar_parse(&state, input, format, 0);
    if (end && !calendar_finish(&state)) end = NULL;
    if (end) *date = state.date;
    errno = saved;
    return (char *)end;
}
