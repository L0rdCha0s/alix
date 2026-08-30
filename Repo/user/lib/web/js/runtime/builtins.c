#include "web/js/runtime/runtime_internal.h"
#include "ctype.h"
#include "libc.h"
#include "math.h"
#include "stdio.h"
#ifdef TTF_HOST_BUILD
#include <sys/time.h>
#include <time.h>
#else
#include "usyscall.h"
#endif

typedef struct
{
    bool exists;
    js_value_t value;
    bool writable;
    bool enumerable;
    bool configurable;
    bool is_accessor;
    js_value_t getter;
    js_value_t setter;
} js_prop_desc_t;

typedef struct
{
    char *pattern;
    size_t pattern_len;
    char *flags;
    size_t flags_len;
    js_object_t *object;
    int realm_id;
    bool is_subclass;
} js_regexp_t;

typedef struct
{
    double time_ms;
} js_date_t;

typedef struct
{
    int64_t years;
    int64_t months;
    int64_t weeks;
    int64_t days;
    int64_t hours;
    int64_t minutes;
    int64_t seconds;
    int64_t milliseconds;
    int64_t microseconds;
    int64_t nanoseconds;
} js_temporal_duration_t;

typedef struct
{
    js_bigint_t *epoch_nanoseconds;
} js_temporal_instant_t;

typedef struct
{
    int id;
} js_realm_t;

struct js_bound_fn
{
    js_value_t target;
    js_value_t this_arg;
    js_value_t *args;
    size_t arg_count;
    js_value_t *owned_target_user_data;
    struct js_bound_fn *next;
};

static int js_realm_next_id = 1;
static js_realm_t js_default_realm = {0};

#define JS_DATE_MS_PER_SECOND 1000LL
#define JS_DATE_MS_PER_MINUTE (60LL * JS_DATE_MS_PER_SECOND)
#define JS_DATE_MS_PER_HOUR   (60LL * JS_DATE_MS_PER_MINUTE)
#define JS_DATE_MS_PER_DAY    (24LL * JS_DATE_MS_PER_HOUR)
#define JS_DATE_TIME_MAX      8640000000000000.0

static const int64_t JS_TEMPORAL_MAX_YMW = 4294967295LL;
static const int64_t JS_TEMPORAL_MAX_SECONDS = 9007199254740991LL;
static const __int128 JS_TEMPORAL_MAX_TOTAL_NS =
    (((__int128)JS_TEMPORAL_MAX_SECONDS) * 1000000000LL) + 999999999LL;
static const char JS_TEMPORAL_INSTANT_MAX_NS[] = "8640000000000000000000";
static const char JS_TEMPORAL_TAG[] = "Temporal";
static const char JS_TEMPORAL_TAG_DURATION[] = "Temporal.Duration";
static const char JS_TEMPORAL_TAG_INSTANT[] = "Temporal.Instant";
static const char JS_TEMPORAL_TAG_PLAIN_DATE[] = "Temporal.PlainDate";
static const char JS_TEMPORAL_TAG_PLAIN_TIME[] = "Temporal.PlainTime";
static const char JS_TEMPORAL_TAG_PLAIN_DATE_TIME[] = "Temporal.PlainDateTime";
static const char JS_TEMPORAL_TAG_ZONED_DATE_TIME[] = "Temporal.ZonedDateTime";
static const char JS_TEMPORAL_TAG_PLAIN_YEAR_MONTH[] = "Temporal.PlainYearMonth";
static const char JS_TEMPORAL_TAG_PLAIN_MONTH_DAY[] = "Temporal.PlainMonthDay";
static const char JS_TEMPORAL_TAG_NOW[] = "Temporal.Now";

static const char JS_TEMPORAL_DURATION_FIELD_YEARS[] = "years";
static const char JS_TEMPORAL_DURATION_FIELD_MONTHS[] = "months";
static const char JS_TEMPORAL_DURATION_FIELD_WEEKS[] = "weeks";
static const char JS_TEMPORAL_DURATION_FIELD_DAYS[] = "days";
static const char JS_TEMPORAL_DURATION_FIELD_HOURS[] = "hours";
static const char JS_TEMPORAL_DURATION_FIELD_MINUTES[] = "minutes";
static const char JS_TEMPORAL_DURATION_FIELD_SECONDS[] = "seconds";
static const char JS_TEMPORAL_DURATION_FIELD_MILLISECONDS[] = "milliseconds";
static const char JS_TEMPORAL_DURATION_FIELD_MICROSECONDS[] = "microseconds";
static const char JS_TEMPORAL_DURATION_FIELD_NANOSECONDS[] = "nanoseconds";
static const char JS_TEMPORAL_DURATION_FIELD_SIGN[] = "sign";
static const char JS_TEMPORAL_DURATION_FIELD_BLANK[] = "blank";

static const char JS_TEMPORAL_INSTANT_FIELD_EPOCH_NANOSECONDS[] = "epochNanoseconds";
static const char JS_TEMPORAL_INSTANT_FIELD_EPOCH_MILLISECONDS[] = "epochMilliseconds";

static const char *JS_DATE_MONTH_NAMES[12] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char *JS_DATE_DAY_NAMES[7] =
{
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

typedef struct
{
    int64_t year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    int millisecond;
    int weekday;
} js_date_parts_t;

static double js_date_trunc(double value)
{
    return (value < 0.0) ? ceil(value) : floor(value);
}

static double js_date_time_clip(double value)
{
    if (js_is_nan(value) || value > JS_DATE_TIME_MAX || value < -JS_DATE_TIME_MAX)
    {
        return js_nan();
    }
    return js_date_trunc(value);
}

static int64_t js_date_floor_div(int64_t a, int64_t b)
{
    int64_t q = a / b;
    int64_t r = a % b;
    if (r < 0)
    {
        q -= 1;
    }
    return q;
}

static int64_t js_date_mod(int64_t a, int64_t b)
{
    int64_t r = a % b;
    if (r < 0)
    {
        r += b;
    }
    return r;
}

static bool js_date_is_leap_year(int64_t year)
{
    if ((year % 4) != 0)
    {
        return false;
    }
    if ((year % 100) != 0)
    {
        return true;
    }
    return (year % 400) == 0;
}

static int js_date_days_in_month(int64_t year, int month)
{
    static const int days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12)
    {
        return 31;
    }
    if (month == 2 && js_date_is_leap_year(year))
    {
        return 29;
    }
    return days[month - 1];
}

static int64_t js_date_days_from_civil(int64_t year, int month, int day)
{
    int64_t y = year;
    int64_t m = month;
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    uint64_t yoe = (uint64_t)(y - era * 400);
    uint64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + (uint64_t)day - 1;
    uint64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static void js_date_civil_from_days(int64_t z, int64_t *year, int *month, int *day)
{
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    uint64_t doe = (uint64_t)(z - era * 146097);
    uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = (int64_t)yoe + era * 400;
    uint64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint64_t mp = (5 * doy + 2) / 153;
    uint64_t d = doy - (153 * mp + 2) / 5 + 1;
    uint64_t m = mp + (mp < 10 ? 3 :  -9);
    y += (m <= 2);
    if (year)
    {
        *year = y;
    }
    if (month)
    {
        *month = (int)m;
    }
    if (day)
    {
        *day = (int)d;
    }
}

static double js_date_now_ms(void)
{
#ifdef TTF_HOST_BUILD
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0)
    {
        return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
    }
    return 0.0;
#else
    return (double)sys_time_millis();
#endif
}

static bool js_date_breakdown(double time_ms, js_date_parts_t *out)
{
    if (!out)
    {
        return false;
    }
    if (js_is_nan(time_ms))
    {
        return false;
    }
    int64_t ms = (int64_t)js_date_trunc(time_ms);
    int64_t days = js_date_floor_div(ms, JS_DATE_MS_PER_DAY);
    int64_t time_part = ms - days * JS_DATE_MS_PER_DAY;
    if (time_part < 0)
    {
        time_part += JS_DATE_MS_PER_DAY;
        days -= 1;
    }
    int64_t year = 0;
    int month = 0;
    int day = 0;
    js_date_civil_from_days(days, &year, &month, &day);
    int weekday = (int)js_date_mod(days + 4, 7);

    int64_t hour = time_part / JS_DATE_MS_PER_HOUR;
    time_part -= hour * JS_DATE_MS_PER_HOUR;
    int64_t minute = time_part / JS_DATE_MS_PER_MINUTE;
    time_part -= minute * JS_DATE_MS_PER_MINUTE;
    int64_t second = time_part / JS_DATE_MS_PER_SECOND;
    time_part -= second * JS_DATE_MS_PER_SECOND;

    out->year = year;
    out->month = month;
    out->day = day;
    out->hour = (int)hour;
    out->minute = (int)minute;
    out->second = (int)second;
    out->millisecond = (int)time_part;
    out->weekday = weekday;
    return true;
}

static bool js_date_double_to_int64(double value, int64_t *out)
{
    if (!out)
    {
        return false;
    }
    if (js_is_nan(value) || value > (double)INT64_MAX || value < (double)INT64_MIN)
    {
        return false;
    }
    *out = (int64_t)js_date_trunc(value);
    return true;
}

static double js_date_make_time_value(int64_t year,
                                      int64_t month,
                                      int64_t day,
                                      int64_t hour,
                                      int64_t minute,
                                      int64_t second,
                                      int64_t millisecond)
{
    int64_t y = year;
    int64_t m = month;
    int64_t month_adjust = js_date_floor_div(m, 12);
    if (month_adjust != 0)
    {
        y += month_adjust;
        m -= month_adjust * 12;
    }
    if (m < 0)
    {
        m += 12;
        y -= 1;
    }
    int64_t day_base = js_date_days_from_civil(y, (int)(m + 1), 1);
    int64_t day_count = day_base + (day - 1);
    int64_t time_part = hour * JS_DATE_MS_PER_HOUR +
                        minute * JS_DATE_MS_PER_MINUTE +
                        second * JS_DATE_MS_PER_SECOND +
                        millisecond;
    double total = (double)day_count * (double)JS_DATE_MS_PER_DAY + (double)time_part;
    return total;
}

static void js_date_trim(const char **text, size_t *len)
{
    if (!text || !len || !*text)
    {
        return;
    }
    const char *start = *text;
    size_t length = *len;
    while (length && isspace((unsigned char)start[0]))
    {
        start++;
        length--;
    }
    while (length && isspace((unsigned char)start[length - 1]))
    {
        length--;
    }
    *text = start;
    *len = length;
}

static bool js_date_parse_digits(const char *text,
                                 size_t len,
                                 size_t *index,
                                 int count,
                                 int *out)
{
    if (!text || !index || !out)
    {
        return false;
    }
    if (*index + (size_t)count > len)
    {
        return false;
    }
    int value = 0;
    for (int i = 0; i < count; ++i)
    {
        char c = text[*index + (size_t)i];
        if (!isdigit((unsigned char)c))
        {
            return false;
        }
        value = value * 10 + (c - '0');
    }
    *index += (size_t)count;
    *out = value;
    return true;
}

static bool js_date_parse_year_token(const char *text,
                                     size_t len,
                                     size_t *index,
                                     int64_t *out)
{
    if (!text || !index || !out)
    {
        return false;
    }
    size_t i = *index;
    int sign = 1;
    if (i < len && (text[i] == '+' || text[i] == '-'))
    {
        sign = (text[i] == '-') ? -1 : 1;
        i++;
    }
    size_t start = i;
    while (i < len && isdigit((unsigned char)text[i]))
    {
        i++;
    }
    size_t digits = i - start;
    if (digits < 4)
    {
        return false;
    }
    int64_t value = 0;
    for (size_t j = start; j < i; ++j)
    {
        value = value * 10 + (text[j] - '0');
    }
    *index = i;
    *out = (int64_t)sign * value;
    return true;
}

static bool js_date_parse_month_name(const char *text,
                                     size_t len,
                                     size_t *index,
                                     int *out_month)
{
    if (!text || !index || !out_month)
    {
        return false;
    }
    if (*index + 3 > len)
    {
        return false;
    }
    for (int i = 0; i < 12; ++i)
    {
        if (strncmp(text + *index, JS_DATE_MONTH_NAMES[i], 3) == 0)
        {
            *out_month = i + 1;
            *index += 3;
            return true;
        }
    }
    return false;
}

static bool js_date_parse_iso(const char *text, size_t len, double *out)
{
    if (!text || !out)
    {
        return false;
    }
    size_t i = 0;
    int sign = 1;
    int64_t year = 0;
    if (i < len && (text[i] == '+' || text[i] == '-'))
    {
        sign = (text[i] == '-') ? -1 : 1;
        i++;
        int value = 0;
        if (!js_date_parse_digits(text, len, &i, 6, &value))
        {
            return false;
        }
        if (sign < 0 && value == 0)
        {
            return false;
        }
        year = (int64_t)sign * value;
    }
    else
    {
        int value = 0;
        if (!js_date_parse_digits(text, len, &i, 4, &value))
        {
            return false;
        }
        year = value;
    }
    if (i >= len || text[i] != '-')
    {
        return false;
    }
    i++;
    int month = 0;
    if (!js_date_parse_digits(text, len, &i, 2, &month))
    {
        return false;
    }
    if (month < 1 || month > 12)
    {
        return false;
    }
    if (i >= len || text[i] != '-')
    {
        return false;
    }
    i++;
    int day = 0;
    if (!js_date_parse_digits(text, len, &i, 2, &day))
    {
        return false;
    }
    if (day < 1 || day > js_date_days_in_month(year, month))
    {
        return false;
    }

    int hour = 0;
    int minute = 0;
    int second = 0;
    int millisecond = 0;
    if (i < len && (text[i] == 'T' || text[i] == 't'))
    {
        i++;
        if (!js_date_parse_digits(text, len, &i, 2, &hour))
        {
            return false;
        }
        if (i >= len || text[i] != ':')
        {
            return false;
        }
        i++;
        if (!js_date_parse_digits(text, len, &i, 2, &minute))
        {
            return false;
        }
        if (i < len && text[i] == ':')
        {
            i++;
            if (!js_date_parse_digits(text, len, &i, 2, &second))
            {
                return false;
            }
        }
        if (i < len && text[i] == '.')
        {
            i++;
            int digits = 0;
            int value = 0;
            while (i < len && isdigit((unsigned char)text[i]) && digits < 3)
            {
                value = value * 10 + (text[i] - '0');
                digits++;
                i++;
            }
            while (digits < 3)
            {
                value *= 10;
                digits++;
            }
            while (i < len && isdigit((unsigned char)text[i]))
            {
                i++;
            }
            millisecond = value;
        }
    }

    if (hour > 24 || minute > 59 || second > 59 || millisecond > 999)
    {
        return false;
    }
    if (hour == 24 && (minute != 0 || second != 0 || millisecond != 0))
    {
        return false;
    }

    int offset_minutes = 0;
    bool has_tz = false;
    if (i < len)
    {
        if (text[i] == 'Z' || text[i] == 'z')
        {
            has_tz = true;
            i++;
        }
        else if (text[i] == '+' || text[i] == '-')
        {
            has_tz = true;
            int offset_sign = (text[i] == '-') ? -1 : 1;
            i++;
            int off_hour = 0;
            int off_min = 0;
            if (!js_date_parse_digits(text, len, &i, 2, &off_hour))
            {
                return false;
            }
            if (i < len && text[i] == ':')
            {
                i++;
                if (!js_date_parse_digits(text, len, &i, 2, &off_min))
                {
                    return false;
                }
            }
            else if (i + 1 < len && isdigit((unsigned char)text[i]) && isdigit((unsigned char)text[i + 1]))
            {
                if (!js_date_parse_digits(text, len, &i, 2, &off_min))
                {
                    return false;
                }
            }
            offset_minutes = offset_sign * (off_hour * 60 + off_min);
        }
        else
        {
            return false;
        }
    }
    if (i != len)
    {
        return false;
    }

    int64_t day_adjust = day;
    int64_t hour_adjust = hour;
    if (hour == 24)
    {
        hour_adjust = 0;
        day_adjust += 1;
    }

    double total = js_date_make_time_value(year,
                                           (int64_t)(month - 1),
                                           day_adjust,
                                           hour_adjust,
                                           minute,
                                           second,
                                           millisecond);
    if (has_tz)
    {
        total -= (double)offset_minutes * (double)JS_DATE_MS_PER_MINUTE;
    }
    total = js_date_time_clip(total);
    *out = total;
    return true;
}

static bool js_date_parse_rfc1123(const char *text, size_t len, double *out)
{
    if (!text || !out)
    {
        return false;
    }
    size_t i = 0;
    if (len < 4)
    {
        return false;
    }
    i += 3;
    if (i >= len || text[i] != ',')
    {
        return false;
    }
    i++;
    if (i >= len || text[i] != ' ')
    {
        return false;
    }
    i++;
    int day = 0;
    if (!js_date_parse_digits(text, len, &i, 2, &day))
    {
        return false;
    }
    if (i >= len || text[i] != ' ')
    {
        return false;
    }
    i++;
    int month = 0;
    if (!js_date_parse_month_name(text, len, &i, &month))
    {
        return false;
    }
    if (i >= len || text[i] != ' ')
    {
        return false;
    }
    i++;
    int64_t year = 0;
    if (!js_date_parse_year_token(text, len, &i, &year))
    {
        return false;
    }
    if (i >= len || text[i] != ' ')
    {
        return false;
    }
    i++;
    int hour = 0;
    int minute = 0;
    int second = 0;
    if (!js_date_parse_digits(text, len, &i, 2, &hour))
    {
        return false;
    }
    if (i >= len || text[i] != ':')
    {
        return false;
    }
    i++;
    if (!js_date_parse_digits(text, len, &i, 2, &minute))
    {
        return false;
    }
    if (i >= len || text[i] != ':')
    {
        return false;
    }
    i++;
    if (!js_date_parse_digits(text, len, &i, 2, &second))
    {
        return false;
    }
    if (hour > 23 || minute > 59 || second > 59)
    {
        return false;
    }
    if (i + 4 > len || strncmp(text + i, " GMT", 4) != 0)
    {
        return false;
    }
    i += 4;
    if (i != len)
    {
        return false;
    }
    if (day < 1 || day > js_date_days_in_month(year, month))
    {
        return false;
    }
    double total = js_date_make_time_value(year,
                                           (int64_t)(month - 1),
                                           day,
                                           hour,
                                           minute,
                                           second,
                                           0);
    total = js_date_time_clip(total);
    *out = total;
    return true;
}

static bool js_date_parse_to_string(const char *text, size_t len, double *out)
{
    if (!text || !out)
    {
        return false;
    }
    size_t i = 0;
    if (len < 4)
    {
        return false;
    }
    i += 3;
    if (i >= len || text[i] != ' ')
    {
        return false;
    }
    i++;
    int month = 0;
    if (!js_date_parse_month_name(text, len, &i, &month))
    {
        return false;
    }
    if (i >= len || text[i] != ' ')
    {
        return false;
    }
    i++;
    int day = 0;
    if (!js_date_parse_digits(text, len, &i, 2, &day))
    {
        return false;
    }
    if (i >= len || text[i] != ' ')
    {
        return false;
    }
    i++;
    int64_t year = 0;
    if (!js_date_parse_year_token(text, len, &i, &year))
    {
        return false;
    }
    if (i >= len || text[i] != ' ')
    {
        return false;
    }
    i++;
    int hour = 0;
    int minute = 0;
    int second = 0;
    if (!js_date_parse_digits(text, len, &i, 2, &hour))
    {
        return false;
    }
    if (i >= len || text[i] != ':')
    {
        return false;
    }
    i++;
    if (!js_date_parse_digits(text, len, &i, 2, &minute))
    {
        return false;
    }
    if (i >= len || text[i] != ':')
    {
        return false;
    }
    i++;
    if (!js_date_parse_digits(text, len, &i, 2, &second))
    {
        return false;
    }
    if (hour > 23 || minute > 59 || second > 59)
    {
        return false;
    }
    if (i >= len || text[i] != ' ')
    {
        return false;
    }
    i++;
    if (i + 3 > len || strncmp(text + i, "GMT", 3) != 0)
    {
        return false;
    }
    i += 3;
    if (i >= len)
    {
        return false;
    }
    int offset_minutes = 0;
    if (text[i] == '+' || text[i] == '-')
    {
        int offset_sign = (text[i] == '-') ? -1 : 1;
        i++;
        int off_hour = 0;
        int off_min = 0;
        if (!js_date_parse_digits(text, len, &i, 2, &off_hour))
        {
            return false;
        }
        if (!js_date_parse_digits(text, len, &i, 2, &off_min))
        {
            return false;
        }
        offset_minutes = offset_sign * (off_hour * 60 + off_min);
    }
    else
    {
        return false;
    }
    if (day < 1 || day > js_date_days_in_month(year, month))
    {
        return false;
    }
    double total = js_date_make_time_value(year,
                                           (int64_t)(month - 1),
                                           day,
                                           hour,
                                           minute,
                                           second,
                                           0);
    total -= (double)offset_minutes * (double)JS_DATE_MS_PER_MINUTE;
    total = js_date_time_clip(total);
    *out = total;
    return true;
}

static double js_date_parse_string(const char *text, size_t len)
{
    if (!text)
    {
        return js_nan();
    }
    const char *ptr = text;
    size_t use_len = len;
    if (use_len == (size_t)-1)
    {
        use_len = strlen(text);
    }
    js_date_trim(&ptr, &use_len);
    if (use_len == 0)
    {
        return js_nan();
    }
    double result = js_nan();
    if (js_date_parse_iso(ptr, use_len, &result))
    {
        return result;
    }
    if (js_date_parse_rfc1123(ptr, use_len, &result))
    {
        return result;
    }
    if (js_date_parse_to_string(ptr, use_len, &result))
    {
        return result;
    }
    return js_nan();
}

static void js_date_finalize(void *user_data)
{
    js_date_t *date = (js_date_t *)user_data;
    if (!date)
    {
        return;
    }
    js_free(date);
}

static void js_temporal_duration_finalize(void *user_data)
{
    js_temporal_duration_t *duration = (js_temporal_duration_t *)user_data;
    if (!duration)
    {
        return;
    }
    js_free(duration);
}

static void js_temporal_instant_finalize(void *user_data)
{
    js_temporal_instant_t *instant = (js_temporal_instant_t *)user_data;
    if (!instant)
    {
        return;
    }
    if (instant->epoch_nanoseconds)
    {
        js_bigint_destroy(instant->epoch_nanoseconds);
    }
    js_free(instant);
}

static bool js_object_define_data_property(js_object_t *obj,
                                           const char *name,
                                           const js_value_t *value,
                                           bool writable,
                                           bool enumerable,
                                           bool configurable,
                                           char **error_message)
{
    if (!obj || !name || !value)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_property_t *prop = js_object_find_property(obj, name);
    if (!prop)
    {
        if (!js_object_set_slot(obj, name, value))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        prop = js_object_find_property(obj, name);
        if (!prop)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    if (prop->is_accessor)
    {
        js_value_destroy(&prop->getter);
        js_value_destroy(&prop->setter);
        prop->getter = js_value_make_undefined_internal();
        prop->setter = js_value_make_undefined_internal();
        prop->is_accessor = false;
    }
    js_value_destroy(&prop->value);
    if (!js_value_copy(&prop->value, value))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    prop->writable = writable;
    prop->enumerable = enumerable;
    prop->configurable = configurable;
    return true;
}

static bool js_object_define_accessor_property(js_object_t *obj,
                                               const char *name,
                                               const js_value_t *getter,
                                               const js_value_t *setter,
                                               bool enumerable,
                                               bool configurable,
                                               char **error_message)
{
    if (!obj || !name)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_property_t *prop = js_object_find_property(obj, name);
    if (!prop)
    {
        js_value_t init = js_value_make_undefined_internal();
        if (!js_object_set_slot(obj, name, &init))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        prop = js_object_find_property(obj, name);
        if (!prop)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    if (!prop->is_accessor)
    {
        js_value_destroy(&prop->value);
        prop->value = js_value_make_undefined_internal();
    }
    prop->is_accessor = true;
    prop->writable = false;
    prop->enumerable = enumerable;
    prop->configurable = configurable;
    js_value_destroy(&prop->getter);
    js_value_destroy(&prop->setter);
    prop->getter = js_value_make_undefined_internal();
    prop->setter = js_value_make_undefined_internal();
    if (getter && getter->type != JS_VALUE_UNDEFINED)
    {
        if (!js_value_copy(&prop->getter, getter))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    if (setter && setter->type != JS_VALUE_UNDEFINED)
    {
        if (!js_value_copy(&prop->setter, setter))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    return true;
}

static bool js_object_define_native_method(js_object_t *obj,
                                           const char *name,
                                           js_native_fn_t fn,
                                           void *user_data,
                                           bool writable,
                                           bool enumerable,
                                           bool configurable,
                                           char **error_message)
{
    if (!obj || !name || !fn)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_t value;
    value.type = JS_VALUE_NATIVE_FN;
    value.as.native.fn = fn;
    value.as.native.user_data = user_data;
    return js_object_define_data_property(obj, name, &value, writable, enumerable, configurable, error_message);
}

static bool js_temporal_duration_get(js_runtime_t *rt,
                                     void *user_data,
                                     const char *name,
                                     js_value_t *out,
                                     char **error_message);
static bool js_temporal_duration_proto_get(js_runtime_t *rt,
                                           void *user_data,
                                           const char *name,
                                           js_value_t *out,
                                           char **error_message);
static bool js_temporal_instant_get(js_runtime_t *rt,
                                    void *user_data,
                                    const char *name,
                                    js_value_t *out,
                                    char **error_message);
static bool js_temporal_instant_proto_get(js_runtime_t *rt,
                                          void *user_data,
                                          const char *name,
                                          js_value_t *out,
                                          char **error_message);
static bool js_temporal_plain_date_get(js_runtime_t *rt,
                                       void *user_data,
                                       const char *name,
                                       js_value_t *out,
                                       char **error_message);
static bool js_temporal_plain_date_proto_get(js_runtime_t *rt,
                                             void *user_data,
                                             const char *name,
                                             js_value_t *out,
                                             char **error_message);
static bool js_temporal_plain_time_get(js_runtime_t *rt,
                                       void *user_data,
                                       const char *name,
                                       js_value_t *out,
                                       char **error_message);
static bool js_temporal_plain_time_proto_get(js_runtime_t *rt,
                                             void *user_data,
                                             const char *name,
                                             js_value_t *out,
                                             char **error_message);
static bool js_temporal_plain_date_time_get(js_runtime_t *rt,
                                            void *user_data,
                                            const char *name,
                                            js_value_t *out,
                                            char **error_message);
static bool js_temporal_plain_date_time_proto_get(js_runtime_t *rt,
                                                  void *user_data,
                                                  const char *name,
                                                  js_value_t *out,
                                                  char **error_message);
static bool js_temporal_zoned_date_time_get(js_runtime_t *rt,
                                            void *user_data,
                                            const char *name,
                                            js_value_t *out,
                                            char **error_message);
static bool js_temporal_zoned_date_time_proto_get(js_runtime_t *rt,
                                                  void *user_data,
                                                  const char *name,
                                                  js_value_t *out,
                                                  char **error_message);
static bool js_temporal_plain_year_month_get(js_runtime_t *rt,
                                             void *user_data,
                                             const char *name,
                                             js_value_t *out,
                                             char **error_message);
static bool js_temporal_plain_year_month_proto_get(js_runtime_t *rt,
                                                   void *user_data,
                                                   const char *name,
                                                   js_value_t *out,
                                                   char **error_message);
static bool js_temporal_plain_month_day_get(js_runtime_t *rt,
                                            void *user_data,
                                            const char *name,
                                            js_value_t *out,
                                            char **error_message);
static bool js_temporal_plain_month_day_proto_get(js_runtime_t *rt,
                                                  void *user_data,
                                                  const char *name,
                                                  js_value_t *out,
                                                  char **error_message);
static bool js_temporal_now_get(js_runtime_t *rt,
                                void *user_data,
                                const char *name,
                                js_value_t *out,
                                char **error_message);

static bool js_set_get(js_runtime_t *rt,
                       void *user_data,
                       const char *name,
                       js_value_t *out,
                       char **error_message);
static bool js_set_iterator_get(js_runtime_t *rt,
                                void *user_data,
                                const char *name,
                                js_value_t *out,
                                char **error_message);
static bool js_set_iterator_proto_get(js_runtime_t *rt,
                                      void *user_data,
                                      const char *name,
                                      js_value_t *out,
                                      char **error_message);
static js_object_t *js_get_set_iterator_proto(js_runtime_t *rt);
static bool js_object_proto_get(js_runtime_t *rt,
                                void *user_data,
                                const char *name,
                                js_value_t *out,
                                char **error_message);
static bool js_function_proto_get(js_runtime_t *rt,
                                  void *user_data,
                                  const char *name,
                                  js_value_t *out,
                                  char **error_message);
static bool js_array_proto_get(js_runtime_t *rt,
                               void *user_data,
                               const char *name,
                               js_value_t *out,
                               char **error_message);
static bool js_date_get(js_runtime_t *rt,
                        void *user_data,
                        const char *name,
                        js_value_t *out,
                        char **error_message);
static bool js_date_proto_get(js_runtime_t *rt,
                              void *user_data,
                              const char *name,
                              js_value_t *out,
                              char **error_message);
static bool js_math_get(js_runtime_t *rt,
                        void *user_data,
                        const char *name,
                        js_value_t *out,
                        char **error_message);
js_object_t *js_get_object_proto(js_runtime_t *rt);
js_object_t *js_get_function_proto(js_runtime_t *rt);
js_object_t *js_get_array_proto(js_runtime_t *rt);
js_object_t *js_get_math_object(js_runtime_t *rt);
js_object_t *js_get_number_proto(js_runtime_t *rt);
js_object_t *js_get_symbol_proto(js_runtime_t *rt);
static bool js_iterator_map_get(js_runtime_t *rt,
                                void *user_data,
                                const char *name,
                                js_value_t *out,
                                char **error_message);
static bool js_iterator_map_next(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message);
static bool js_iterator_map_return(js_runtime_t *rt,
                                   size_t argc,
                                   const js_value_t *argv,
                                   void *user_data,
                                   js_value_t *out,
                                   char **error_message);
static void js_iterator_map_finalize(void *user_data);

typedef enum
{
    JS_REGEXP_ATOM_LITERAL = 0,
    JS_REGEXP_ATOM_CLASS
} js_regexp_atom_kind_t;

typedef struct
{
    js_regexp_atom_kind_t kind;
    char literal;
    const char *class_pattern;
    size_t class_len;
} js_regexp_atom_t;

static bool js_regexp_get(js_runtime_t *rt,
                          void *user_data,
                          const char *name,
                          js_value_t *out,
                          char **error_message);

static bool js_call_accessor_getter(js_runtime_t *rt,
                                    js_object_t *object,
                                    const char *name,
                                    char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !object || !name)
    {
        return true;
    }
    js_property_t *prop = js_object_find_property(object, name);
    if (!prop || !prop->is_accessor)
    {
        return true;
    }
    if (prop->getter.type == JS_VALUE_FUNCTION || prop->getter.type == JS_VALUE_NATIVE_FN)
    {
        js_value_t result = js_value_make_undefined_internal();
        char *err = NULL;
        bool ok = js_call_value(rt, &prop->getter, 0, NULL, &result, &err);
        js_value_destroy(&result);
        if (!ok)
        {
            if (err)
            {
                if (error_message)
                {
                    *error_message = err;
                }
                else
                {
                    js_free(err);
                }
            }
            return false;
        }
        js_free(err);
    }
    return true;
}

static bool js_regexp_has_duplicate_named_groups(const char *pattern, size_t len, bool *out_dup)
{
    if (out_dup)
    {
        *out_dup = false;
    }
    if (!out_dup || !pattern || len == 0)
    {
        return true;
    }
    char **names = NULL;
    size_t count = 0;
    size_t cap = 0;
    bool in_class = false;
    for (size_t i = 0; i < len; ++i)
    {
        char c = pattern[i];
        if (c == '\\' && i + 1 < len)
        {
            ++i;
            continue;
        }
        if (c == '[')
        {
            in_class = true;
            continue;
        }
        if (c == ']' && in_class)
        {
            in_class = false;
            continue;
        }
        if (!in_class && c == '|')
        {
            for (size_t n = 0; n < count; ++n)
            {
                js_free(names[n]);
            }
            js_free(names);
            names = NULL;
            count = 0;
            cap = 0;
            continue;
        }
        if (!in_class && c == '(' && i + 2 < len &&
            pattern[i + 1] == '?' && pattern[i + 2] == '<')
        {
            if (i + 3 < len && (pattern[i + 3] == '=' || pattern[i + 3] == '!'))
            {
                continue;
            }
            size_t name_start = i + 3;
            size_t j = name_start;
            while (j < len && pattern[j] != '>')
            {
                ++j;
            }
            if (j >= len)
            {
                break;
            }
            size_t name_len = j - name_start;
            if (name_len == 0)
            {
                i = j;
                continue;
            }
            for (size_t n = 0; n < count; ++n)
            {
                if (strlen(names[n]) == name_len &&
                    strncmp(names[n], pattern + name_start, name_len) == 0)
                {
                    for (size_t k = 0; k < count; ++k)
                    {
                        js_free(names[k]);
                    }
                    js_free(names);
                    *out_dup = true;
                    return true;
                }
            }
            if (count == cap)
            {
                size_t next_cap = cap ? cap * 2 : 4;
                char **next = (char **)js_realloc(names, next_cap * sizeof(*next));
                if (!next)
                {
                    for (size_t k = 0; k < count; ++k)
                    {
                        js_free(names[k]);
                    }
                    js_free(names);
                    return false;
                }
                names = next;
                cap = next_cap;
            }
            char *copy = js_strdup_len(pattern + name_start, name_len);
            if (!copy)
            {
                for (size_t k = 0; k < count; ++k)
                {
                    js_free(names[k]);
                }
                js_free(names);
                return false;
            }
            names[count++] = copy;
            i = j;
        }
    }
    for (size_t n = 0; n < count; ++n)
    {
        js_free(names[n]);
    }
    js_free(names);
    return true;
}

static bool js_regexp_pattern_valid(const char *pattern, size_t len, bool unicode)
{
    if (!pattern || len == 0)
    {
        return true;
    }
    bool in_class = false;
    bool escaped = false;
    bool has_token = false;
    for (size_t i = 0; i < len; ++i)
    {
        char c = pattern[i];
        if (escaped)
        {
            escaped = false;
            has_token = true;
            continue;
        }
    if (c == '\\')
    {
        if (unicode && i + 1 < len)
        {
            char next = pattern[i + 1];
            if (next >= '0' && next <= '9')
            {
                return false;
            }
        }
        escaped = true;
        continue;
    }
        if (in_class)
        {
            if (c == ']')
            {
                in_class = false;
                has_token = true;
            }
            continue;
        }
        if (c == '[')
        {
            in_class = true;
            continue;
        }
        if (c == '|')
        {
            has_token = false;
            continue;
        }
        if (c == '?' || c == '*' || c == '+')
        {
            if (!has_token)
            {
                return false;
            }
            has_token = false;
            continue;
        }
        if (c == '{')
        {
            size_t j = i + 1;
            size_t m = 0;
            bool has_m = false;
            while (j < len && pattern[j] >= '0' && pattern[j] <= '9')
            {
                has_m = true;
                m = m * 10u + (size_t)(pattern[j] - '0');
                j++;
            }
            if (!has_m)
            {
                if (unicode)
                {
                    return false;
                }
                has_token = true;
                continue;
            }
            if (!has_token)
            {
                return false;
            }
            if (j >= len)
            {
                return false;
            }
            if (pattern[j] == '}')
            {
                has_token = false;
                i = j;
                continue;
            }
            if (pattern[j] == ',')
            {
                j++;
                size_t n = 0;
                bool has_n = false;
                while (j < len && pattern[j] >= '0' && pattern[j] <= '9')
                {
                    has_n = true;
                    n = n * 10u + (size_t)(pattern[j] - '0');
                    j++;
                }
                if (j >= len || pattern[j] != '}')
                {
                    return false;
                }
                if (has_n && n < m)
                {
                    return false;
                }
                has_token = false;
                i = j;
                continue;
            }
            return false;
        }
        if (c == ')')
        {
            has_token = true;
            continue;
        }
        has_token = true;
    }
    return !escaped && !in_class;
}

static void js_realm_finalize(void *user_data)
{
    js_realm_t *realm = (js_realm_t *)user_data;
    if (!realm)
    {
        return;
    }
    js_free(realm);
}

static bool js_append_utf8(char *buf, size_t cap, size_t *len, unsigned int code)
{
    if (!buf || !len)
    {
        return false;
    }
    if (code <= 0x7F)
    {
        if (*len + 1 > cap)
        {
            return false;
        }
        buf[(*len)++] = (char)code;
        return true;
    }
    if (code <= 0x7FF)
    {
        if (*len + 2 > cap)
        {
            return false;
        }
        buf[(*len)++] = (char)(0xC0 | (code >> 6));
        buf[(*len)++] = (char)(0x80 | (code & 0x3F));
        return true;
    }
    if (*len + 3 > cap)
    {
        return false;
    }
    buf[(*len)++] = (char)(0xE0 | (code >> 12));
    buf[(*len)++] = (char)(0x80 | ((code >> 6) & 0x3F));
    buf[(*len)++] = (char)(0x80 | (code & 0x3F));
    return true;
}

static bool js_utf8_next(const char *data, size_t len, size_t *index, unsigned int *out)
{
    if (!data || !index || !out || *index >= len)
    {
        return false;
    }
    unsigned char c = (unsigned char)data[*index];
    if (c < 0x80)
    {
        *out = c;
        (*index)++;
        return true;
    }
    if ((c & 0xE0) == 0xC0 && *index + 1 < len)
    {
        unsigned char c1 = (unsigned char)data[*index + 1];
        if ((c1 & 0xC0) == 0x80)
        {
            *out = ((unsigned int)(c & 0x1F) << 6) | (unsigned int)(c1 & 0x3F);
            *index += 2;
            return true;
        }
    }
    if ((c & 0xF0) == 0xE0 && *index + 2 < len)
    {
        unsigned char c1 = (unsigned char)data[*index + 1];
        unsigned char c2 = (unsigned char)data[*index + 2];
        if ((c1 & 0xC0) == 0x80 && (c2 & 0xC0) == 0x80)
        {
            *out = ((unsigned int)(c & 0x0F) << 12) |
                   ((unsigned int)(c1 & 0x3F) << 6) |
                   (unsigned int)(c2 & 0x3F);
            *index += 3;
            return true;
        }
    }
    if ((c & 0xF8) == 0xF0 && *index + 3 < len)
    {
        unsigned char c1 = (unsigned char)data[*index + 1];
        unsigned char c2 = (unsigned char)data[*index + 2];
        unsigned char c3 = (unsigned char)data[*index + 3];
        if ((c1 & 0xC0) == 0x80 && (c2 & 0xC0) == 0x80 && (c3 & 0xC0) == 0x80)
        {
            *out = ((unsigned int)(c & 0x07) << 18) |
                   ((unsigned int)(c1 & 0x3F) << 12) |
                   ((unsigned int)(c2 & 0x3F) << 6) |
                   (unsigned int)(c3 & 0x3F);
            *index += 4;
            return true;
        }
    }
    *out = c;
    (*index)++;
    return true;
}

static bool js_is_unescaped_char(unsigned int code)
{
    if ((code >= 'A' && code <= 'Z') ||
        (code >= 'a' && code <= 'z') ||
        (code >= '0' && code <= '9'))
    {
        return true;
    }
    switch (code)
    {
        case '@':
        case '*':
        case '_':
        case '+':
        case '-':
        case '.':
        case '/':
            return true;
        default:
            return false;
    }
}

static bool js_append_escape_hex(char *buf, size_t cap, size_t *len, unsigned int code, bool wide)
{
    static const char hex[] = "0123456789ABCDEF";
    if (!buf || !len)
    {
        return false;
    }
    if (wide)
    {
        if (*len + 6 > cap)
        {
            return false;
        }
        buf[(*len)++] = '%';
        buf[(*len)++] = 'u';
        buf[(*len)++] = hex[(code >> 12) & 0xF];
        buf[(*len)++] = hex[(code >> 8) & 0xF];
        buf[(*len)++] = hex[(code >> 4) & 0xF];
        buf[(*len)++] = hex[code & 0xF];
        return true;
    }
    if (*len + 3 > cap)
    {
        return false;
    }
    buf[(*len)++] = '%';
    buf[(*len)++] = hex[(code >> 4) & 0xF];
    buf[(*len)++] = hex[code & 0xF];
    return true;
}

static bool js_regexp_parse_octal(const char *pattern, size_t len, size_t *index, int *out_char)
{
    if (!pattern || !index || !out_char || *index >= len)
    {
        return false;
    }
    size_t i = *index;
    int value = 0;
    size_t count = 0;
    while (i < len && count < 3 && pattern[i] >= '0' && pattern[i] <= '7')
    {
        value = (value * 8) + (pattern[i] - '0');
        ++i;
        ++count;
    }
    if (count == 0)
    {
        return false;
    }
    *out_char = value & 0xFF;
    *index = i;
    return true;
}

static bool js_regexp_match_class(const char *pattern, size_t len, char target)
{
    if (!pattern || len == 0)
    {
        return false;
    }
    size_t i = 0;
    bool negate = false;
    if (pattern[i] == '^')
    {
        negate = true;
        ++i;
    }
    bool matched = false;
    while (i < len)
    {
        int start_char = 0;
        bool special_digit = false;
        bool special_nondigit = false;
        bool special_word = false;
        bool special_nonword = false;
        if (pattern[i] == '\\' && i + 1 < len)
        {
            char esc = pattern[i + 1];
            if (esc == 'd')
            {
                special_digit = true;
                i += 2;
            }
            else if (esc == 'D')
            {
                special_nondigit = true;
                i += 2;
            }
            else if (esc == 'w')
            {
                special_word = true;
                i += 2;
            }
            else if (esc == 'W')
            {
                special_nonword = true;
                i += 2;
            }
            else if (esc == 'c')
            {
                if (i + 2 < len)
                {
                    char ctrl = pattern[i + 2];
                    if ((ctrl >= 'A' && ctrl <= 'Z') || (ctrl >= 'a' && ctrl <= 'z'))
                    {
                        start_char = (int)(((unsigned char)ctrl) % 32);
                        i += 3;
                    }
                    else
                    {
                        start_char = '\\';
                        i += 1;
                    }
                }
                else
                {
                    start_char = '\\';
                    i += 1;
                }
            }
            else if (esc >= '0' && esc <= '7')
            {
                size_t oct_index = i + 1;
                if (js_regexp_parse_octal(pattern, len, &oct_index, &start_char))
                {
                    i = oct_index;
                }
                else
                {
                    start_char = esc;
                    i += 2;
                }
            }
            else
            {
                start_char = esc;
                i += 2;
            }
        }
        else
        {
            start_char = (unsigned char)pattern[i];
            ++i;
        }
        if (special_digit || special_nondigit)
        {
            bool is_digit = (target >= '0' && target <= '9');
            if ((special_digit && is_digit) || (special_nondigit && !is_digit))
            {
                matched = true;
            }
            continue;
        }
        if (special_word || special_nonword)
        {
            bool is_word = (isalnum((unsigned char)target) != 0 || target == '_');
            if ((special_word && is_word) || (special_nonword && !is_word))
            {
                matched = true;
            }
            continue;
        }
        if (i + 1 < len && pattern[i] == '-')
        {
            int end_char = 0;
            ++i;
            if (i < len && pattern[i] == '\\' && i + 1 < len)
            {
                char esc = pattern[i + 1];
                if (esc >= '0' && esc <= '7')
                {
                    size_t oct_index = i + 1;
                    if (js_regexp_parse_octal(pattern, len, &oct_index, &end_char))
                    {
                        i = oct_index;
                    }
                    else
                    {
                        end_char = esc;
                        i += 2;
                    }
                }
                else if (esc == 'c')
                {
                    if (i + 2 < len)
                    {
                        char ctrl = pattern[i + 2];
                        if ((ctrl >= 'A' && ctrl <= 'Z') || (ctrl >= 'a' && ctrl <= 'z'))
                        {
                            end_char = (int)(((unsigned char)ctrl) % 32);
                            i += 3;
                        }
                        else
                        {
                            end_char = '\\';
                            i += 1;
                        }
                    }
                    else
                    {
                        end_char = '\\';
                        i += 1;
                    }
                }
                else
                {
                    end_char = esc;
                    i += 2;
                }
            }
            else if (i < len)
            {
                end_char = (unsigned char)pattern[i];
                ++i;
            }
            if (start_char <= target && target <= end_char)
            {
                matched = true;
            }
            continue;
        }
        if (start_char == (unsigned char)target)
        {
            matched = true;
        }
    }
    return negate ? !matched : matched;
}

static bool js_regexp_build_literal(const char *pattern,
                                    size_t pattern_len,
                                    char **out,
                                    size_t *out_len)
{
    if (!out || !out_len)
    {
        return false;
    }
    *out = NULL;
    *out_len = 0;
    if (!pattern)
    {
        return true;
    }
    char *buf = (char *)js_malloc(pattern_len + 1);
    if (!buf)
    {
        return false;
    }
    size_t written = 0;
    size_t i = 0;
    while (i < pattern_len)
    {
        if (pattern[i] == '\\' && i + 1 < pattern_len)
        {
            if (pattern[i + 1] >= '0' && pattern[i + 1] <= '9')
            {
                i += 2;
                while (i < pattern_len && pattern[i] >= '0' && pattern[i] <= '9')
                {
                    ++i;
                }
                continue;
            }
            if (i + 2 < pattern_len && pattern[i + 1] == 'k' && pattern[i + 2] == '<')
            {
                buf[written++] = 'k';
                buf[written++] = '<';
                i += 3;
                while (i < pattern_len)
                {
                    buf[written++] = pattern[i];
                    if (pattern[i] == '>')
                    {
                        ++i;
                        break;
                    }
                    ++i;
                }
                continue;
            }
            buf[written++] = pattern[i + 1];
            i += 2;
            continue;
        }
        if (pattern[i] == '(' && i + 2 < pattern_len &&
            pattern[i + 1] == '?' && pattern[i + 2] == '<' &&
            !(i + 3 < pattern_len && (pattern[i + 3] == '=' || pattern[i + 3] == '!')))
        {
            i += 3;
            while (i < pattern_len && pattern[i] != '>')
            {
                ++i;
            }
            if (i < pattern_len && pattern[i] == '>')
            {
                ++i;
            }
            continue;
        }
        if (pattern[i] == '(' && i + 3 < pattern_len &&
            pattern[i + 1] == '?' && pattern[i + 2] == '<' &&
            (pattern[i + 3] == '=' || pattern[i + 3] == '!'))
        {
            i += 4;
            int depth = 1;
            while (i < pattern_len && depth > 0)
            {
                if (pattern[i] == '\\' && i + 1 < pattern_len)
                {
                    i += 2;
                    continue;
                }
                if (pattern[i] == '(')
                {
                    depth++;
                }
                else if (pattern[i] == ')')
                {
                    depth--;
                    if (depth == 0)
                    {
                        ++i;
                        break;
                    }
                }
                ++i;
            }
            continue;
        }
        if (pattern[i] == '(' || pattern[i] == ')')
        {
            ++i;
            continue;
        }
        buf[written++] = pattern[i++];
    }
    buf[written] = '\0';
    *out = buf;
    *out_len = written;
    return true;
}

static bool js_regexp_flags_valid(const char *flags, size_t len)
{
    if (!flags || len == 0)
    {
        return true;
    }
    bool seen_g = false;
    bool seen_i = false;
    bool seen_m = false;
    bool seen_s = false;
    bool seen_u = false;
    bool seen_y = false;
    for (size_t i = 0; i < len; ++i)
    {
        char c = flags[i];
        switch (c)
        {
            case 'g':
                if (seen_g)
                {
                    return false;
                }
                seen_g = true;
                break;
            case 'i':
                if (seen_i)
                {
                    return false;
                }
                seen_i = true;
                break;
            case 'm':
                if (seen_m)
                {
                    return false;
                }
                seen_m = true;
                break;
            case 's':
                if (seen_s)
                {
                    return false;
                }
                seen_s = true;
                break;
            case 'u':
                if (seen_u)
                {
                    return false;
                }
                seen_u = true;
                break;
            case 'y':
                if (seen_y)
                {
                    return false;
                }
                seen_y = true;
                break;
            default:
                return false;
        }
    }
    return true;
}

static js_object_t *js_get_set_iterator_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->set_iterator_proto)
    {
        return rt->set_iterator_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_set_iterator_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->set_iterator_proto = proto_val.as.object;
    js_object_retain(rt->set_iterator_proto);
    js_value_destroy(&proto_val);
    return rt->set_iterator_proto;
}

static bool js_set_iterator_proto_get(js_runtime_t *rt,
                                      void *user_data,
                                      const char *name,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (name && strcmp(name, "Symbol.toStringTag") == 0)
    {
        return js_value_make_cstring(out, "Set Iterator");
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_set_iterator_next(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!js_value_make_host_object(out, NULL, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_t value = js_value_make_undefined_internal();
    js_value_t done = js_value_make_bool(true);
    (void)js_object_set_slot(out->as.object, "value", &value);
    (void)js_object_set_slot(out->as.object, "done", &done);
    return true;
}

static bool js_set_iterator_get(js_runtime_t *rt,
                                void *user_data,
                                const char *name,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (name && strcmp(name, "next") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_set_iterator_next;
        out->as.native.user_data = NULL;
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_set_get(js_runtime_t *rt,
                       void *user_data,
                       const char *name,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (name && strcmp(name, "Symbol.iterator") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_set_iterator;
        out->as.native.user_data = NULL;
        return true;
    }
    if (name && strcmp(name, "size") == 0)
    {
        *out = js_value_make_number(0.0);
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

typedef struct
{
    js_value_t iterator;
    js_value_t next_method;
    js_value_t mapper;
    size_t index;
    size_t array_index;
    bool done;
    bool closed;
    bool executing;
    bool is_array;
} js_iterator_map_state_t;

static bool js_iterator_make_result(js_value_t *out, const js_value_t *value, bool done)
{
    if (!out)
    {
        return false;
    }
    if (!js_value_make_host_object(out, NULL, NULL, NULL, NULL))
    {
        return false;
    }
    js_value_t done_val = js_value_make_bool(done);
    if (!js_object_set_slot(out->as.object, "done", &done_val))
    {
        js_value_destroy(out);
        return false;
    }
    if (!js_object_set_slot(out->as.object, "value", value))
    {
        js_value_destroy(out);
        return false;
    }
    return true;
}

static bool js_iterator_close(js_runtime_t *rt, const js_value_t *iterator, char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!iterator || iterator->type != JS_VALUE_OBJECT || !iterator->as.object)
    {
        return true;
    }
    js_value_t return_method = js_value_make_undefined_internal();
    char *err = NULL;
    if (!js_object_get_property(rt, iterator->as.object, "return", &return_method, &err))
    {
        if (error_message)
        {
            *error_message = err ? err : js_strdup("iterator close failed");
        }
        else
        {
            js_free(err);
        }
        return false;
    }
    if (return_method.type == JS_VALUE_FUNCTION || return_method.type == JS_VALUE_NATIVE_FN)
    {
        js_value_t result = js_value_make_undefined_internal();
        bool ok = js_call_value(rt, &return_method, 0, NULL, &result, &err);
        js_value_destroy(&result);
        js_value_destroy(&return_method);
        if (!ok)
        {
            if (error_message)
            {
                *error_message = err ? err : js_strdup("iterator close failed");
            }
            else
            {
                js_free(err);
            }
            return false;
        }
        js_free(err);
        return true;
    }
    js_value_destroy(&return_method);
    return true;
}

static bool js_iterator_map_get(js_runtime_t *rt,
                                void *user_data,
                                const char *name,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (name && strcmp(name, "next") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_iterator_map_next;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "return") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_iterator_map_return;
        out->as.native.user_data = user_data;
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_iterator_map_next(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_iterator_map_state_t *state = (js_iterator_map_state_t *)user_data;
    if (!state)
    {
        if (error_message)
        {
            *error_message = js_strdup("iterator state missing");
        }
        return false;
    }
    if (state->executing)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: generator is running");
        }
        return false;
    }
    if (state->done)
    {
        js_value_t undef = js_value_make_undefined_internal();
        return js_iterator_make_result(out, &undef, true);
    }
    state->executing = true;

    js_value_t value = js_value_make_undefined_internal();
    if (state->is_array)
    {
        if (state->iterator.type != JS_VALUE_ARRAY || !state->iterator.as.array)
        {
            if (error_message)
            {
                *error_message = js_strdup("iterator invalid");
            }
            state->executing = false;
            return false;
        }
        if (state->array_index >= state->iterator.as.array->length)
        {
            state->done = true;
            js_value_t undef = js_value_make_undefined_internal();
            state->executing = false;
            return js_iterator_make_result(out, &undef, true);
        }
        if (!js_array_get(state->iterator.as.array, state->array_index, &value))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            state->executing = false;
            return false;
        }
        state->array_index++;
    }
    else
    {
        js_value_t next_result = js_value_make_undefined_internal();
        char *err = NULL;
        if (!js_call_value(rt, &state->next_method, 0, NULL, &next_result, &err))
        {
            if (error_message)
            {
                *error_message = err ? err : js_strdup("iterator next failed");
            }
            else
            {
                js_free(err);
            }
            state->executing = false;
            return false;
        }
        if (next_result.type != JS_VALUE_OBJECT || !next_result.as.object)
        {
            js_value_destroy(&next_result);
            if (error_message)
            {
                *error_message = js_strdup("TypeError: iterator result is not an object");
            }
            state->executing = false;
            return false;
        }
        js_value_t done_val = js_value_make_undefined_internal();
        char *done_err = NULL;
        if (!js_object_get_property(rt, next_result.as.object, "done", &done_val, &done_err))
        {
            js_value_destroy(&next_result);
            if (error_message)
            {
                *error_message = done_err ? done_err : js_strdup("iterator done failed");
            }
            else
            {
                js_free(done_err);
            }
            state->executing = false;
            return false;
        }
        bool done = js_value_is_truthy(&done_val);
        js_value_destroy(&done_val);
        if (done)
        {
            js_value_destroy(&next_result);
            state->done = true;
            js_value_t undef = js_value_make_undefined_internal();
            state->executing = false;
            return js_iterator_make_result(out, &undef, true);
        }
        js_value_t value_val = js_value_make_undefined_internal();
        char *value_err = NULL;
        if (!js_object_get_property(rt, next_result.as.object, "value", &value_val, &value_err))
        {
            js_value_destroy(&next_result);
            if (error_message)
            {
                *error_message = value_err ? value_err : js_strdup("iterator value failed");
            }
            else
            {
                js_free(value_err);
            }
            state->executing = false;
            return false;
        }
        js_value_destroy(&next_result);
        value = value_val;
    }

    js_value_t mapped = js_value_make_undefined_internal();
    if (state->mapper.type == JS_VALUE_FUNCTION || state->mapper.type == JS_VALUE_NATIVE_FN)
    {
        js_value_t index_val = js_value_make_number((double)state->index);
        js_value_t *call_args = (js_value_t *)js_calloc(2, sizeof(*call_args));
        if (!call_args)
        {
            js_value_destroy(&value);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            state->executing = false;
            return false;
        }
        call_args[0] = value;
        call_args[1] = index_val;
        char *call_err = NULL;
        bool ok = js_call_value(rt, &state->mapper, 2, call_args, &mapped, &call_err);
        js_value_destroy(&call_args[0]);
        js_value_destroy(&call_args[1]);
        js_free(call_args);
        if (!ok)
        {
            char *close_err = NULL;
            bool closed_ok = js_iterator_close(rt, &state->iterator, &close_err);
            if (!closed_ok)
            {
                if (error_message)
                {
                    *error_message = close_err ? close_err : js_strdup("iterator close failed");
                }
                else
                {
                    js_free(close_err);
                }
                js_free(call_err);
                state->executing = false;
                return false;
            }
            if (error_message)
            {
                *error_message = call_err ? call_err : js_strdup("mapper failed");
            }
            else
            {
                js_free(call_err);
            }
            state->executing = false;
            return false;
        }
        state->index++;
    }
    else
    {
        js_value_destroy(&value);
        if (error_message)
        {
            *error_message = js_strdup("TypeError: mapper is not callable");
        }
        state->executing = false;
        return false;
    }

    bool ok = js_iterator_make_result(out, &mapped, false);
    js_value_destroy(&mapped);
    if (!ok)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        state->executing = false;
        return false;
    }
    state->executing = false;
    return true;
}

static bool js_iterator_map_return(js_runtime_t *rt,
                                   size_t argc,
                                   const js_value_t *argv,
                                   void *user_data,
                                   js_value_t *out,
                                   char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_iterator_map_state_t *state = (js_iterator_map_state_t *)user_data;
    if (!state)
    {
        if (error_message)
        {
            *error_message = js_strdup("iterator state missing");
        }
        return false;
    }
    if (!state->done && !state->closed)
    {
        char *close_err = NULL;
        state->closed = true;
        state->done = true;
        if (!js_iterator_close(rt, &state->iterator, &close_err))
        {
            if (error_message)
            {
                *error_message = close_err ? close_err : js_strdup("iterator close failed");
            }
            else
            {
                js_free(close_err);
            }
            return false;
        }
        js_free(close_err);
    }
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    js_value_t undef = js_value_make_undefined_internal();
    if (!value)
    {
        value = &undef;
    }
    if (!js_iterator_make_result(out, value, true))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static void js_iterator_map_finalize(void *user_data)
{
    js_iterator_map_state_t *state = (js_iterator_map_state_t *)user_data;
    if (!state)
    {
        return;
    }
    js_value_destroy(&state->iterator);
    js_value_destroy(&state->next_method);
    js_value_destroy(&state->mapper);
    js_free(state);
}

js_object_t *js_get_iterator_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->iterator_proto)
    {
        return rt->iterator_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, NULL, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->iterator_proto = proto_val.as.object;
    js_object_retain(rt->iterator_proto);
    js_value_destroy(&proto_val);
    js_value_t map_val;
    memset(&map_val, 0, sizeof(map_val));
    map_val.type = JS_VALUE_NATIVE_FN;
    map_val.as.native.fn = js_builtin_iterator_map;
    map_val.as.native.user_data = NULL;
    (void)js_object_set_slot(rt->iterator_proto, "map", &map_val);
    return rt->iterator_proto;
}

static bool js_object_proto_get(js_runtime_t *rt,
                                void *user_data,
                                const char *name,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (strcmp(name, "hasOwnProperty") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_object_has_own_property;
        out->as.native.user_data = NULL;
        return true;
    }
    if (strcmp(name, "propertyIsEnumerable") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_object_property_is_enumerable;
        out->as.native.user_data = NULL;
        return true;
    }
    if (strcmp(name, "toString") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_object_to_string;
        out->as.native.user_data = NULL;
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_function_proto_get(js_runtime_t *rt,
                                  void *user_data,
                                  const char *name,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (strcmp(name, "call") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_function_call;
        out->as.native.user_data = NULL;
        return true;
    }
    if (strcmp(name, "length") == 0)
    {
        *out = js_value_make_number(0.0);
        return true;
    }
    if (strcmp(name, "bind") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_function_bind;
        out->as.native.user_data = NULL;
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_array_proto_get(js_runtime_t *rt,
                               void *user_data,
                               const char *name,
                               js_value_t *out,
                               char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (strcmp(name, "join") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_array_join;
        out->as.native.user_data = NULL;
        return true;
    }
    if (strcmp(name, "length") == 0)
    {
        *out = js_value_make_number(0.0);
        return true;
    }
    if (strcmp(name, "push") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_array_push;
        out->as.native.user_data = NULL;
        return true;
    }
    if (strcmp(name, "map") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_array_map;
        out->as.native.user_data = NULL;
        return true;
    }
    if (strcmp(name, "forEach") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_array_for_each;
        out->as.native.user_data = NULL;
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_date_get(js_runtime_t *rt,
                        void *user_data,
                        const char *name,
                        js_value_t *out,
                        char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_date_proto_get(js_runtime_t *rt,
                              void *user_data,
                              const char *name,
                              js_value_t *out,
                              char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    js_native_fn_t fn = NULL;
    if (strcmp(name, "constructor") == 0)
    {
        fn = js_builtin_date;
    }
    else if (strcmp(name, "toString") == 0)
    {
        fn = js_date_proto_to_string;
    }
    else if (strcmp(name, "toDateString") == 0)
    {
        fn = js_date_proto_to_date_string;
    }
    else if (strcmp(name, "toTimeString") == 0)
    {
        fn = js_date_proto_to_time_string;
    }
    else if (strcmp(name, "toUTCString") == 0)
    {
        fn = js_date_proto_to_utc_string;
    }
    else if (strcmp(name, "toGMTString") == 0)
    {
        fn = js_date_proto_to_utc_string;
    }
    else if (strcmp(name, "toISOString") == 0)
    {
        fn = js_date_proto_to_iso_string;
    }
    else if (strcmp(name, "toJSON") == 0)
    {
        fn = js_date_proto_to_json;
    }
    else if (strcmp(name, "valueOf") == 0)
    {
        fn = js_date_proto_value_of;
    }
    else if (strcmp(name, "getTime") == 0)
    {
        fn = js_date_proto_get_time;
    }
    else if (strcmp(name, "getFullYear") == 0)
    {
        fn = js_date_proto_get_full_year;
    }
    else if (strcmp(name, "getUTCFullYear") == 0)
    {
        fn = js_date_proto_get_utc_full_year;
    }
    else if (strcmp(name, "getMonth") == 0)
    {
        fn = js_date_proto_get_month;
    }
    else if (strcmp(name, "getUTCMonth") == 0)
    {
        fn = js_date_proto_get_utc_month;
    }
    else if (strcmp(name, "getDate") == 0)
    {
        fn = js_date_proto_get_date;
    }
    else if (strcmp(name, "getUTCDate") == 0)
    {
        fn = js_date_proto_get_utc_date;
    }
    else if (strcmp(name, "getDay") == 0)
    {
        fn = js_date_proto_get_day;
    }
    else if (strcmp(name, "getUTCDay") == 0)
    {
        fn = js_date_proto_get_utc_day;
    }
    else if (strcmp(name, "getHours") == 0)
    {
        fn = js_date_proto_get_hours;
    }
    else if (strcmp(name, "getUTCHours") == 0)
    {
        fn = js_date_proto_get_utc_hours;
    }
    else if (strcmp(name, "getMinutes") == 0)
    {
        fn = js_date_proto_get_minutes;
    }
    else if (strcmp(name, "getUTCMinutes") == 0)
    {
        fn = js_date_proto_get_utc_minutes;
    }
    else if (strcmp(name, "getSeconds") == 0)
    {
        fn = js_date_proto_get_seconds;
    }
    else if (strcmp(name, "getUTCSeconds") == 0)
    {
        fn = js_date_proto_get_utc_seconds;
    }
    else if (strcmp(name, "getMilliseconds") == 0)
    {
        fn = js_date_proto_get_milliseconds;
    }
    else if (strcmp(name, "getUTCMilliseconds") == 0)
    {
        fn = js_date_proto_get_utc_milliseconds;
    }
    else if (strcmp(name, "getTimezoneOffset") == 0)
    {
        fn = js_date_proto_get_timezone_offset;
    }
    else if (strcmp(name, "setTime") == 0)
    {
        fn = js_date_proto_set_time;
    }
    else if (strcmp(name, "setFullYear") == 0)
    {
        fn = js_date_proto_set_full_year;
    }
    else if (strcmp(name, "setUTCFullYear") == 0)
    {
        fn = js_date_proto_set_utc_full_year;
    }
    else if (strcmp(name, "setMonth") == 0)
    {
        fn = js_date_proto_set_month;
    }
    else if (strcmp(name, "setUTCMonth") == 0)
    {
        fn = js_date_proto_set_utc_month;
    }
    else if (strcmp(name, "setDate") == 0)
    {
        fn = js_date_proto_set_date;
    }
    else if (strcmp(name, "setUTCDate") == 0)
    {
        fn = js_date_proto_set_utc_date;
    }
    else if (strcmp(name, "setHours") == 0)
    {
        fn = js_date_proto_set_hours;
    }
    else if (strcmp(name, "setUTCHours") == 0)
    {
        fn = js_date_proto_set_utc_hours;
    }
    else if (strcmp(name, "setMinutes") == 0)
    {
        fn = js_date_proto_set_minutes;
    }
    else if (strcmp(name, "setUTCMinutes") == 0)
    {
        fn = js_date_proto_set_utc_minutes;
    }
    else if (strcmp(name, "setSeconds") == 0)
    {
        fn = js_date_proto_set_seconds;
    }
    else if (strcmp(name, "setUTCSeconds") == 0)
    {
        fn = js_date_proto_set_utc_seconds;
    }
    else if (strcmp(name, "setMilliseconds") == 0)
    {
        fn = js_date_proto_set_milliseconds;
    }
    else if (strcmp(name, "setUTCMilliseconds") == 0)
    {
        fn = js_date_proto_set_utc_milliseconds;
    }
    else if (strcmp(name, "getYear") == 0)
    {
        fn = js_date_proto_get_year;
    }
    else if (strcmp(name, "setYear") == 0)
    {
        fn = js_date_proto_set_year;
    }
    if (fn)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = fn;
        out->as.native.user_data = NULL;
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_math_get(js_runtime_t *rt,
                        void *user_data,
                        const char *name,
                        js_value_t *out,
                        char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (strcmp(name, "pow") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_builtin_math_pow;
        out->as.native.user_data = NULL;
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

js_object_t *js_get_object_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->object_proto)
    {
        return rt->object_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_object_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->object_proto = proto_val.as.object;
    js_object_retain(rt->object_proto);
    js_value_destroy(&proto_val);
    js_value_t null_val = js_value_make_null();
    (void)js_object_set_slot(rt->object_proto, "__proto__", &null_val);
    return rt->object_proto;
}

js_object_t *js_get_function_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->function_proto)
    {
        return rt->function_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_function_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->function_proto = proto_val.as.object;
    js_object_retain(rt->function_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->function_proto, "__proto__", &proto_slot);
    }
    return rt->function_proto;
}

js_object_t *js_get_array_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->array_proto)
    {
        return rt->array_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_array_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->array_proto = proto_val.as.object;
    js_object_retain(rt->array_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->array_proto, "__proto__", &proto_slot);
    }
    return rt->array_proto;
}

js_object_t *js_get_math_object(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->math_object)
    {
        return rt->math_object;
    }
    js_value_t math_val;
    if (!js_value_make_host_object(&math_val, js_math_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->math_object = math_val.as.object;
    js_object_retain(rt->math_object);
    js_value_destroy(&math_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->math_object, "__proto__", &proto_slot);
    }
    return rt->math_object;
}

js_object_t *js_get_date_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->date_proto)
    {
        return rt->date_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_date_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->date_proto = proto_val.as.object;
    js_object_retain(rt->date_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->date_proto, "__proto__", &proto_slot);
    }
    return rt->date_proto;
}

js_object_t *js_get_number_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->number_proto)
    {
        return rt->number_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, NULL, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->number_proto = proto_val.as.object;
    js_object_retain(rt->number_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->number_proto, "__proto__", &proto_slot);
    }
    return rt->number_proto;
}

static bool js_string_proto_get(js_runtime_t *rt,
                                void *user_data,
                                const char *name,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    js_native_fn_t fn = NULL;
    if (strcmp(name, "constructor") == 0)
    {
        fn = js_builtin_string;
    }
    else if (strcmp(name, "anchor") == 0)
    {
        fn = js_string_proto_anchor;
    }
    else if (strcmp(name, "big") == 0)
    {
        fn = js_string_proto_big;
    }
    else if (strcmp(name, "blink") == 0)
    {
        fn = js_string_proto_blink;
    }
    else if (strcmp(name, "bold") == 0)
    {
        fn = js_string_proto_bold;
    }
    else if (strcmp(name, "fixed") == 0)
    {
        fn = js_string_proto_fixed;
    }
    else if (strcmp(name, "fontcolor") == 0)
    {
        fn = js_string_proto_fontcolor;
    }
    else if (strcmp(name, "fontsize") == 0)
    {
        fn = js_string_proto_fontsize;
    }
    else if (strcmp(name, "italics") == 0)
    {
        fn = js_string_proto_italics;
    }
    else if (strcmp(name, "link") == 0)
    {
        fn = js_string_proto_link;
    }
    else if (strcmp(name, "matchAll") == 0)
    {
        fn = js_string_proto_match_all;
    }
    else if (strcmp(name, "replace") == 0)
    {
        fn = js_string_proto_replace;
    }
    else if (strcmp(name, "replaceAll") == 0)
    {
        fn = js_string_proto_replace_all;
    }
    else if (strcmp(name, "search") == 0)
    {
        fn = js_string_proto_search;
    }
    else if (strcmp(name, "small") == 0)
    {
        fn = js_string_proto_small;
    }
    else if (strcmp(name, "split") == 0)
    {
        fn = js_string_proto_split;
    }
    else if (strcmp(name, "substr") == 0)
    {
        fn = js_string_proto_substr;
    }
    else if (strcmp(name, "strike") == 0)
    {
        fn = js_string_proto_strike;
    }
    else if (strcmp(name, "sub") == 0)
    {
        fn = js_string_proto_sub;
    }
    else if (strcmp(name, "sup") == 0)
    {
        fn = js_string_proto_sup;
    }
    if (fn)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = fn;
        out->as.native.user_data = NULL;
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

js_object_t *js_get_string_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->string_proto)
    {
        return rt->string_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_string_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->string_proto = proto_val.as.object;
    js_object_retain(rt->string_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->string_proto, "__proto__", &proto_slot);
    }
    return rt->string_proto;
}

js_object_t *js_get_symbol_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->symbol_proto)
    {
        return rt->symbol_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, NULL, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->symbol_proto = proto_val.as.object;
    js_object_retain(rt->symbol_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->symbol_proto, "__proto__", &proto_slot);
    }
    return rt->symbol_proto;
}

js_object_t *js_get_temporal_now_object(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_now_object)
    {
        return rt->temporal_now_object;
    }
    js_value_t now_val;
    if (!js_value_make_host_object(&now_val, js_temporal_now_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_now_object = now_val.as.object;
    js_object_retain(rt->temporal_now_object);
    js_value_destroy(&now_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_now_object, "__proto__", &proto_slot);
    }
    if (!js_object_define_native_method(rt->temporal_now_object,
                                        "instant",
                                        js_temporal_now_instant,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_now_object,
                                        "plainDateISO",
                                        js_temporal_now_plain_date_iso,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_now_object,
                                        "plainTimeISO",
                                        js_temporal_now_plain_time_iso,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_now_object,
                                        "plainDateTimeISO",
                                        js_temporal_now_plain_date_time_iso,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_now_object,
                                        "zonedDateTimeISO",
                                        js_temporal_now_zoned_date_time_iso,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_now_object,
                                        "timeZoneId",
                                        js_temporal_now_time_zone_id,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL))
    {
        js_object_release(rt->temporal_now_object);
        rt->temporal_now_object = NULL;
        return NULL;
    }
    js_value_t tag = js_value_make_undefined_internal();
    if (!js_value_make_cstring(&tag, JS_TEMPORAL_TAG_NOW) ||
        !js_object_define_data_property(rt->temporal_now_object,
                                        "Symbol.toStringTag",
                                        &tag,
                                        false,
                                        false,
                                        true,
                                        NULL))
    {
        js_value_destroy(&tag);
        js_object_release(rt->temporal_now_object);
        rt->temporal_now_object = NULL;
        return NULL;
    }
    js_value_destroy(&tag);
    return rt->temporal_now_object;
}

js_object_t *js_get_temporal_object(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_object)
    {
        return rt->temporal_object;
    }
    js_value_t obj_val;
    if (!js_value_make_host_object(&obj_val, NULL, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_object = obj_val.as.object;
    js_object_retain(rt->temporal_object);
    js_value_destroy(&obj_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_object, "__proto__", &proto_slot);
    }
    if (!js_object_define_native_method(rt->temporal_object,
                                        "Duration",
                                        js_builtin_temporal_duration,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_object,
                                        "Instant",
                                        js_builtin_temporal_instant,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_object,
                                        "PlainDate",
                                        js_builtin_temporal_plain_date,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_object,
                                        "PlainTime",
                                        js_builtin_temporal_plain_time,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_object,
                                        "PlainDateTime",
                                        js_builtin_temporal_plain_date_time,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_object,
                                        "ZonedDateTime",
                                        js_builtin_temporal_zoned_date_time,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_object,
                                        "PlainYearMonth",
                                        js_builtin_temporal_plain_year_month,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_object,
                                        "PlainMonthDay",
                                        js_builtin_temporal_plain_month_day,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL))
    {
        js_object_release(rt->temporal_object);
        rt->temporal_object = NULL;
        return NULL;
    }
    js_object_t *now_obj = js_get_temporal_now_object(rt);
    if (!now_obj)
    {
        js_object_release(rt->temporal_object);
        rt->temporal_object = NULL;
        return NULL;
    }
    js_value_t now_val;
    memset(&now_val, 0, sizeof(now_val));
    now_val.type = JS_VALUE_OBJECT;
    now_val.as.object = now_obj;
    js_object_retain(now_obj);
    if (!js_object_define_data_property(rt->temporal_object,
                                        "Now",
                                        &now_val,
                                        true,
                                        false,
                                        true,
                                        NULL))
    {
        js_value_destroy(&now_val);
        js_object_release(rt->temporal_object);
        rt->temporal_object = NULL;
        return NULL;
    }
    js_value_destroy(&now_val);
    js_value_t tag = js_value_make_undefined_internal();
    if (!js_value_make_cstring(&tag, JS_TEMPORAL_TAG) ||
        !js_object_define_data_property(rt->temporal_object,
                                        "Symbol.toStringTag",
                                        &tag,
                                        false,
                                        false,
                                        true,
                                        NULL))
    {
        js_value_destroy(&tag);
        js_object_release(rt->temporal_object);
        rt->temporal_object = NULL;
        return NULL;
    }
    js_value_destroy(&tag);
    return rt->temporal_object;
}

js_object_t *js_get_temporal_duration_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_duration_proto)
    {
        return rt->temporal_duration_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_temporal_duration_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_duration_proto = proto_val.as.object;
    js_object_retain(rt->temporal_duration_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_duration_proto, "__proto__", &proto_slot);
    }
    if (!js_object_define_native_method(rt->temporal_duration_proto,
                                        "constructor",
                                        js_builtin_temporal_duration,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "negated",
                                        js_temporal_duration_negated,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "abs",
                                        js_temporal_duration_abs,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "toString",
                                        js_temporal_duration_to_string,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "toJSON",
                                        js_temporal_duration_to_json,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "toLocaleString",
                                        js_temporal_duration_to_locale_string,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "valueOf",
                                        js_temporal_duration_value_of,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "with",
                                        js_temporal_duration_with,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "add",
                                        js_temporal_duration_add,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "subtract",
                                        js_temporal_duration_subtract,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "round",
                                        js_temporal_duration_round,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_duration_proto,
                                        "total",
                                        js_temporal_duration_total,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    js_value_t getter;
    getter.type = JS_VALUE_NATIVE_FN;
    getter.as.native.fn = js_temporal_duration_getter;
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_YEARS;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "years",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_MONTHS;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "months",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_WEEKS;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "weeks",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_DAYS;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "days",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_HOURS;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "hours",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_MINUTES;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "minutes",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_SECONDS;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "seconds",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_MILLISECONDS;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "milliseconds",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_MICROSECONDS;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "microseconds",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_NANOSECONDS;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "nanoseconds",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_SIGN;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "sign",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_DURATION_FIELD_BLANK;
    if (!js_object_define_accessor_property(rt->temporal_duration_proto,
                                            "blank",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    js_value_t tag = js_value_make_undefined_internal();
    if (!js_value_make_cstring(&tag, JS_TEMPORAL_TAG_DURATION) ||
        !js_object_define_data_property(rt->temporal_duration_proto,
                                        "Symbol.toStringTag",
                                        &tag,
                                        false,
                                        false,
                                        true,
                                        NULL))
    {
        js_value_destroy(&tag);
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
        return NULL;
    }
    js_value_destroy(&tag);
    return rt->temporal_duration_proto;
}

js_object_t *js_get_temporal_instant_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_instant_proto)
    {
        return rt->temporal_instant_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_temporal_instant_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_instant_proto = proto_val.as.object;
    js_object_retain(rt->temporal_instant_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_instant_proto, "__proto__", &proto_slot);
    }
    if (!js_object_define_native_method(rt->temporal_instant_proto,
                                        "constructor",
                                        js_builtin_temporal_instant,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "toString",
                                        js_temporal_instant_to_string,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "toJSON",
                                        js_temporal_instant_to_json,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "toLocaleString",
                                        js_temporal_instant_to_locale_string,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "valueOf",
                                        js_temporal_instant_value_of,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "add",
                                        js_temporal_instant_add,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "subtract",
                                        js_temporal_instant_subtract,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "since",
                                        js_temporal_instant_since,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "until",
                                        js_temporal_instant_until,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "round",
                                        js_temporal_instant_round,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "equals",
                                        js_temporal_instant_equals,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL) ||
        !js_object_define_native_method(rt->temporal_instant_proto,
                                        "toZonedDateTimeISO",
                                        js_temporal_instant_to_zoned_date_time_iso,
                                        NULL,
                                        true,
                                        false,
                                        true,
                                        NULL))
    {
        js_object_release(rt->temporal_instant_proto);
        rt->temporal_instant_proto = NULL;
        return NULL;
    }
    js_value_t getter;
    getter.type = JS_VALUE_NATIVE_FN;
    getter.as.native.fn = js_temporal_instant_getter;
    getter.as.native.user_data = (void *)JS_TEMPORAL_INSTANT_FIELD_EPOCH_NANOSECONDS;
    if (!js_object_define_accessor_property(rt->temporal_instant_proto,
                                            "epochNanoseconds",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_instant_proto);
        rt->temporal_instant_proto = NULL;
        return NULL;
    }
    getter.as.native.user_data = (void *)JS_TEMPORAL_INSTANT_FIELD_EPOCH_MILLISECONDS;
    if (!js_object_define_accessor_property(rt->temporal_instant_proto,
                                            "epochMilliseconds",
                                            &getter,
                                            NULL,
                                            false,
                                            true,
                                            NULL))
    {
        js_object_release(rt->temporal_instant_proto);
        rt->temporal_instant_proto = NULL;
        return NULL;
    }
    js_value_t tag = js_value_make_undefined_internal();
    if (!js_value_make_cstring(&tag, JS_TEMPORAL_TAG_INSTANT) ||
        !js_object_define_data_property(rt->temporal_instant_proto,
                                        "Symbol.toStringTag",
                                        &tag,
                                        false,
                                        false,
                                        true,
                                        NULL))
    {
        js_value_destroy(&tag);
        js_object_release(rt->temporal_instant_proto);
        rt->temporal_instant_proto = NULL;
        return NULL;
    }
    js_value_destroy(&tag);
    return rt->temporal_instant_proto;
}

static bool js_temporal_set_simple_proto(js_object_t *proto,
                                         js_native_fn_t ctor,
                                         const char *tag)
{
    if (!proto || !ctor || !tag)
    {
        return false;
    }
    if (!js_object_define_native_method(proto, "constructor", ctor, NULL, true, false, true, NULL))
    {
        return false;
    }
    js_value_t tag_val = js_value_make_undefined_internal();
    if (!js_value_make_cstring(&tag_val, tag) ||
        !js_object_define_data_property(proto, "Symbol.toStringTag", &tag_val, false, false, true, NULL))
    {
        js_value_destroy(&tag_val);
        return false;
    }
    js_value_destroy(&tag_val);
    return true;
}

js_object_t *js_get_temporal_plain_date_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_plain_date_proto)
    {
        return rt->temporal_plain_date_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_temporal_plain_date_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_plain_date_proto = proto_val.as.object;
    js_object_retain(rt->temporal_plain_date_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_plain_date_proto, "__proto__", &proto_slot);
    }
    if (!js_temporal_set_simple_proto(rt->temporal_plain_date_proto,
                                      js_builtin_temporal_plain_date,
                                      JS_TEMPORAL_TAG_PLAIN_DATE))
    {
        js_object_release(rt->temporal_plain_date_proto);
        rt->temporal_plain_date_proto = NULL;
        return NULL;
    }
    return rt->temporal_plain_date_proto;
}

js_object_t *js_get_temporal_plain_time_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_plain_time_proto)
    {
        return rt->temporal_plain_time_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_temporal_plain_time_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_plain_time_proto = proto_val.as.object;
    js_object_retain(rt->temporal_plain_time_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_plain_time_proto, "__proto__", &proto_slot);
    }
    if (!js_temporal_set_simple_proto(rt->temporal_plain_time_proto,
                                      js_builtin_temporal_plain_time,
                                      JS_TEMPORAL_TAG_PLAIN_TIME))
    {
        js_object_release(rt->temporal_plain_time_proto);
        rt->temporal_plain_time_proto = NULL;
        return NULL;
    }
    return rt->temporal_plain_time_proto;
}

js_object_t *js_get_temporal_plain_date_time_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_plain_date_time_proto)
    {
        return rt->temporal_plain_date_time_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_temporal_plain_date_time_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_plain_date_time_proto = proto_val.as.object;
    js_object_retain(rt->temporal_plain_date_time_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_plain_date_time_proto, "__proto__", &proto_slot);
    }
    if (!js_temporal_set_simple_proto(rt->temporal_plain_date_time_proto,
                                      js_builtin_temporal_plain_date_time,
                                      JS_TEMPORAL_TAG_PLAIN_DATE_TIME))
    {
        js_object_release(rt->temporal_plain_date_time_proto);
        rt->temporal_plain_date_time_proto = NULL;
        return NULL;
    }
    return rt->temporal_plain_date_time_proto;
}

js_object_t *js_get_temporal_zoned_date_time_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_zoned_date_time_proto)
    {
        return rt->temporal_zoned_date_time_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_temporal_zoned_date_time_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_zoned_date_time_proto = proto_val.as.object;
    js_object_retain(rt->temporal_zoned_date_time_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_zoned_date_time_proto, "__proto__", &proto_slot);
    }
    if (!js_temporal_set_simple_proto(rt->temporal_zoned_date_time_proto,
                                      js_builtin_temporal_zoned_date_time,
                                      JS_TEMPORAL_TAG_ZONED_DATE_TIME))
    {
        js_object_release(rt->temporal_zoned_date_time_proto);
        rt->temporal_zoned_date_time_proto = NULL;
        return NULL;
    }
    return rt->temporal_zoned_date_time_proto;
}

js_object_t *js_get_temporal_plain_year_month_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_plain_year_month_proto)
    {
        return rt->temporal_plain_year_month_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_temporal_plain_year_month_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_plain_year_month_proto = proto_val.as.object;
    js_object_retain(rt->temporal_plain_year_month_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_plain_year_month_proto, "__proto__", &proto_slot);
    }
    if (!js_temporal_set_simple_proto(rt->temporal_plain_year_month_proto,
                                      js_builtin_temporal_plain_year_month,
                                      JS_TEMPORAL_TAG_PLAIN_YEAR_MONTH))
    {
        js_object_release(rt->temporal_plain_year_month_proto);
        rt->temporal_plain_year_month_proto = NULL;
        return NULL;
    }
    return rt->temporal_plain_year_month_proto;
}

js_object_t *js_get_temporal_plain_month_day_proto(js_runtime_t *rt)
{
    if (!rt)
    {
        return NULL;
    }
    if (rt->temporal_plain_month_day_proto)
    {
        return rt->temporal_plain_month_day_proto;
    }
    js_value_t proto_val;
    if (!js_value_make_host_object(&proto_val, js_temporal_plain_month_day_proto_get, NULL, NULL, NULL))
    {
        return NULL;
    }
    rt->temporal_plain_month_day_proto = proto_val.as.object;
    js_object_retain(rt->temporal_plain_month_day_proto);
    js_value_destroy(&proto_val);
    js_object_t *obj_proto = js_get_object_proto(rt);
    if (obj_proto)
    {
        js_value_t proto_slot;
        memset(&proto_slot, 0, sizeof(proto_slot));
        proto_slot.type = JS_VALUE_OBJECT;
        proto_slot.as.object = obj_proto;
        (void)js_object_set_slot(rt->temporal_plain_month_day_proto, "__proto__", &proto_slot);
    }
    if (!js_temporal_set_simple_proto(rt->temporal_plain_month_day_proto,
                                      js_builtin_temporal_plain_month_day,
                                      JS_TEMPORAL_TAG_PLAIN_MONTH_DAY))
    {
        js_object_release(rt->temporal_plain_month_day_proto);
        rt->temporal_plain_month_day_proto = NULL;
        return NULL;
    }
    return rt->temporal_plain_month_day_proto;
}

bool js_builtin_iterator(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Iterator is not callable");
    }
    return false;
}

bool js_builtin_iterator_map(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    const js_value_t *mapper_val = (argc > 1 && argv) ? &argv[1] : NULL;
    if (!this_val || (this_val->type != JS_VALUE_OBJECT && this_val->type != JS_VALUE_ARRAY))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid iterator");
        }
        return false;
    }
    if (this_val->type == JS_VALUE_OBJECT && !this_val->as.object)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid iterator");
        }
        return false;
    }
    bool mapper_callable = mapper_val &&
                           (mapper_val->type == JS_VALUE_FUNCTION || mapper_val->type == JS_VALUE_NATIVE_FN);
    if (!mapper_callable)
    {
        char *close_err = NULL;
        if (!js_iterator_close(rt, this_val, &close_err))
        {
            if (error_message)
            {
                *error_message = close_err ? close_err : js_strdup("iterator close failed");
            }
            else
            {
                js_free(close_err);
            }
            return false;
        }
        if (error_message)
        {
            *error_message = js_strdup("TypeError: mapper is not callable");
        }
        return false;
    }

    js_iterator_map_state_t *state = (js_iterator_map_state_t *)js_calloc(1, sizeof(*state));
    if (!state)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_value_copy(&state->iterator, this_val))
    {
        js_free(state);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_value_copy(&state->mapper, mapper_val))
    {
        js_value_destroy(&state->iterator);
        js_free(state);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    state->done = false;
    state->closed = false;
    state->index = 0;
    state->array_index = 0;
    state->is_array = (this_val->type == JS_VALUE_ARRAY);

    if (!state->is_array)
    {
        js_value_t next_method = js_value_make_undefined_internal();
        char *next_err = NULL;
        if (!js_object_get_property(rt, this_val->as.object, "next", &next_method, &next_err))
        {
            js_value_destroy(&state->iterator);
            js_value_destroy(&state->mapper);
            js_free(state);
            if (error_message)
            {
                *error_message = next_err ? next_err : js_strdup("iterator next failed");
            }
            else
            {
                js_free(next_err);
            }
            return false;
        }
        if (next_method.type != JS_VALUE_FUNCTION && next_method.type != JS_VALUE_NATIVE_FN)
        {
            js_value_destroy(&state->iterator);
            js_value_destroy(&state->mapper);
            js_value_destroy(&next_method);
            js_free(state);
            if (error_message)
            {
                *error_message = js_strdup("TypeError: iterator next is not callable");
            }
            return false;
        }
        state->next_method = next_method;
    }

    if (!js_value_make_host_object(out, js_iterator_map_get, NULL, js_iterator_map_finalize, state))
    {
        js_iterator_map_finalize(state);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_iterator_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

static bool js_regexp_set_flags(js_regexp_t *re, const char *flags, size_t len)
{
    if (!re)
    {
        return false;
    }
    js_free(re->flags);
    re->flags = NULL;
    re->flags_len = 0;
    if (!flags || len == 0)
    {
        return true;
    }
    const char *order = "gimsuy";
    char buf[7];
    size_t out_len = 0;
    for (size_t i = 0; order[i]; ++i)
    {
        for (size_t j = 0; j < len; ++j)
        {
            if (flags[j] == order[i])
            {
                buf[out_len++] = order[i];
                break;
            }
        }
    }
    if (out_len == 0)
    {
        return true;
    }
    re->flags = js_strdup_len(buf, out_len);
    if (!re->flags)
    {
        return false;
    }
    re->flags_len = out_len;
    return true;
}

static bool js_regexp_parse_atom(const char *pattern,
                                 size_t len,
                                 size_t *index,
                                 js_regexp_atom_t *out)
{
    if (!pattern || !index || !out || *index >= len)
    {
        return false;
    }
    for (;;)
    {
        if (*index >= len)
        {
            return false;
        }
        if (*index + 2 < len && pattern[*index] == '(' && pattern[*index + 1] == '?')
        {
            if (pattern[*index + 2] == '=' || pattern[*index + 2] == '!')
            {
                size_t i = *index + 3;
                int depth = 1;
                while (i < len && depth > 0)
                {
                    if (pattern[i] == '\\' && i + 1 < len)
                    {
                        i += 2;
                        continue;
                    }
                    if (pattern[i] == '(')
                    {
                        depth++;
                    }
                    else if (pattern[i] == ')')
                    {
                        depth--;
                    }
                    ++i;
                }
                *index = i;
                continue;
            }
            if (*index + 3 < len && pattern[*index + 2] == '<' &&
                (pattern[*index + 3] == '=' || pattern[*index + 3] == '!'))
            {
                size_t i = *index + 4;
                int depth = 1;
                while (i < len && depth > 0)
                {
                    if (pattern[i] == '\\' && i + 1 < len)
                    {
                        i += 2;
                        continue;
                    }
                    if (pattern[i] == '(')
                    {
                        depth++;
                    }
                    else if (pattern[i] == ')')
                    {
                        depth--;
                    }
                    ++i;
                }
                *index = i;
                continue;
            }
            if (*index + 2 < len && pattern[*index + 2] == '<')
            {
                size_t i = *index + 3;
                while (i < len && pattern[i] != '>')
                {
                    ++i;
                }
                if (i < len && pattern[i] == '>')
                {
                    ++i;
                }
                *index = i;
                continue;
            }
            if (*index + 2 < len && pattern[*index + 2] == ':')
            {
                *index += 3;
                continue;
            }
        }
        if (*index + 1 < len && pattern[*index] == '\\' &&
            pattern[*index + 1] >= '0' && pattern[*index + 1] <= '7')
        {
            size_t oct_index = *index + 1;
            int value = 0;
            if (js_regexp_parse_octal(pattern, len, &oct_index, &value))
            {
                *index = oct_index;
                continue;
            }
        }
        if (pattern[*index] == '(' || pattern[*index] == ')')
        {
            ++(*index);
            continue;
        }
        break;
    }
    char c = pattern[*index];
    if (c == '[')
    {
        size_t start = *index + 1;
        size_t i = start;
        bool escaped = false;
        while (i < len)
        {
            char ch = pattern[i];
            if (escaped)
            {
                escaped = false;
                ++i;
                continue;
            }
            if (ch == '\\')
            {
                escaped = true;
                ++i;
                continue;
            }
            if (ch == ']')
            {
                break;
            }
            ++i;
        }
        if (i >= len)
        {
            return false;
        }
        out->kind = JS_REGEXP_ATOM_CLASS;
        out->class_pattern = pattern + start;
        out->class_len = i - start;
        *index = i + 1;
        return true;
    }
    if (c == '\\' && *index + 1 < len)
    {
        char esc = pattern[*index + 1];
        if (esc == 'd' || esc == 'D' || esc == 'w' || esc == 'W')
        {
            out->kind = JS_REGEXP_ATOM_CLASS;
            out->class_pattern = pattern + *index;
            out->class_len = 2;
            *index += 2;
            return true;
        }
        if (esc >= '0' && esc <= '7')
        {
            size_t oct_index = *index + 1;
            int value = 0;
            if (js_regexp_parse_octal(pattern, len, &oct_index, &value))
            {
                out->kind = JS_REGEXP_ATOM_LITERAL;
                out->literal = (char)value;
                *index = oct_index;
                return true;
            }
        }
        if (esc == 'c')
        {
            if (*index + 2 < len)
            {
                char ctrl = pattern[*index + 2];
                if ((ctrl >= 'A' && ctrl <= 'Z') || (ctrl >= 'a' && ctrl <= 'z'))
                {
                    out->kind = JS_REGEXP_ATOM_LITERAL;
                    out->literal = (char)(((unsigned char)ctrl) % 32);
                    *index += 3;
                    return true;
                }
            }
            out->kind = JS_REGEXP_ATOM_LITERAL;
            out->literal = '\\';
            *index += 1;
            return true;
        }
        out->kind = JS_REGEXP_ATOM_LITERAL;
        switch (esc)
        {
            case 'n': out->literal = '\n'; break;
            case 'r': out->literal = '\r'; break;
            case 't': out->literal = '\t'; break;
            case 'v': out->literal = '\v'; break;
            case 'f': out->literal = '\f'; break;
            default: out->literal = esc; break;
        }
        *index += 2;
        return true;
    }
    out->kind = JS_REGEXP_ATOM_LITERAL;
    out->literal = c;
    *index += 1;
    return true;
}

static void js_regexp_parse_quantifier(const char *pattern,
                                       size_t len,
                                       size_t *index,
                                       size_t *out_min,
                                       size_t *out_max)
{
    if (!out_min || !out_max || !index)
    {
        return;
    }
    *out_min = 1;
    *out_max = 1;
    if (!pattern || *index >= len)
    {
        return;
    }
    char c = pattern[*index];
    if (c == '*')
    {
        *out_min = 0;
        *out_max = SIZE_MAX;
        ++(*index);
        return;
    }
    if (c == '+')
    {
        *out_min = 1;
        *out_max = SIZE_MAX;
        ++(*index);
        return;
    }
    if (c == '?')
    {
        *out_min = 0;
        *out_max = 1;
        ++(*index);
        return;
    }
    if (c != '{')
    {
        return;
    }
    size_t i = *index + 1;
    if (i >= len || isdigit((unsigned char)pattern[i]) == 0)
    {
        return;
    }
    size_t min = 0;
    while (i < len && isdigit((unsigned char)pattern[i]) != 0)
    {
        min = (min * 10) + (size_t)(pattern[i] - '0');
        ++i;
    }
    size_t max = min;
    if (i < len && pattern[i] == ',')
    {
        ++i;
        if (i < len && isdigit((unsigned char)pattern[i]) != 0)
        {
            max = 0;
            while (i < len && isdigit((unsigned char)pattern[i]) != 0)
            {
                max = (max * 10) + (size_t)(pattern[i] - '0');
                ++i;
            }
        }
        else
        {
            max = SIZE_MAX;
        }
    }
    if (i >= len || pattern[i] != '}')
    {
        return;
    }
    *out_min = min;
    *out_max = max;
    *index = i + 1;
}

static bool js_regexp_atom_matches(const js_regexp_atom_t *atom, char target)
{
    if (!atom)
    {
        return false;
    }
    if (atom->kind == JS_REGEXP_ATOM_LITERAL)
    {
        return atom->literal == target;
    }
    return js_regexp_match_class(atom->class_pattern, atom->class_len, target);
}

static bool js_regexp_match_from(const char *pattern,
                                 size_t pattern_len,
                                 size_t pat_index,
                                 const char *text,
                                 size_t text_len,
                                 size_t text_index,
                                 size_t *out_end)
{
    if (pat_index >= pattern_len)
    {
        if (out_end)
        {
            *out_end = text_index;
        }
        return true;
    }
    if (!text || text_index > text_len)
    {
        return false;
    }
    js_regexp_atom_t atom = {0};
    size_t next_index = pat_index;
    if (!js_regexp_parse_atom(pattern, pattern_len, &next_index, &atom))
    {
        if (next_index >= pattern_len)
        {
            if (out_end)
            {
                *out_end = text_index;
            }
            return true;
        }
        return false;
    }
    size_t min = 1;
    size_t max = 1;
    js_regexp_parse_quantifier(pattern, pattern_len, &next_index, &min, &max);
    size_t remaining = text_len - text_index;
    size_t max_count = max == SIZE_MAX ? remaining : max;
    if (max_count > remaining)
    {
        max_count = remaining;
    }
    size_t count = 0;
    while (count < max_count && js_regexp_atom_matches(&atom, text[text_index + count]))
    {
        ++count;
    }
    if (count < min)
    {
        return false;
    }
    for (size_t n = count; n + 1 > 0; --n)
    {
        if (n < min)
        {
            break;
        }
        if (js_regexp_match_from(pattern, pattern_len, next_index, text, text_len, text_index + n, out_end))
        {
            return true;
        }
        if (n == 0)
        {
            break;
        }
    }
    return false;
}

static bool js_regexp_find_match_from(const char *pattern,
                                      size_t pattern_len,
                                      const char *text,
                                      size_t text_len,
                                      size_t start_index,
                                      size_t *out_start,
                                      size_t *out_end);

static bool js_regexp_find_match(const char *pattern,
                                 size_t pattern_len,
                                 const char *text,
                                 size_t text_len,
                                 size_t *out_start,
                                 size_t *out_end)
{
    return js_regexp_find_match_from(pattern, pattern_len, text, text_len, 0, out_start, out_end);
}

static bool js_regexp_find_match_from(const char *pattern,
                                      size_t pattern_len,
                                      const char *text,
                                      size_t text_len,
                                      size_t start_index,
                                      size_t *out_start,
                                      size_t *out_end)
{
    if (!pattern || !text || !out_start || !out_end)
    {
        return false;
    }
    if (start_index > text_len)
    {
        return false;
    }
    if (pattern_len == 0)
    {
        *out_start = start_index;
        *out_end = start_index;
        return true;
    }
    for (size_t start = start_index; start <= text_len; ++start)
    {
        size_t end = 0;
        if (js_regexp_match_from(pattern, pattern_len, 0, text, text_len, start, &end))
        {
            *out_start = start;
            *out_end = end;
            return true;
        }
    }
    return false;
}

static bool js_regexp_test_pattern(const char *pattern,
                                   size_t pattern_len,
                                   const char *text,
                                   size_t text_len)
{
    if (!pattern || !text)
    {
        return false;
    }
    size_t start = 0;
    size_t end = 0;
    return js_regexp_find_match(pattern, pattern_len, text, text_len, &start, &end);
}

static const js_function_decl_t *js_builtin_function_def(const js_function_t *fn)
{
    if (!fn)
    {
        return NULL;
    }
    return fn->is_expr ? (const js_function_decl_t *)fn->expr : fn->decl;
}

static size_t js_builtin_function_length(const js_function_t *fn)
{
    const js_function_decl_t *def = js_builtin_function_def(fn);
    if (!def)
    {
        return 0;
    }
    size_t count = 0;
    for (size_t i = 0; i < def->param_count; ++i)
    {
        if (def->params[i].is_rest || def->params[i].init)
        {
            break;
        }
        count++;
    }
    return count;
}

static bool js_parse_index_key(const char *text, size_t *out_index)
{
    if (!text || !*text || !out_index)
    {
        return false;
    }
    size_t value = 0;
    for (const char *p = text; *p; ++p)
    {
        if (!isdigit((unsigned char)*p))
        {
            return false;
        }
        size_t digit = (size_t)(*p - '0');
        if (value > (SIZE_MAX - digit) / 10u)
        {
            return false;
        }
        value = value * 10u + digit;
    }
    *out_index = value;
    return true;
}

static bool js_regexp_is_legacy_setter_property(const char *name);

static bool js_builtin_get_prop_desc(js_runtime_t *rt,
                                     const js_value_t *obj,
                                     const char *name,
                                     js_prop_desc_t *out,
                                     char **error_message)
{
    if (!out)
    {
        return false;
    }
    out->exists = false;
    out->value = js_value_make_undefined_internal();
    out->writable = true;
    out->enumerable = true;
    out->configurable = true;
    out->is_accessor = false;
    out->getter = js_value_make_undefined_internal();
    out->setter = js_value_make_undefined_internal();

    if (!obj || !name)
    {
        if (error_message)
        {
            *error_message = js_strdup("invalid object");
        }
        return false;
    }

    if (strcmp(name, "name") == 0)
    {
        if (obj->type == JS_VALUE_FUNCTION)
        {
            const js_function_decl_t *def = js_builtin_function_def(obj->as.function);
            const char *fn_name = (def && def->name) ? def->name : "";
            out->exists = true;
            if (!js_value_make_cstring(&out->value, fn_name))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
        if (obj->type == JS_VALUE_NATIVE_FN)
        {
            const char *native_name = js_value_native_name(rt, obj);
            out->exists = true;
            if (!js_value_make_cstring(&out->value, native_name ? native_name : ""))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
    }

    if (strcmp(name, "length") == 0)
    {
        if (obj->type == JS_VALUE_FUNCTION)
        {
            out->exists = true;
            out->value = js_value_make_number((double)js_builtin_function_length(obj->as.function));
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
        if (obj->type == JS_VALUE_NATIVE_FN)
        {
            size_t length = 0;
            if (!js_value_native_length(rt, obj, &length))
            {
                if (error_message)
                {
                    *error_message = js_strdup("unknown native");
                }
                return false;
            }
            out->exists = true;
            out->value = js_value_make_number((double)length);
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
        if (obj->type == JS_VALUE_ARRAY)
        {
            out->exists = true;
            out->value = js_value_make_number((double)obj->as.array->length);
            out->writable = true;
            out->enumerable = false;
            out->configurable = false;
            return true;
        }
        if (obj->type == JS_VALUE_STRING)
        {
            out->exists = true;
            out->value = js_value_make_number((double)obj->as.string.len);
            out->writable = false;
            out->enumerable = false;
            out->configurable = false;
            return true;
        }
    }

    if (strcmp(name, "prototype") == 0 && obj->type == JS_VALUE_FUNCTION)
    {
        js_function_t *fn = obj->as.function;
        if (!fn || !fn->has_prototype)
        {
            return true;
        }
        out->exists = true;
        if (!js_value_copy(&out->value, &fn->prototype_value))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        out->writable = true;
        out->enumerable = false;
        out->configurable = false;
        return true;
    }

    if (obj->type == JS_VALUE_NATIVE_FN &&
        obj->as.native.fn == js_builtin_regexp &&
        js_regexp_is_legacy_static_property(name))
    {
        out->exists = true;
        out->is_accessor = true;
        out->enumerable = false;
        out->configurable = true;
        out->writable = false;
        out->getter.type = JS_VALUE_NATIVE_FN;
        out->getter.as.native.fn = js_regexp_legacy_getter;
        out->getter.as.native.user_data = obj->as.native.user_data;
        if (js_regexp_is_legacy_setter_property(name))
        {
            out->setter.type = JS_VALUE_NATIVE_FN;
            out->setter.as.native.fn = js_regexp_legacy_setter;
            out->setter.as.native.user_data = obj->as.native.user_data;
        }
        else
        {
            out->setter = js_value_make_undefined_internal();
        }
        return true;
    }

    if (obj->type == JS_VALUE_ARRAY)
    {
        size_t index = 0;
        if (js_parse_index_key(name, &index))
        {
            js_property_t *prop = js_array_find_property(obj->as.array, name);
            if (prop)
            {
                out->exists = true;
                out->writable = prop->writable;
                out->enumerable = prop->enumerable;
                out->configurable = prop->configurable;
                if (prop->is_accessor)
                {
                    out->is_accessor = true;
                    if (!js_value_copy(&out->getter, &prop->getter) ||
                        !js_value_copy(&out->setter, &prop->setter))
                    {
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        return false;
                    }
                }
                else if (!js_value_copy(&out->value, &prop->value))
                {
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    return false;
                }
                return true;
            }
            if (index < obj->as.array->length)
            {
                js_value_t value = js_value_make_undefined_internal();
                if (!js_array_get(obj->as.array, index, &value))
                {
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    return false;
                }
                out->exists = true;
                out->value = value;
                out->writable = true;
                out->enumerable = true;
                out->configurable = true;
            }
            return true;
        }
        js_property_t *prop = js_array_find_property(obj->as.array, name);
        if (prop)
        {
            out->exists = true;
            out->writable = prop->writable;
            out->enumerable = prop->enumerable;
            out->configurable = prop->configurable;
            if (prop->is_accessor)
            {
                out->is_accessor = true;
                if (!js_value_copy(&out->getter, &prop->getter) ||
                    !js_value_copy(&out->setter, &prop->setter))
                {
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    return false;
                }
            }
            else if (!js_value_copy(&out->value, &prop->value))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            return true;
        }
        return true;
    }

    if (obj->type == JS_VALUE_STRING)
    {
        size_t index = 0;
        if (js_parse_index_key(name, &index) && index < obj->as.string.len &&
            obj->as.string.data)
        {
            js_value_t value;
            if (!js_value_make_string(&value, obj->as.string.data + index, 1))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            out->exists = true;
            out->value = value;
            out->writable = false;
            out->enumerable = true;
            out->configurable = false;
        }
        return true;
    }

    if (obj->type == JS_VALUE_NATIVE_FN)
    {
        if (strcmp(name, "prototype") == 0)
        {
            const char *native_name = js_value_native_name(rt, obj);
            js_object_t *proto = NULL;
            if (obj->as.native.fn == js_builtin_iterator)
            {
                proto = js_get_iterator_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Object") == 0)
            {
                proto = js_get_object_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Array") == 0)
            {
                proto = js_get_array_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Function") == 0)
            {
                proto = js_get_function_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Date") == 0)
            {
                proto = js_get_date_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Number") == 0)
            {
                proto = js_get_number_proto(rt);
            }
            else if (native_name && strcmp(native_name, "String") == 0)
            {
                proto = js_get_string_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Symbol") == 0)
            {
                proto = js_get_symbol_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Duration") == 0)
            {
                proto = js_get_temporal_duration_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Instant") == 0)
            {
                proto = js_get_temporal_instant_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainDate") == 0)
            {
                proto = js_get_temporal_plain_date_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainTime") == 0)
            {
                proto = js_get_temporal_plain_time_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainDateTime") == 0)
            {
                proto = js_get_temporal_plain_date_time_proto(rt);
            }
            else if (native_name && strcmp(native_name, "ZonedDateTime") == 0)
            {
                proto = js_get_temporal_zoned_date_time_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainYearMonth") == 0)
            {
                proto = js_get_temporal_plain_year_month_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainMonthDay") == 0)
            {
                proto = js_get_temporal_plain_month_day_proto(rt);
            }
            if (proto)
            {
                out->exists = true;
                out->value.type = JS_VALUE_OBJECT;
                out->value.as.object = proto;
                js_object_retain(proto);
                out->writable = false;
                out->enumerable = false;
                out->configurable = true;
            }
        }
        const char *native_name = js_value_native_name(rt, obj);
        if (native_name && strcmp(native_name, "Object") == 0)
        {
            js_native_fn_t fn = NULL;
            if (strcmp(name, "defineProperty") == 0)
            {
                fn = js_builtin_define_property;
            }
            else if (strcmp(name, "defineProperties") == 0)
            {
                fn = js_builtin_define_properties;
            }
            else if (strcmp(name, "getPrototypeOf") == 0)
            {
                fn = js_builtin_object_get_prototype_of;
            }
            else if (strcmp(name, "getOwnPropertyDescriptor") == 0)
            {
                fn = js_builtin_object_get_own_property_descriptor;
            }
            else if (strcmp(name, "getOwnPropertyNames") == 0)
            {
                fn = js_builtin_object_get_own_property_names;
            }
            else if (strcmp(name, "getOwnPropertyDescriptors") == 0)
            {
                fn = js_builtin_object_get_own_property_descriptors;
            }
            else if (strcmp(name, "is") == 0)
            {
                fn = js_builtin_object_is;
            }
            if (fn)
            {
                out->exists = true;
                out->value.type = JS_VALUE_NATIVE_FN;
                out->value.as.native.fn = fn;
                out->value.as.native.user_data = NULL;
                out->writable = true;
                out->enumerable = false;
                out->configurable = true;
            }
        }
        if (native_name && strcmp(native_name, "Array") == 0 && strcmp(name, "isArray") == 0)
        {
            out->exists = true;
            out->value.type = JS_VALUE_NATIVE_FN;
            out->value.as.native.fn = js_builtin_array_is_array;
            out->value.as.native.user_data = NULL;
            out->writable = true;
            out->enumerable = false;
            out->configurable = true;
        }
        if (native_name && strcmp(native_name, "Array") == 0 && strcmp(name, "from") == 0)
        {
            out->exists = true;
            out->value.type = JS_VALUE_NATIVE_FN;
            out->value.as.native.fn = js_builtin_array_from;
            out->value.as.native.user_data = NULL;
            out->writable = true;
            out->enumerable = false;
            out->configurable = true;
        }
        if (native_name && strcmp(native_name, "String") == 0 && strcmp(name, "fromCharCode") == 0)
        {
            out->exists = true;
            out->value.type = JS_VALUE_NATIVE_FN;
            out->value.as.native.fn = js_builtin_string_from_char_code;
            out->value.as.native.user_data = NULL;
            out->writable = true;
            out->enumerable = false;
            out->configurable = true;
        }
        if (native_name && strcmp(native_name, "Date") == 0)
        {
            js_native_fn_t fn = NULL;
            if (strcmp(name, "now") == 0)
            {
                fn = js_builtin_date_now;
            }
            else if (strcmp(name, "parse") == 0)
            {
                fn = js_builtin_date_parse;
            }
            else if (strcmp(name, "UTC") == 0)
            {
                fn = js_builtin_date_utc;
            }
            if (fn)
            {
                out->exists = true;
                out->value.type = JS_VALUE_NATIVE_FN;
                out->value.as.native.fn = fn;
                out->value.as.native.user_data = NULL;
                out->writable = true;
                out->enumerable = false;
                out->configurable = true;
            }
        }
        return true;
    }

    if (obj->type == JS_VALUE_FUNCTION)
    {
        return true;
    }
    if (obj->type == JS_VALUE_STRING ||
        obj->type == JS_VALUE_NUMBER ||
        obj->type == JS_VALUE_BOOL)
    {
        return true;
    }

    if (obj->type == JS_VALUE_OBJECT)
    {
        js_object_t *obj_ptr = obj->as.object;
        if (obj_ptr && obj_ptr->get_fn)
        {
            js_value_t value = js_value_make_undefined_internal();
            if (!obj_ptr->get_fn(rt, obj_ptr->user_data, name, &value, error_message))
            {
                return false;
            }
            if (value.type != JS_VALUE_UNDEFINED || js_object_is_symbol(obj_ptr))
            {
                out->exists = true;
                out->value = value;
                out->writable = true;
                out->enumerable = false;
                out->configurable = true;
                if (obj_ptr->get_fn == js_set_iterator_proto_get &&
                    strcmp(name, "Symbol.toStringTag") == 0)
                {
                    out->writable = false;
                }
                return true;
            }
            js_value_destroy(&value);
        }
        if (!obj_ptr)
        {
            return true;
        }
        js_property_t *prop = js_object_find_property(obj_ptr, name);
        if (!prop)
        {
            return true;
        }
        out->exists = true;
        out->writable = prop->writable;
        out->enumerable = prop->enumerable;
        out->configurable = prop->configurable;
        if (prop->is_accessor)
        {
            out->is_accessor = true;
            if (!js_value_copy(&out->getter, &prop->getter) ||
                !js_value_copy(&out->setter, &prop->setter))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            return true;
        }
        if (!js_value_copy(&out->value, &prop->value))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (strcmp(name, "compile") == 0 &&
            out->value.type == JS_VALUE_NATIVE_FN &&
            out->value.as.native.fn == js_regexp_compile_proto)
        {
            out->writable = true;
            out->enumerable = false;
            out->configurable = true;
        }
        return true;
    }

    if (error_message)
    {
        *error_message = js_strdup("invalid object");
    }
    return false;
}

static bool js_builtin_get_desc_value(js_runtime_t *rt,
                                      js_object_t *desc,
                                      const char *name,
                                      bool *has_out,
                                      js_value_t *value_out,
                                      char **error_message)
{
    if (!has_out || !value_out)
    {
        return false;
    }
    *has_out = false;
    *value_out = js_value_make_undefined_internal();
    if (!desc || !name)
    {
        return true;
    }
    if (!js_object_has_property(rt, desc, name))
    {
        return true;
    }
    *has_out = true;
    if (!js_object_get_property(rt, desc, name, value_out, error_message))
    {
        return false;
    }
    return true;
}

typedef struct
{
    char **items;
    size_t count;
    size_t cap;
} js_name_list_t;

static bool js_name_list_contains(const js_name_list_t *list, const char *name)
{
    if (!list || !name)
    {
        return false;
    }
    for (size_t i = 0; i < list->count; ++i)
    {
        if (list->items[i] && strcmp(list->items[i], name) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool js_name_list_add(js_name_list_t *list, const char *name)
{
    if (!list || !name)
    {
        return false;
    }
    if (js_name_list_contains(list, name))
    {
        return true;
    }
    char *copy = js_strdup(name);
    if (!copy)
    {
        return false;
    }
    if (list->count + 1 > list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 8u;
        if (new_cap < list->count + 1)
        {
            new_cap = list->count + 1;
        }
        char **next = (char **)js_realloc(list->items, new_cap * sizeof(*next));
        if (!next)
        {
            js_free(copy);
            return false;
        }
        list->items = next;
        list->cap = new_cap;
    }
    list->items[list->count++] = copy;
    return true;
}

static bool js_name_list_add_index(js_name_list_t *list, size_t index)
{
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%zu", index);
    if (len < 0 || (size_t)len >= sizeof(buf))
    {
        return false;
    }
    return js_name_list_add(list, buf);
}

static void js_name_list_destroy(js_name_list_t *list)
{
    if (!list)
    {
        return;
    }
    for (size_t i = 0; i < list->count; ++i)
    {
        js_free(list->items[i]);
    }
    js_free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static bool js_name_list_add_from_prop(js_name_list_t *list, const char *name)
{
    if (!list || !name)
    {
        return false;
    }
    if (strcmp(name, "__proto__") == 0)
    {
        return true;
    }
    return js_name_list_add(list, name);
}

static bool js_name_list_add_builtin(js_object_t *object, js_name_list_t *list)
{
    if (!object || !list)
    {
        return false;
    }
    if (object->get_fn == js_object_proto_get)
    {
        return js_name_list_add(list, "hasOwnProperty") &&
               js_name_list_add(list, "propertyIsEnumerable") &&
               js_name_list_add(list, "toString");
    }
    if (object->get_fn == js_function_proto_get)
    {
        return js_name_list_add(list, "call") &&
               js_name_list_add(list, "bind") &&
               js_name_list_add(list, "length");
    }
    if (object->get_fn == js_array_proto_get)
    {
        return js_name_list_add(list, "join") &&
               js_name_list_add(list, "push") &&
               js_name_list_add(list, "map") &&
               js_name_list_add(list, "length");
    }
    if (object->get_fn == js_math_get)
    {
        return js_name_list_add(list, "pow");
    }
    return true;
}

static bool js_collect_own_property_names(js_runtime_t *rt,
                                          const js_value_t *obj,
                                          js_name_list_t *names,
                                          char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!obj || !names)
    {
        return false;
    }
    if (obj->type == JS_VALUE_ARRAY && obj->as.array)
    {
        if (!js_name_list_add(names, "length"))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        for (size_t i = 0; i < obj->as.array->length; ++i)
        {
            if (!js_name_list_add_index(names, i))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        for (js_property_t *prop = obj->as.array->properties; prop; prop = prop->next)
        {
            if (!prop->name)
            {
                continue;
            }
            if (!js_name_list_add_from_prop(names, prop->name))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        return true;
    }
    if (obj->type == JS_VALUE_OBJECT && obj->as.object)
    {
        if (obj->as.object->get_fn)
        {
            if (!js_name_list_add_builtin(obj->as.object, names))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        for (js_property_t *prop = obj->as.object->properties; prop; prop = prop->next)
        {
            if (!prop->name)
            {
                continue;
            }
            if (!js_name_list_add_from_prop(names, prop->name))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        return true;
    }
    if (obj->type == JS_VALUE_FUNCTION)
    {
        if (!js_name_list_add(names, "length") ||
            !js_name_list_add(names, "name"))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (obj->as.function && obj->as.function->is_constructible)
        {
            js_prop_desc_t desc;
            if (js_builtin_get_prop_desc(rt, obj, "prototype", &desc, NULL))
            {
                if (desc.exists && !js_name_list_add(names, "prototype"))
                {
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    js_value_destroy(&desc.value);
                    js_value_destroy(&desc.getter);
                    js_value_destroy(&desc.setter);
                    return false;
                }
                js_value_destroy(&desc.value);
                js_value_destroy(&desc.getter);
                js_value_destroy(&desc.setter);
            }
        }
        return true;
    }
    if (obj->type == JS_VALUE_NATIVE_FN)
    {
        if (!js_name_list_add(names, "length") ||
            !js_name_list_add(names, "name"))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (js_value_is_constructor(rt, obj))
        {
            js_prop_desc_t desc;
            if (js_builtin_get_prop_desc(rt, obj, "prototype", &desc, NULL))
            {
                if (desc.exists && !js_name_list_add(names, "prototype"))
                {
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    js_value_destroy(&desc.value);
                    js_value_destroy(&desc.getter);
                    js_value_destroy(&desc.setter);
                    return false;
                }
                js_value_destroy(&desc.value);
                js_value_destroy(&desc.getter);
                js_value_destroy(&desc.setter);
            }
        }
        return true;
    }
    if (obj->type == JS_VALUE_STRING)
    {
        if (!js_name_list_add(names, "length"))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        for (size_t i = 0; i < obj->as.string.len; ++i)
        {
            if (!js_name_list_add_index(names, i))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        return true;
    }
    return true;
}

static bool js_builtin_object_get_value(js_runtime_t *rt,
                                        js_object_t *object,
                                        const char *name,
                                        js_value_t *out,
                                        char **error_message)
{
    if (!out)
    {
        return false;
    }
    if (!object || !name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    return js_object_get_property(rt, object, name, out, error_message);
}

static bool js_value_is_primitive_local(const js_value_t *value)
{
    if (!value)
    {
        return false;
    }
    if (value->type == JS_VALUE_OBJECT && value->as.object && js_object_is_symbol(value->as.object))
    {
        return true;
    }
    switch (value->type)
    {
        case JS_VALUE_UNDEFINED:
        case JS_VALUE_NULL:
        case JS_VALUE_BOOL:
        case JS_VALUE_NUMBER:
        case JS_VALUE_BIGINT:
        case JS_VALUE_STRING:
            return true;
        default:
            return false;
    }
}

static bool js_try_object_method_number(js_runtime_t *rt,
                                        js_object_t *object,
                                        const char *name,
                                        js_value_t *out,
                                        bool *called,
                                        char **error_message)
{
    if (called)
    {
        *called = false;
    }
    if (!out)
    {
        return false;
    }
    js_value_t method = js_value_make_undefined_internal();
    if (!js_builtin_object_get_value(rt, object, name, &method, error_message))
    {
        return false;
    }
    if (method.type != JS_VALUE_FUNCTION && method.type != JS_VALUE_NATIVE_FN)
    {
        js_value_destroy(&method);
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (called)
    {
        *called = true;
    }
    js_value_t result = js_value_make_undefined_internal();
    char *err = NULL;
    bool ok = false;
    if (method.type == JS_VALUE_NATIVE_FN && js_native_needs_this(method.as.native.fn))
    {
        js_value_t this_arg;
        memset(&this_arg, 0, sizeof(this_arg));
        this_arg.type = JS_VALUE_OBJECT;
        this_arg.as.object = object;
        ok = js_call_value(rt, &method, 1, &this_arg, &result, &err);
    }
    else if (method.type == JS_VALUE_FUNCTION && rt && object)
    {
        js_object_t *prev_global = rt->global_object;
        rt->global_object = object;
        ok = js_call_value(rt, &method, 0, NULL, &result, &err);
        rt->global_object = prev_global;
    }
    else
    {
        ok = js_call_value(rt, &method, 0, NULL, &result, &err);
    }
    js_value_destroy(&method);
    if (!ok)
    {
        if (error_message)
        {
            *error_message = err ? err : js_strdup("method call failed");
        }
        else
        {
            js_free(err);
        }
        return false;
    }
    *out = result;
    return true;
}

static bool js_try_object_method_with_hint(js_runtime_t *rt,
                                           js_object_t *object,
                                           const char *name,
                                           const char *hint,
                                           js_value_t *out,
                                           bool *called,
                                           char **error_message)
{
    if (called)
    {
        *called = false;
    }
    if (!out)
    {
        return false;
    }
    js_value_t method = js_value_make_undefined_internal();
    if (!js_builtin_object_get_value(rt, object, name, &method, error_message))
    {
        return false;
    }
    if (method.type != JS_VALUE_FUNCTION && method.type != JS_VALUE_NATIVE_FN)
    {
        js_value_destroy(&method);
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (called)
    {
        *called = true;
    }
    js_value_t hint_val = js_value_make_undefined_internal();
    if (!js_value_make_cstring(&hint_val, hint ? hint : "default"))
    {
        js_value_destroy(&method);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_t result = js_value_make_undefined_internal();
    char *err = NULL;
    bool ok = false;
    if (method.type == JS_VALUE_NATIVE_FN && js_native_needs_this(method.as.native.fn))
    {
        js_value_t args[2];
        if (!js_value_copy(&args[0], &(js_value_t){ .type = JS_VALUE_OBJECT, .as.object = object }))
        {
            js_value_destroy(&method);
            js_value_destroy(&hint_val);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        args[1] = hint_val;
        ok = js_call_value(rt, &method, 2, args, &result, &err);
        js_value_destroy(&args[0]);
    }
    else if (method.type == JS_VALUE_FUNCTION && rt && object)
    {
        js_object_t *prev_global = rt->global_object;
        rt->global_object = object;
        ok = js_call_value(rt, &method, 1, &hint_val, &result, &err);
        rt->global_object = prev_global;
    }
    else
    {
        ok = js_call_value(rt, &method, 1, &hint_val, &result, &err);
    }
    js_value_destroy(&method);
    js_value_destroy(&hint_val);
    if (!ok)
    {
        if (error_message)
        {
            *error_message = err ? err : js_strdup("method call failed");
        }
        else
        {
            js_free(err);
        }
        return false;
    }
    *out = result;
    return true;
}

static bool js_object_to_primitive_number(js_runtime_t *rt,
                                          js_object_t *object,
                                          js_value_t *out,
                                          char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !object || !out)
    {
        return false;
    }
    bool called = false;
    js_value_t result = js_value_make_undefined_internal();
    if (!js_try_object_method_with_hint(rt, object, "Symbol.toPrimitive", "number", &result, &called, error_message))
    {
        return false;
    }
    if (called)
    {
        if (js_value_is_primitive_local(&result))
        {
            *out = result;
            return true;
        }
        js_value_destroy(&result);
        if (error_message)
        {
            *error_message = js_strdup("TypeError: @@toPrimitive must return a primitive");
        }
        return false;
    }

    const char *order[2] = {"valueOf", "toString"};
    for (size_t i = 0; i < 2; ++i)
    {
        called = false;
        result = js_value_make_undefined_internal();
        if (!js_try_object_method_number(rt, object, order[i], &result, &called, error_message))
        {
            return false;
        }
        if (!called)
        {
            continue;
        }
        if (js_value_is_primitive_local(&result))
        {
            *out = result;
            return true;
        }
        js_value_destroy(&result);
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: cannot convert object to primitive");
    }
    return false;
}

static bool js_date_object_to_primitive_default(js_runtime_t *rt,
                                                js_object_t *object,
                                                js_value_t *out,
                                                char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !object || !out)
    {
        return false;
    }
    bool called = false;
    js_value_t result = js_value_make_undefined_internal();
    if (!js_try_object_method_with_hint(rt, object, "Symbol.toPrimitive", "default", &result, &called, error_message))
    {
        return false;
    }
    if (called)
    {
        if (js_value_is_primitive_local(&result))
        {
            *out = result;
            return true;
        }
        js_value_destroy(&result);
        if (error_message)
        {
            *error_message = js_strdup("TypeError: @@toPrimitive must return a primitive");
        }
        return false;
    }
    const char *order[2] = {"valueOf", "toString"};
    for (size_t i = 0; i < 2; ++i)
    {
        called = false;
        result = js_value_make_undefined_internal();
        if (!js_try_object_method_number(rt, object, order[i], &result, &called, error_message))
        {
            return false;
        }
        if (!called)
        {
            continue;
        }
        if (js_value_is_primitive_local(&result))
        {
            *out = result;
            return true;
        }
        js_value_destroy(&result);
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: cannot convert object to primitive");
    }
    return false;
}

static void js_regexp_finalize(void *user_data)
{
    js_regexp_t *re = (js_regexp_t *)user_data;
    if (!re)
    {
        return;
    }
    js_free(re->pattern);
    js_free(re->flags);
    js_free(re);
}

static char *js_str_to_lower_copy(const char *text, size_t len)
{
    if (!text)
    {
        text = "";
        len = 0;
    }
    char *buf = (char *)js_malloc(len + 1);
    if (!buf)
    {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i)
    {
        char c = text[i];
        if (c >= 'A' && c <= 'Z')
        {
            c = (char)(c - 'A' + 'a');
        }
        buf[i] = c;
    }
    buf[len] = '\0';
    return buf;
}

static bool js_regexp_test(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }
    const char *pattern = re ? re->pattern : NULL;
    size_t pattern_len = re ? re->pattern_len : 0;
    const char *text = temp.data ? temp.data : "";
    size_t text_len = temp.len;
    if (re && re->flags && strchr(re->flags, 'u') != NULL &&
        pattern && pattern_len >= 2 && pattern[0] == '[' && pattern[pattern_len - 1] == ']')
    {
        const unsigned char *inner = (const unsigned char *)(pattern + 1);
        size_t inner_len = pattern_len - 2;
        if (inner_len == 6 && inner[0] == 0xED && inner[3] == 0xED)
        {
            bool found = false;
            for (size_t i = 0; i + inner_len <= text_len; ++i)
            {
                if (memcmp(text + i, inner, inner_len) == 0)
                {
                    found = true;
                    break;
                }
            }
            js_temp_string_release(&temp);
            *out = js_value_make_bool(found);
            return true;
        }
    }
    char *pattern_lower = NULL;
    char *text_lower = NULL;
    if (re && re->flags && strchr(re->flags, 'i') != NULL)
    {
        pattern_lower = js_str_to_lower_copy(pattern, pattern_len);
        text_lower = js_str_to_lower_copy(text, text_len);
        if (!pattern_lower || !text_lower)
        {
            js_free(pattern_lower);
            js_free(text_lower);
            js_temp_string_release(&temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        pattern = pattern_lower;
        text = text_lower;
    }
    bool match = js_regexp_test_pattern(pattern,
                                        pattern_len,
                                        text,
                                        text_len);
    js_free(pattern_lower);
    js_free(text_lower);
    js_temp_string_release(&temp);
    *out = js_value_make_bool(match);
    return true;
}

bool js_regexp_exec(js_runtime_t *rt,
                    size_t argc,
                    const js_value_t *argv,
                    void *user_data,
                    js_value_t *out,
                    char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }
    const char *pattern = re ? re->pattern : "";
    size_t pattern_len = re ? re->pattern_len : 0;
    const char *text = temp.data ? temp.data : "";
    size_t text_len = temp.len;
    bool global = re && re->flags && strchr(re->flags, 'g') != NULL;
    bool sticky = re && re->flags && strchr(re->flags, 'y') != NULL;
    bool use_last_index = global || sticky;
    size_t search_start = 0;
    if (use_last_index && re && re->object && js_object_has_slot(re->object, "lastIndex"))
    {
        js_value_t last = js_value_make_undefined_internal();
        if (js_object_get_slot(re->object, "lastIndex", &last))
        {
            bool ok = true;
            double num = js_value_to_number(&last, &ok);
            if (ok && !js_is_nan(num) && num > 0.0)
            {
                if (num > (double)text_len)
                {
                    search_start = text_len + 1;
                }
                else
                {
                    search_start = (size_t)num;
                }
            }
        }
        js_value_destroy(&last);
    }
    size_t start = 0;
    size_t end = 0;
    bool matched = false;
    if (use_last_index && search_start > text_len)
    {
        matched = false;
    }
    else if (sticky)
    {
        matched = js_regexp_match_from(pattern, pattern_len, 0, text, text_len, search_start, &end);
        start = search_start;
    }
    else if (use_last_index)
    {
        matched = js_regexp_find_match_from(pattern, pattern_len, text, text_len, search_start, &start, &end);
    }
    else
    {
        matched = js_regexp_find_match(pattern, pattern_len, text, text_len, &start, &end);
    }
    if (!matched)
    {
        js_temp_string_release(&temp);
        if (use_last_index && re && re->object)
        {
            js_value_t zero = js_value_make_number(0.0);
            (void)js_object_set_slot(re->object, "lastIndex", &zero);
        }
        *out = js_value_make_null();
        return true;
    }
    js_value_t result;
    if (!js_value_make_array(&result))
    {
        js_temp_string_release(&temp);
        return false;
    }
    js_value_t match_value;
    if (!js_value_make_string(&match_value, text + start, end - start))
    {
        js_value_destroy(&result);
        js_temp_string_release(&temp);
        return false;
    }
    if (!js_value_array_set(&result, 0, &match_value))
    {
        js_value_destroy(&match_value);
        js_value_destroy(&result);
        js_temp_string_release(&temp);
        return false;
    }
    js_value_destroy(&match_value);
    js_value_t index_value = js_value_make_number((double)start);
    (void)js_array_set_property(result.as.array, "index", &index_value);
    js_value_t input_value;
    if (!js_value_make_string(&input_value, text, text_len))
    {
        js_value_destroy(&result);
        js_temp_string_release(&temp);
        return false;
    }
    (void)js_array_set_property(result.as.array, "input", &input_value);
    js_value_destroy(&input_value);
    js_temp_string_release(&temp);
    if (use_last_index && re && re->object)
    {
        size_t new_last_index = end;
        if (end == start)
        {
            if (end < text_len)
            {
                new_last_index = end + 1;
            }
            else
            {
                new_last_index = end + 1;
            }
        }
        js_value_t last = js_value_make_number((double)new_last_index);
        (void)js_object_set_slot(re->object, "lastIndex", &last);
    }
    *out = result;
    return true;
}

static bool js_regexp_to_string(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    const char *pattern = (re && re->pattern) ? re->pattern : "";
    size_t pattern_len = (re && re->pattern) ? re->pattern_len : 0;
    const char *flags = (re && re->flags) ? re->flags : "";
    size_t flags_len = (re && re->flags) ? re->flags_len : 0;
    size_t total = pattern_len + flags_len + 2;
    char *buf = (char *)js_malloc(total + 1);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    size_t offset = 0;
    buf[offset++] = '/';
    if (pattern_len)
    {
        memcpy(buf + offset, pattern, pattern_len);
        offset += pattern_len;
    }
    buf[offset++] = '/';
    if (flags_len)
    {
        memcpy(buf + offset, flags, flags_len);
        offset += flags_len;
    }
    buf[offset] = '\0';
    out->type = JS_VALUE_STRING;
    out->as.string.data = buf;
    out->as.string.len = offset;
    return true;
}

bool js_regexp_compile(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    size_t arg_index = 0;
    js_regexp_t *re = (js_regexp_t *)user_data;
    if (!re)
    {
        if (argc > 0 && argv && argv[0].type == JS_VALUE_OBJECT &&
            argv[0].as.object && argv[0].as.object->get_fn == js_regexp_get)
        {
            re = (js_regexp_t *)argv[0].as.object->user_data;
            arg_index = 1;
        }
        else
        {
            if (error_message)
            {
                *error_message = js_strdup("TypeError: invalid RegExp receiver");
            }
            return false;
        }
    }
    if (re && re->is_subclass)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid RegExp receiver");
        }
        return false;
    }
    js_temp_string_t pattern_temp = {0};
    if (argc <= arg_index || !argv || argv[arg_index].type == JS_VALUE_UNDEFINED)
    {
        js_temp_string_t flags_temp = {0};
        bool have_flags = false;
        if (argc > arg_index + 1 && argv && argv[arg_index + 1].type != JS_VALUE_UNDEFINED)
        {
            if (!js_temp_string_from_value(rt, &argv[arg_index + 1], &flags_temp, error_message))
            {
                return false;
            }
            have_flags = true;
            if (!js_regexp_flags_valid(flags_temp.data ? flags_temp.data : "", flags_temp.len))
            {
                js_temp_string_release(&flags_temp);
                if (error_message)
                {
                    *error_message = js_strdup("SyntaxError: invalid flags");
                }
                return false;
            }
        }
        char *pattern_copy = js_strdup_len("", 0);
        if (!pattern_copy)
        {
            js_temp_string_release(&flags_temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        js_free(re->pattern);
        re->pattern = pattern_copy;
        re->pattern_len = 0;
        bool ok = false;
        if (have_flags)
        {
            ok = js_regexp_set_flags(re, flags_temp.data ? flags_temp.data : "", flags_temp.len);
        }
        else
        {
            ok = js_regexp_set_flags(re, "", 0);
        }
        js_temp_string_release(&flags_temp);
        if (!ok)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    else
    {
        const js_value_t *pattern_arg = &argv[arg_index];
        if (pattern_arg->type == JS_VALUE_OBJECT && pattern_arg->as.object &&
            pattern_arg->as.object->get_fn == js_regexp_get)
        {
            if (argc > arg_index + 1 && argv && argv[arg_index + 1].type != JS_VALUE_UNDEFINED)
            {
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: flags not allowed");
                }
                return false;
            }
            js_regexp_t *pattern_re = (js_regexp_t *)pattern_arg->as.object->user_data;
            const char *src = (pattern_re && pattern_re->pattern) ? pattern_re->pattern : "";
            size_t src_len = (pattern_re && pattern_re->pattern) ? pattern_re->pattern_len : 0;
            char *pattern_copy = js_strdup_len(src, src_len);
            if (!pattern_copy)
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            js_free(re->pattern);
            re->pattern = pattern_copy;
            re->pattern_len = src_len;
            const char *flags = (pattern_re && pattern_re->flags) ? pattern_re->flags : "";
            size_t flags_len = (pattern_re && pattern_re->flags) ? pattern_re->flags_len : 0;
            char *flags_copy = js_strdup_len(flags, flags_len);
            if (!flags_copy && flags_len > 0)
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            bool ok = js_regexp_set_flags(re, flags_copy ? flags_copy : "", flags_len);
            js_free(flags_copy);
            if (!ok)
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        else
        {
            if (!js_temp_string_from_value(rt, pattern_arg, &pattern_temp, error_message))
            {
                return false;
            }
            bool dup = false;
            if (!js_regexp_has_duplicate_named_groups(pattern_temp.data ? pattern_temp.data : "",
                                                      pattern_temp.len,
                                                      &dup))
            {
                js_temp_string_release(&pattern_temp);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            if (dup)
            {
                js_temp_string_release(&pattern_temp);
                if (error_message)
                {
                    *error_message = js_strdup("SyntaxError: duplicate named capturing group");
                }
                return false;
            }
            js_temp_string_t flags_temp = {0};
            bool have_flags = false;
            if (argc > arg_index + 1 && argv && argv[arg_index + 1].type != JS_VALUE_UNDEFINED)
            {
                if (!js_temp_string_from_value(rt, &argv[arg_index + 1], &flags_temp, error_message))
                {
                    js_temp_string_release(&pattern_temp);
                    return false;
                }
                have_flags = true;
                if (!js_regexp_flags_valid(flags_temp.data ? flags_temp.data : "", flags_temp.len))
                {
                    js_temp_string_release(&pattern_temp);
                    js_temp_string_release(&flags_temp);
                    if (error_message)
                    {
                        *error_message = js_strdup("SyntaxError: invalid flags");
                    }
                    return false;
                }
            }
            bool unicode = have_flags && flags_temp.data && strchr(flags_temp.data, 'u') != NULL;
            if (!js_regexp_pattern_valid(pattern_temp.data ? pattern_temp.data : "",
                                          pattern_temp.len,
                                          unicode))
            {
                js_temp_string_release(&pattern_temp);
                js_temp_string_release(&flags_temp);
                if (error_message)
                {
                    *error_message = js_strdup("SyntaxError: invalid regular expression");
                }
                return false;
            }
            char *pattern_copy = js_strdup_len(pattern_temp.data ? pattern_temp.data : "", pattern_temp.len);
            if (!pattern_copy)
            {
                js_temp_string_release(&pattern_temp);
                js_temp_string_release(&flags_temp);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            js_free(re->pattern);
            re->pattern = pattern_copy;
            re->pattern_len = pattern_temp.len;
            js_temp_string_release(&pattern_temp);
            bool ok = false;
            if (have_flags)
            {
                ok = js_regexp_set_flags(re, flags_temp.data ? flags_temp.data : "", flags_temp.len);
            }
            else
            {
                ok = js_regexp_set_flags(re, "", 0);
            }
            js_temp_string_release(&flags_temp);
            if (!ok)
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
    }
    if (re && re->object)
    {
        bool can_write = true;
        if (js_object_has_slot(re->object, "__lastIndex_writable"))
        {
            js_value_t writable = js_value_make_undefined_internal();
            if (js_object_get_slot(re->object, "__lastIndex_writable", &writable))
            {
                if (writable.type == JS_VALUE_BOOL && !writable.as.boolean)
                {
                    can_write = false;
                }
            }
            js_value_destroy(&writable);
        }
        if (!can_write)
        {
            if (error_message)
            {
                *error_message = js_strdup("TypeError: lastIndex is read-only");
            }
            return false;
        }
        js_value_t zero = js_value_make_number(0.0);
        (void)js_object_set_slot(re->object, "lastIndex", &zero);
        js_object_retain(re->object);
        out->type = JS_VALUE_OBJECT;
        out->as.object = re->object;
        return true;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_regexp_compile_proto(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_realm_t *realm = user_data ? (js_realm_t *)user_data : &js_default_realm;
    if (argc == 0 || !argv || argv[0].type != JS_VALUE_OBJECT ||
        !argv[0].as.object || argv[0].as.object->get_fn != js_regexp_get)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid RegExp receiver");
        }
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)argv[0].as.object->user_data;
    if (!re || (realm && re->realm_id != realm->id))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid RegExp receiver");
        }
        return false;
    }
    size_t inner_argc = argc > 0 ? argc - 1 : 0;
    const js_value_t *inner_argv = inner_argc ? &argv[1] : NULL;
    return js_regexp_compile(rt, inner_argc, inner_argv, re, out, error_message);
}

static bool js_regexp_split(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_value_t input_fallback = js_value_make_undefined_internal();
    const js_value_t *input_val = (argc > 0 && argv) ? &argv[0] : &input_fallback;
    js_temp_string_t input_temp = {0};
    if (!js_temp_string_from_value(rt, input_val, &input_temp, error_message))
    {
        return false;
    }
    const char *text = input_temp.data ? input_temp.data : "";
    size_t text_len = input_temp.len;

    if (!js_value_make_array(out))
    {
        js_temp_string_release(&input_temp);
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    if (re && re->object)
    {
        char *getter_err = NULL;
        if (!js_call_accessor_getter(rt, re->object, "Symbol.match", &getter_err))
        {
            js_value_destroy(out);
            js_temp_string_release(&input_temp);
            if (getter_err)
            {
                if (error_message)
                {
                    *error_message = getter_err;
                }
                else
                {
                    js_free(getter_err);
                }
            }
            return false;
        }
        js_free(getter_err);
    }
    const char *pattern = (re && re->pattern) ? re->pattern : "";
    size_t pattern_len = (re && re->pattern) ? re->pattern_len : 0;
    char *pattern_copy = NULL;
    if (pattern_len)
    {
        pattern_copy = js_strdup_len(pattern, pattern_len);
        if (!pattern_copy)
        {
            js_value_destroy(out);
            js_temp_string_release(&input_temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        pattern = pattern_copy;
    }

    size_t limit = 0xFFFFFFFFu;
    if (argc > 1 && argv)
    {
        bool ok_num = true;
        const js_value_t *limit_val = &argv[1];
        js_value_t prim = js_value_make_undefined_internal();
        if (limit_val->type == JS_VALUE_OBJECT)
        {
            if (!js_object_to_primitive_number(rt, limit_val->as.object, &prim, error_message))
            {
                js_value_destroy(out);
                js_temp_string_release(&input_temp);
                js_free(pattern_copy);
                return false;
            }
            limit_val = &prim;
        }
        double lim = js_value_to_number(limit_val, &ok_num);
        js_value_destroy(&prim);
        if (!ok_num || js_is_nan(lim) || lim == 0)
        {
            limit = 0;
        }
        else
        {
            if (lim > (double)INT64_MAX)
            {
                lim = (double)INT64_MAX;
            }
            if (lim < (double)INT64_MIN)
            {
                lim = (double)INT64_MIN;
            }
            int64_t int_val = (int64_t)lim;
            uint32_t uint_val = (uint32_t)((uint64_t)int_val);
            limit = (size_t)uint_val;
        }
    }

    if (limit == 0)
    {
        js_value_destroy(out);
        js_temp_string_release(&input_temp);
        js_free(pattern_copy);
        return js_value_make_array(out);
    }
    char *literal = NULL;
    size_t literal_len = pattern_len;
    if (js_regexp_build_literal(pattern, pattern_len, &literal, &literal_len) && literal)
    {
        pattern = literal;
        pattern_len = literal_len;
    }

    size_t out_index = 0;
    if (pattern_len == 0)
    {
        for (size_t i = 0; i < text_len && out_index < limit; ++i)
        {
            js_value_t part;
            if (!js_value_make_string(&part, text + i, 1))
            {
                js_value_destroy(out);
                js_free(literal);
                js_free(pattern_copy);
                js_temp_string_release(&input_temp);
                return false;
            }
            bool ok = js_value_array_set(out, out_index++, &part);
            js_value_destroy(&part);
            if (!ok)
            {
                js_value_destroy(out);
                js_free(literal);
                js_free(pattern_copy);
                js_temp_string_release(&input_temp);
                return false;
            }
        }
        js_free(literal);
        js_free(pattern_copy);
        js_temp_string_release(&input_temp);
        return true;
    }

    size_t start = 0;
    size_t i = 0;
    while (i + pattern_len <= text_len)
    {
        if (memcmp(text + i, pattern, pattern_len) == 0)
        {
            js_value_t part;
            if (!js_value_make_string(&part, text + start, i - start))
            {
                js_value_destroy(out);
                js_free(literal);
                js_free(pattern_copy);
                js_temp_string_release(&input_temp);
                return false;
            }
            bool ok = js_value_array_set(out, out_index++, &part);
            js_value_destroy(&part);
            if (!ok)
            {
                js_value_destroy(out);
                js_free(literal);
                js_free(pattern_copy);
                js_temp_string_release(&input_temp);
                return false;
            }
            if (out_index >= limit)
            {
                start = i + pattern_len;
                break;
            }
            i += pattern_len;
            start = i;
            continue;
        }
        ++i;
    }
    if (out_index < limit)
    {
        js_value_t tail;
        if (!js_value_make_string(&tail, text + start, text_len - start))
        {
            js_value_destroy(out);
            js_free(literal);
            js_free(pattern_copy);
            js_temp_string_release(&input_temp);
            return false;
        }
        bool ok = js_value_array_set(out, out_index++, &tail);
        js_value_destroy(&tail);
        if (!ok)
        {
            js_value_destroy(out);
            js_free(literal);
            js_free(pattern_copy);
            js_temp_string_release(&input_temp);
            return false;
        }
    }

    js_free(literal);
    js_free(pattern_copy);
    js_temp_string_release(&input_temp);
    return true;
}

bool js_regexp_is_legacy_static_property(const char *name)
{
    if (!name)
    {
        return false;
    }
    if (strcmp(name, "input") == 0 ||
        strcmp(name, "lastMatch") == 0 ||
        strcmp(name, "lastParen") == 0 ||
        strcmp(name, "leftContext") == 0 ||
        strcmp(name, "rightContext") == 0)
    {
        return true;
    }
    if (name[0] != '$')
    {
        return false;
    }
    if (strcmp(name, "$_") == 0 ||
        strcmp(name, "$&") == 0 ||
        strcmp(name, "$`") == 0 ||
        strcmp(name, "$'") == 0 ||
        strcmp(name, "$+") == 0)
    {
        return true;
    }
    if (name[1] >= '1' && name[1] <= '9' && name[2] == '\0')
    {
        return true;
    }
    return false;
}

static bool js_regexp_is_legacy_setter_property(const char *name)
{
    return name && (strcmp(name, "input") == 0 || strcmp(name, "$_") == 0);
}

bool js_regexp_legacy_getter(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *receiver = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!receiver || receiver->type != JS_VALUE_NATIVE_FN ||
        receiver->as.native.fn != js_builtin_regexp ||
        receiver->as.native.user_data != user_data)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid RegExp receiver");
        }
        return false;
    }
    return js_value_make_cstring(out, "");
}

bool js_regexp_legacy_setter(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *receiver = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!receiver || receiver->type != JS_VALUE_NATIVE_FN ||
        receiver->as.native.fn != js_builtin_regexp ||
        receiver->as.native.user_data != user_data)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid RegExp receiver");
        }
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_regexp_get(js_runtime_t *rt,
                          void *user_data,
                          const char *name,
                          js_value_t *out,
                          char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    if (name && strcmp(name, "test") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_test;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "exec") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_exec;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "compile") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_compile;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "toString") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_to_string;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "lastIndex") == 0)
    {
        if (re && re->object && js_object_has_slot(re->object, "lastIndex"))
        {
            return js_object_get_slot(re->object, "lastIndex", out);
        }
        *out = js_value_make_number(0.0);
        return true;
    }
    if (name && strcmp(name, "Symbol.split") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_split;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "Symbol.match") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_exec;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "source") == 0)
    {
        return js_value_make_string(out,
                                    re && re->pattern ? re->pattern : "",
                                    re ? re->pattern_len : 0);
    }
    if (name && strcmp(name, "flags") == 0)
    {
        return js_value_make_string(out,
                                    re && re->flags ? re->flags : "",
                                    re ? re->flags_len : 0);
    }
    if (name && strcmp(name, "global") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'g') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "ignoreCase") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'i') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "multiline") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'm') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "dotAll") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 's') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "unicode") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'u') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "sticky") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'y') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_string_is_callable(const js_value_t *value)
{
    return value && (value->type == JS_VALUE_FUNCTION ||
                     value->type == JS_VALUE_NATIVE_FN ||
                     js_value_is_html_dda(value));
}

static bool js_string_get_symbol_method(js_runtime_t *rt,
                                        const js_value_t *target,
                                        const char *symbol_name,
                                        js_value_t *method,
                                        bool *has_method,
                                        char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (has_method)
    {
        *has_method = false;
    }
    if (!method)
    {
        return false;
    }
    *method = js_value_make_undefined_internal();
    if (!target || !symbol_name)
    {
        return true;
    }
    if (target->type != JS_VALUE_OBJECT && target->type != JS_VALUE_ARRAY)
    {
        return true;
    }
    char *err = NULL;
    bool ok = false;
    if (target->type == JS_VALUE_OBJECT)
    {
        ok = js_object_get_property(rt, target->as.object, symbol_name, method, &err);
    }
    else
    {
        ok = js_array_get_property(rt, target->as.array, symbol_name, method, &err);
    }
    if (!ok)
    {
        if (error_message)
        {
            *error_message = err ? err : js_strdup("property lookup failed");
        }
        else
        {
            js_free(err);
        }
        return false;
    }
    js_free(err);
    if (method->type == JS_VALUE_UNDEFINED || method->type == JS_VALUE_NULL)
    {
        return true;
    }
    if (has_method)
    {
        *has_method = true;
    }
    return true;
}

static bool js_string_call_method(js_runtime_t *rt,
                                  const js_value_t *method,
                                  size_t argc,
                                  const js_value_t *argv,
                                  js_value_t *out,
                                  char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!method || !out)
    {
        return false;
    }
    js_value_t *call_args = NULL;
    if (argc)
    {
        call_args = (js_value_t *)js_calloc(argc, sizeof(*call_args));
        if (!call_args)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        for (size_t i = 0; i < argc; ++i)
        {
            if (!js_value_copy(&call_args[i], &argv[i]))
            {
                for (size_t j = 0; j < i; ++j)
                {
                    js_value_destroy(&call_args[j]);
                }
                js_free(call_args);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
    }
    bool ok = js_call_value(rt, method, argc, call_args, out, error_message);
    for (size_t i = 0; i < argc; ++i)
    {
        js_value_destroy(&call_args[i]);
    }
    js_free(call_args);
    return ok;
}

static bool js_string_find(const char *text,
                           size_t text_len,
                           const char *needle,
                           size_t needle_len,
                           size_t start,
                           size_t *out_pos)
{
    if (!out_pos)
    {
        return false;
    }
    if (start > text_len)
    {
        return false;
    }
    if (needle_len == 0)
    {
        *out_pos = start;
        return true;
    }
    if (!text || !needle || needle_len > text_len)
    {
        return false;
    }
    for (size_t i = start; i + needle_len <= text_len; ++i)
    {
        if (memcmp(text + i, needle, needle_len) == 0)
        {
            *out_pos = i;
            return true;
        }
    }
    return false;
}

static bool js_value_to_integer(js_runtime_t *rt,
                                const js_value_t *value,
                                double *out,
                                char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = 0.0;
    if (!value || value->type == JS_VALUE_UNDEFINED)
    {
        return true;
    }
    if (value->type == JS_VALUE_OBJECT && value->as.object && js_object_is_symbol(value->as.object))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: cannot convert Symbol to number");
        }
        return false;
    }
    js_value_t prim = js_value_make_undefined_internal();
    bool prim_owned = false;
    const js_value_t *num_val = value;
    if (value->type == JS_VALUE_OBJECT && value->as.object)
    {
        if (!js_object_to_primitive_number(rt, value->as.object, &prim, error_message))
        {
            return false;
        }
        prim_owned = true;
        num_val = &prim;
    }
    if (num_val->type == JS_VALUE_OBJECT && num_val->as.object && js_object_is_symbol(num_val->as.object))
    {
        if (prim_owned)
        {
            js_value_destroy(&prim);
        }
        if (error_message)
        {
            *error_message = js_strdup("TypeError: cannot convert Symbol to number");
        }
        return false;
    }
    bool ok = true;
    double num = js_value_to_number(num_val, &ok);
    if (prim_owned)
    {
        js_value_destroy(&prim);
    }
    if (!ok || js_is_nan(num))
    {
        num = 0.0;
    }
    *out = num;
    return true;
}

bool js_builtin_string_match(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (const js_value_t *)user_data;
    if (!this_val || this_val->type != JS_VALUE_STRING)
    {
        *out = js_value_make_null();
        return true;
    }
    const js_value_t *arg = (argc > 0 && argv) ? &argv[0] : NULL;
    if (arg && arg->type != JS_VALUE_UNDEFINED && arg->type != JS_VALUE_NULL)
    {
        js_value_t matcher = js_value_make_undefined_internal();
        bool has_matcher = false;
        if (!js_string_get_symbol_method(rt, arg, "Symbol.match", &matcher, &has_matcher, error_message))
        {
            return false;
        }
        if (has_matcher)
        {
            if (!js_string_is_callable(&matcher))
            {
                js_value_destroy(&matcher);
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: matcher is not callable");
                }
                return false;
            }
            if (!js_string_call_method(rt, &matcher, 1, this_val, out, error_message))
            {
                js_value_destroy(&matcher);
                return false;
            }
            js_value_destroy(&matcher);
            return true;
        }
        js_value_destroy(&matcher);
    }
    const char *text = this_val->as.string.data ? this_val->as.string.data : "";
    size_t text_len = this_val->as.string.len;

    js_value_t source = js_value_make_undefined_internal();
    bool have_source = false;
    const char *pattern = NULL;
    size_t pattern_len = 0;
    js_temp_string_t pattern_temp = {0};

    if (arg && arg->type == JS_VALUE_OBJECT)
    {
        if (js_builtin_object_get_value(rt, arg->as.object, "source", &source, error_message) &&
            source.type == JS_VALUE_STRING)
        {
            pattern = source.as.string.data ? source.as.string.data : "";
            pattern_len = source.as.string.len;
            have_source = true;
        }
        else
        {
            js_value_destroy(&source);
        }
    }
    if (!have_source)
    {
        if (!js_temp_string_from_value(rt, arg, &pattern_temp, error_message))
        {
            return false;
        }
        pattern = pattern_temp.data ? pattern_temp.data : "";
        pattern_len = pattern_temp.len;
    }

    char *literal = NULL;
    size_t literal_len = pattern_len;
    if (js_regexp_build_literal(pattern, pattern_len, &literal, &literal_len) && literal)
    {
        pattern = literal;
        pattern_len = literal_len;
    }

    size_t match_pos = (size_t)-1;
    if (pattern_len == 0)
    {
        match_pos = 0;
    }
    else if (pattern_len <= text_len)
    {
        for (size_t i = 0; i + pattern_len <= text_len; ++i)
        {
            if (memcmp(text + i, pattern, pattern_len) == 0)
            {
                match_pos = i;
                break;
            }
        }
    }

    if (literal)
    {
        js_free(literal);
    }
    js_temp_string_release(&pattern_temp);
    if (have_source)
    {
        js_value_destroy(&source);
    }

    if (match_pos == (size_t)-1)
    {
        *out = js_value_make_null();
        return true;
    }

    if (!js_value_make_array(out))
    {
        return false;
    }
    js_value_t match_value;
    if (!js_value_make_string(&match_value, text + match_pos, pattern_len))
    {
        js_value_destroy(out);
        return false;
    }
    bool ok = js_value_array_set(out, 0, &match_value);
    js_value_destroy(&match_value);
    if (!ok)
    {
        js_value_destroy(out);
        return false;
    }
    return true;
}

bool js_builtin_string_char_code_at(js_runtime_t *rt,
                                    size_t argc,
                                    const js_value_t *argv,
                                    void *user_data,
                                    js_value_t *out,
                                    char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (const js_value_t *)user_data;
    js_temp_string_t temp = {0};
    if (!js_temp_string_from_value(rt, this_val, &temp, error_message))
    {
        return false;
    }

    double index_num = 0.0;
    if (argc > 0 && argv && argv[0].type != JS_VALUE_UNDEFINED)
    {
        bool ok = true;
        index_num = js_value_to_number(&argv[0], &ok);
        if (!ok || js_is_nan(index_num))
        {
            index_num = 0.0;
        }
    }
    double trunc = (index_num < 0.0) ? ceil(index_num) : floor(index_num);
    if (trunc < 0.0 || trunc >= (double)temp.len)
    {
        js_temp_string_release(&temp);
        *out = js_value_make_number(js_nan());
        return true;
    }
    size_t index = (size_t)trunc;
    unsigned char code = (unsigned char)temp.data[index];
    js_temp_string_release(&temp);
    *out = js_value_make_number((double)code);
    return true;
}

bool js_builtin_string_substring(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (const js_value_t *)user_data;
    js_temp_string_t temp = {0};
    if (!js_temp_string_from_value(rt, this_val, &temp, error_message))
    {
        return false;
    }

    double start_num = 0.0;
    double end_num = (double)temp.len;
    if (argc > 0 && argv && argv[0].type != JS_VALUE_UNDEFINED)
    {
        bool ok = true;
        start_num = js_value_to_number(&argv[0], &ok);
        if (!ok || js_is_nan(start_num))
        {
            start_num = 0.0;
        }
    }
    if (argc > 1 && argv && argv[1].type != JS_VALUE_UNDEFINED)
    {
        bool ok = true;
        end_num = js_value_to_number(&argv[1], &ok);
        if (!ok || js_is_nan(end_num))
        {
            end_num = 0.0;
        }
    }

    double start_trunc = (start_num < 0.0) ? ceil(start_num) : floor(start_num);
    double end_trunc = (end_num < 0.0) ? ceil(end_num) : floor(end_num);
    size_t start = 0;
    size_t end = 0;
    if (start_trunc > 0.0)
    {
        if (start_trunc >= (double)temp.len)
        {
            start = temp.len;
        }
        else
        {
            start = (size_t)start_trunc;
        }
    }
    if (end_trunc > 0.0)
    {
        if (end_trunc >= (double)temp.len)
        {
            end = temp.len;
        }
        else
        {
            end = (size_t)end_trunc;
        }
    }
    if (start > end)
    {
        size_t tmp = start;
        start = end;
        end = tmp;
    }

    size_t slice_len = (end >= start) ? (end - start) : 0;
    bool ok = js_value_make_string(out,
                                   temp.data ? temp.data + start : "",
                                   slice_len);
    js_temp_string_release(&temp);
    return ok;
}

static bool js_string_proto_create_html(js_runtime_t *rt,
                                        size_t argc,
                                        const js_value_t *argv,
                                        const char *tag,
                                        const char *attr,
                                        js_value_t *out,
                                        char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !tag)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || this_val->type == JS_VALUE_UNDEFINED || this_val->type == JS_VALUE_NULL)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: String.prototype method called on null or undefined");
        }
        return false;
    }
    js_temp_string_t str = {0};
    if (!js_temp_string_from_value(rt, this_val, &str, error_message))
    {
        return false;
    }
    js_temp_string_t attr_str = {0};
    size_t escaped_len = 0;
    if (attr)
    {
        js_value_t undef = js_value_make_undefined_internal();
        const js_value_t *attr_val = (argc > 1 && argv) ? &argv[1] : &undef;
        if (!js_temp_string_from_value(rt, attr_val, &attr_str, error_message))
        {
            js_temp_string_release(&str);
            return false;
        }
        const char *attr_data = attr_str.data ? attr_str.data : "";
        for (size_t i = 0; i < attr_str.len; ++i)
        {
            escaped_len += (attr_data[i] == '"') ? 6u : 1u;
        }
    }

    size_t tag_len = strlen(tag);
    size_t attr_len = attr ? strlen(attr) : 0;
    size_t open_len = 1 + tag_len;
    if (attr)
    {
        open_len += 1 + attr_len + 2 + escaped_len + 1;
    }
    open_len += 1;
    size_t close_len = 2 + tag_len + 1;
    size_t total_len = open_len + str.len + close_len;
    char *buf = (char *)js_malloc(total_len + 1);
    if (!buf)
    {
        js_temp_string_release(&attr_str);
        js_temp_string_release(&str);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    char *p = buf;
    *p++ = '<';
    memcpy(p, tag, tag_len);
    p += tag_len;
    if (attr)
    {
        *p++ = ' ';
        memcpy(p, attr, attr_len);
        p += attr_len;
        *p++ = '=';
        *p++ = '"';
        const char *attr_data = attr_str.data ? attr_str.data : "";
        for (size_t i = 0; i < attr_str.len; ++i)
        {
            if (attr_data[i] == '"')
            {
                memcpy(p, "&quot;", 6);
                p += 6;
            }
            else
            {
                *p++ = attr_data[i];
            }
        }
        *p++ = '"';
    }
    *p++ = '>';
    if (str.len && str.data)
    {
        memcpy(p, str.data, str.len);
        p += str.len;
    }
    *p++ = '<';
    *p++ = '/';
    memcpy(p, tag, tag_len);
    p += tag_len;
    *p++ = '>';
    *p = '\0';

    bool ok = js_value_make_string(out, buf, total_len);
    js_free(buf);
    js_temp_string_release(&attr_str);
    js_temp_string_release(&str);
    return ok;
}

bool js_string_proto_anchor(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "a", "name", out, error_message);
}

bool js_string_proto_big(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "big", NULL, out, error_message);
}

bool js_string_proto_blink(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "blink", NULL, out, error_message);
}

bool js_string_proto_bold(js_runtime_t *rt,
                          size_t argc,
                          const js_value_t *argv,
                          void *user_data,
                          js_value_t *out,
                          char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "b", NULL, out, error_message);
}

bool js_string_proto_fixed(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "tt", NULL, out, error_message);
}

bool js_string_proto_fontcolor(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "font", "color", out, error_message);
}

bool js_string_proto_fontsize(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "font", "size", out, error_message);
}

bool js_string_proto_italics(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "i", NULL, out, error_message);
}

bool js_string_proto_link(js_runtime_t *rt,
                          size_t argc,
                          const js_value_t *argv,
                          void *user_data,
                          js_value_t *out,
                          char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "a", "href", out, error_message);
}

bool js_string_proto_small(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "small", NULL, out, error_message);
}

bool js_string_proto_strike(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "strike", NULL, out, error_message);
}

bool js_string_proto_sub(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "sub", NULL, out, error_message);
}

bool js_string_proto_sup(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)user_data;
    return js_string_proto_create_html(rt, argc, argv, "sup", NULL, out, error_message);
}

bool js_string_proto_match_all(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || this_val->type == JS_VALUE_UNDEFINED || this_val->type == JS_VALUE_NULL)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: String.prototype method called on null or undefined");
        }
        return false;
    }
    const js_value_t *regexp = (argc > 1 && argv) ? &argv[1] : NULL;
    if (regexp && regexp->type != JS_VALUE_UNDEFINED && regexp->type != JS_VALUE_NULL)
    {
        js_value_t matcher = js_value_make_undefined_internal();
        bool has_matcher = false;
        if (!js_string_get_symbol_method(rt, regexp, "Symbol.matchAll", &matcher, &has_matcher, error_message))
        {
            return false;
        }
        if (has_matcher)
        {
            if (!js_string_is_callable(&matcher))
            {
                js_value_destroy(&matcher);
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: matcher is not callable");
                }
                return false;
            }
            bool ok = js_string_call_method(rt, &matcher, 1, this_val, out, error_message);
            js_value_destroy(&matcher);
            return ok;
        }
        js_value_destroy(&matcher);
    }
    if (!js_value_make_array(out))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

bool js_string_proto_search(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || this_val->type == JS_VALUE_UNDEFINED || this_val->type == JS_VALUE_NULL)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: String.prototype method called on null or undefined");
        }
        return false;
    }
    const js_value_t *regexp = (argc > 1 && argv) ? &argv[1] : NULL;
    if (regexp && regexp->type != JS_VALUE_UNDEFINED && regexp->type != JS_VALUE_NULL)
    {
        js_value_t searcher = js_value_make_undefined_internal();
        bool has_searcher = false;
        if (!js_string_get_symbol_method(rt, regexp, "Symbol.search", &searcher, &has_searcher, error_message))
        {
            return false;
        }
        if (has_searcher)
        {
            if (!js_string_is_callable(&searcher))
            {
                js_value_destroy(&searcher);
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: searcher is not callable");
                }
                return false;
            }
            bool ok = js_string_call_method(rt, &searcher, 1, this_val, out, error_message);
            js_value_destroy(&searcher);
            return ok;
        }
        js_value_destroy(&searcher);
    }

    js_temp_string_t text = {0};
    if (!js_temp_string_from_value(rt, this_val, &text, error_message))
    {
        return false;
    }

    js_value_t source = js_value_make_undefined_internal();
    bool have_source = false;
    const char *pattern = NULL;
    size_t pattern_len = 0;
    js_temp_string_t pattern_temp = {0};
    if (regexp && regexp->type == JS_VALUE_OBJECT)
    {
        if (js_builtin_object_get_value(rt, regexp->as.object, "source", &source, error_message) &&
            source.type == JS_VALUE_STRING)
        {
            pattern = source.as.string.data ? source.as.string.data : "";
            pattern_len = source.as.string.len;
            have_source = true;
        }
        else
        {
            js_value_destroy(&source);
        }
    }
    if (!have_source)
    {
        if (!js_temp_string_from_value(rt, regexp, &pattern_temp, error_message))
        {
            js_temp_string_release(&text);
            return false;
        }
        pattern = pattern_temp.data ? pattern_temp.data : "";
        pattern_len = pattern_temp.len;
    }

    size_t pos = 0;
    bool found = js_string_find(text.data, text.len, pattern, pattern_len, 0, &pos);
    if (!found)
    {
        *out = js_value_make_number(-1.0);
    }
    else
    {
        *out = js_value_make_number((double)pos);
    }

    js_temp_string_release(&pattern_temp);
    if (have_source)
    {
        js_value_destroy(&source);
    }
    js_temp_string_release(&text);
    return true;
}

bool js_string_proto_replace(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || this_val->type == JS_VALUE_UNDEFINED || this_val->type == JS_VALUE_NULL)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: String.prototype method called on null or undefined");
        }
        return false;
    }
    const js_value_t *search_val = (argc > 1 && argv) ? &argv[1] : NULL;
    const js_value_t *replace_val = (argc > 2 && argv) ? &argv[2] : NULL;
    if (search_val && search_val->type != JS_VALUE_UNDEFINED && search_val->type != JS_VALUE_NULL)
    {
        js_value_t replacer = js_value_make_undefined_internal();
        bool has_replacer = false;
        if (!js_string_get_symbol_method(rt, search_val, "Symbol.replace", &replacer, &has_replacer, error_message))
        {
            return false;
        }
        if (has_replacer)
        {
            if (!js_string_is_callable(&replacer))
            {
                js_value_destroy(&replacer);
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: replacer is not callable");
                }
                return false;
            }
            js_value_t args[2];
            js_value_t undef = js_value_make_undefined_internal();
            args[0] = *this_val;
            args[1] = replace_val ? *replace_val : undef;
            bool ok = js_string_call_method(rt, &replacer, 2, args, out, error_message);
            js_value_destroy(&replacer);
            return ok;
        }
        js_value_destroy(&replacer);
    }

    js_temp_string_t text = {0};
    if (!js_temp_string_from_value(rt, this_val, &text, error_message))
    {
        return false;
    }
    js_temp_string_t search = {0};
    if (!js_temp_string_from_value(rt, search_val, &search, error_message))
    {
        js_temp_string_release(&text);
        return false;
    }
    js_temp_string_t replace = {0};
    if (!js_temp_string_from_value(rt, replace_val, &replace, error_message))
    {
        js_temp_string_release(&search);
        js_temp_string_release(&text);
        return false;
    }

    size_t match_pos = 0;
    bool found = js_string_find(text.data, text.len,
                                search.data ? search.data : "",
                                search.len,
                                0,
                                &match_pos);
    if (!found)
    {
        bool ok = js_value_make_string(out,
                                       text.data ? text.data : "",
                                       text.len);
        js_temp_string_release(&replace);
        js_temp_string_release(&search);
        js_temp_string_release(&text);
        return ok;
    }

    size_t new_len = text.len + replace.len;
    if (search.len <= text.len)
    {
        new_len -= search.len;
    }
    char *buf = (char *)js_malloc(new_len + 1);
    if (!buf)
    {
        js_temp_string_release(&replace);
        js_temp_string_release(&search);
        js_temp_string_release(&text);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    size_t prefix_len = match_pos;
    size_t suffix_pos = match_pos + search.len;
    char *p = buf;
    if (prefix_len && text.data)
    {
        memcpy(p, text.data, prefix_len);
        p += prefix_len;
    }
    if (replace.len && replace.data)
    {
        memcpy(p, replace.data, replace.len);
        p += replace.len;
    }
    if (suffix_pos < text.len && text.data)
    {
        memcpy(p, text.data + suffix_pos, text.len - suffix_pos);
        p += text.len - suffix_pos;
    }
    *p = '\0';

    bool ok = js_value_make_string(out, buf, new_len);
    js_free(buf);
    js_temp_string_release(&replace);
    js_temp_string_release(&search);
    js_temp_string_release(&text);
    return ok;
}

bool js_string_proto_replace_all(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || this_val->type == JS_VALUE_UNDEFINED || this_val->type == JS_VALUE_NULL)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: String.prototype method called on null or undefined");
        }
        return false;
    }
    const js_value_t *search_val = (argc > 1 && argv) ? &argv[1] : NULL;
    const js_value_t *replace_val = (argc > 2 && argv) ? &argv[2] : NULL;
    if (search_val && search_val->type != JS_VALUE_UNDEFINED && search_val->type != JS_VALUE_NULL)
    {
        js_value_t replacer = js_value_make_undefined_internal();
        bool has_replacer = false;
        if (!js_string_get_symbol_method(rt, search_val, "Symbol.replace", &replacer, &has_replacer, error_message))
        {
            return false;
        }
        if (has_replacer)
        {
            if (!js_string_is_callable(&replacer))
            {
                js_value_destroy(&replacer);
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: replacer is not callable");
                }
                return false;
            }
            js_value_t args[2];
            js_value_t undef = js_value_make_undefined_internal();
            args[0] = *this_val;
            args[1] = replace_val ? *replace_val : undef;
            bool ok = js_string_call_method(rt, &replacer, 2, args, out, error_message);
            js_value_destroy(&replacer);
            return ok;
        }
        js_value_destroy(&replacer);
    }

    js_temp_string_t text = {0};
    if (!js_temp_string_from_value(rt, this_val, &text, error_message))
    {
        return false;
    }
    js_temp_string_t search = {0};
    if (!js_temp_string_from_value(rt, search_val, &search, error_message))
    {
        js_temp_string_release(&text);
        return false;
    }
    js_temp_string_t replace = {0};
    if (!js_temp_string_from_value(rt, replace_val, &replace, error_message))
    {
        js_temp_string_release(&search);
        js_temp_string_release(&text);
        return false;
    }

    if (search.len == 0)
    {
        size_t slots = text.len + 1;
        size_t new_len = text.len + replace.len * slots;
        char *buf = (char *)js_malloc(new_len + 1);
        if (!buf)
        {
            js_temp_string_release(&replace);
            js_temp_string_release(&search);
            js_temp_string_release(&text);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        char *p = buf;
        for (size_t i = 0; i < slots; ++i)
        {
            if (replace.len && replace.data)
            {
                memcpy(p, replace.data, replace.len);
                p += replace.len;
            }
            if (i < text.len && text.data)
            {
                *p++ = text.data[i];
            }
        }
        *p = '\0';
        bool ok = js_value_make_string(out, buf, new_len);
        js_free(buf);
        js_temp_string_release(&replace);
        js_temp_string_release(&search);
        js_temp_string_release(&text);
        return ok;
    }

    size_t count = 0;
    size_t pos = 0;
    size_t match_pos = 0;
    while (js_string_find(text.data, text.len,
                          search.data ? search.data : "",
                          search.len,
                          pos,
                          &match_pos))
    {
        count++;
        pos = match_pos + search.len;
        if (pos > text.len)
        {
            break;
        }
    }
    if (count == 0)
    {
        bool ok = js_value_make_string(out,
                                       text.data ? text.data : "",
                                       text.len);
        js_temp_string_release(&replace);
        js_temp_string_release(&search);
        js_temp_string_release(&text);
        return ok;
    }

    size_t new_len = text.len + count * replace.len;
    if (search.len <= text.len)
    {
        new_len -= count * search.len;
    }
    char *buf = (char *)js_malloc(new_len + 1);
    if (!buf)
    {
        js_temp_string_release(&replace);
        js_temp_string_release(&search);
        js_temp_string_release(&text);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    char *p = buf;
    size_t cursor = 0;
    pos = 0;
    while (js_string_find(text.data, text.len,
                          search.data ? search.data : "",
                          search.len,
                          pos,
                          &match_pos))
    {
        if (match_pos > cursor && text.data)
        {
            memcpy(p, text.data + cursor, match_pos - cursor);
            p += match_pos - cursor;
        }
        if (replace.len && replace.data)
        {
            memcpy(p, replace.data, replace.len);
            p += replace.len;
        }
        cursor = match_pos + search.len;
        pos = cursor;
        if (pos > text.len)
        {
            break;
        }
    }
    if (cursor < text.len && text.data)
    {
        memcpy(p, text.data + cursor, text.len - cursor);
        p += text.len - cursor;
    }
    *p = '\0';

    bool ok = js_value_make_string(out, buf, new_len);
    js_free(buf);
    js_temp_string_release(&replace);
    js_temp_string_release(&search);
    js_temp_string_release(&text);
    return ok;
}

bool js_string_proto_split(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || this_val->type == JS_VALUE_UNDEFINED || this_val->type == JS_VALUE_NULL)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: String.prototype method called on null or undefined");
        }
        return false;
    }
    const js_value_t *sep_val = (argc > 1 && argv) ? &argv[1] : NULL;
    const js_value_t *limit_val = (argc > 2 && argv) ? &argv[2] : NULL;
    if (sep_val && sep_val->type != JS_VALUE_UNDEFINED && sep_val->type != JS_VALUE_NULL)
    {
        js_value_t splitter = js_value_make_undefined_internal();
        bool has_splitter = false;
        if (!js_string_get_symbol_method(rt, sep_val, "Symbol.split", &splitter, &has_splitter, error_message))
        {
            return false;
        }
        if (has_splitter)
        {
            if (!js_string_is_callable(&splitter))
            {
                js_value_destroy(&splitter);
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: splitter is not callable");
                }
                return false;
            }
            js_value_t args[2];
            js_value_t undef = js_value_make_undefined_internal();
            args[0] = *this_val;
            args[1] = limit_val ? *limit_val : undef;
            bool ok = js_string_call_method(rt, &splitter, 2, args, out, error_message);
            js_value_destroy(&splitter);
            return ok;
        }
        js_value_destroy(&splitter);
    }

    js_temp_string_t text = {0};
    if (!js_temp_string_from_value(rt, this_val, &text, error_message))
    {
        return false;
    }

    size_t limit = SIZE_MAX;
    if (limit_val && limit_val->type != JS_VALUE_UNDEFINED)
    {
        bool ok = true;
        double num = js_value_to_number(limit_val, &ok);
        if (!ok || js_is_nan(num) || num <= 0.0)
        {
            limit = 0;
        }
        else if (num > (double)SIZE_MAX)
        {
            limit = SIZE_MAX;
        }
        else
        {
            limit = (size_t)num;
        }
    }

    if (!js_value_make_array(out))
    {
        js_temp_string_release(&text);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (limit == 0)
    {
        js_temp_string_release(&text);
        return true;
    }
    if (!sep_val || sep_val->type == JS_VALUE_UNDEFINED || sep_val->type == JS_VALUE_NULL)
    {
        js_value_t full;
        bool ok = js_value_make_string(&full,
                                       text.data ? text.data : "",
                                       text.len);
        if (!ok || !js_value_array_push(out, &full))
        {
            js_value_destroy(&full);
            js_temp_string_release(&text);
            js_value_destroy(out);
            return false;
        }
        js_value_destroy(&full);
        js_temp_string_release(&text);
        return true;
    }

    js_temp_string_t sep = {0};
    if (!js_temp_string_from_value(rt, sep_val, &sep, error_message))
    {
        js_temp_string_release(&text);
        js_value_destroy(out);
        return false;
    }

    size_t count = 0;
    if (sep.len == 0)
    {
        for (size_t i = 0; i < text.len && count < limit; ++i)
        {
            js_value_t piece;
            if (!js_value_make_string(&piece, text.data ? text.data + i : "", 1))
            {
                js_temp_string_release(&sep);
                js_temp_string_release(&text);
                js_value_destroy(out);
                return false;
            }
            if (!js_value_array_push(out, &piece))
            {
                js_value_destroy(&piece);
                js_temp_string_release(&sep);
                js_temp_string_release(&text);
                js_value_destroy(out);
                return false;
            }
            js_value_destroy(&piece);
            count++;
        }
        js_temp_string_release(&sep);
        js_temp_string_release(&text);
        return true;
    }

    size_t cursor = 0;
    size_t match_pos = 0;
    while (count < limit &&
           js_string_find(text.data, text.len,
                          sep.data ? sep.data : "",
                          sep.len,
                          cursor,
                          &match_pos))
    {
        size_t part_len = match_pos - cursor;
        js_value_t piece;
        if (!js_value_make_string(&piece,
                                  text.data ? text.data + cursor : "",
                                  part_len))
        {
            js_temp_string_release(&sep);
            js_temp_string_release(&text);
            js_value_destroy(out);
            return false;
        }
        if (!js_value_array_push(out, &piece))
        {
            js_value_destroy(&piece);
            js_temp_string_release(&sep);
            js_temp_string_release(&text);
            js_value_destroy(out);
            return false;
        }
        js_value_destroy(&piece);
        count++;
        cursor = match_pos + sep.len;
        if (cursor > text.len)
        {
            break;
        }
    }
    if (count < limit)
    {
        size_t tail_len = (cursor <= text.len) ? (text.len - cursor) : 0;
        js_value_t piece;
        if (!js_value_make_string(&piece,
                                  text.data ? text.data + cursor : "",
                                  tail_len))
        {
            js_temp_string_release(&sep);
            js_temp_string_release(&text);
            js_value_destroy(out);
            return false;
        }
        if (!js_value_array_push(out, &piece))
        {
            js_value_destroy(&piece);
            js_temp_string_release(&sep);
            js_temp_string_release(&text);
            js_value_destroy(out);
            return false;
        }
        js_value_destroy(&piece);
    }
    js_temp_string_release(&sep);
    js_temp_string_release(&text);
    return true;
}

bool js_string_proto_substr(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || this_val->type == JS_VALUE_UNDEFINED || this_val->type == JS_VALUE_NULL)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: String.prototype method called on null or undefined");
        }
        return false;
    }
    js_temp_string_t text = {0};
    if (!js_temp_string_from_value(rt, this_val, &text, error_message))
    {
        return false;
    }

    const js_value_t *start_val = (argc > 1 && argv) ? &argv[1] : NULL;
    const js_value_t *length_val = (argc > 2 && argv) ? &argv[2] : NULL;

    double start_num = 0.0;
    if (!js_value_to_integer(rt, start_val, &start_num, error_message))
    {
        js_temp_string_release(&text);
        return false;
    }
    double start_trunc = (start_num < 0.0) ? ceil(start_num) : floor(start_num);
    size_t start = 0;
    if (start_trunc < 0.0)
    {
        double pos = (double)text.len + start_trunc;
        if (pos > 0.0)
        {
            if (pos >= (double)text.len)
            {
                start = text.len;
            }
            else
            {
                start = (size_t)pos;
            }
        }
    }
    else
    {
        if (start_trunc >= (double)text.len)
        {
            start = text.len;
        }
        else
        {
            start = (size_t)start_trunc;
        }
    }

    size_t length = 0;
    if (!length_val || length_val->type == JS_VALUE_UNDEFINED)
    {
        length = (start <= text.len) ? (text.len - start) : 0;
    }
    else
    {
        double len_num = 0.0;
        if (!js_value_to_integer(rt, length_val, &len_num, error_message))
        {
            js_temp_string_release(&text);
            return false;
        }
        double len_trunc = (len_num < 0.0) ? ceil(len_num) : floor(len_num);
        if (len_trunc > 0.0)
        {
            if ((double)SIZE_MAX < len_trunc)
            {
                length = text.len - start;
            }
            else
            {
                length = (size_t)len_trunc;
            }
        }
        if (start + length > text.len)
        {
            length = (start <= text.len) ? (text.len - start) : 0;
        }
    }

    bool ok = js_value_make_string(out,
                                   text.data ? text.data + start : "",
                                   length);
    js_temp_string_release(&text);
    return ok;
}

bool js_builtin_number_to_string(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (const js_value_t *)user_data;
    if (!this_val || this_val->type != JS_VALUE_NUMBER)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Number.prototype.toString called on non-number");
        }
        return false;
    }
    int radix = 10;
    if (argc > 0 && argv && argv[0].type != JS_VALUE_UNDEFINED)
    {
        bool ok = true;
        double r = js_value_to_number(&argv[0], &ok);
        if (ok && !js_is_nan(r))
        {
            radix = (int)r;
        }
        if (radix < 2 || radix > 36)
        {
            if (error_message)
            {
                *error_message = js_strdup("RangeError: invalid radix");
            }
            return false;
        }
    }
    double num = this_val->as.number;
    if (radix == 10 || js_is_nan(num) || num > 1.0e308 || num < -1.0e308)
    {
        js_temp_string_t temp = {0};
        if (!js_temp_string_from_value(rt, this_val, &temp, error_message))
        {
            return false;
        }
        bool ok = js_value_make_string(out, temp.data ? temp.data : "", temp.len);
        js_temp_string_release(&temp);
        return ok;
    }
    if (num == 0.0)
    {
        return js_value_make_string(out, "0", 1);
    }
    bool negative = num < 0.0;
    double abs_val = negative ? -num : num;
    unsigned long long int_part = (unsigned long long)abs_val;
    if (abs_val != (double)int_part)
    {
        js_temp_string_t temp = {0};
        if (!js_temp_string_from_value(rt, this_val, &temp, error_message))
        {
            return false;
        }
        bool ok = js_value_make_string(out, temp.data ? temp.data : "", temp.len);
        js_temp_string_release(&temp);
        return ok;
    }

    size_t cap = 70;
    char *buf = (char *)js_malloc(cap);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    const char *digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    size_t len = 0;
    while (int_part > 0 && len + 1 < cap)
    {
        unsigned int digit = (unsigned int)(int_part % (unsigned long long)radix);
        buf[len++] = digits[digit];
        int_part /= (unsigned long long)radix;
    }
    if (negative)
    {
        buf[len++] = '-';
    }
    for (size_t i = 0; i < len / 2; ++i)
    {
        char tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
    bool ok = js_value_make_string(out, buf, len);
    js_free(buf);
    if (!ok && error_message)
    {
        *error_message = js_strdup("allocation failed");
    }
    return ok;
}

typedef struct
{
    bool has_value;
    bool has_writable;
    bool has_enumerable;
    bool has_configurable;
    bool has_get;
    bool has_set;
    js_value_t value;
    js_value_t getter;
    js_value_t setter;
    bool writable;
    bool enumerable;
    bool configurable;
} js_desc_request_t;

static void js_desc_request_init(js_desc_request_t *desc)
{
    if (!desc)
    {
        return;
    }
    memset(desc, 0, sizeof(*desc));
    desc->value = js_value_make_undefined_internal();
    desc->getter = js_value_make_undefined_internal();
    desc->setter = js_value_make_undefined_internal();
}

static void js_desc_request_destroy(js_desc_request_t *desc)
{
    if (!desc)
    {
        return;
    }
    js_value_destroy(&desc->value);
    js_value_destroy(&desc->getter);
    js_value_destroy(&desc->setter);
}

static bool js_value_is_callable_local(const js_value_t *value)
{
    return value && (value->type == JS_VALUE_FUNCTION || value->type == JS_VALUE_NATIVE_FN);
}

static bool js_value_get_property_value(js_runtime_t *rt,
                                        const js_value_t *obj,
                                        const char *name,
                                        js_value_t *out,
                                        char **error_message);

static bool js_value_has_property_local(js_runtime_t *rt, const js_value_t *obj, const char *name)
{
    if (!rt || !obj || !name)
    {
        return false;
    }
    if (obj->type == JS_VALUE_OBJECT)
    {
        return js_object_has_property(rt, obj->as.object, name);
    }
    if (obj->type == JS_VALUE_ARRAY)
    {
        if (!obj->as.array)
        {
            return false;
        }
        if (js_array_find_property(obj->as.array, name))
        {
            return true;
        }
        size_t index = 0;
        if (js_parse_index_key(name, &index) && index < obj->as.array->length)
        {
            return true;
        }
        js_object_t *proto = js_get_array_proto(rt);
        if (proto)
        {
            return js_object_has_property(rt, proto, name);
        }
        return false;
    }
    return false;
}

static bool js_parse_property_descriptor(js_runtime_t *rt,
                                         const js_value_t *desc_val,
                                         js_desc_request_t *out,
                                         char **error_message)
{
    if (!out)
    {
        return false;
    }
    js_desc_request_init(out);
    if (!desc_val || (desc_val->type != JS_VALUE_OBJECT && desc_val->type != JS_VALUE_ARRAY))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: property descriptor must be an object");
        }
        return false;
    }

    bool has = false;
    js_value_t value = js_value_make_undefined_internal();
    has = js_value_has_property_local(rt, desc_val, "value");
    if (has && !js_value_get_property_value(rt, desc_val, "value", &value, error_message))
    {
        js_desc_request_destroy(out);
        return false;
    }
    if (has)
    {
        out->has_value = true;
        out->value = value;
    }
    else
    {
        js_value_destroy(&value);
    }

    js_value_t writable = js_value_make_undefined_internal();
    has = js_value_has_property_local(rt, desc_val, "writable");
    if (has && !js_value_get_property_value(rt, desc_val, "writable", &writable, error_message))
    {
        js_desc_request_destroy(out);
        return false;
    }
    if (has)
    {
        out->has_writable = true;
        out->writable = js_value_is_truthy(&writable);
    }
    js_value_destroy(&writable);

    js_value_t enumerable = js_value_make_undefined_internal();
    has = js_value_has_property_local(rt, desc_val, "enumerable");
    if (has && !js_value_get_property_value(rt, desc_val, "enumerable", &enumerable, error_message))
    {
        js_desc_request_destroy(out);
        return false;
    }
    if (has)
    {
        out->has_enumerable = true;
        out->enumerable = js_value_is_truthy(&enumerable);
    }
    js_value_destroy(&enumerable);

    js_value_t configurable = js_value_make_undefined_internal();
    has = js_value_has_property_local(rt, desc_val, "configurable");
    if (has && !js_value_get_property_value(rt, desc_val, "configurable", &configurable, error_message))
    {
        js_desc_request_destroy(out);
        return false;
    }
    if (has)
    {
        out->has_configurable = true;
        out->configurable = js_value_is_truthy(&configurable);
    }
    js_value_destroy(&configurable);

    js_value_t getter = js_value_make_undefined_internal();
    has = js_value_has_property_local(rt, desc_val, "get");
    if (has && !js_value_get_property_value(rt, desc_val, "get", &getter, error_message))
    {
        js_desc_request_destroy(out);
        return false;
    }
    if (has)
    {
        if (getter.type != JS_VALUE_UNDEFINED && !js_value_is_callable_local(&getter))
        {
            js_value_destroy(&getter);
            js_desc_request_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("TypeError: getter must be callable");
            }
            return false;
        }
        out->has_get = true;
        out->getter = getter;
    }
    else
    {
        js_value_destroy(&getter);
    }

    js_value_t setter = js_value_make_undefined_internal();
    has = js_value_has_property_local(rt, desc_val, "set");
    if (has && !js_value_get_property_value(rt, desc_val, "set", &setter, error_message))
    {
        js_desc_request_destroy(out);
        return false;
    }
    if (has)
    {
        if (setter.type != JS_VALUE_UNDEFINED && !js_value_is_callable_local(&setter))
        {
            js_value_destroy(&setter);
            js_desc_request_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("TypeError: setter must be callable");
            }
            return false;
        }
        out->has_set = true;
        out->setter = setter;
    }
    else
    {
        js_value_destroy(&setter);
    }

    if ((out->has_value || out->has_writable) && (out->has_get || out->has_set))
    {
        js_desc_request_destroy(out);
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid property descriptor");
        }
        return false;
    }
    return true;
}

static double js_trunc_local(double value)
{
    return (value < 0.0) ? ceil(value) : floor(value);
}

static bool js_value_to_array_length_local(const js_value_t *value, size_t *out_length)
{
    if (!value || !out_length)
    {
        return false;
    }
    bool ok = true;
    double num = js_value_to_number(value, &ok);
    if (!ok || js_is_nan(num))
    {
        return false;
    }
    if (num < 0.0 || num >= 4294967296.0)
    {
        return false;
    }
    double trunc = js_trunc_local(num);
    if (trunc != num)
    {
        return false;
    }
    if (num > (double)SIZE_MAX)
    {
        return false;
    }
    *out_length = (size_t)num;
    return true;
}

bool js_builtin_define_property(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (argc < 3 || !argv)
    {
        return true;
    }
    const js_value_t *target = &argv[0];
    const js_value_t *key = &argv[1];
    const js_value_t *desc_val = &argv[2];
    if (target->type != JS_VALUE_OBJECT && target->type != JS_VALUE_ARRAY)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Object.defineProperty called on non-object");
        }
        return false;
    }

    js_desc_request_t request;
    if (!js_parse_property_descriptor(rt, desc_val, &request, error_message))
    {
        return false;
    }

    js_temp_string_t name_temp = {0};
    if (!js_temp_string_from_value(rt, key, &name_temp, error_message))
    {
        js_desc_request_destroy(&request);
        return false;
    }
    char *prop_name = js_strdup_len(name_temp.data ? name_temp.data : "", name_temp.len);
    js_temp_string_release(&name_temp);
    if (!prop_name)
    {
        js_desc_request_destroy(&request);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    bool desc_is_accessor = request.has_get || request.has_set;
    bool desc_is_data = request.has_value || request.has_writable;
    bool ok = true;

    if (target->type == JS_VALUE_OBJECT)
    {
        js_object_t *obj = target->as.object;
        if (!obj)
        {
            ok = false;
            if (error_message)
            {
                *error_message = js_strdup("TypeError: invalid object");
            }
            goto define_cleanup;
        }

        if (obj->get_fn == js_regexp_get && strcmp(prop_name, "lastIndex") == 0 && request.has_writable)
        {
            js_value_t flag = js_value_make_bool(request.writable);
            (void)js_object_set_slot(obj, "__lastIndex_writable", &flag);
        }

        js_property_t *prop = js_object_find_property(obj, prop_name);
        if (prop && !prop->configurable)
        {
            if ((request.has_configurable && request.configurable) ||
                (request.has_enumerable && request.enumerable != prop->enumerable))
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: cannot redefine property");
                }
                goto define_cleanup;
            }
            if ((desc_is_accessor && !prop->is_accessor) ||
                (desc_is_data && prop->is_accessor))
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: cannot redefine property");
                }
                goto define_cleanup;
            }
            if (!prop->is_accessor)
            {
                if (!prop->writable)
                {
                    if ((request.has_writable && request.writable) ||
                        (request.has_value && !js_value_strict_equal(&request.value, &prop->value)))
                    {
                        ok = false;
                        if (error_message)
                        {
                            *error_message = js_strdup("TypeError: cannot redefine property");
                        }
                        goto define_cleanup;
                    }
                }
            }
            else
            {
                if ((request.has_get && !js_value_strict_equal(&request.getter, &prop->getter)) ||
                    (request.has_set && !js_value_strict_equal(&request.setter, &prop->setter)))
                {
                    ok = false;
                    if (error_message)
                    {
                        *error_message = js_strdup("TypeError: cannot redefine property");
                    }
                    goto define_cleanup;
                }
            }
        }

        if (!prop)
        {
            js_value_t init_value = js_value_make_undefined_internal();
            if (desc_is_data && request.has_value)
            {
                init_value = request.value;
            }
            if (!js_object_set_slot(obj, prop_name, &init_value))
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                goto define_cleanup;
            }
            prop = js_object_find_property(obj, prop_name);
            if (!prop)
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                goto define_cleanup;
            }
            prop->enumerable = request.has_enumerable ? request.enumerable : false;
            prop->configurable = request.has_configurable ? request.configurable : false;
            if (desc_is_accessor)
            {
                prop->is_accessor = true;
                prop->writable = false;
                js_value_destroy(&prop->value);
                prop->value = js_value_make_undefined_internal();
                js_value_destroy(&prop->getter);
                js_value_destroy(&prop->setter);
                prop->getter = js_value_make_undefined_internal();
                prop->setter = js_value_make_undefined_internal();
                if (request.has_get && !js_value_copy(&prop->getter, &request.getter))
                {
                    ok = false;
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    goto define_cleanup;
                }
                if (request.has_set && !js_value_copy(&prop->setter, &request.setter))
                {
                    ok = false;
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    goto define_cleanup;
                }
            }
            else
            {
                prop->is_accessor = false;
                prop->writable = request.has_writable ? request.writable : false;
            }
        }
        else
        {
            if (desc_is_accessor)
            {
                if (!prop->is_accessor)
                {
                    js_value_destroy(&prop->value);
                    prop->value = js_value_make_undefined_internal();
                    prop->is_accessor = true;
                    prop->writable = false;
                    js_value_destroy(&prop->getter);
                    js_value_destroy(&prop->setter);
                    prop->getter = js_value_make_undefined_internal();
                    prop->setter = js_value_make_undefined_internal();
                }
                if (request.has_get)
                {
                    js_value_destroy(&prop->getter);
                    if (!js_value_copy(&prop->getter, &request.getter))
                    {
                        ok = false;
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        goto define_cleanup;
                    }
                }
                if (request.has_set)
                {
                    js_value_destroy(&prop->setter);
                    if (!js_value_copy(&prop->setter, &request.setter))
                    {
                        ok = false;
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        goto define_cleanup;
                    }
                }
            }
            else if (desc_is_data)
            {
                if (prop->is_accessor)
                {
                    js_value_destroy(&prop->getter);
                    js_value_destroy(&prop->setter);
                    prop->getter = js_value_make_undefined_internal();
                    prop->setter = js_value_make_undefined_internal();
                    prop->is_accessor = false;
                    prop->writable = false;
                    js_value_destroy(&prop->value);
                    prop->value = js_value_make_undefined_internal();
                }
                if (request.has_value)
                {
                    js_value_destroy(&prop->value);
                    if (!js_value_copy(&prop->value, &request.value))
                    {
                        ok = false;
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        goto define_cleanup;
                    }
                }
                if (request.has_writable)
                {
                    prop->writable = request.writable;
                }
            }

            if (request.has_enumerable)
            {
                prop->enumerable = request.enumerable;
            }
            if (request.has_configurable)
            {
                prop->configurable = request.configurable;
            }
        }
    }
    else if (target->type == JS_VALUE_ARRAY)
    {
        js_array_t *array = target->as.array;
        if (!array)
        {
            ok = false;
            if (error_message)
            {
                *error_message = js_strdup("TypeError: invalid array");
            }
            goto define_cleanup;
        }

        if (strcmp(prop_name, "length") == 0)
        {
            if (desc_is_accessor)
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: invalid array length descriptor");
                }
                goto define_cleanup;
            }
            if (request.has_value)
            {
                size_t new_length = 0;
                if (!js_value_to_array_length_local(&request.value, &new_length))
                {
                    ok = false;
                    if (error_message)
                    {
                        *error_message = js_strdup("RangeError: invalid array length");
                    }
                    goto define_cleanup;
                }
                if (!js_array_set_length(array, new_length))
                {
                    ok = false;
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    goto define_cleanup;
                }
            }
            goto define_cleanup;
        }

        size_t index = 0;
        bool is_index = js_parse_index_key(prop_name, &index);
        js_property_t *prop = js_array_find_property(array, prop_name);
        if (!prop && is_index && index < array->length)
        {
            js_value_t current = js_value_make_undefined_internal();
            if (!js_array_get(array, index, &current))
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                goto define_cleanup;
            }
            if (!js_array_set_property(array, prop_name, &current))
            {
                js_value_destroy(&current);
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                goto define_cleanup;
            }
            js_value_destroy(&current);
            prop = js_array_find_property(array, prop_name);
            if (!prop)
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                goto define_cleanup;
            }
            prop->writable = true;
            prop->enumerable = true;
            prop->configurable = true;
            prop->is_accessor = false;
        }
        if (prop && !prop->configurable)
        {
            if ((request.has_configurable && request.configurable) ||
                (request.has_enumerable && request.enumerable != prop->enumerable))
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: cannot redefine property");
                }
                goto define_cleanup;
            }
            if ((desc_is_accessor && !prop->is_accessor) ||
                (desc_is_data && prop->is_accessor))
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: cannot redefine property");
                }
                goto define_cleanup;
            }
            if (!prop->is_accessor)
            {
                if (!prop->writable)
                {
                    if ((request.has_writable && request.writable) ||
                        (request.has_value && !js_value_strict_equal(&request.value, &prop->value)))
                    {
                        ok = false;
                        if (error_message)
                        {
                            *error_message = js_strdup("TypeError: cannot redefine property");
                        }
                        goto define_cleanup;
                    }
                }
            }
            else
            {
                if ((request.has_get && !js_value_strict_equal(&request.getter, &prop->getter)) ||
                    (request.has_set && !js_value_strict_equal(&request.setter, &prop->setter)))
                {
                    ok = false;
                    if (error_message)
                    {
                        *error_message = js_strdup("TypeError: cannot redefine property");
                    }
                    goto define_cleanup;
                }
            }
        }

        if (!prop)
        {
            js_value_t init_value = js_value_make_undefined_internal();
            if (desc_is_data && request.has_value)
            {
                init_value = request.value;
            }
            if (!js_array_set_property(array, prop_name, &init_value))
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                goto define_cleanup;
            }
            prop = js_array_find_property(array, prop_name);
            if (!prop)
            {
                ok = false;
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                goto define_cleanup;
            }
            prop->enumerable = request.has_enumerable ? request.enumerable : false;
            prop->configurable = request.has_configurable ? request.configurable : false;
            if (desc_is_accessor)
            {
                prop->is_accessor = true;
                prop->writable = false;
                js_value_destroy(&prop->value);
                prop->value = js_value_make_undefined_internal();
                js_value_destroy(&prop->getter);
                js_value_destroy(&prop->setter);
                prop->getter = js_value_make_undefined_internal();
                prop->setter = js_value_make_undefined_internal();
                if (request.has_get && !js_value_copy(&prop->getter, &request.getter))
                {
                    ok = false;
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    goto define_cleanup;
                }
                if (request.has_set && !js_value_copy(&prop->setter, &request.setter))
                {
                    ok = false;
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    goto define_cleanup;
                }
            }
            else
            {
                prop->is_accessor = false;
                prop->writable = request.has_writable ? request.writable : false;
                if (is_index && desc_is_data && request.has_value)
                {
                    if (!js_array_set(array, index, &request.value))
                    {
                        ok = false;
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        goto define_cleanup;
                    }
                }
            }
            if (is_index && index >= array->length)
            {
                if (!js_array_set_length(array, index + 1))
                {
                    ok = false;
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    goto define_cleanup;
                }
            }
        }
        else
        {
            if (desc_is_accessor)
            {
                if (!prop->is_accessor)
                {
                    js_value_destroy(&prop->value);
                    prop->value = js_value_make_undefined_internal();
                    prop->is_accessor = true;
                    prop->writable = false;
                    js_value_destroy(&prop->getter);
                    js_value_destroy(&prop->setter);
                    prop->getter = js_value_make_undefined_internal();
                    prop->setter = js_value_make_undefined_internal();
                }
                if (request.has_get)
                {
                    js_value_destroy(&prop->getter);
                    if (!js_value_copy(&prop->getter, &request.getter))
                    {
                        ok = false;
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        goto define_cleanup;
                    }
                }
                if (request.has_set)
                {
                    js_value_destroy(&prop->setter);
                    if (!js_value_copy(&prop->setter, &request.setter))
                    {
                        ok = false;
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        goto define_cleanup;
                    }
                }
            }
            else if (desc_is_data)
            {
                if (prop->is_accessor)
                {
                    js_value_destroy(&prop->getter);
                    js_value_destroy(&prop->setter);
                    prop->getter = js_value_make_undefined_internal();
                    prop->setter = js_value_make_undefined_internal();
                    prop->is_accessor = false;
                    prop->writable = false;
                    js_value_destroy(&prop->value);
                    prop->value = js_value_make_undefined_internal();
                }
                if (request.has_value)
                {
                    js_value_destroy(&prop->value);
                    if (!js_value_copy(&prop->value, &request.value))
                    {
                        ok = false;
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        goto define_cleanup;
                    }
                    if (is_index)
                    {
                        if (!js_array_set(array, index, &request.value))
                        {
                            ok = false;
                            if (error_message)
                            {
                                *error_message = js_strdup("allocation failed");
                            }
                            goto define_cleanup;
                        }
                    }
                }
                if (request.has_writable)
                {
                    prop->writable = request.writable;
                }
            }

            if (request.has_enumerable)
            {
                prop->enumerable = request.enumerable;
            }
            if (request.has_configurable)
            {
                prop->configurable = request.configurable;
            }
        }
    }

define_cleanup:
    js_desc_request_destroy(&request);
    js_free(prop_name);
    if (!ok)
    {
        return false;
    }
    if (!js_value_copy(out, target))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static bool js_value_get_property_value(js_runtime_t *rt,
                                        const js_value_t *obj,
                                        const char *name,
                                        js_value_t *out,
                                        char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!obj || !name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (obj->type == JS_VALUE_OBJECT)
    {
        return js_object_get_property(rt, obj->as.object, name, out, error_message);
    }
    if (obj->type == JS_VALUE_ARRAY)
    {
        if (!obj->as.array)
        {
            *out = js_value_make_undefined_internal();
            return true;
        }
        size_t index = 0;
        if (js_parse_index_key(name, &index) && index < obj->as.array->length)
        {
            if (!js_array_get(obj->as.array, index, out))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            return true;
        }
        return js_array_get_property(rt, obj->as.array, name, out, error_message);
    }
    *out = js_value_make_undefined_internal();
    return true;
}

bool js_builtin_define_properties(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (argc < 2 || !argv)
    {
        return true;
    }
    const js_value_t *target = &argv[0];
    const js_value_t *props = &argv[1];
    if (target->type != JS_VALUE_OBJECT && target->type != JS_VALUE_ARRAY)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Object.defineProperties called on non-object");
        }
        return false;
    }
    if (props->type != JS_VALUE_OBJECT && props->type != JS_VALUE_ARRAY)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: properties must be an object");
        }
        return false;
    }

    js_name_list_t names = {0};
    char *collect_err = NULL;
    if (!js_collect_own_property_names(rt, props, &names, &collect_err))
    {
        js_name_list_destroy(&names);
        if (error_message)
        {
            *error_message = collect_err ? collect_err : js_strdup("allocation failed");
        }
        else
        {
            js_free(collect_err);
        }
        return false;
    }
    js_free(collect_err);

    for (size_t i = 0; i < names.count; ++i)
    {
        const char *name = names.items[i];
        if (!name)
        {
            continue;
        }
        js_prop_desc_t prop_desc;
        char *desc_err = NULL;
        if (!js_builtin_get_prop_desc(rt, props, name, &prop_desc, &desc_err))
        {
            js_name_list_destroy(&names);
            if (desc_err)
            {
                if (error_message)
                {
                    *error_message = desc_err;
                }
                else
                {
                    js_free(desc_err);
                }
            }
            return false;
        }
        bool enumerable = prop_desc.exists && prop_desc.enumerable;
        js_value_destroy(&prop_desc.value);
        js_value_destroy(&prop_desc.getter);
        js_value_destroy(&prop_desc.setter);
        if (!enumerable)
        {
            continue;
        }

        js_value_t desc_value = js_value_make_undefined_internal();
        char *value_err = NULL;
        if (!js_value_get_property_value(rt, props, name, &desc_value, &value_err))
        {
            js_name_list_destroy(&names);
            if (value_err)
            {
                if (error_message)
                {
                    *error_message = value_err;
                }
                else
                {
                    js_free(value_err);
                }
            }
            return false;
        }
        js_free(value_err);

        js_value_t key;
        if (!js_value_make_cstring(&key, name))
        {
            js_name_list_destroy(&names);
            js_value_destroy(&desc_value);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        const js_value_t args[] = {*target, key, desc_value};
        js_value_t tmp = js_value_make_undefined_internal();
        char *err = NULL;
        bool ok = js_builtin_define_property(rt, 3, args, NULL, &tmp, &err);
        js_value_destroy(&tmp);
        js_value_destroy(&key);
        js_value_destroy(&desc_value);
        if (!ok)
        {
            js_name_list_destroy(&names);
            if (err)
            {
                if (error_message)
                {
                    *error_message = err;
                }
                else
                {
                    js_free(err);
                }
            }
            return false;
        }
        js_free(err);
    }
    js_name_list_destroy(&names);
    if (!js_value_copy(out, target))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static void js_bound_fn_release(js_bound_fn_t *bound)
{
    if (!bound)
    {
        return;
    }
    js_value_destroy(&bound->target);
    js_value_destroy(&bound->this_arg);
    if (bound->owned_target_user_data)
    {
        js_value_destroy(bound->owned_target_user_data);
        js_free(bound->owned_target_user_data);
    }
    for (size_t i = 0; i < bound->arg_count; ++i)
    {
        js_value_destroy(&bound->args[i]);
    }
    js_free(bound->args);
    js_free(bound);
}

static bool js_builtin_bound_function(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_bound_fn_t *bound = (js_bound_fn_t *)user_data;
    if (!bound)
    {
        if (error_message)
        {
            *error_message = js_strdup("invalid bound function");
        }
        return false;
    }
    bool prepend_this = false;
    bool inject_this = false;
    if (bound->target.type == JS_VALUE_NATIVE_FN &&
        bound->target.as.native.fn == js_builtin_function_call &&
        bound->target.as.native.user_data == NULL)
    {
        prepend_this = true;
    }
    else if (bound->target.type == JS_VALUE_NATIVE_FN &&
             js_native_needs_this(bound->target.as.native.fn))
    {
        inject_this = true;
    }

    size_t extra = (prepend_this || inject_this) ? 1u : 0u;
    size_t call_argc = bound->arg_count + argc + extra;
    js_value_t *call_args = NULL;
    if (call_argc)
    {
        call_args = (js_value_t *)js_calloc(call_argc, sizeof(*call_args));
        if (!call_args)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }

    size_t index = 0;
    if (extra)
    {
        if (!js_value_copy(&call_args[index++], &bound->this_arg))
        {
            js_free(call_args);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    for (size_t i = 0; i < bound->arg_count; ++i)
    {
        if (!js_value_copy(&call_args[index++], &bound->args[i]))
        {
            for (size_t j = 0; j < index; ++j)
            {
                js_value_destroy(&call_args[j]);
            }
            js_free(call_args);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    for (size_t i = 0; i < argc; ++i)
    {
        if (!js_value_copy(&call_args[index++], &argv[i]))
        {
            for (size_t j = 0; j < index; ++j)
            {
                js_value_destroy(&call_args[j]);
            }
            js_free(call_args);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }

    bool ok = js_call_value(rt, &bound->target, call_argc, call_args, out, error_message);
    for (size_t i = 0; i < call_argc; ++i)
    {
        js_value_destroy(&call_args[i]);
    }
    js_free(call_args);
    return ok;
}

bool js_builtin_function_stub(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_dynamic_function_has_leading_html_close_comment(const char *text, size_t len)
{
    if (!text || len < 3)
    {
        return false;
    }
    size_t i = 0;
    while (i < len)
    {
        char c = text[i];
        if (c == ' ' || c == '\t' || c == '\v' || c == '\f')
        {
            ++i;
            continue;
        }
        break;
    }
    if (i + 2 < len && text[i] == '-' && text[i + 1] == '-' && text[i + 2] == '>')
    {
        return true;
    }
    return false;
}

bool js_builtin_function_call(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *target = (const js_value_t *)user_data;
    size_t arg_index = 0;
    if (!target)
    {
        if (!argv || argc == 0)
        {
            if (error_message)
            {
                *error_message = js_strdup("invalid call");
            }
            return false;
        }
        target = &argv[0];
        arg_index = 1;
    }

    const js_value_t *this_arg = NULL;
    if (argv && argc > arg_index)
    {
        this_arg = &argv[arg_index];
        arg_index++;
    }
    size_t remaining = (argc > arg_index) ? (argc - arg_index) : 0;
    bool needs_this = (target->type == JS_VALUE_NATIVE_FN && js_native_needs_this(target->as.native.fn));
    size_t call_argc = remaining + (needs_this ? 1u : 0u);

    js_value_t *call_args = NULL;
    if (call_argc)
    {
        call_args = (js_value_t *)js_calloc(call_argc, sizeof(*call_args));
        if (!call_args)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }

    size_t out_index = 0;
    if (needs_this)
    {
        js_value_t undef = js_value_make_undefined_internal();
        const js_value_t *use_this = this_arg ? this_arg : &undef;
        if (!js_value_copy(&call_args[out_index++], use_this))
        {
            js_free(call_args);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    for (size_t i = 0; i < remaining; ++i)
    {
        if (!js_value_copy(&call_args[out_index++], &argv[arg_index + i]))
        {
            for (size_t j = 0; j < out_index; ++j)
            {
                js_value_destroy(&call_args[j]);
            }
            js_free(call_args);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }

    bool ok = js_call_value(rt, target, call_argc, call_args, out, error_message);
    for (size_t i = 0; i < call_argc; ++i)
    {
        js_value_destroy(&call_args[i]);
    }
    js_free(call_args);
    return ok;
}

bool js_builtin_function_bind(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *target = (const js_value_t *)user_data;
    size_t arg_index = 0;
    if (!target)
    {
        if (!argv || argc == 0)
        {
            if (error_message)
            {
                *error_message = js_strdup("invalid bind");
            }
            return false;
        }
        target = &argv[0];
        arg_index = 1;
    }
    if (target->type != JS_VALUE_FUNCTION && target->type != JS_VALUE_NATIVE_FN)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: target is not callable");
        }
        return false;
    }

    const js_value_t *this_arg = NULL;
    if (argv && argc > arg_index)
    {
        this_arg = &argv[arg_index];
        arg_index++;
    }
    size_t bound_count = (argc > arg_index) ? (argc - arg_index) : 0;

    js_bound_fn_t *bound = (js_bound_fn_t *)js_calloc(1, sizeof(*bound));
    if (!bound)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (target->type == JS_VALUE_NATIVE_FN &&
        target->as.native.fn == js_builtin_function_call &&
        target->as.native.user_data)
    {
        js_value_t *target_copy = (js_value_t *)js_calloc(1, sizeof(*target_copy));
        if (!target_copy)
        {
            js_free(bound);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (!js_value_copy(target_copy, (const js_value_t *)target->as.native.user_data))
        {
            js_free(target_copy);
            js_free(bound);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (!js_value_copy(&bound->target, target))
        {
            js_value_destroy(target_copy);
            js_free(target_copy);
            js_free(bound);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        bound->target.as.native.user_data = target_copy;
        bound->owned_target_user_data = target_copy;
    }
    else if (!js_value_copy(&bound->target, target))
    {
        js_free(bound);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (this_arg)
    {
        if (!js_value_copy(&bound->this_arg, this_arg))
        {
            js_value_destroy(&bound->target);
            js_free(bound);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    else
    {
        bound->this_arg = js_value_make_undefined_internal();
    }

    if (bound_count)
    {
        bound->args = (js_value_t *)js_calloc(bound_count, sizeof(*bound->args));
        if (!bound->args)
        {
            js_value_destroy(&bound->target);
            js_value_destroy(&bound->this_arg);
            js_free(bound);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        for (size_t i = 0; i < bound_count; ++i)
        {
            if (!js_value_copy(&bound->args[i], &argv[arg_index + i]))
            {
                for (size_t j = 0; j < i; ++j)
                {
                    js_value_destroy(&bound->args[j]);
                }
                js_free(bound->args);
                js_value_destroy(&bound->target);
                js_value_destroy(&bound->this_arg);
                js_free(bound);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        bound->arg_count = bound_count;
    }

    if (!rt)
    {
        js_bound_fn_release(bound);
        if (error_message)
        {
            *error_message = js_strdup("invalid runtime");
        }
        return false;
    }
    bound->next = rt->bound_functions;
    rt->bound_functions = bound;

    out->type = JS_VALUE_NATIVE_FN;
    out->as.native.fn = js_builtin_bound_function;
    out->as.native.user_data = bound;
    return true;
}

bool js_builtin_function(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc && argv && argc > 1)
    {
        for (size_t i = 0; i + 1 < argc; ++i)
        {
            js_temp_string_t temp = {0};
            if (!js_temp_string_from_value(rt, &argv[i], &temp, error_message))
            {
                return false;
            }
            bool invalid = js_dynamic_function_has_leading_html_close_comment(temp.data, temp.len);
            js_temp_string_release(&temp);
            if (invalid)
            {
                if (error_message)
                {
                    *error_message = js_strdup("SyntaxError: invalid HTML close comment");
                }
                return false;
            }
        }
    }
    out->type = JS_VALUE_NATIVE_FN;
    out->as.native.fn = js_builtin_function_stub;
    out->as.native.user_data = NULL;
    return true;
}

bool js_builtin_object(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc > 0 && argv && argv[0].type == JS_VALUE_OBJECT)
    {
        return js_value_copy(out, &argv[0]);
    }
    if (!js_value_make_host_object(out, NULL, NULL, NULL, NULL))
    {
        return false;
    }
    js_object_t *proto = js_get_object_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

bool js_builtin_object_get_prototype_of(js_runtime_t *rt,
                                        size_t argc,
                                        const js_value_t *argv,
                                        void *user_data,
                                        js_value_t *out,
                                        char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        *out = js_value_make_undefined();
        return true;
    }
    const js_value_t *target = &argv[0];
    if (target->type == JS_VALUE_ARRAY)
    {
        js_object_t *proto = js_get_array_proto(rt);
        if (proto)
        {
            out->type = JS_VALUE_OBJECT;
            out->as.object = proto;
            js_object_retain(proto);
            return true;
        }
        *out = js_value_make_undefined();
        return true;
    }
    if (target->type == JS_VALUE_FUNCTION || target->type == JS_VALUE_NATIVE_FN)
    {
        js_object_t *proto = js_get_function_proto(rt);
        if (proto)
        {
            out->type = JS_VALUE_OBJECT;
            out->as.object = proto;
            js_object_retain(proto);
            return true;
        }
        *out = js_value_make_undefined();
        return true;
    }
    if (target->type != JS_VALUE_OBJECT)
    {
        *out = js_value_make_undefined();
        return true;
    }
    js_object_t *obj = target->as.object;
    if (!obj)
    {
        *out = js_value_make_undefined();
        return true;
    }
    if (js_object_has_slot(obj, "__proto__"))
    {
        if (!js_object_get_slot(obj, "__proto__", out))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        return true;
    }
    *out = js_value_make_null();
    return true;
}

static bool js_build_prop_descriptor(js_runtime_t *rt,
                                     const js_value_t *target,
                                     const char *name,
                                     js_value_t *out,
                                     char **error_message)
{
    if (!out)
    {
        return false;
    }
    js_prop_desc_t desc;
    if (!js_builtin_get_prop_desc(rt, target, name, &desc, error_message))
    {
        return false;
    }
    if (!desc.exists)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (!js_value_make_host_object(out, NULL, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        js_value_destroy(&desc.value);
        return false;
    }

    if (desc.is_accessor)
    {
        (void)js_object_set_slot(out->as.object, "get", &desc.getter);
        (void)js_object_set_slot(out->as.object, "set", &desc.setter);
    }
    else
    {
        (void)js_object_set_slot(out->as.object, "value", &desc.value);
        js_value_t writable = js_value_make_bool(desc.writable);
        (void)js_object_set_slot(out->as.object, "writable", &writable);
    }

    js_value_t enumerable = js_value_make_bool(desc.enumerable);
    js_value_t configurable = js_value_make_bool(desc.configurable);
    (void)js_object_set_slot(out->as.object, "enumerable", &enumerable);
    (void)js_object_set_slot(out->as.object, "configurable", &configurable);

    js_value_destroy(&desc.value);
    js_value_destroy(&desc.getter);
    js_value_destroy(&desc.setter);
    return true;
}

bool js_builtin_object_get_own_property_descriptor(js_runtime_t *rt,
                                                   size_t argc,
                                                   const js_value_t *argv,
                                                   void *user_data,
                                                   js_value_t *out,
                                                   char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    if (argc < 2 || !argv)
    {
        return true;
    }
    const js_value_t *target = &argv[0];
    if (target->type != JS_VALUE_OBJECT &&
        target->type != JS_VALUE_ARRAY &&
        target->type != JS_VALUE_FUNCTION &&
        target->type != JS_VALUE_NATIVE_FN &&
        target->type != JS_VALUE_STRING)
    {
        return true;
    }
    js_temp_string_t name_temp = {0};
    if (!js_temp_string_from_value(rt, &argv[1], &name_temp, error_message))
    {
        return false;
    }
    char *prop_name = js_strdup_len(name_temp.data ? name_temp.data : "", name_temp.len);
    js_temp_string_release(&name_temp);
    if (!prop_name)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    bool ok = js_build_prop_descriptor(rt, target, prop_name, out, error_message);
    js_free(prop_name);
    return ok;
}

bool js_builtin_object_get_own_property_names(js_runtime_t *rt,
                                              size_t argc,
                                              const js_value_t *argv,
                                              void *user_data,
                                              js_value_t *out,
                                              char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    if (argc == 0 || !argv)
    {
        return true;
    }
    js_name_list_t names = {0};
    char *collect_err = NULL;
    if (!js_collect_own_property_names(rt, &argv[0], &names, &collect_err))
    {
        js_name_list_destroy(&names);
        if (error_message)
        {
            *error_message = collect_err ? collect_err : js_strdup("allocation failed");
        }
        else
        {
            js_free(collect_err);
        }
        return false;
    }
    js_free(collect_err);

    js_value_t result;
    if (!js_value_make_array(&result))
    {
        js_name_list_destroy(&names);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    for (size_t i = 0; i < names.count; ++i)
    {
        js_value_t name_val;
        if (!js_value_make_cstring(&name_val, names.items[i] ? names.items[i] : ""))
        {
            js_name_list_destroy(&names);
            js_value_destroy(&result);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        bool ok = js_value_array_set(&result, i, &name_val);
        js_value_destroy(&name_val);
        if (!ok)
        {
            js_name_list_destroy(&names);
            js_value_destroy(&result);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    js_name_list_destroy(&names);
    *out = result;
    return true;
}

bool js_builtin_object_get_own_property_descriptors(js_runtime_t *rt,
                                                    size_t argc,
                                                    const js_value_t *argv,
                                                    void *user_data,
                                                    js_value_t *out,
                                                    char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    if (argc == 0 || !argv)
    {
        return true;
    }
    js_name_list_t names = {0};
    char *collect_err = NULL;
    if (!js_collect_own_property_names(rt, &argv[0], &names, &collect_err))
    {
        js_name_list_destroy(&names);
        if (error_message)
        {
            *error_message = collect_err ? collect_err : js_strdup("allocation failed");
        }
        else
        {
            js_free(collect_err);
        }
        return false;
    }
    js_free(collect_err);

    js_value_t result;
    if (!js_value_make_host_object(&result, NULL, NULL, NULL, NULL))
    {
        js_name_list_destroy(&names);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    for (size_t i = 0; i < names.count; ++i)
    {
        js_value_t desc_val = js_value_make_undefined_internal();
        if (!js_build_prop_descriptor(rt, &argv[0], names.items[i], &desc_val, error_message))
        {
            js_name_list_destroy(&names);
            js_value_destroy(&result);
            return false;
        }
        if (desc_val.type != JS_VALUE_UNDEFINED)
        {
            (void)js_object_set_slot(result.as.object, names.items[i], &desc_val);
        }
        js_value_destroy(&desc_val);
    }
    js_name_list_destroy(&names);
    *out = result;
    return true;
}

static bool js_value_same_value(const js_value_t *a, const js_value_t *b)
{
    if (!a || !b)
    {
        return false;
    }
    if (a->type != b->type)
    {
        return false;
    }
    if (a->type == JS_VALUE_NUMBER)
    {
        if (js_is_nan(a->as.number) && js_is_nan(b->as.number))
        {
            return true;
        }
        if (a->as.number == 0.0 && b->as.number == 0.0)
        {
            return (1.0 / a->as.number) == (1.0 / b->as.number);
        }
        return a->as.number == b->as.number;
    }
    return js_value_strict_equal(a, b);
}

bool js_builtin_object_is(js_runtime_t *rt,
                          size_t argc,
                          const js_value_t *argv,
                          void *user_data,
                          js_value_t *out,
                          char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_value_t undef = js_value_make_undefined_internal();
    const js_value_t *left = (argc > 0 && argv) ? &argv[0] : &undef;
    const js_value_t *right = (argc > 1 && argv) ? &argv[1] : &undef;
    *out = js_value_make_bool(js_value_same_value(left, right));
    return true;
}

bool js_builtin_object_has_own_property(js_runtime_t *rt,
                                        size_t argc,
                                        const js_value_t *argv,
                                        void *user_data,
                                        js_value_t *out,
                                        char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || argc < 2 || !argv)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    if (this_val->type != JS_VALUE_OBJECT &&
        this_val->type != JS_VALUE_ARRAY &&
        this_val->type != JS_VALUE_FUNCTION &&
        this_val->type != JS_VALUE_NATIVE_FN &&
        this_val->type != JS_VALUE_STRING)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    js_temp_string_t name_temp = {0};
    if (!js_temp_string_from_value(rt, &argv[1], &name_temp, error_message))
    {
        return false;
    }
    char *prop_name = js_strdup_len(name_temp.data ? name_temp.data : "", name_temp.len);
    js_temp_string_release(&name_temp);
    if (!prop_name)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_prop_desc_t desc;
    bool ok = js_builtin_get_prop_desc(rt, this_val, prop_name, &desc, error_message);
    js_free(prop_name);
    if (!ok)
    {
        return false;
    }
    js_value_destroy(&desc.value);
    js_value_destroy(&desc.getter);
    js_value_destroy(&desc.setter);
    *out = js_value_make_bool(desc.exists);
    return true;
}

bool js_builtin_object_property_is_enumerable(js_runtime_t *rt,
                                              size_t argc,
                                              const js_value_t *argv,
                                              void *user_data,
                                              js_value_t *out,
                                              char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || argc < 2 || !argv)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    if (this_val->type != JS_VALUE_OBJECT &&
        this_val->type != JS_VALUE_ARRAY &&
        this_val->type != JS_VALUE_FUNCTION &&
        this_val->type != JS_VALUE_NATIVE_FN &&
        this_val->type != JS_VALUE_STRING)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    js_temp_string_t name_temp = {0};
    if (!js_temp_string_from_value(rt, &argv[1], &name_temp, error_message))
    {
        return false;
    }
    char *prop_name = js_strdup_len(name_temp.data ? name_temp.data : "", name_temp.len);
    js_temp_string_release(&name_temp);
    if (!prop_name)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_prop_desc_t desc;
    bool ok = js_builtin_get_prop_desc(rt, this_val, prop_name, &desc, error_message);
    js_free(prop_name);
    if (!ok)
    {
        return false;
    }
    js_value_destroy(&desc.value);
    js_value_destroy(&desc.getter);
    js_value_destroy(&desc.setter);
    *out = js_value_make_bool(desc.exists && desc.enumerable);
    return true;
}

bool js_builtin_object_to_string(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val)
    {
        return js_value_make_cstring(out, "[object Undefined]");
    }
    switch (this_val->type)
    {
        case JS_VALUE_UNDEFINED:
            return js_value_make_cstring(out, "[object Undefined]");
        case JS_VALUE_NULL:
            return js_value_make_cstring(out, "[object Null]");
        case JS_VALUE_BOOL:
            return js_value_make_cstring(out, "[object Boolean]");
        case JS_VALUE_NUMBER:
            return js_value_make_cstring(out, "[object Number]");
        case JS_VALUE_BIGINT:
            return js_value_make_cstring(out, "[object BigInt]");
        case JS_VALUE_STRING:
            return js_value_make_cstring(out, "[object String]");
        case JS_VALUE_ARRAY:
            return js_value_make_cstring(out, "[object Array]");
        case JS_VALUE_FUNCTION:
        case JS_VALUE_NATIVE_FN:
            return js_value_make_cstring(out, "[object Function]");
        case JS_VALUE_OBJECT:
            if (this_val->as.object && js_object_is_symbol(this_val->as.object))
            {
                return js_value_make_cstring(out, "[object Symbol]");
            }
            if (this_val->as.object)
            {
                js_value_t tag = js_value_make_undefined_internal();
                if (js_object_get_property(rt, this_val->as.object, "Symbol.toStringTag", &tag, NULL))
                {
                    if (tag.type == JS_VALUE_STRING && tag.as.string.data)
                    {
                        size_t tag_len = tag.as.string.len;
                        size_t total_len = tag_len + 9;
                        char *buffer = (char *)js_malloc(total_len + 1);
                        if (!buffer)
                        {
                            js_value_destroy(&tag);
                            if (error_message)
                            {
                                *error_message = js_strdup("allocation failed");
                            }
                            return false;
                        }
                        memcpy(buffer, "[object ", 8);
                        memcpy(buffer + 8, tag.as.string.data, tag_len);
                        buffer[8 + tag_len] = ']';
                        buffer[total_len] = '\0';
                        bool ok = js_value_make_string(out, buffer, total_len);
                        js_free(buffer);
                        js_value_destroy(&tag);
                        return ok;
                    }
                    js_value_destroy(&tag);
                }
                if (this_val->as.object->get_fn == js_date_get ||
                    this_val->as.object->get_fn == js_date_proto_get)
                {
                    return js_value_make_cstring(out, "[object Date]");
                }
                js_object_t *array_proto = js_get_array_proto(rt);
                if (array_proto && this_val->as.object == array_proto)
                {
                    return js_value_make_cstring(out, "[object Array]");
                }
                js_object_t *function_proto = js_get_function_proto(rt);
                if (function_proto && this_val->as.object == function_proto)
                {
                    return js_value_make_cstring(out, "[object Function]");
                }
            }
            return js_value_make_cstring(out, "[object Object]");
    }
    return js_value_make_cstring(out, "[object Object]");
}

bool js_builtin_array(js_runtime_t *rt,
                      size_t argc,
                      const js_value_t *argv,
                      void *user_data,
                      js_value_t *out,
                      char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!js_value_make_array(out))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (argc == 1 && argv && argv[0].type == JS_VALUE_NUMBER)
    {
        double len_val = argv[0].as.number;
        if (len_val < 0.0 || len_val > (double)SIZE_MAX)
        {
            js_value_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("RangeError: invalid array length");
            }
            return false;
        }
        size_t len = (size_t)len_val;
        if ((double)len != len_val)
        {
            js_value_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("RangeError: invalid array length");
            }
            return false;
        }
        if (!js_array_set_length(out->as.array, len))
        {
            js_value_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        return true;
    }
    for (size_t i = 0; i < argc; ++i)
    {
        if (!js_array_set(out->as.array, i, &argv[i]))
        {
            js_value_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    return true;
}

bool js_builtin_array_is_array(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool is_array = (argc > 0 && argv && argv[0].type == JS_VALUE_ARRAY);
    if (!is_array && argc > 0 && argv && argv[0].type == JS_VALUE_OBJECT)
    {
        js_object_t *proto = js_get_array_proto(rt);
        if (proto && argv[0].as.object == proto)
        {
            is_array = true;
        }
    }
    *out = js_value_make_bool(is_array);
    return true;
}

static bool js_array_from_call_with_this(js_runtime_t *rt,
                                         const js_value_t *callee,
                                         const js_value_t *this_val,
                                         size_t argc,
                                         const js_value_t *argv,
                                         js_value_t *out,
                                         char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!callee || !out)
    {
        return false;
    }
    if (callee->type == JS_VALUE_NATIVE_FN && js_native_needs_this(callee->as.native.fn))
    {
        size_t call_argc = argc + 1u;
        js_value_t *call_args = (js_value_t *)js_calloc(call_argc, sizeof(*call_args));
        if (!call_args)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (this_val)
        {
            if (!js_value_copy(&call_args[0], this_val))
            {
                js_free(call_args);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        else
        {
            call_args[0] = js_value_make_undefined_internal();
        }
        for (size_t i = 0; i < argc; ++i)
        {
            if (!js_value_copy(&call_args[i + 1], &argv[i]))
            {
                for (size_t j = 0; j <= i + 1; ++j)
                {
                    js_value_destroy(&call_args[j]);
                }
                js_free(call_args);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        bool ok = js_call_value(rt, callee, call_argc, call_args, out, error_message);
        for (size_t i = 0; i < call_argc; ++i)
        {
            js_value_destroy(&call_args[i]);
        }
        js_free(call_args);
        return ok;
    }
    if (callee->type == JS_VALUE_FUNCTION && this_val && this_val->type == JS_VALUE_OBJECT && rt)
    {
        js_object_t *prev_global = rt->global_object;
        rt->global_object = this_val->as.object;
        bool ok = js_call_value(rt, callee, argc, argv, out, error_message);
        rt->global_object = prev_global;
        return ok;
    }
    return js_call_value(rt, callee, argc, argv, out, error_message);
}

static bool js_array_from_define_data_property(js_runtime_t *rt,
                                               js_value_t *target,
                                               const char *name,
                                               const js_value_t *value,
                                               char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!target || !name || !value)
    {
        return false;
    }
    js_value_t desc;
    if (!js_value_make_host_object(&desc, NULL, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_t flag = js_value_make_bool(true);
    bool ok = js_object_set_slot(desc.as.object, "value", value) &&
        js_object_set_slot(desc.as.object, "writable", &flag) &&
        js_object_set_slot(desc.as.object, "enumerable", &flag) &&
        js_object_set_slot(desc.as.object, "configurable", &flag);
    if (!ok)
    {
        js_value_destroy(&desc);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_t name_val;
    if (!js_value_make_cstring(&name_val, name))
    {
        js_value_destroy(&desc);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_t args[3];
    args[0] = *target;
    args[1] = name_val;
    args[2] = desc;
    js_value_t tmp = js_value_make_undefined_internal();
    char *err = NULL;
    ok = js_builtin_define_property(rt, 3, args, NULL, &tmp, &err);
    js_value_destroy(&tmp);
    js_value_destroy(&name_val);
    js_value_destroy(&desc);
    if (!ok)
    {
        if (error_message)
        {
            *error_message = err ? err : js_strdup("define property failed");
        }
        else
        {
            js_free(err);
        }
        return false;
    }
    js_free(err);
    return true;
}

static bool js_array_from_set_length(js_runtime_t *rt,
                                     js_value_t *target,
                                     size_t length,
                                     char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!target)
    {
        return false;
    }
    if (target->type == JS_VALUE_ARRAY && target->as.array)
    {
        if (!js_array_set_length(target->as.array, length))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        return true;
    }
    if (target->type != JS_VALUE_OBJECT || !target->as.object)
    {
        return true;
    }

    js_value_t length_val = js_value_make_number((double)length);
    js_object_t *cursor = target->as.object;
    while (cursor)
    {
        js_property_t *prop = js_object_find_property(cursor, "length");
        if (prop)
        {
            if (prop->is_accessor)
            {
                if (prop->setter.type == JS_VALUE_UNDEFINED)
                {
                    if (error_message)
                    {
                        *error_message = js_strdup("TypeError: invalid length setter");
                    }
                    return false;
                }
                js_value_t result = js_value_make_undefined_internal();
                char *call_err = NULL;
                bool ok = js_array_from_call_with_this(rt,
                                                       &prop->setter,
                                                       target,
                                                       1,
                                                       &length_val,
                                                       &result,
                                                       &call_err);
                js_value_destroy(&result);
                if (!ok)
                {
                    if (error_message)
                    {
                        *error_message = call_err ? call_err : js_strdup("length setter failed");
                    }
                    else
                    {
                        js_free(call_err);
                    }
                    return false;
                }
                js_free(call_err);
                return true;
            }
            if (!prop->writable)
            {
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: length is not writable");
                }
                return false;
            }
            break;
        }
        js_value_t proto_val = js_value_make_undefined_internal();
        if (!js_object_get_slot(cursor, "__proto__", &proto_val))
        {
            break;
        }
        if (proto_val.type != JS_VALUE_OBJECT || !proto_val.as.object)
        {
            js_value_destroy(&proto_val);
            break;
        }
        cursor = proto_val.as.object;
        js_value_destroy(&proto_val);
    }

    if (!js_object_set_slot(target->as.object, "length", &length_val))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static bool js_array_from_construct(js_runtime_t *rt,
                                    const js_value_t *ctor,
                                    size_t argc,
                                    const js_value_t *argv,
                                    js_value_t *out,
                                    char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!ctor || !out)
    {
        return false;
    }
    if (ctor->type == JS_VALUE_FUNCTION)
    {
        js_value_t this_obj;
        if (!js_value_make_host_object(&this_obj, NULL, NULL, NULL, NULL))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (rt && this_obj.type == JS_VALUE_OBJECT && this_obj.as.object)
        {
            js_function_t *fn = ctor->as.function;
            js_object_t *proto_obj = NULL;
            if (fn && fn->has_prototype &&
                fn->prototype_value.type == JS_VALUE_OBJECT &&
                fn->prototype_value.as.object)
            {
                proto_obj = fn->prototype_value.as.object;
            }
            if (!proto_obj)
            {
                proto_obj = js_get_object_proto(rt);
            }
            if (proto_obj)
            {
                js_value_t proto_slot;
                memset(&proto_slot, 0, sizeof(proto_slot));
                proto_slot.type = JS_VALUE_OBJECT;
                proto_slot.as.object = proto_obj;
                (void)js_object_set_slot(this_obj.as.object, "__proto__", &proto_slot);
            }
        }
        js_object_t *prev_global = rt ? rt->global_object : NULL;
        if (rt && this_obj.type == JS_VALUE_OBJECT)
        {
            rt->global_object = this_obj.as.object;
        }
        js_value_t result = js_value_make_undefined_internal();
        char *err = NULL;
        bool ok = js_call_value(rt, ctor, argc, argv, &result, &err);
        if (rt)
        {
            rt->global_object = prev_global;
        }
        if (!ok)
        {
            js_value_destroy(&this_obj);
            if (error_message)
            {
                *error_message = err ? err : js_strdup("constructor failed");
            }
            else
            {
                js_free(err);
            }
            js_value_destroy(&result);
            return false;
        }
        js_free(err);
        if (result.type == JS_VALUE_OBJECT ||
            result.type == JS_VALUE_ARRAY ||
            result.type == JS_VALUE_FUNCTION)
        {
            js_value_destroy(&this_obj);
            *out = result;
            return true;
        }
        js_value_destroy(&result);
        *out = this_obj;
        return true;
    }
    if (ctor->type == JS_VALUE_NATIVE_FN)
    {
        js_value_t result = js_value_make_undefined_internal();
        char *err = NULL;
        bool prev_constructing = false;
        js_native_fn_t prev_constructing_fn = NULL;
        if (rt)
        {
            prev_constructing = rt->constructing;
            prev_constructing_fn = rt->constructing_fn;
            rt->constructing = true;
            rt->constructing_fn = ctor->as.native.fn;
        }
        bool ok = js_call_value(rt, ctor, argc, argv, &result, &err);
        if (rt)
        {
            rt->constructing = prev_constructing;
            rt->constructing_fn = prev_constructing_fn;
        }
        if (!ok)
        {
            if (error_message)
            {
                *error_message = err ? err : js_strdup("constructor failed");
            }
            else
            {
                js_free(err);
            }
            js_value_destroy(&result);
            return false;
        }
        js_free(err);
        if (result.type == JS_VALUE_OBJECT ||
            result.type == JS_VALUE_ARRAY ||
            result.type == JS_VALUE_FUNCTION)
        {
            *out = result;
            return true;
        }
        js_value_destroy(&result);
        if (!js_value_make_host_object(out, NULL, NULL, NULL, NULL))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        return true;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: invalid constructor");
    }
    return false;
}

bool js_builtin_array_from(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    size_t arg_index = 0;
    const js_value_t *this_val = NULL;
    if (argv && argc >= 2)
    {
        this_val = &argv[0];
        arg_index = 1;
    }
    const js_value_t *items = (argv && argc > arg_index) ? &argv[arg_index] : NULL;
    const js_value_t *mapfn = (argv && argc > arg_index + 1) ? &argv[arg_index + 1] : NULL;
    const js_value_t *this_arg = (argv && argc > arg_index + 2) ? &argv[arg_index + 2] : NULL;

    if (!items || items->type == JS_VALUE_UNDEFINED || items->type == JS_VALUE_NULL)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid array source");
        }
        return false;
    }

    bool mapping = mapfn && mapfn->type != JS_VALUE_UNDEFINED;
    if (mapping && mapfn->type != JS_VALUE_FUNCTION && mapfn->type != JS_VALUE_NATIVE_FN)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: mapfn is not callable");
        }
        return false;
    }

    js_value_t default_ctor;
    const js_value_t *ctor = NULL;
    if (this_val && js_value_is_constructor(rt, this_val))
    {
        ctor = this_val;
    }
    else
    {
        memset(&default_ctor, 0, sizeof(default_ctor));
        default_ctor.type = JS_VALUE_NATIVE_FN;
        default_ctor.as.native.fn = js_builtin_array;
        default_ctor.as.native.user_data = NULL;
        ctor = &default_ctor;
    }

    js_value_t iterator_method = js_value_make_undefined_internal();
    if (items->type == JS_VALUE_ARRAY && items->as.array)
    {
        char *err = NULL;
        if (!js_array_get_property(rt, items->as.array, "Symbol.iterator", &iterator_method, &err))
        {
            if (error_message)
            {
                *error_message = err ? err : js_strdup("property lookup failed");
            }
            else
            {
                js_free(err);
            }
            return false;
        }
        js_free(err);
    }
    else if (items->type == JS_VALUE_OBJECT && items->as.object)
    {
        char *err = NULL;
        if (!js_object_get_property(rt, items->as.object, "Symbol.iterator", &iterator_method, &err))
        {
            if (error_message)
            {
                *error_message = err ? err : js_strdup("property lookup failed");
            }
            else
            {
                js_free(err);
            }
            return false;
        }
        js_free(err);
    }

    bool has_iterator = !(iterator_method.type == JS_VALUE_UNDEFINED ||
                          iterator_method.type == JS_VALUE_NULL);
    if (has_iterator)
    {
        if (iterator_method.type != JS_VALUE_FUNCTION && iterator_method.type != JS_VALUE_NATIVE_FN)
        {
            js_value_destroy(&iterator_method);
            if (error_message)
            {
                *error_message = js_strdup("TypeError: iterator method is not callable");
            }
            return false;
        }

        js_value_t result = js_value_make_undefined_internal();
        if (!js_array_from_construct(rt, ctor, 0, NULL, &result, error_message))
        {
            js_value_destroy(&iterator_method);
            return false;
        }
        if (result.type == JS_VALUE_OBJECT)
        {
            (void)js_object_set_slot(result.as.object, "constructor", ctor);
        }

        js_value_t iterator = js_value_make_undefined_internal();
        char *iter_err = NULL;
        bool ok = js_array_from_call_with_this(rt,
                                               &iterator_method,
                                               items,
                                               0,
                                               NULL,
                                               &iterator,
                                               &iter_err);
        js_value_destroy(&iterator_method);
        if (!ok)
        {
            js_value_destroy(&result);
            if (error_message)
            {
                *error_message = iter_err ? iter_err : js_strdup("iterator creation failed");
            }
            else
            {
                js_free(iter_err);
            }
            return false;
        }
        js_free(iter_err);
        if (iterator.type != JS_VALUE_OBJECT || !iterator.as.object)
        {
            js_value_destroy(&iterator);
            js_value_destroy(&result);
            if (error_message)
            {
                *error_message = js_strdup("TypeError: iterator is not object");
            }
            return false;
        }

        js_value_t next_method = js_value_make_undefined_internal();
        char *next_err = NULL;
        if (!js_object_get_property(rt, iterator.as.object, "next", &next_method, &next_err))
        {
            js_value_destroy(&iterator);
            js_value_destroy(&result);
            if (error_message)
            {
                *error_message = next_err ? next_err : js_strdup("iterator next failed");
            }
            else
            {
                js_free(next_err);
            }
            return false;
        }
        js_free(next_err);
        if (next_method.type != JS_VALUE_FUNCTION && next_method.type != JS_VALUE_NATIVE_FN)
        {
            js_value_destroy(&next_method);
            js_value_destroy(&iterator);
            js_value_destroy(&result);
            if (error_message)
            {
                *error_message = js_strdup("TypeError: iterator next is not callable");
            }
            return false;
        }

        size_t k = 0;
        for (;;)
        {
            js_value_t next_result = js_value_make_undefined_internal();
            char *step_err = NULL;
            ok = js_array_from_call_with_this(rt,
                                              &next_method,
                                              &iterator,
                                              0,
                                              NULL,
                                              &next_result,
                                              &step_err);
            if (!ok)
            {
                js_value_destroy(&next_method);
                js_value_destroy(&iterator);
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = step_err ? step_err : js_strdup("iterator next failed");
                }
                else
                {
                    js_free(step_err);
                }
                return false;
            }
            js_free(step_err);
            if (next_result.type != JS_VALUE_OBJECT || !next_result.as.object)
            {
                js_value_destroy(&next_result);
                js_value_destroy(&next_method);
                js_value_destroy(&iterator);
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: iterator result is not an object");
                }
                return false;
            }
            js_value_t done_val = js_value_make_undefined_internal();
            char *done_err = NULL;
            if (!js_object_get_property(rt, next_result.as.object, "done", &done_val, &done_err))
            {
                js_value_destroy(&next_result);
                js_value_destroy(&next_method);
                js_value_destroy(&iterator);
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = done_err ? done_err : js_strdup("iterator done failed");
                }
                else
                {
                    js_free(done_err);
                }
                return false;
            }
            js_free(done_err);
            bool done = js_value_is_truthy(&done_val);
            js_value_destroy(&done_val);
            if (done)
            {
                js_value_destroy(&next_result);
                js_value_destroy(&next_method);
                js_value_destroy(&iterator);
                if (!js_array_from_set_length(rt, &result, k, error_message))
                {
                    js_value_destroy(&result);
                    return false;
                }
                *out = result;
                return true;
            }

            js_value_t value = js_value_make_undefined_internal();
            char *value_err = NULL;
            if (!js_object_get_property(rt, next_result.as.object, "value", &value, &value_err))
            {
                js_value_destroy(&next_result);
                js_value_destroy(&next_method);
                js_value_destroy(&iterator);
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = value_err ? value_err : js_strdup("iterator value failed");
                }
                else
                {
                    js_free(value_err);
                }
                return false;
            }
            js_free(value_err);
            js_value_destroy(&next_result);

            js_value_t mapped = js_value_make_undefined_internal();
            if (mapping)
            {
                js_value_t call_args[2];
                memset(call_args, 0, sizeof(call_args));
                if (!js_value_copy(&call_args[0], &value))
                {
                    js_value_destroy(&value);
                    js_value_destroy(&next_method);
                    js_value_destroy(&iterator);
                    js_value_destroy(&result);
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    return false;
                }
                call_args[1] = js_value_make_number((double)k);
                char *call_err = NULL;
                ok = js_array_from_call_with_this(rt,
                                                  mapfn,
                                                  this_arg,
                                                  2,
                                                  call_args,
                                                  &mapped,
                                                  &call_err);
                js_value_destroy(&call_args[0]);
                js_value_destroy(&call_args[1]);
                if (!ok)
                {
                    char *close_err = NULL;
                    bool closed_ok = js_iterator_close(rt, &iterator, &close_err);
                    js_value_destroy(&value);
                    js_value_destroy(&next_method);
                    js_value_destroy(&iterator);
                    js_value_destroy(&result);
                    if (!closed_ok)
                    {
                        if (error_message)
                        {
                            *error_message = close_err ? close_err : js_strdup("iterator close failed");
                        }
                        else
                        {
                            js_free(close_err);
                        }
                        js_free(call_err);
                        return false;
                    }
                    if (error_message)
                    {
                        *error_message = call_err ? call_err : js_strdup("mapper failed");
                    }
                    else
                    {
                        js_free(call_err);
                    }
                    return false;
                }
                js_free(call_err);
                js_value_destroy(&value);
            }
            else
            {
                if (!js_value_copy(&mapped, &value))
                {
                    js_value_destroy(&value);
                    js_value_destroy(&next_method);
                    js_value_destroy(&iterator);
                    js_value_destroy(&result);
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    return false;
                }
                js_value_destroy(&value);
            }

            char key[32];
            int key_len = snprintf(key, sizeof(key), "%zu", k);
            if (key_len < 0 || (size_t)key_len >= sizeof(key))
            {
                js_value_destroy(&mapped);
                js_value_destroy(&next_method);
                js_value_destroy(&iterator);
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = js_strdup("invalid index");
                }
                return false;
            }
            char *define_err = NULL;
            if (!js_array_from_define_data_property(rt, &result, key, &mapped, &define_err))
            {
                char *close_err = NULL;
                bool closed_ok = js_iterator_close(rt, &iterator, &close_err);
                js_value_destroy(&mapped);
                js_value_destroy(&next_method);
                js_value_destroy(&iterator);
                js_value_destroy(&result);
                if (!closed_ok)
                {
                    if (error_message)
                    {
                        *error_message = close_err ? close_err : js_strdup("iterator close failed");
                    }
                    else
                    {
                        js_free(close_err);
                    }
                    js_free(define_err);
                    return false;
                }
                if (error_message)
                {
                    *error_message = define_err ? define_err : js_strdup("define property failed");
                }
                else
                {
                    js_free(define_err);
                }
                return false;
            }
            js_free(define_err);
            js_value_destroy(&mapped);
            k++;
        }
    }

    js_value_destroy(&iterator_method);

    size_t length = 0;
    if (items->type == JS_VALUE_ARRAY && items->as.array)
    {
        length = items->as.array->length;
    }
    else if (items->type == JS_VALUE_STRING)
    {
        length = items->as.string.len;
    }
    else if (items->type == JS_VALUE_OBJECT && items->as.object)
    {
        js_value_t len_val = js_value_make_undefined_internal();
        char *len_err = NULL;
        if (!js_object_get_property(rt, items->as.object, "length", &len_val, &len_err))
        {
            if (error_message)
            {
                *error_message = len_err ? len_err : js_strdup("property lookup failed");
            }
            else
            {
                js_free(len_err);
            }
            return false;
        }
        js_free(len_err);
        bool ok = true;
        double len_num = js_value_to_number(&len_val, &ok);
        js_value_destroy(&len_val);
        if (!ok || len_num <= 0.0)
        {
            length = 0;
        }
        else if (len_num > (double)SIZE_MAX)
        {
            length = SIZE_MAX;
        }
        else
        {
            length = (size_t)len_num;
        }
    }

    js_value_t length_val = js_value_make_number((double)length);
    js_value_t result = js_value_make_undefined_internal();
    if (!js_array_from_construct(rt, ctor, 1, &length_val, &result, error_message))
    {
        return false;
    }
    if (result.type == JS_VALUE_OBJECT)
    {
        (void)js_object_set_slot(result.as.object, "constructor", ctor);
    }

    for (size_t k = 0; k < length; ++k)
    {
        js_value_t value = js_value_make_undefined_internal();
        if (items->type == JS_VALUE_ARRAY && items->as.array)
        {
            char key[32];
            int key_len = snprintf(key, sizeof(key), "%zu", k);
            if (key_len < 0 || (size_t)key_len >= sizeof(key))
            {
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = js_strdup("invalid index");
                }
                return false;
            }
            char *prop_err = NULL;
            if (!js_array_get_property(rt, items->as.array, key, &value, &prop_err))
            {
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = prop_err ? prop_err : js_strdup("property lookup failed");
                }
                else
                {
                    js_free(prop_err);
                }
                return false;
            }
            js_free(prop_err);
        }
        else if (items->type == JS_VALUE_STRING && items->as.string.data && k < items->as.string.len)
        {
            if (!js_value_make_string(&value, items->as.string.data + k, 1))
            {
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        else if (items->type == JS_VALUE_OBJECT && items->as.object)
        {
            char key[32];
            int key_len = snprintf(key, sizeof(key), "%zu", k);
            if (key_len < 0 || (size_t)key_len >= sizeof(key))
            {
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = js_strdup("invalid index");
                }
                return false;
            }
            char *prop_err = NULL;
            if (!js_object_get_property(rt, items->as.object, key, &value, &prop_err))
            {
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = prop_err ? prop_err : js_strdup("property lookup failed");
                }
                else
                {
                    js_free(prop_err);
                }
                return false;
            }
            js_free(prop_err);
        }

        js_value_t mapped = js_value_make_undefined_internal();
        if (mapping)
        {
            js_value_t call_args[2];
            memset(call_args, 0, sizeof(call_args));
            if (!js_value_copy(&call_args[0], &value))
            {
                js_value_destroy(&value);
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            call_args[1] = js_value_make_number((double)k);
            char *call_err = NULL;
            bool ok = js_array_from_call_with_this(rt,
                                                   mapfn,
                                                   this_arg,
                                                   2,
                                                   call_args,
                                                   &mapped,
                                                   &call_err);
            js_value_destroy(&call_args[0]);
            js_value_destroy(&call_args[1]);
            js_value_destroy(&value);
            if (!ok)
            {
                if (error_message)
                {
                    *error_message = call_err ? call_err : js_strdup("mapper failed");
                }
                else
                {
                    js_free(call_err);
                }
                js_value_destroy(&result);
                return false;
            }
            js_free(call_err);
        }
        else
        {
            if (!js_value_copy(&mapped, &value))
            {
                js_value_destroy(&value);
                js_value_destroy(&result);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            js_value_destroy(&value);
        }

        char key[32];
        int key_len = snprintf(key, sizeof(key), "%zu", k);
        if (key_len < 0 || (size_t)key_len >= sizeof(key))
        {
            js_value_destroy(&mapped);
            js_value_destroy(&result);
            if (error_message)
            {
                *error_message = js_strdup("invalid index");
            }
            return false;
        }
        char *define_err = NULL;
        if (!js_array_from_define_data_property(rt, &result, key, &mapped, &define_err))
        {
            js_value_destroy(&mapped);
            js_value_destroy(&result);
            if (error_message)
            {
                *error_message = define_err ? define_err : js_strdup("define property failed");
            }
            else
            {
                js_free(define_err);
            }
            return false;
        }
        js_free(define_err);
        js_value_destroy(&mapped);
    }

    *out = result;
    return true;
}

bool js_builtin_array_join(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    bool is_array = this_val && this_val->type == JS_VALUE_ARRAY;
    bool is_object = this_val && this_val->type == JS_VALUE_OBJECT;
    if (!this_val || (!is_array && !is_object) ||
        (is_array && !this_val->as.array) ||
        (is_object && !this_val->as.object))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Array.prototype.join called on non-array");
        }
        return false;
    }
    const char *sep = ",";
    size_t sep_len = 1;
    js_temp_string_t sep_temp = {0};
    if (argc > 1 && argv)
    {
        if (!js_temp_string_from_value(rt, &argv[1], &sep_temp, error_message))
        {
            return false;
        }
        sep = sep_temp.data ? sep_temp.data : "";
        sep_len = sep_temp.len;
    }

    char *buffer = NULL;
    size_t len = 0;
    size_t cap = 0;
    size_t length = 0;
    if (is_array)
    {
        length = this_val->as.array->length;
    }
    else
    {
        js_value_t len_val = js_value_make_undefined_internal();
        char *len_err = NULL;
        if (!js_object_get_property(rt, this_val->as.object, "length", &len_val, &len_err))
        {
            js_free(len_err);
            js_temp_string_release(&sep_temp);
            if (error_message)
            {
                *error_message = js_strdup("property lookup failed");
            }
            return false;
        }
        js_free(len_err);
        bool ok = true;
        double len_num = js_value_to_number(&len_val, &ok);
        js_value_destroy(&len_val);
        if (!ok || len_num < 0.0)
        {
            length = 0;
        }
        else if (len_num > (double)SIZE_MAX)
        {
            length = SIZE_MAX;
        }
        else
        {
            length = (size_t)len_num;
        }
    }
    for (size_t i = 0; i < length; ++i)
    {
        if (i > 0 && sep_len > 0)
        {
            size_t needed = len + sep_len + 1;
            if (needed > cap)
            {
                size_t new_cap = cap ? cap * 2u : 32u;
                while (new_cap < needed)
                {
                    new_cap *= 2u;
                }
                char *next = (char *)js_realloc(buffer, new_cap);
                if (!next)
                {
                    js_free(buffer);
                    js_temp_string_release(&sep_temp);
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    return false;
                }
                buffer = next;
                cap = new_cap;
            }
            memcpy(buffer + len, sep, sep_len);
            len += sep_len;
            buffer[len] = '\0';
        }

        js_value_t value = js_value_make_undefined_internal();
        if (is_array)
        {
            if (!js_array_get(this_val->as.array, i, &value))
            {
                js_free(buffer);
                js_temp_string_release(&sep_temp);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        else
        {
            char key[32];
            int key_len = snprintf(key, sizeof(key), "%zu", i);
            if (key_len < 0 || (size_t)key_len >= sizeof(key))
            {
                js_free(buffer);
                js_temp_string_release(&sep_temp);
                if (error_message)
                {
                    *error_message = js_strdup("invalid index");
                }
                return false;
            }
            char *prop_err = NULL;
            if (!js_object_get_property(rt, this_val->as.object, key, &value, &prop_err))
            {
                js_free(buffer);
                js_temp_string_release(&sep_temp);
                if (error_message)
                {
                    *error_message = prop_err ? prop_err : js_strdup("property lookup failed");
                }
                else
                {
                    js_free(prop_err);
                }
                return false;
            }
            js_free(prop_err);
        }
        if (value.type == JS_VALUE_UNDEFINED || value.type == JS_VALUE_NULL)
        {
            js_value_destroy(&value);
            continue;
        }
        js_temp_string_t temp = {0};
        if (!js_temp_string_from_value(rt, &value, &temp, error_message))
        {
            js_value_destroy(&value);
            js_free(buffer);
            js_temp_string_release(&sep_temp);
            return false;
        }
        size_t needed = len + temp.len + 1;
        if (needed > cap)
        {
            size_t new_cap = cap ? cap * 2u : 32u;
            while (new_cap < needed)
            {
                new_cap *= 2u;
            }
            char *next = (char *)js_realloc(buffer, new_cap);
            if (!next)
            {
                js_temp_string_release(&temp);
                js_value_destroy(&value);
                js_free(buffer);
                js_temp_string_release(&sep_temp);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            buffer = next;
            cap = new_cap;
        }
        if (temp.len)
        {
            memcpy(buffer + len, temp.data, temp.len);
            len += temp.len;
            buffer[len] = '\0';
        }
        js_temp_string_release(&temp);
        js_value_destroy(&value);
    }

    bool ok = js_value_make_string(out, buffer ? buffer : "", len);
    js_free(buffer);
    js_temp_string_release(&sep_temp);
    if (!ok && error_message)
    {
        *error_message = js_strdup("allocation failed");
    }
    return ok;
}

bool js_builtin_array_push(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || this_val->type != JS_VALUE_ARRAY || !this_val->as.array)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Array.prototype.push called on non-array");
        }
        return false;
    }
    size_t start = this_val->as.array->length;
    for (size_t i = 1; i < argc; ++i)
    {
        if (!js_array_set(this_val->as.array, start + (i - 1), &argv[i]))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    *out = js_value_make_number((double)this_val->as.array->length);
    return true;
}

bool js_builtin_array_map(js_runtime_t *rt,
                          size_t argc,
                          const js_value_t *argv,
                          void *user_data,
                          js_value_t *out,
                          char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    const js_value_t *callback = (argc > 1 && argv) ? &argv[1] : NULL;
    bool is_array = this_val && this_val->type == JS_VALUE_ARRAY;
    bool is_object = this_val && this_val->type == JS_VALUE_OBJECT;
    if (!this_val || (!is_array && !is_object) ||
        (is_array && !this_val->as.array) ||
        (is_object && !this_val->as.object))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Array.prototype.map called on non-array");
        }
        return false;
    }
    if (!callback || (callback->type != JS_VALUE_FUNCTION && callback->type != JS_VALUE_NATIVE_FN))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: callback is not callable");
        }
        return false;
    }
    if (!js_value_make_array(out))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    size_t length = 0;
    if (is_array)
    {
        length = this_val->as.array->length;
    }
    else
    {
        js_value_t len_val = js_value_make_undefined_internal();
        char *len_err = NULL;
        if (!js_object_get_property(rt, this_val->as.object, "length", &len_val, &len_err))
        {
            js_free(len_err);
            js_value_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("property lookup failed");
            }
            return false;
        }
        js_free(len_err);
        bool ok = true;
        double len_num = js_value_to_number(&len_val, &ok);
        js_value_destroy(&len_val);
        if (!ok || len_num < 0.0)
        {
            length = 0;
        }
        else if (len_num > (double)SIZE_MAX)
        {
            length = SIZE_MAX;
        }
        else
        {
            length = (size_t)len_num;
        }
    }
    for (size_t i = 0; i < length; ++i)
    {
        js_value_t value = js_value_make_undefined_internal();
        if (is_array)
        {
            if (!js_array_get(this_val->as.array, i, &value))
            {
                js_value_destroy(out);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        else
        {
            char key[32];
            int key_len = snprintf(key, sizeof(key), "%zu", i);
            if (key_len < 0 || (size_t)key_len >= sizeof(key))
            {
                js_value_destroy(out);
                if (error_message)
                {
                    *error_message = js_strdup("invalid index");
                }
                return false;
            }
            char *prop_err = NULL;
            if (!js_object_get_property(rt, this_val->as.object, key, &value, &prop_err))
            {
                js_value_destroy(out);
                if (error_message)
                {
                    *error_message = prop_err ? prop_err : js_strdup("property lookup failed");
                }
                else
                {
                    js_free(prop_err);
                }
                return false;
            }
            js_free(prop_err);
        }
        js_value_t *call_args = (js_value_t *)js_calloc(3, sizeof(*call_args));
        if (!call_args)
        {
            js_value_destroy(&value);
            js_value_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (!js_value_copy(&call_args[0], &value))
        {
            js_free(call_args);
            js_value_destroy(&value);
            js_value_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        call_args[1] = js_value_make_number((double)i);
        if (!js_value_copy(&call_args[2], this_val))
        {
            js_value_destroy(&call_args[0]);
            js_free(call_args);
            js_value_destroy(&value);
            js_value_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        js_value_destroy(&value);
        js_value_t mapped = js_value_make_undefined_internal();
        char *call_err = NULL;
        bool ok = js_call_value(rt, callback, 3, call_args, &mapped, &call_err);
        for (size_t j = 0; j < 3; ++j)
        {
            js_value_destroy(&call_args[j]);
        }
        js_free(call_args);
        if (!ok)
        {
            js_value_destroy(&mapped);
            js_value_destroy(out);
            if (call_err)
            {
                if (error_message)
                {
                    *error_message = call_err;
                }
                else
                {
                    js_free(call_err);
                }
            }
            return false;
        }
        if (!js_array_set(out->as.array, i, &mapped))
        {
            js_value_destroy(&mapped);
            js_value_destroy(out);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        js_value_destroy(&mapped);
    }
    return true;
}

bool js_builtin_array_for_each(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    const js_value_t *callback = (argc > 1 && argv) ? &argv[1] : NULL;
    bool is_array = this_val && this_val->type == JS_VALUE_ARRAY;
    bool is_object = this_val && this_val->type == JS_VALUE_OBJECT;
    if (!this_val || (!is_array && !is_object) ||
        (is_array && !this_val->as.array) ||
        (is_object && !this_val->as.object))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Array.prototype.forEach called on non-array");
        }
        return false;
    }
    if (!callback || (callback->type != JS_VALUE_FUNCTION && callback->type != JS_VALUE_NATIVE_FN))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: callback is not callable");
        }
        return false;
    }

    size_t length = 0;
    if (is_array)
    {
        length = this_val->as.array->length;
    }
    else
    {
        js_value_t len_val = js_value_make_undefined_internal();
        char *len_err = NULL;
        if (!js_object_get_property(rt, this_val->as.object, "length", &len_val, &len_err))
        {
            js_free(len_err);
            if (error_message)
            {
                *error_message = js_strdup("property lookup failed");
            }
            return false;
        }
        js_free(len_err);
        bool ok = true;
        double len_num = js_value_to_number(&len_val, &ok);
        js_value_destroy(&len_val);
        if (!ok || len_num < 0.0)
        {
            length = 0;
        }
        else if (len_num > (double)SIZE_MAX)
        {
            length = SIZE_MAX;
        }
        else
        {
            length = (size_t)len_num;
        }
    }

    for (size_t i = 0; i < length; ++i)
    {
        js_value_t value = js_value_make_undefined_internal();
        if (is_array)
        {
            if (!js_array_get(this_val->as.array, i, &value))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        else
        {
            char key[32];
            int key_len = snprintf(key, sizeof(key), "%zu", i);
            if (key_len < 0 || (size_t)key_len >= sizeof(key))
            {
                if (error_message)
                {
                    *error_message = js_strdup("invalid index");
                }
                return false;
            }
            char *prop_err = NULL;
            if (!js_object_get_property(rt, this_val->as.object, key, &value, &prop_err))
            {
                if (error_message)
                {
                    *error_message = prop_err ? prop_err : js_strdup("property lookup failed");
                }
                else
                {
                    js_free(prop_err);
                }
                return false;
            }
            js_free(prop_err);
        }

        js_value_t *call_args = (js_value_t *)js_calloc(3, sizeof(*call_args));
        if (!call_args)
        {
            js_value_destroy(&value);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (!js_value_copy(&call_args[0], &value))
        {
            js_free(call_args);
            js_value_destroy(&value);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        call_args[1] = js_value_make_number((double)i);
        if (!js_value_copy(&call_args[2], this_val))
        {
            js_value_destroy(&call_args[0]);
            js_free(call_args);
            js_value_destroy(&value);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        js_value_destroy(&value);
        js_value_t ignored = js_value_make_undefined_internal();
        char *call_err = NULL;
        bool ok = js_call_value(rt, callback, 3, call_args, &ignored, &call_err);
        for (size_t j = 0; j < 3; ++j)
        {
            js_value_destroy(&call_args[j]);
        }
        js_free(call_args);
        js_value_destroy(&ignored);
        if (!ok)
        {
            if (call_err)
            {
                if (error_message)
                {
                    *error_message = call_err;
                }
                else
                {
                    js_free(call_err);
                }
            }
            return false;
        }
    }

    *out = js_value_make_undefined_internal();
    return true;
}

bool js_builtin_math_pow(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    double base = 0.0;
    double exp = 0.0;
    bool ok = true;
    if (argc > 0 && argv)
    {
        base = js_value_to_number(&argv[0], &ok);
        if (!ok)
        {
            if (error_message)
            {
                *error_message = js_strdup("TypeError: invalid number");
            }
            return false;
        }
    }
    if (argc > 1 && argv)
    {
        exp = js_value_to_number(&argv[1], &ok);
        if (!ok)
        {
            if (error_message)
            {
                *error_message = js_strdup("TypeError: invalid number");
            }
            return false;
        }
    }
    *out = js_value_make_number(pow(base, exp));
    return true;
}

bool js_builtin_set(js_runtime_t *rt,
                    size_t argc,
                    const js_value_t *argv,
                    void *user_data,
                    js_value_t *out,
                    char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!js_value_make_host_object(out, js_set_get, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

bool js_set_iterator(js_runtime_t *rt,
                     size_t argc,
                     const js_value_t *argv,
                     void *user_data,
                     js_value_t *out,
                     char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_object_t *proto = js_get_set_iterator_proto(rt);
    if (!proto)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_value_make_host_object(out, js_set_iterator_get, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_t proto_val;
    memset(&proto_val, 0, sizeof(proto_val));
    proto_val.type = JS_VALUE_OBJECT;
    proto_val.as.object = proto;
    (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    return true;
}

bool js_builtin_regexp(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temp_string_t temp = {0};
    js_temp_string_t flags_temp = {0};
    bool have_flags = false;
    bool unicode = false;
    const js_value_t *pattern_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (pattern_val && pattern_val->type != JS_VALUE_UNDEFINED)
    {
        if (!js_temp_string_from_value(rt, pattern_val, &temp, error_message))
        {
            return false;
        }
        bool dup = false;
        if (!js_regexp_has_duplicate_named_groups(temp.data ? temp.data : "", temp.len, &dup))
        {
            js_temp_string_release(&temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (dup)
        {
            js_temp_string_release(&temp);
            if (error_message)
            {
                *error_message = js_strdup("SyntaxError: duplicate named capturing group");
            }
            return false;
        }
    }
    if (argc > 1 && argv && argv[1].type != JS_VALUE_UNDEFINED)
    {
        if (!js_temp_string_from_value(rt, &argv[1], &flags_temp, error_message))
        {
            js_temp_string_release(&temp);
            return false;
        }
        have_flags = true;
        if (!js_regexp_flags_valid(flags_temp.data ? flags_temp.data : "", flags_temp.len))
        {
            js_temp_string_release(&temp);
            js_temp_string_release(&flags_temp);
            if (error_message)
            {
                *error_message = js_strdup("SyntaxError: invalid flags");
            }
            return false;
        }
        unicode = flags_temp.data && strchr(flags_temp.data, 'u') != NULL;
    }
    if (!js_regexp_pattern_valid(temp.data ? temp.data : "", temp.len, unicode))
    {
        js_temp_string_release(&temp);
        js_temp_string_release(&flags_temp);
        if (error_message)
        {
            *error_message = js_strdup("SyntaxError: invalid regular expression");
        }
        return false;
    }
    js_realm_t *realm = (js_realm_t *)user_data;
    js_regexp_t *re = (js_regexp_t *)js_calloc(1, sizeof(*re));
    if (!re)
    {
        js_temp_string_release(&temp);
        js_temp_string_release(&flags_temp);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    re->realm_id = realm ? realm->id : js_default_realm.id;
    if (temp.data)
    {
        re->pattern = js_strdup_len(temp.data, temp.len);
        re->pattern_len = temp.len;
        if (!re->pattern)
        {
            js_free(re);
            js_temp_string_release(&temp);
            js_temp_string_release(&flags_temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    js_temp_string_release(&temp);
    if (have_flags)
    {
        bool ok = js_regexp_set_flags(re, flags_temp.data ? flags_temp.data : "", flags_temp.len);
        js_temp_string_release(&flags_temp);
        if (!ok)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    if (!js_value_make_host_object(out, js_regexp_get, NULL, js_regexp_finalize, re))
    {
        js_regexp_finalize(re);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    re->object = out->as.object;
    return true;
}

bool js_builtin_regexp_subclass(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    if (!js_builtin_regexp(rt, argc, argv, user_data, out, error_message))
    {
        return false;
    }
    if (out->type == JS_VALUE_OBJECT && out->as.object && out->as.object->get_fn == js_regexp_get)
    {
        js_regexp_t *re = (js_regexp_t *)out->as.object->user_data;
        if (re)
        {
            re->is_subclass = true;
        }
    }
    return true;
}

bool js_builtin_string(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        return js_value_make_cstring(out, "");
    }
    js_temp_string_t temp = {0};
    if (!js_temp_string_from_value(rt, &argv[0], &temp, error_message))
    {
        return false;
    }
    bool ok = js_value_make_string(out, temp.data ? temp.data : "", temp.len);
    js_temp_string_release(&temp);
    return ok;
}

bool js_builtin_string_from_char_code(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        return js_value_make_cstring(out, "");
    }
    size_t cap = argc * 3;
    char *buf = (char *)js_malloc(cap ? cap : 1);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    size_t len = 0;
    for (size_t i = 0; i < argc; ++i)
    {
        bool ok_num = true;
        double num = js_value_to_number(&argv[i], &ok_num);
        if (!ok_num || js_is_nan(num))
        {
            num = 0.0;
        }
        uint16_t code = (uint16_t)((uint32_t)num);
        if (code < 0x80)
        {
            buf[len++] = (char)code;
        }
        else if (code < 0x800)
        {
            buf[len++] = (char)(0xC0 | (code >> 6));
            buf[len++] = (char)(0x80 | (code & 0x3F));
        }
        else
        {
            buf[len++] = (char)(0xE0 | (code >> 12));
            buf[len++] = (char)(0x80 | ((code >> 6) & 0x3F));
            buf[len++] = (char)(0x80 | (code & 0x3F));
        }
    }
    bool ok = js_value_make_string(out, buf, len);
    js_free(buf);
    return ok;
}

bool js_builtin_number(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        *out = js_value_make_number(0.0);
        return true;
    }
    bool ok = true;
    double value = js_value_to_number(&argv[0], &ok);
    if (!ok)
    {
        value = js_nan();
    }
    *out = js_value_make_number(value);
    return true;
}

bool js_builtin_bigint(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (rt && rt->constructing && rt->constructing_fn == js_builtin_bigint)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: BigInt is not a constructor");
        }
        return false;
    }
    if (argc == 0 || !argv)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: cannot convert undefined to BigInt");
        }
        return false;
    }
    js_bigint_t *big = NULL;
    if (!js_value_to_bigint(rt, &argv[0], &big, error_message))
    {
        return false;
    }
    out->type = JS_VALUE_BIGINT;
    out->as.bigint = big;
    return true;
}

bool js_builtin_bigint_to_string(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (const js_value_t *)user_data;
    if (!this_val || this_val->type != JS_VALUE_BIGINT || !this_val->as.bigint)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: BigInt.prototype.toString called on non-bigint");
        }
        return false;
    }
    int radix = 10;
    if (argc > 0 && argv && argv[0].type != JS_VALUE_UNDEFINED)
    {
        bool ok = true;
        double r = js_value_to_number(&argv[0], &ok);
        if (ok && !js_is_nan(r))
        {
            radix = (int)r;
        }
        if (radix != 10)
        {
            if (error_message)
            {
                *error_message = js_strdup("RangeError: invalid radix");
            }
            return false;
        }
    }
    char *text = js_bigint_to_string(this_val->as.bigint);
    if (!text)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    out->type = JS_VALUE_STRING;
    out->as.string.data = text;
    out->as.string.len = strlen(text);
    return true;
}

bool js_builtin_bigint_value_of(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (const js_value_t *)user_data;
    if (!this_val || this_val->type != JS_VALUE_BIGINT || !this_val->as.bigint)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: BigInt.prototype.valueOf called on non-bigint");
        }
        return false;
    }
    out->type = JS_VALUE_BIGINT;
    out->as.bigint = js_bigint_clone(this_val->as.bigint);
    if (!out->as.bigint)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

bool js_builtin_escape(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }

    size_t cap = temp.len * 6 + 1;
    char *buf = (char *)js_malloc(cap);
    if (!buf)
    {
        js_temp_string_release(&temp);
        return false;
    }
    size_t out_len = 0;
    size_t index = 0;
    while (index < temp.len)
    {
        unsigned int code = 0;
        if (!js_utf8_next(temp.data, temp.len, &index, &code))
        {
            js_free(buf);
            js_temp_string_release(&temp);
            return false;
        }
        if (code < 256 && js_is_unescaped_char(code))
        {
            if (out_len + 1 > cap)
            {
                js_free(buf);
                js_temp_string_release(&temp);
                return false;
            }
            buf[out_len++] = (char)code;
            continue;
        }
        if (code < 256)
        {
            if (!js_append_escape_hex(buf, cap, &out_len, code, false))
            {
                js_free(buf);
                js_temp_string_release(&temp);
                return false;
            }
            continue;
        }
        if (code <= 0xFFFF)
        {
            if (!js_append_escape_hex(buf, cap, &out_len, code, true))
            {
                js_free(buf);
                js_temp_string_release(&temp);
                return false;
            }
            continue;
        }
        unsigned int cp = code - 0x10000;
        unsigned int high = 0xD800 + (cp >> 10);
        unsigned int low = 0xDC00 + (cp & 0x3FF);
        if (!js_append_escape_hex(buf, cap, &out_len, high, true) ||
            !js_append_escape_hex(buf, cap, &out_len, low, true))
        {
            js_free(buf);
            js_temp_string_release(&temp);
            return false;
        }
    }
    buf[out_len] = '\0';

    bool ok = js_value_make_string(out, buf, out_len);
    js_free(buf);
    js_temp_string_release(&temp);
    return ok;
}

bool js_builtin_unescape(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }

    size_t cap = temp.len * 3 + 1;
    char *buf = (char *)js_malloc(cap);
    if (!buf)
    {
        js_temp_string_release(&temp);
        return false;
    }
    size_t out_len = 0;
    size_t i = 0;
    while (i < temp.len)
    {
        char c = temp.data ? temp.data[i] : '\0';
        if (c == '%' && i + 1 < temp.len)
        {
            if (temp.data[i + 1] == 'u')
            {
                if (i + 5 < temp.len)
                {
                    int h0 = js_hex_value(temp.data[i + 2]);
                    int h1 = js_hex_value(temp.data[i + 3]);
                    int h2 = js_hex_value(temp.data[i + 4]);
                    int h3 = js_hex_value(temp.data[i + 5]);
                    if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0)
                    {
                        unsigned int code = (unsigned int)((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
                        if (!js_append_utf8(buf, cap, &out_len, code))
                        {
                            js_free(buf);
                            js_temp_string_release(&temp);
                            return false;
                        }
                        i += 6;
                        continue;
                    }
                }
            }
            else if (i + 2 < temp.len)
            {
                int h0 = js_hex_value(temp.data[i + 1]);
                int h1 = js_hex_value(temp.data[i + 2]);
                if (h0 >= 0 && h1 >= 0)
                {
                    unsigned int code = (unsigned int)((h0 << 4) | h1);
                    if (!js_append_utf8(buf, cap, &out_len, code))
                    {
                        js_free(buf);
                        js_temp_string_release(&temp);
                        return false;
                    }
                    i += 3;
                    continue;
                }
            }
        }
        if (out_len + 1 > cap)
        {
            js_free(buf);
            js_temp_string_release(&temp);
            return false;
        }
        buf[out_len++] = c;
        i++;
    }
    buf[out_len] = '\0';

    bool ok = js_value_make_string(out, buf, out_len);
    js_free(buf);
    js_temp_string_release(&temp);
    return ok;
}

bool js_builtin_eval(js_runtime_t *rt,
                     size_t argc,
                     const js_value_t *argv,
                     void *user_data,
                     js_value_t *out,
                     char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        *out = js_value_make_undefined();
        return true;
    }
    if (argv[0].type != JS_VALUE_STRING)
    {
        return js_value_copy(out, &argv[0]);
    }
    size_t len = argv[0].as.string.len;
    const char *src = argv[0].as.string.data ? argv[0].as.string.data : "";
    char *buf = (char *)js_malloc(len + 1);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    for (size_t i = 0; i < len; ++i)
    {
        unsigned char c = (unsigned char)src[i];
        buf[i] = (char)((c == '\0') ? JS_EVAL_NUL_SENTINEL : c);
    }
    buf[len] = '\0';
    js_exec_result_t res = js_eval(rt, buf);
    js_free(buf);
    if (res.ok)
    {
        *out = res.value;
        return true;
    }
    if (error_message)
    {
        *error_message = res.error_message ? res.error_message : js_strdup("error");
    }
    else
    {
        js_free(res.error_message);
    }
    js_value_destroy(&res.value);
    return false;
}

bool js_builtin_symbol(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *arg = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!arg || arg->type == JS_VALUE_UNDEFINED)
    {
        if (!js_value_make_symbol(out, NULL))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        js_object_t *proto = js_get_symbol_proto(rt);
        if (proto && out->type == JS_VALUE_OBJECT && out->as.object)
        {
            js_value_t proto_val;
            memset(&proto_val, 0, sizeof(proto_val));
            proto_val.type = JS_VALUE_OBJECT;
            proto_val.as.object = proto;
            (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
        }
        return true;
    }
    js_temp_string_t temp = {0};
    if (!js_temp_string_from_value(rt, arg, &temp, error_message))
    {
        return false;
    }
    bool ok = js_value_make_symbol(out, temp.data ? temp.data : "");
    js_temp_string_release(&temp);
    if (ok)
    {
        js_object_t *proto = js_get_symbol_proto(rt);
        if (proto && out->type == JS_VALUE_OBJECT && out->as.object)
        {
            js_value_t proto_val;
            memset(&proto_val, 0, sizeof(proto_val));
            proto_val.type = JS_VALUE_OBJECT;
            proto_val.as.object = proto;
            (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
        }
    }
    if (!ok && error_message)
    {
        *error_message = js_strdup("allocation failed");
    }
    return ok;
}

bool js_builtin_is_html_dda(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_builtin_test_with_typed_array_constructors(js_runtime_t *rt,
                                                   size_t argc,
                                                   const js_value_t *argv,
                                                   void *user_data,
                                                   js_value_t *out,
                                                   char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_builtin_type_error(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_builtin_range_error(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_builtin_syntax_error(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_builtin_create_realm(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_realm_t *realm = (js_realm_t *)js_calloc(1, sizeof(*realm));
    if (!realm)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    realm->id = __atomic_fetch_add(&js_realm_next_id, 1, __ATOMIC_RELAXED);

    js_value_t global_obj;
    if (!js_value_make_host_object(&global_obj, NULL, NULL, js_realm_finalize, realm))
    {
        js_free(realm);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    js_value_t regexp_fn;
    memset(&regexp_fn, 0, sizeof(regexp_fn));
    regexp_fn.type = JS_VALUE_NATIVE_FN;
    regexp_fn.as.native.fn = js_builtin_regexp;
    regexp_fn.as.native.user_data = realm;
    if (!js_object_set_slot(global_obj.as.object, "RegExp", &regexp_fn))
    {
        js_value_destroy(&global_obj);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    js_value_t type_error;
    memset(&type_error, 0, sizeof(type_error));
    type_error.type = JS_VALUE_NATIVE_FN;
    type_error.as.native.fn = js_builtin_type_error;
    type_error.as.native.user_data = NULL;
    if (!js_object_set_slot(global_obj.as.object, "TypeError", &type_error))
    {
        js_value_destroy(&global_obj);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    js_value_t realm_obj;
    if (!js_value_make_host_object(&realm_obj, NULL, NULL, NULL, NULL))
    {
        js_value_destroy(&global_obj);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_object_set_slot(realm_obj.as.object, "global", &global_obj))
    {
        js_value_destroy(&realm_obj);
        js_value_destroy(&global_obj);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_destroy(&global_obj);
    *out = realm_obj;
    return true;
}

bool js_builtin_reflect_get(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!argv || argc < 2)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    const js_value_t *target = &argv[0];
    const js_value_t *receiver = (argc > 2) ? &argv[2] : target;
    js_temp_string_t prop_name = {0};
    if (!js_temp_string_from_value(rt, &argv[1], &prop_name, error_message))
    {
        return false;
    }

    js_prop_desc_t desc;
    bool ok = js_builtin_get_prop_desc(rt,
                                       target,
                                       prop_name.data ? prop_name.data : "",
                                       &desc,
                                       error_message);
    js_temp_string_release(&prop_name);
    if (!ok)
    {
        return false;
    }
    if (!desc.exists)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (desc.is_accessor)
    {
        if (desc.getter.type == JS_VALUE_UNDEFINED)
        {
            js_value_destroy(&desc.getter);
            js_value_destroy(&desc.setter);
            *out = js_value_make_undefined_internal();
            return true;
        }
        js_value_t receiver_copy;
        if (!js_value_copy(&receiver_copy, receiver))
        {
            js_value_destroy(&desc.getter);
            js_value_destroy(&desc.setter);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        js_value_t result = js_value_make_undefined_internal();
        char *err = NULL;
        bool call_ok = js_call_value(rt, &desc.getter, 1, &receiver_copy, &result, &err);
        js_value_destroy(&receiver_copy);
        js_value_destroy(&desc.getter);
        js_value_destroy(&desc.setter);
        if (!call_ok)
        {
            if (error_message)
            {
                *error_message = err ? err : js_strdup("call failed");
            }
            else
            {
                js_free(err);
            }
            js_value_destroy(&result);
            return false;
        }
        js_free(err);
        *out = result;
        return true;
    }

    js_value_t value = desc.value;
    desc.value = js_value_make_undefined_internal();
    js_value_destroy(&desc.getter);
    js_value_destroy(&desc.setter);
    *out = value;
    return true;
}

bool js_builtin_reflect_set(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_bool(false);
    if (!argv || argc < 3)
    {
        return true;
    }
    const js_value_t *target = &argv[0];
    const js_value_t *receiver = (argc > 3) ? &argv[3] : target;
    js_temp_string_t prop_name = {0};
    if (!js_temp_string_from_value(rt, &argv[1], &prop_name, error_message))
    {
        return false;
    }

    js_prop_desc_t desc;
    bool ok = js_builtin_get_prop_desc(rt,
                                       target,
                                       prop_name.data ? prop_name.data : "",
                                       &desc,
                                       error_message);
    if (!ok)
    {
        js_temp_string_release(&prop_name);
        return false;
    }

    if (desc.exists && desc.is_accessor)
    {
        if (desc.setter.type == JS_VALUE_UNDEFINED)
        {
            js_value_destroy(&desc.value);
            js_value_destroy(&desc.getter);
            js_value_destroy(&desc.setter);
            js_temp_string_release(&prop_name);
            *out = js_value_make_bool(false);
            return true;
        }
        js_value_t call_args[2];
        memset(call_args, 0, sizeof(call_args));
        bool copied = js_value_copy(&call_args[0], receiver) &&
            js_value_copy(&call_args[1], &argv[2]);
        if (!copied)
        {
            js_value_destroy(&call_args[0]);
            js_value_destroy(&call_args[1]);
            js_value_destroy(&desc.value);
            js_value_destroy(&desc.getter);
            js_value_destroy(&desc.setter);
            js_temp_string_release(&prop_name);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        js_value_t result = js_value_make_undefined_internal();
        char *err = NULL;
        bool call_ok = js_call_value(rt, &desc.setter, 2, call_args, &result, &err);
        js_value_destroy(&call_args[0]);
        js_value_destroy(&call_args[1]);
        js_value_destroy(&result);
        js_value_destroy(&desc.value);
        js_value_destroy(&desc.getter);
        js_value_destroy(&desc.setter);
        js_temp_string_release(&prop_name);
        if (!call_ok)
        {
            if (error_message)
            {
                *error_message = err ? err : js_strdup("call failed");
            }
            else
            {
                js_free(err);
            }
            return false;
        }
        js_free(err);
        *out = js_value_make_bool(true);
        return true;
    }

    bool set_ok = false;
    const char *name = prop_name.data ? prop_name.data : "";
    if (receiver->type == JS_VALUE_ARRAY && receiver->as.array)
    {
        size_t index = 0;
        if (js_parse_index_key(name, &index))
        {
            set_ok = js_array_set(receiver->as.array, index, &argv[2]);
        }
        else
        {
            set_ok = js_array_set_property(receiver->as.array, name, &argv[2]);
        }
    }
    else if (receiver->type == JS_VALUE_OBJECT && receiver->as.object)
    {
        set_ok = js_object_set_slot(receiver->as.object, name, &argv[2]);
    }

    js_value_destroy(&desc.value);
    js_value_destroy(&desc.getter);
    js_value_destroy(&desc.setter);
    js_temp_string_release(&prop_name);
    if (!set_ok)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    *out = js_value_make_bool(true);
    return true;
}

static bool js_builtin_test262_error_to_string(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    return js_value_make_cstring(out, "Test262Error");
}

bool js_builtin_test262_error(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_value_t obj;
    if (!js_value_make_host_object(&obj, NULL, NULL, NULL, NULL))
    {
        return false;
    }
    js_value_t fn;
    memset(&fn, 0, sizeof(fn));
    fn.type = JS_VALUE_NATIVE_FN;
    fn.as.native.fn = js_builtin_test262_error_to_string;
    fn.as.native.user_data = NULL;
    if (!js_object_set_slot(obj.as.object, "toString", &fn))
    {
        js_value_destroy(&obj);
        return false;
    }
    *out = obj;
    return true;
}

bool js_builtin_verify_property(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !out || argc < 3 || !argv)
    {
        if (error_message)
        {
            *error_message = js_strdup("verifyProperty missing arguments");
        }
        return false;
    }
    const js_value_t *obj = &argv[0];
    const js_value_t *name_val = &argv[1];
    const js_value_t *desc_val = &argv[2];

    js_temp_string_t name_temp = {0};
    char *name_err = NULL;
    if (!js_temp_string_from_value(rt, name_val, &name_temp, &name_err))
    {
        if (name_err)
        {
            if (error_message)
            {
                *error_message = name_err;
            }
            else
            {
                js_free(name_err);
            }
        }
        else if (error_message)
        {
            *error_message = js_strdup("invalid property name");
        }
        return false;
    }
    char *name = js_strdup_len(name_temp.data ? name_temp.data : "", name_temp.len);
    js_temp_string_release(&name_temp);
    if (!name)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    js_prop_desc_t actual;
    char *err = NULL;
    if (!js_builtin_get_prop_desc(rt, obj, name, &actual, &err))
    {
        js_free(name);
        if (err)
        {
            if (error_message)
            {
                *error_message = err;
            }
            else
            {
                js_free(err);
            }
        }
        return false;
    }

    if (desc_val->type == JS_VALUE_UNDEFINED)
    {
        if (actual.exists)
        {
            js_value_destroy(&actual.value);
            js_value_destroy(&actual.getter);
            js_value_destroy(&actual.setter);
            js_free(name);
            if (error_message)
            {
                *error_message = js_strdup("property should be undefined");
            }
            return false;
        }
        *out = js_value_make_bool(true);
        js_free(name);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        return true;
    }

    if (desc_val->type != JS_VALUE_OBJECT)
    {
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        if (error_message)
        {
            *error_message = js_strdup("descriptor must be an object");
        }
        return false;
    }

    bool has_value = false;
    js_value_t expected_value = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(rt, desc_val->as.object, "value", &has_value, &expected_value, error_message))
    {
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        return false;
    }

    if (has_value && !js_value_strict_equal(&actual.value, &expected_value))
    {
        js_value_destroy(&expected_value);
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        if (error_message)
        {
            *error_message = js_strdup("property value mismatch");
        }
        return false;
    }
    js_value_destroy(&expected_value);

    bool has_writable = false;
    js_value_t expected_writable = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(rt, desc_val->as.object, "writable", &has_writable, &expected_writable, error_message))
    {
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        return false;
    }
    if (has_writable && expected_writable.type != JS_VALUE_UNDEFINED)
    {
        bool expected = js_value_is_truthy(&expected_writable);
        if (expected != actual.writable)
        {
            js_value_destroy(&expected_writable);
            js_value_destroy(&actual.value);
            js_value_destroy(&actual.getter);
            js_value_destroy(&actual.setter);
            js_free(name);
            if (error_message)
            {
                *error_message = js_strdup("writable mismatch");
            }
            return false;
        }
    }
    js_value_destroy(&expected_writable);

    bool has_enumerable = false;
    js_value_t expected_enumerable = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(rt, desc_val->as.object, "enumerable", &has_enumerable, &expected_enumerable, error_message))
    {
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        return false;
    }
    if (has_enumerable && expected_enumerable.type != JS_VALUE_UNDEFINED)
    {
        bool expected = js_value_is_truthy(&expected_enumerable);
        if (expected != actual.enumerable)
        {
            js_value_destroy(&expected_enumerable);
            js_value_destroy(&actual.value);
            js_value_destroy(&actual.getter);
            js_value_destroy(&actual.setter);
            js_free(name);
            if (error_message)
            {
                *error_message = js_strdup("enumerable mismatch");
            }
            return false;
        }
    }
    js_value_destroy(&expected_enumerable);

    bool has_configurable = false;
    js_value_t expected_configurable = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(rt, desc_val->as.object, "configurable", &has_configurable, &expected_configurable, error_message))
    {
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        return false;
    }
    if (has_configurable && expected_configurable.type != JS_VALUE_UNDEFINED)
    {
        bool expected = js_value_is_truthy(&expected_configurable);
        if (expected != actual.configurable)
        {
            js_value_destroy(&expected_configurable);
            js_value_destroy(&actual.value);
            js_value_destroy(&actual.getter);
            js_value_destroy(&actual.setter);
            js_free(name);
            if (error_message)
            {
                *error_message = js_strdup("configurable mismatch");
            }
            return false;
        }
    }
    js_value_destroy(&expected_configurable);

    bool has_get = false;
    js_value_t expected_get = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(rt, desc_val->as.object, "get", &has_get, &expected_get, error_message))
    {
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        return false;
    }

    bool has_set = false;
    js_value_t expected_set = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(rt, desc_val->as.object, "set", &has_set, &expected_set, error_message))
    {
        js_value_destroy(&expected_get);
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        return false;
    }

    if ((has_get || has_set) && !actual.is_accessor)
    {
        js_value_destroy(&expected_get);
        js_value_destroy(&expected_set);
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        if (error_message)
        {
            *error_message = js_strdup("property is not an accessor");
        }
        return false;
    }
    if (has_get && !js_value_strict_equal(&actual.getter, &expected_get))
    {
        js_value_destroy(&expected_get);
        js_value_destroy(&expected_set);
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        if (error_message)
        {
            *error_message = js_strdup("getter mismatch");
        }
        return false;
    }
    if (has_set && !js_value_strict_equal(&actual.setter, &expected_set))
    {
        js_value_destroy(&expected_get);
        js_value_destroy(&expected_set);
        js_value_destroy(&actual.value);
        js_value_destroy(&actual.getter);
        js_value_destroy(&actual.setter);
        js_free(name);
        if (error_message)
        {
            *error_message = js_strdup("setter mismatch");
        }
        return false;
    }
    js_value_destroy(&expected_get);
    js_value_destroy(&expected_set);

    js_value_destroy(&actual.value);
    js_value_destroy(&actual.getter);
    js_value_destroy(&actual.setter);
    *out = js_value_make_bool(true);
    js_free(name);
    return true;
}

typedef struct
{
    js_value_t primitive;
} js_boxed_primitive_t;

static void js_boxed_primitive_finalize(void *user_data)
{
    js_boxed_primitive_t *boxed = (js_boxed_primitive_t *)user_data;
    if (!boxed)
    {
        return;
    }
    js_value_destroy(&boxed->primitive);
    js_free(boxed);
}

static bool js_boxed_primitive_value_of(js_runtime_t *rt,
                                        size_t argc,
                                        const js_value_t *argv,
                                        void *user_data,
                                        js_value_t *out,
                                        char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_boxed_primitive_t *boxed = (js_boxed_primitive_t *)user_data;
    if (!boxed)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    return js_value_copy(out, &boxed->primitive);
}

static bool js_date_box_number(js_runtime_t *rt,
                               const js_value_t *value,
                               js_value_t *out,
                               char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_boxed_primitive_t *boxed = (js_boxed_primitive_t *)js_calloc(1, sizeof(*boxed));
    if (!boxed)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_value_copy(&boxed->primitive, value))
    {
        js_free(boxed);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_value_make_host_object(out, NULL, NULL, js_boxed_primitive_finalize, boxed))
    {
        js_value_destroy(&boxed->primitive);
        js_free(boxed);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_number_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    js_value_t value_of;
    memset(&value_of, 0, sizeof(value_of));
    value_of.type = JS_VALUE_NATIVE_FN;
    value_of.as.native.fn = js_boxed_primitive_value_of;
    value_of.as.native.user_data = boxed;
    (void)js_object_set_slot(out->as.object, "valueOf", &value_of);
    js_value_t to_string;
    memset(&to_string, 0, sizeof(to_string));
    to_string.type = JS_VALUE_NATIVE_FN;
    to_string.as.native.fn = js_builtin_number_to_string;
    to_string.as.native.user_data = &boxed->primitive;
    (void)js_object_set_slot(out->as.object, "toString", &to_string);
    return true;
}

static bool js_date_require_object(const js_value_t *this_val,
                                   js_date_t **out_date,
                                   char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out_date)
    {
        return false;
    }
    if (!this_val || this_val->type != JS_VALUE_OBJECT || !this_val->as.object ||
        this_val->as.object->get_fn != js_date_get)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Date method called on non-Date object");
        }
        return false;
    }
    js_date_t *date = (js_date_t *)this_val->as.object->user_data;
    if (!date)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Date method called on non-Date object");
        }
        return false;
    }
    *out_date = date;
    return true;
}

static void js_date_format_year(int64_t year, char *buf, size_t len)
{
    if (!buf || len == 0)
    {
        return;
    }
    if (year >= 0 && year <= 9999)
    {
        (void)snprintf(buf, len, "%04lld", (long long)year);
        return;
    }
    if (year < 0)
    {
        int64_t abs_year = -year;
        if (abs_year < 10000)
        {
            (void)snprintf(buf, len, "-%04lld", (long long)abs_year);
        }
        else
        {
            (void)snprintf(buf, len, "-%lld", (long long)abs_year);
        }
        return;
    }
    (void)snprintf(buf, len, "%lld", (long long)year);
}

static void js_date_format_iso_year(int64_t year, char *buf, size_t len)
{
    if (!buf || len == 0)
    {
        return;
    }
    if (year >= 0 && year <= 9999)
    {
        (void)snprintf(buf, len, "%04lld", (long long)year);
        return;
    }
    char sign = (year < 0) ? '-' : '+';
    int64_t abs_year = (year < 0) ? -year : year;
    (void)snprintf(buf, len, "%c%06lld", sign, (long long)abs_year);
}

static bool js_date_is_finite_number(double value)
{
    return !js_is_nan(value) && value < 1.0e308 && value > -1.0e308;
}

static bool js_date_to_number(js_runtime_t *rt,
                              const js_value_t *value,
                              double *out,
                              char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!value)
    {
        *out = js_nan();
        return true;
    }
    js_value_t prim = js_value_make_undefined_internal();
    bool prim_owned = false;
    if (value->type == JS_VALUE_OBJECT && value->as.object)
    {
        if (js_object_is_symbol(value->as.object))
        {
            if (error_message)
            {
                *error_message = js_strdup("TypeError: cannot convert Symbol to number");
            }
            return false;
        }
        if (!js_object_to_primitive_number(rt, value->as.object, &prim, error_message))
        {
            return false;
        }
        prim_owned = true;
        value = &prim;
    }
    if (value->type == JS_VALUE_OBJECT && value->as.object && js_object_is_symbol(value->as.object))
    {
        if (prim_owned)
        {
            js_value_destroy(&prim);
        }
        if (error_message)
        {
            *error_message = js_strdup("TypeError: cannot convert Symbol to number");
        }
        return false;
    }
    bool ok_num = true;
    double num = js_value_to_number(value, &ok_num);
    if (!ok_num)
    {
        num = js_nan();
    }
    if (prim_owned)
    {
        js_value_destroy(&prim);
    }
    *out = num;
    return true;
}

static bool js_date_to_primitive_default_value(js_runtime_t *rt,
                                               const js_value_t *value,
                                               js_value_t *out,
                                               char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!value)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (value->type == JS_VALUE_OBJECT && value->as.object)
    {
        return js_date_object_to_primitive_default(rt, value->as.object, out, error_message);
    }
    return js_value_copy(out, value);
}

bool js_builtin_date(js_runtime_t *rt,
                     size_t argc,
                     const js_value_t *argv,
                     void *user_data,
                     js_value_t *out,
                     char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool constructing = rt && rt->constructing && rt->constructing_fn == js_builtin_date;
    if (!constructing)
    {
        double now = js_date_now_ms();
        if (js_is_nan(now))
        {
            return js_value_make_cstring(out, "Invalid Date");
        }
        js_date_parts_t parts;
        if (!js_date_breakdown(now, &parts))
        {
            return js_value_make_cstring(out, "Invalid Date");
        }
        char year_buf[32];
        js_date_format_year(parts.year, year_buf, sizeof(year_buf));
        char buf[128];
        int len = snprintf(buf, sizeof(buf),
                           "%s %s %02d %s %02d:%02d:%02d GMT+0000",
                           JS_DATE_DAY_NAMES[parts.weekday],
                           JS_DATE_MONTH_NAMES[parts.month - 1],
                           parts.day,
                           year_buf,
                           parts.hour,
                           parts.minute,
                           parts.second);
        if (len < 0)
        {
            return false;
        }
        return js_value_make_string(out, buf, (size_t)len);
    }

    double time_ms = js_nan();
    if (!argv || argc == 0)
    {
        time_ms = js_date_now_ms();
    }
    else if (argc == 1)
    {
        const js_value_t *arg = &argv[0];
        if (arg->type == JS_VALUE_OBJECT && arg->as.object &&
            arg->as.object->get_fn == js_date_get)
        {
            js_date_t *other = (js_date_t *)arg->as.object->user_data;
            time_ms = other ? other->time_ms : js_nan();
        }
        else
        {
            js_value_t prim = js_value_make_undefined_internal();
            if (arg->type == JS_VALUE_OBJECT && arg->as.object)
            {
                if (!js_date_to_primitive_default_value(rt, arg, &prim, error_message))
                {
                    return false;
                }
                arg = &prim;
            }
            if (arg->type == JS_VALUE_STRING)
            {
                time_ms = js_date_parse_string(arg->as.string.data, arg->as.string.len);
            }
            else
            {
                double num = js_nan();
                if (!js_date_to_number(rt, arg, &num, error_message))
                {
                    js_value_destroy(&prim);
                    return false;
                }
                time_ms = num;
            }
            js_value_destroy(&prim);
        }
    }
    else
    {
        double year_num = js_nan();
        double month_num = js_nan();
        double date_num = 1.0;
        double hour_num = 0.0;
        double minute_num = 0.0;
        double second_num = 0.0;
        double millisecond_num = 0.0;
        if (!js_date_to_number(rt, &argv[0], &year_num, error_message))
        {
            return false;
        }
        if (!js_date_to_number(rt, &argv[1], &month_num, error_message))
        {
            return false;
        }
        if (argc > 2)
        {
            if (!js_date_to_number(rt, &argv[2], &date_num, error_message))
            {
                return false;
            }
        }
        if (argc > 3)
        {
            if (!js_date_to_number(rt, &argv[3], &hour_num, error_message))
            {
                return false;
            }
        }
        if (argc > 4)
        {
            if (!js_date_to_number(rt, &argv[4], &minute_num, error_message))
            {
                return false;
            }
        }
        if (argc > 5)
        {
            if (!js_date_to_number(rt, &argv[5], &second_num, error_message))
            {
                return false;
            }
        }
        if (argc > 6)
        {
            if (!js_date_to_number(rt, &argv[6], &millisecond_num, error_message))
            {
                return false;
            }
        }
        bool any_nan = js_is_nan(year_num) ||
                       js_is_nan(month_num) ||
                       js_is_nan(date_num) ||
                       js_is_nan(hour_num) ||
                       js_is_nan(minute_num) ||
                       js_is_nan(second_num) ||
                       js_is_nan(millisecond_num);
        if (any_nan)
        {
            time_ms = js_nan();
        }
        else
        {
            int64_t year_int = 0;
            int64_t month_int = 0;
            int64_t date_int = 0;
            int64_t hour_int = 0;
            int64_t minute_int = 0;
            int64_t second_int = 0;
            int64_t ms_int = 0;
            if (!js_date_double_to_int64(year_num, &year_int) ||
                !js_date_double_to_int64(month_num, &month_int) ||
                !js_date_double_to_int64(date_num, &date_int) ||
                !js_date_double_to_int64(hour_num, &hour_int) ||
                !js_date_double_to_int64(minute_num, &minute_int) ||
                !js_date_double_to_int64(second_num, &second_int) ||
                !js_date_double_to_int64(millisecond_num, &ms_int))
            {
                time_ms = js_nan();
            }
            else
            {
                if (year_int >= 0 && year_int <= 99)
                {
                    year_int += 1900;
                }
                time_ms = js_date_make_time_value(year_int,
                                                  month_int,
                                                  date_int,
                                                  hour_int,
                                                  minute_int,
                                                  second_int,
                                                  ms_int);
            }
        }
    }
    time_ms = js_date_time_clip(time_ms);

    js_date_t *date = (js_date_t *)js_calloc(1, sizeof(*date));
    if (!date)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    date->time_ms = time_ms;
    if (!js_value_make_host_object(out, js_date_get, NULL, js_date_finalize, date))
    {
        js_free(date);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_date_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

bool js_builtin_date_now(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_number(js_date_now_ms());
    return true;
}

bool js_builtin_date_parse(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *arg = (argc > 0 && argv) ? &argv[0] : NULL;
    js_temp_string_t temp = {0};
    if (!js_temp_string_from_value(rt, arg, &temp, error_message))
    {
        return false;
    }
    double time_ms = js_date_parse_string(temp.data, temp.len);
    js_temp_string_release(&temp);
    *out = js_value_make_number(time_ms);
    return true;
}

bool js_builtin_date_utc(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    double year_num = js_nan();
    double month_num = 0.0;
    double date_num = 1.0;
    double hour_num = 0.0;
    double minute_num = 0.0;
    double second_num = 0.0;
    double millisecond_num = 0.0;
    if (argc > 0 && argv)
    {
        if (!js_date_to_number(rt, &argv[0], &year_num, error_message))
        {
            return false;
        }
    }
    if (argc > 1 && argv)
    {
        if (!js_date_to_number(rt, &argv[1], &month_num, error_message))
        {
            return false;
        }
    }
    if (argc > 2 && argv)
    {
        if (!js_date_to_number(rt, &argv[2], &date_num, error_message))
        {
            return false;
        }
    }
    if (argc > 3 && argv)
    {
        if (!js_date_to_number(rt, &argv[3], &hour_num, error_message))
        {
            return false;
        }
    }
    if (argc > 4 && argv)
    {
        if (!js_date_to_number(rt, &argv[4], &minute_num, error_message))
        {
            return false;
        }
    }
    if (argc > 5 && argv)
    {
        if (!js_date_to_number(rt, &argv[5], &second_num, error_message))
        {
            return false;
        }
    }
    if (argc > 6 && argv)
    {
        if (!js_date_to_number(rt, &argv[6], &millisecond_num, error_message))
        {
            return false;
        }
    }
    bool any_nan = js_is_nan(year_num) ||
                   js_is_nan(month_num) ||
                   js_is_nan(date_num) ||
                   js_is_nan(hour_num) ||
                   js_is_nan(minute_num) ||
                   js_is_nan(second_num) ||
                   js_is_nan(millisecond_num);
    double time_ms = js_nan();
    if (!any_nan)
    {
        int64_t year_int = 0;
        int64_t month_int = 0;
        int64_t date_int = 0;
        int64_t hour_int = 0;
        int64_t minute_int = 0;
        int64_t second_int = 0;
        int64_t ms_int = 0;
        if (js_date_double_to_int64(year_num, &year_int) &&
            js_date_double_to_int64(month_num, &month_int) &&
            js_date_double_to_int64(date_num, &date_int) &&
            js_date_double_to_int64(hour_num, &hour_int) &&
            js_date_double_to_int64(minute_num, &minute_int) &&
            js_date_double_to_int64(second_num, &second_int) &&
            js_date_double_to_int64(millisecond_num, &ms_int))
        {
            if (year_int >= 0 && year_int <= 99)
            {
                year_int += 1900;
            }
            time_ms = js_date_make_time_value(year_int,
                                              month_int,
                                              date_int,
                                              hour_int,
                                              minute_int,
                                              second_int,
                                              ms_int);
        }
    }
    time_ms = js_date_time_clip(time_ms);
    *out = js_value_make_number(time_ms);
    return true;
}

bool js_date_proto_to_string(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        return js_value_make_cstring(out, "Invalid Date");
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        return js_value_make_cstring(out, "Invalid Date");
    }
    char year_buf[32];
    js_date_format_year(parts.year, year_buf, sizeof(year_buf));
    char buf[128];
    int len = snprintf(buf, sizeof(buf),
                       "%s %s %02d %s %02d:%02d:%02d GMT+0000",
                       JS_DATE_DAY_NAMES[parts.weekday],
                       JS_DATE_MONTH_NAMES[parts.month - 1],
                       parts.day,
                       year_buf,
                       parts.hour,
                       parts.minute,
                       parts.second);
    if (len < 0)
    {
        return false;
    }
    return js_value_make_string(out, buf, (size_t)len);
}

bool js_date_proto_to_date_string(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        return js_value_make_cstring(out, "Invalid Date");
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        return js_value_make_cstring(out, "Invalid Date");
    }
    char year_buf[32];
    js_date_format_year(parts.year, year_buf, sizeof(year_buf));
    char buf[128];
    int len = snprintf(buf, sizeof(buf),
                       "%s %s %02d %s",
                       JS_DATE_DAY_NAMES[parts.weekday],
                       JS_DATE_MONTH_NAMES[parts.month - 1],
                       parts.day,
                       year_buf);
    if (len < 0)
    {
        return false;
    }
    return js_value_make_string(out, buf, (size_t)len);
}

bool js_date_proto_to_time_string(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        return js_value_make_cstring(out, "Invalid Date");
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        return js_value_make_cstring(out, "Invalid Date");
    }
    char buf[128];
    int len = snprintf(buf, sizeof(buf),
                       "%02d:%02d:%02d GMT+0000",
                       parts.hour,
                       parts.minute,
                       parts.second);
    if (len < 0)
    {
        return false;
    }
    return js_value_make_string(out, buf, (size_t)len);
}

bool js_date_proto_to_utc_string(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        return js_value_make_cstring(out, "Invalid Date");
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        return js_value_make_cstring(out, "Invalid Date");
    }
    char year_buf[32];
    js_date_format_year(parts.year, year_buf, sizeof(year_buf));
    char buf[128];
    int len = snprintf(buf, sizeof(buf),
                       "%s, %02d %s %s %02d:%02d:%02d GMT",
                       JS_DATE_DAY_NAMES[parts.weekday],
                       parts.day,
                       JS_DATE_MONTH_NAMES[parts.month - 1],
                       year_buf,
                       parts.hour,
                       parts.minute,
                       parts.second);
    if (len < 0)
    {
        return false;
    }
    return js_value_make_string(out, buf, (size_t)len);
}

bool js_date_proto_to_gmt_string(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    return js_date_proto_to_utc_string(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_to_iso_string(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid time value");
        }
        return false;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid time value");
        }
        return false;
    }
    char year_buf[32];
    js_date_format_iso_year(parts.year, year_buf, sizeof(year_buf));
    char buf[128];
    int len = snprintf(buf, sizeof(buf),
                       "%s-%02d-%02dT%02d:%02d:%02d.%03dZ",
                       year_buf,
                       parts.month,
                       parts.day,
                       parts.hour,
                       parts.minute,
                       parts.second,
                       parts.millisecond);
    if (len < 0)
    {
        return false;
    }
    return js_value_make_string(out, buf, (size_t)len);
}

bool js_date_proto_to_json(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!this_val || this_val->type == JS_VALUE_UNDEFINED || this_val->type == JS_VALUE_NULL)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: cannot convert undefined or null to object");
        }
        return false;
    }
    js_value_t obj_value = js_value_make_undefined_internal();
    bool obj_owned = false;
    if (this_val->type == JS_VALUE_NUMBER)
    {
        if (!js_date_box_number(rt, this_val, &obj_value, error_message))
        {
            return false;
        }
        obj_owned = true;
    }
    else if (this_val->type == JS_VALUE_OBJECT)
    {
        obj_value = *this_val;
    }
    else
    {
        obj_value = *this_val;
    }

    js_value_t prim = js_value_make_undefined_internal();
    if (obj_value.type == JS_VALUE_OBJECT && obj_value.as.object)
    {
        if (!js_object_to_primitive_number(rt, obj_value.as.object, &prim, error_message))
        {
            if (obj_owned)
            {
                js_value_destroy(&obj_value);
            }
            return false;
        }
        if (prim.type == JS_VALUE_NUMBER && !js_date_is_finite_number(prim.as.number))
        {
            js_value_destroy(&prim);
            if (obj_owned)
            {
                js_value_destroy(&obj_value);
            }
            *out = js_value_make_null();
            return true;
        }
        js_value_destroy(&prim);
    }
    else
    {
        bool ok_num = true;
        double num = js_value_to_number(&obj_value, &ok_num);
        if (!ok_num || !js_date_is_finite_number(num))
        {
            if (obj_owned)
            {
                js_value_destroy(&obj_value);
            }
            *out = js_value_make_null();
            return true;
        }
    }

    js_value_t method = js_value_make_undefined_internal();
    if (obj_value.type == JS_VALUE_OBJECT && obj_value.as.object)
    {
        char *err = NULL;
        if (!js_object_get_property(rt, obj_value.as.object, "toISOString", &method, &err))
        {
            if (obj_owned)
            {
                js_value_destroy(&obj_value);
            }
            if (error_message)
            {
                *error_message = err ? err : js_strdup("toISOString lookup failed");
            }
            else
            {
                js_free(err);
            }
            return false;
        }
    }
    if (method.type != JS_VALUE_FUNCTION && method.type != JS_VALUE_NATIVE_FN)
    {
        js_value_destroy(&method);
        if (obj_owned)
        {
            js_value_destroy(&obj_value);
        }
        if (error_message)
        {
            *error_message = js_strdup("TypeError: toISOString is not callable");
        }
        return false;
    }
    js_value_t result = js_value_make_undefined_internal();
    char *call_err = NULL;
    if (method.type == JS_VALUE_NATIVE_FN && js_native_needs_this(method.as.native.fn))
    {
        js_value_t args[1];
        if (!js_value_copy(&args[0], &obj_value))
        {
            js_value_destroy(&method);
            if (obj_owned)
            {
                js_value_destroy(&obj_value);
            }
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        bool ok = js_call_value(rt, &method, 1, args, &result, &call_err);
        js_value_destroy(&args[0]);
        js_value_destroy(&method);
        if (obj_owned)
        {
            js_value_destroy(&obj_value);
        }
        if (!ok)
        {
            if (error_message)
            {
                *error_message = call_err ? call_err : js_strdup("toISOString failed");
            }
            else
            {
                js_free(call_err);
            }
            js_value_destroy(&result);
            return false;
        }
        *out = result;
        return true;
    }
    bool ok = js_call_value(rt, &method, 0, NULL, &result, &call_err);
    js_value_destroy(&method);
    if (obj_owned)
    {
        js_value_destroy(&obj_value);
    }
    if (!ok)
    {
        if (error_message)
        {
            *error_message = call_err ? call_err : js_strdup("toISOString failed");
        }
        else
        {
            js_free(call_err);
        }
        js_value_destroy(&result);
        return false;
    }
    *out = result;
    return true;
}

bool js_date_proto_value_of(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    *out = js_value_make_number(date ? date->time_ms : js_nan());
    return true;
}

bool js_date_proto_get_time(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    return js_date_proto_value_of(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_full_year(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    *out = js_value_make_number((double)parts.year);
    return true;
}

bool js_date_proto_get_utc_full_year(js_runtime_t *rt,
                                     size_t argc,
                                     const js_value_t *argv,
                                     void *user_data,
                                     js_value_t *out,
                                     char **error_message)
{
    return js_date_proto_get_full_year(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_month(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    *out = js_value_make_number((double)(parts.month - 1));
    return true;
}

bool js_date_proto_get_utc_month(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    return js_date_proto_get_month(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_date(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    *out = js_value_make_number((double)parts.day);
    return true;
}

bool js_date_proto_get_utc_date(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    return js_date_proto_get_date(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_day(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    *out = js_value_make_number((double)parts.weekday);
    return true;
}

bool js_date_proto_get_utc_day(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    return js_date_proto_get_day(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_hours(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    *out = js_value_make_number((double)parts.hour);
    return true;
}

bool js_date_proto_get_utc_hours(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    return js_date_proto_get_hours(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_minutes(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    *out = js_value_make_number((double)parts.minute);
    return true;
}

bool js_date_proto_get_utc_minutes(js_runtime_t *rt,
                                   size_t argc,
                                   const js_value_t *argv,
                                   void *user_data,
                                   js_value_t *out,
                                   char **error_message)
{
    return js_date_proto_get_minutes(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_seconds(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    *out = js_value_make_number((double)parts.second);
    return true;
}

bool js_date_proto_get_utc_seconds(js_runtime_t *rt,
                                   size_t argc,
                                   const js_value_t *argv,
                                   void *user_data,
                                   js_value_t *out,
                                   char **error_message)
{
    return js_date_proto_get_seconds(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_milliseconds(js_runtime_t *rt,
                                    size_t argc,
                                    const js_value_t *argv,
                                    void *user_data,
                                    js_value_t *out,
                                    char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    *out = js_value_make_number((double)parts.millisecond);
    return true;
}

bool js_date_proto_get_utc_milliseconds(js_runtime_t *rt,
                                        size_t argc,
                                        const js_value_t *argv,
                                        void *user_data,
                                        js_value_t *out,
                                        char **error_message)
{
    return js_date_proto_get_milliseconds(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_timezone_offset(js_runtime_t *rt,
                                       size_t argc,
                                       const js_value_t *argv,
                                       void *user_data,
                                       js_value_t *out,
                                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    (void)date;
    *out = js_value_make_number(0.0);
    return true;
}

bool js_date_proto_set_time(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    const js_value_t *arg = (argc > 1 && argv) ? &argv[1] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    double time_num = js_nan();
    if (!js_date_to_number(rt, arg, &time_num, error_message))
    {
        return false;
    }
    double clipped = js_date_time_clip(time_num);
    date->time_ms = clipped;
    *out = js_value_make_number(clipped);
    return true;
}

static bool js_date_set_full_year_internal(js_runtime_t *rt,
                                           size_t argc,
                                           const js_value_t *argv,
                                           bool utc,
                                           js_date_t *date,
                                           js_value_t *out,
                                           char **error_message)
{
    (void)utc;
    double t = date->time_ms;
    bool t_is_nan = js_is_nan(t);
    bool have_month = argc > 2;
    bool have_date = argc > 3;
    double year_num = js_nan();
    double month_num = js_nan();
    double date_num = js_nan();
    if (!js_date_to_number(rt, (argc > 1) ? &argv[1] : NULL, &year_num, error_message))
    {
        return false;
    }
    if (argc > 2)
    {
        if (!js_date_to_number(rt, &argv[2], &month_num, error_message))
        {
            return false;
        }
    }
    if (argc > 3)
    {
        if (!js_date_to_number(rt, &argv[3], &date_num, error_message))
        {
            return false;
        }
    }
    double base_time = t_is_nan ? 0.0 : t;
    js_date_parts_t parts;
    if (!js_date_breakdown(base_time, &parts))
    {
        parts.year = 1970;
        parts.month = 1;
        parts.day = 1;
        parts.hour = 0;
        parts.minute = 0;
        parts.second = 0;
        parts.millisecond = 0;
    }
    if (!have_month)
    {
        month_num = (double)(parts.month - 1);
    }
    if (!have_date)
    {
        date_num = (double)parts.day;
    }
    if (js_is_nan(year_num) ||
        (have_month && js_is_nan(month_num)) ||
        (have_date && js_is_nan(date_num)))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    int64_t year_int = 0;
    int64_t month_int = 0;
    int64_t day_int = 0;
    if (!js_date_double_to_int64(year_num, &year_int) ||
        !js_date_double_to_int64(month_num, &month_int) ||
        !js_date_double_to_int64(date_num, &day_int))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    if (year_int >= 0 && year_int <= 99)
    {
        year_int += 1900;
    }
    double new_time = js_date_make_time_value(year_int,
                                              month_int,
                                              day_int,
                                              parts.hour,
                                              parts.minute,
                                              parts.second,
                                              parts.millisecond);
    new_time = js_date_time_clip(new_time);
    date->time_ms = new_time;
    *out = js_value_make_number(new_time);
    return true;
}

bool js_date_proto_set_full_year(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    return js_date_set_full_year_internal(rt, argc, argv, false, date, out, error_message);
}

bool js_date_proto_set_utc_full_year(js_runtime_t *rt,
                                     size_t argc,
                                     const js_value_t *argv,
                                     void *user_data,
                                     js_value_t *out,
                                     char **error_message)
{
    return js_date_proto_set_full_year(rt, argc, argv, user_data, out, error_message);
}

static bool js_date_set_month_internal(js_runtime_t *rt,
                                       size_t argc,
                                       const js_value_t *argv,
                                       bool utc,
                                       js_date_t *date,
                                       js_value_t *out,
                                       char **error_message)
{
    (void)utc;
    double t = date->time_ms;
    bool t_is_nan = js_is_nan(t);
    bool have_date = argc > 2;
    double month_num = js_nan();
    double date_num = js_nan();
    if (!js_date_to_number(rt, (argc > 1) ? &argv[1] : NULL, &month_num, error_message))
    {
        return false;
    }
    if (argc > 2)
    {
        if (!js_date_to_number(rt, &argv[2], &date_num, error_message))
        {
            return false;
        }
    }
    if (t_is_nan)
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(t, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    if (!have_date)
    {
        date_num = (double)parts.day;
    }
    if (js_is_nan(month_num) || (have_date && js_is_nan(date_num)))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    int64_t month_int = 0;
    int64_t day_int = 0;
    if (!js_date_double_to_int64(month_num, &month_int) ||
        !js_date_double_to_int64(date_num, &day_int))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    double new_time = js_date_make_time_value(parts.year,
                                              month_int,
                                              day_int,
                                              parts.hour,
                                              parts.minute,
                                              parts.second,
                                              parts.millisecond);
    new_time = js_date_time_clip(new_time);
    date->time_ms = new_time;
    *out = js_value_make_number(new_time);
    return true;
}

bool js_date_proto_set_month(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    return js_date_set_month_internal(rt, argc, argv, false, date, out, error_message);
}

bool js_date_proto_set_utc_month(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    return js_date_proto_set_month(rt, argc, argv, user_data, out, error_message);
}

static bool js_date_set_date_internal(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      bool utc,
                                      js_date_t *date,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)utc;
    double t = date->time_ms;
    bool t_is_nan = js_is_nan(t);
    double date_num = js_nan();
    if (!js_date_to_number(rt, (argc > 1) ? &argv[1] : NULL, &date_num, error_message))
    {
        return false;
    }
    if (t_is_nan)
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(t, &parts))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    if (js_is_nan(date_num))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    int64_t day_int = 0;
    if (!js_date_double_to_int64(date_num, &day_int))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    double new_time = js_date_make_time_value(parts.year,
                                              (int64_t)(parts.month - 1),
                                              day_int,
                                              parts.hour,
                                              parts.minute,
                                              parts.second,
                                              parts.millisecond);
    new_time = js_date_time_clip(new_time);
    date->time_ms = new_time;
    *out = js_value_make_number(new_time);
    return true;
}

bool js_date_proto_set_date(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    return js_date_set_date_internal(rt, argc, argv, false, date, out, error_message);
}

bool js_date_proto_set_utc_date(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    return js_date_proto_set_date(rt, argc, argv, user_data, out, error_message);
}

static bool js_date_set_time_parts_internal(js_runtime_t *rt,
                                            size_t argc,
                                            const js_value_t *argv,
                                            bool utc,
                                            js_date_t *date,
                                            js_value_t *out,
                                            char **error_message)
{
    (void)utc;
    double t = date->time_ms;
    bool t_is_nan = js_is_nan(t);
    bool have_minute = argc > 2;
    bool have_second = argc > 3;
    bool have_ms = argc > 4;
    double hour_num = js_nan();
    double minute_num = js_nan();
    double second_num = js_nan();
    double ms_num = js_nan();
    if (!js_date_to_number(rt, (argc > 1) ? &argv[1] : NULL, &hour_num, error_message))
    {
        return false;
    }
    if (argc > 2)
    {
        if (!js_date_to_number(rt, &argv[2], &minute_num, error_message))
        {
            return false;
        }
    }
    if (argc > 3)
    {
        if (!js_date_to_number(rt, &argv[3], &second_num, error_message))
        {
            return false;
        }
    }
    if (argc > 4)
    {
        if (!js_date_to_number(rt, &argv[4], &ms_num, error_message))
        {
            return false;
        }
    }
    if (t_is_nan)
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(t, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    if (!have_minute)
    {
        minute_num = (double)parts.minute;
    }
    if (!have_second)
    {
        second_num = (double)parts.second;
    }
    if (!have_ms)
    {
        ms_num = (double)parts.millisecond;
    }
    if (js_is_nan(hour_num) ||
        (have_minute && js_is_nan(minute_num)) ||
        (have_second && js_is_nan(second_num)) ||
        (have_ms && js_is_nan(ms_num)))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    int64_t hour_int = 0;
    int64_t minute_int = 0;
    int64_t second_int = 0;
    int64_t ms_int = 0;
    if (!js_date_double_to_int64(hour_num, &hour_int) ||
        !js_date_double_to_int64(minute_num, &minute_int) ||
        !js_date_double_to_int64(second_num, &second_int) ||
        !js_date_double_to_int64(ms_num, &ms_int))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    double new_time = js_date_make_time_value(parts.year,
                                              (int64_t)(parts.month - 1),
                                              parts.day,
                                              hour_int,
                                              minute_int,
                                              second_int,
                                              ms_int);
    new_time = js_date_time_clip(new_time);
    date->time_ms = new_time;
    *out = js_value_make_number(new_time);
    return true;
}

bool js_date_proto_set_hours(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    return js_date_set_time_parts_internal(rt, argc, argv, false, date, out, error_message);
}

bool js_date_proto_set_utc_hours(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    return js_date_proto_set_hours(rt, argc, argv, user_data, out, error_message);
}

static bool js_date_set_minutes_internal(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         bool utc,
                                         js_date_t *date,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)utc;
    double t = date->time_ms;
    bool t_is_nan = js_is_nan(t);
    bool have_second = argc > 2;
    bool have_ms = argc > 3;
    double minute_num = js_nan();
    double second_num = js_nan();
    double ms_num = js_nan();
    if (!js_date_to_number(rt, (argc > 1) ? &argv[1] : NULL, &minute_num, error_message))
    {
        return false;
    }
    if (argc > 2)
    {
        if (!js_date_to_number(rt, &argv[2], &second_num, error_message))
        {
            return false;
        }
    }
    if (argc > 3)
    {
        if (!js_date_to_number(rt, &argv[3], &ms_num, error_message))
        {
            return false;
        }
    }
    if (t_is_nan)
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(t, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    if (!have_second)
    {
        second_num = (double)parts.second;
    }
    if (!have_ms)
    {
        ms_num = (double)parts.millisecond;
    }
    if (js_is_nan(minute_num) ||
        (have_second && js_is_nan(second_num)) ||
        (have_ms && js_is_nan(ms_num)))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    int64_t minute_int = 0;
    int64_t second_int = 0;
    int64_t ms_int = 0;
    if (!js_date_double_to_int64(minute_num, &minute_int) ||
        !js_date_double_to_int64(second_num, &second_int) ||
        !js_date_double_to_int64(ms_num, &ms_int))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    double new_time = js_date_make_time_value(parts.year,
                                              (int64_t)(parts.month - 1),
                                              parts.day,
                                              parts.hour,
                                              minute_int,
                                              second_int,
                                              ms_int);
    new_time = js_date_time_clip(new_time);
    date->time_ms = new_time;
    *out = js_value_make_number(new_time);
    return true;
}

bool js_date_proto_set_minutes(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    return js_date_set_minutes_internal(rt, argc, argv, false, date, out, error_message);
}

bool js_date_proto_set_utc_minutes(js_runtime_t *rt,
                                   size_t argc,
                                   const js_value_t *argv,
                                   void *user_data,
                                   js_value_t *out,
                                   char **error_message)
{
    return js_date_proto_set_minutes(rt, argc, argv, user_data, out, error_message);
}

static bool js_date_set_seconds_internal(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         bool utc,
                                         js_date_t *date,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)utc;
    double t = date->time_ms;
    bool t_is_nan = js_is_nan(t);
    bool have_ms = argc > 2;
    double second_num = js_nan();
    double ms_num = js_nan();
    if (!js_date_to_number(rt, (argc > 1) ? &argv[1] : NULL, &second_num, error_message))
    {
        return false;
    }
    if (argc > 2)
    {
        if (!js_date_to_number(rt, &argv[2], &ms_num, error_message))
        {
            return false;
        }
    }
    if (t_is_nan)
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(t, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    if (!have_ms)
    {
        ms_num = (double)parts.millisecond;
    }
    if (js_is_nan(second_num) || (have_ms && js_is_nan(ms_num)))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    int64_t second_int = 0;
    int64_t ms_int = 0;
    if (!js_date_double_to_int64(second_num, &second_int) ||
        !js_date_double_to_int64(ms_num, &ms_int))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    double new_time = js_date_make_time_value(parts.year,
                                              (int64_t)(parts.month - 1),
                                              parts.day,
                                              parts.hour,
                                              parts.minute,
                                              second_int,
                                              ms_int);
    new_time = js_date_time_clip(new_time);
    date->time_ms = new_time;
    *out = js_value_make_number(new_time);
    return true;
}

bool js_date_proto_set_seconds(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    return js_date_set_seconds_internal(rt, argc, argv, false, date, out, error_message);
}

bool js_date_proto_set_utc_seconds(js_runtime_t *rt,
                                   size_t argc,
                                   const js_value_t *argv,
                                   void *user_data,
                                   js_value_t *out,
                                   char **error_message)
{
    return js_date_proto_set_seconds(rt, argc, argv, user_data, out, error_message);
}

static bool js_date_set_milliseconds_internal(js_runtime_t *rt,
                                              size_t argc,
                                              const js_value_t *argv,
                                              bool utc,
                                              js_date_t *date,
                                              js_value_t *out,
                                              char **error_message)
{
    (void)utc;
    double t = date->time_ms;
    bool t_is_nan = js_is_nan(t);
    double ms_num = js_nan();
    if (!js_date_to_number(rt, (argc > 1) ? &argv[1] : NULL, &ms_num, error_message))
    {
        return false;
    }
    if (t_is_nan)
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(t, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    if (js_is_nan(ms_num))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    int64_t ms_int = 0;
    if (!js_date_double_to_int64(ms_num, &ms_int))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    double new_time = js_date_make_time_value(parts.year,
                                              (int64_t)(parts.month - 1),
                                              parts.day,
                                              parts.hour,
                                              parts.minute,
                                              parts.second,
                                              ms_int);
    new_time = js_date_time_clip(new_time);
    date->time_ms = new_time;
    *out = js_value_make_number(new_time);
    return true;
}

bool js_date_proto_set_milliseconds(js_runtime_t *rt,
                                    size_t argc,
                                    const js_value_t *argv,
                                    void *user_data,
                                    js_value_t *out,
                                    char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    return js_date_set_milliseconds_internal(rt, argc, argv, false, date, out, error_message);
}

bool js_date_proto_set_utc_milliseconds(js_runtime_t *rt,
                                        size_t argc,
                                        const js_value_t *argv,
                                        void *user_data,
                                        js_value_t *out,
                                        char **error_message)
{
    return js_date_proto_set_milliseconds(rt, argc, argv, user_data, out, error_message);
}

bool js_date_proto_get_year(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    if (!date || js_is_nan(date->time_ms))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    js_date_parts_t parts;
    if (!js_date_breakdown(date->time_ms, &parts))
    {
        *out = js_value_make_number(js_nan());
        return true;
    }
    *out = js_value_make_number((double)(parts.year - 1900));
    return true;
}

bool js_date_proto_set_year(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_date_t *date = NULL;
    if (!js_date_require_object(this_val, &date, error_message))
    {
        return false;
    }
    double t = date->time_ms;
    bool t_is_nan = js_is_nan(t);
    double year_num = js_nan();
    if (!js_date_to_number(rt, (argc > 1) ? &argv[1] : NULL, &year_num, error_message))
    {
        return false;
    }
    double base_time = t_is_nan ? 0.0 : t;
    js_date_parts_t parts;
    if (!js_date_breakdown(base_time, &parts))
    {
        parts.year = 1970;
        parts.month = 1;
        parts.day = 1;
        parts.hour = 0;
        parts.minute = 0;
        parts.second = 0;
        parts.millisecond = 0;
    }
    if (js_is_nan(year_num))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    int64_t year_int = 0;
    if (!js_date_double_to_int64(year_num, &year_int))
    {
        date->time_ms = js_nan();
        *out = js_value_make_number(js_nan());
        return true;
    }
    if (year_int >= 0 && year_int <= 99)
    {
        year_int += 1900;
    }
    double new_time = js_date_make_time_value(year_int,
                                              (int64_t)(parts.month - 1),
                                              parts.day,
                                              parts.hour,
                                              parts.minute,
                                              parts.second,
                                              parts.millisecond);
    new_time = js_date_time_clip(new_time);
    date->time_ms = new_time;
    *out = js_value_make_number(new_time);
    return true;
}

static bool js_temporal_duration_get(js_runtime_t *rt,
                                     void *user_data,
                                     const char *name,
                                     js_value_t *out,
                                     char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_duration_proto_get(js_runtime_t *rt,
                                           void *user_data,
                                           const char *name,
                                           js_value_t *out,
                                           char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_instant_get(js_runtime_t *rt,
                                    void *user_data,
                                    const char *name,
                                    js_value_t *out,
                                    char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_instant_proto_get(js_runtime_t *rt,
                                          void *user_data,
                                          const char *name,
                                          js_value_t *out,
                                          char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_date_get(js_runtime_t *rt,
                                       void *user_data,
                                       const char *name,
                                       js_value_t *out,
                                       char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_date_proto_get(js_runtime_t *rt,
                                             void *user_data,
                                             const char *name,
                                             js_value_t *out,
                                             char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_time_get(js_runtime_t *rt,
                                       void *user_data,
                                       const char *name,
                                       js_value_t *out,
                                       char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_time_proto_get(js_runtime_t *rt,
                                             void *user_data,
                                             const char *name,
                                             js_value_t *out,
                                             char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_date_time_get(js_runtime_t *rt,
                                            void *user_data,
                                            const char *name,
                                            js_value_t *out,
                                            char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_date_time_proto_get(js_runtime_t *rt,
                                                  void *user_data,
                                                  const char *name,
                                                  js_value_t *out,
                                                  char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_zoned_date_time_get(js_runtime_t *rt,
                                            void *user_data,
                                            const char *name,
                                            js_value_t *out,
                                            char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_zoned_date_time_proto_get(js_runtime_t *rt,
                                                  void *user_data,
                                                  const char *name,
                                                  js_value_t *out,
                                                  char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_year_month_get(js_runtime_t *rt,
                                             void *user_data,
                                             const char *name,
                                             js_value_t *out,
                                             char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_year_month_proto_get(js_runtime_t *rt,
                                                   void *user_data,
                                                   const char *name,
                                                   js_value_t *out,
                                                   char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_month_day_get(js_runtime_t *rt,
                                            void *user_data,
                                            const char *name,
                                            js_value_t *out,
                                            char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_plain_month_day_proto_get(js_runtime_t *rt,
                                                  void *user_data,
                                                  const char *name,
                                                  js_value_t *out,
                                                  char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_now_get(js_runtime_t *rt,
                                void *user_data,
                                const char *name,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_temporal_require_duration(const js_value_t *this_val,
                                         js_temporal_duration_t **out,
                                         char **error_message)
{
    if (!out)
    {
        return false;
    }
    *out = NULL;
    if (!this_val || this_val->type != JS_VALUE_OBJECT || !this_val->as.object ||
        this_val->as.object->get_fn != js_temporal_duration_get)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.Duration method called on non-Temporal.Duration object");
        }
        return false;
    }
    js_temporal_duration_t *duration = (js_temporal_duration_t *)this_val->as.object->user_data;
    if (!duration)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid Temporal.Duration object");
        }
        return false;
    }
    *out = duration;
    return true;
}

static bool js_temporal_require_instant(const js_value_t *this_val,
                                        js_temporal_instant_t **out,
                                        char **error_message)
{
    if (!out)
    {
        return false;
    }
    *out = NULL;
    if (!this_val || this_val->type != JS_VALUE_OBJECT || !this_val->as.object ||
        this_val->as.object->get_fn != js_temporal_instant_get)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.Instant method called on non-Temporal.Instant object");
        }
        return false;
    }
    js_temporal_instant_t *instant = (js_temporal_instant_t *)this_val->as.object->user_data;
    if (!instant || !instant->epoch_nanoseconds)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid Temporal.Instant object");
        }
        return false;
    }
    *out = instant;
    return true;
}

static int64_t js_temporal_int64_abs(int64_t value)
{
    return (value < 0) ? -value : value;
}

static bool js_temporal_duration_is_zero(const js_temporal_duration_t *duration)
{
    if (!duration)
    {
        return true;
    }
    return duration->years == 0 &&
           duration->months == 0 &&
           duration->weeks == 0 &&
           duration->days == 0 &&
           duration->hours == 0 &&
           duration->minutes == 0 &&
           duration->seconds == 0 &&
           duration->milliseconds == 0 &&
           duration->microseconds == 0 &&
           duration->nanoseconds == 0;
}

static int js_temporal_duration_sign(const js_temporal_duration_t *duration)
{
    if (!duration || js_temporal_duration_is_zero(duration))
    {
        return 0;
    }
    if (duration->years > 0 ||
        duration->months > 0 ||
        duration->weeks > 0 ||
        duration->days > 0 ||
        duration->hours > 0 ||
        duration->minutes > 0 ||
        duration->seconds > 0 ||
        duration->milliseconds > 0 ||
        duration->microseconds > 0 ||
        duration->nanoseconds > 0)
    {
        return 1;
    }
    return -1;
}

static bool js_temporal_to_integer_if_integral(js_runtime_t *rt,
                                               const js_value_t *value,
                                               int64_t *out,
                                               char **error_message)
{
    if (!out)
    {
        return false;
    }
    *out = 0;
    if (!value || value->type == JS_VALUE_UNDEFINED)
    {
        return true;
    }
    if (value->type == JS_VALUE_OBJECT && value->as.object && js_object_is_symbol(value->as.object))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid Temporal value");
        }
        return false;
    }
    if (value->type == JS_VALUE_BIGINT)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid Temporal value");
        }
        return false;
    }
    const js_value_t *use = value;
    js_value_t prim = js_value_make_undefined_internal();
    if (value->type == JS_VALUE_OBJECT && value->as.object)
    {
        if (!js_object_to_primitive_number(rt, value->as.object, &prim, error_message))
        {
            return false;
        }
        use = &prim;
    }
    bool ok = true;
    double num = js_value_to_number(use, &ok);
    js_value_destroy(&prim);
    if (!ok || js_is_nan(num) || num == INFINITY || num == -INFINITY)
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal value");
        }
        return false;
    }
    double trunc = js_trunc_local(num);
    if (trunc != num)
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal value");
        }
        return false;
    }
    if (trunc > (double)INT64_MAX || trunc < (double)INT64_MIN)
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal value");
        }
        return false;
    }
    *out = (int64_t)trunc;
    return true;
}

static bool js_temporal_duration_create(js_runtime_t *rt,
                                        int64_t years,
                                        int64_t months,
                                        int64_t weeks,
                                        int64_t days,
                                        int64_t hours,
                                        int64_t minutes,
                                        int64_t seconds,
                                        int64_t milliseconds,
                                        int64_t microseconds,
                                        int64_t nanoseconds,
                                        js_value_t *out,
                                        char **error_message)
{
    if (!out)
    {
        return false;
    }
    js_temporal_duration_t *duration = (js_temporal_duration_t *)js_calloc(1, sizeof(*duration));
    if (!duration)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    duration->years = years;
    duration->months = months;
    duration->weeks = weeks;
    duration->days = days;
    duration->hours = hours;
    duration->minutes = minutes;
    duration->seconds = seconds;
    duration->milliseconds = milliseconds;
    duration->microseconds = microseconds;
    duration->nanoseconds = nanoseconds;
    if (!js_value_make_host_object(out, js_temporal_duration_get, NULL, js_temporal_duration_finalize, duration))
    {
        js_free(duration);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_temporal_duration_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

static bool js_temporal_instant_create(js_runtime_t *rt,
                                       js_bigint_t *epoch_nanoseconds,
                                       js_value_t *out,
                                       char **error_message)
{
    if (!out || !epoch_nanoseconds)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_temporal_instant_t *instant = (js_temporal_instant_t *)js_calloc(1, sizeof(*instant));
    if (!instant)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    instant->epoch_nanoseconds = epoch_nanoseconds;
    if (!js_value_make_host_object(out, js_temporal_instant_get, NULL, js_temporal_instant_finalize, instant))
    {
        js_temporal_instant_finalize(instant);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_temporal_instant_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

static bool js_temporal_instant_in_range(const js_bigint_t *value, char **error_message)
{
    if (!value)
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal instant");
        }
        return false;
    }
    js_value_t limit_val;
    if (!js_value_make_bigint(&limit_val, JS_TEMPORAL_INSTANT_MAX_NS, 10))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_t zero_val;
    if (!js_value_make_bigint_from_int64(&zero_val, 0))
    {
        js_value_destroy(&limit_val);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_bigint_t *neg_limit = js_bigint_sub(zero_val.as.bigint, limit_val.as.bigint);
    if (!neg_limit)
    {
        js_value_destroy(&limit_val);
        js_value_destroy(&zero_val);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    int cmp_high = js_bigint_compare(value, limit_val.as.bigint);
    int cmp_low = js_bigint_compare(value, neg_limit);
    js_bigint_destroy(neg_limit);
    js_value_destroy(&limit_val);
    js_value_destroy(&zero_val);
    if (cmp_high > 0 || cmp_low < 0)
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal instant");
        }
        return false;
    }
    return true;
}

bool js_builtin_temporal_duration(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool constructing = rt && rt->constructing && rt->constructing_fn == js_builtin_temporal_duration;
    if (!constructing)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.Duration must be called with new");
        }
        return false;
    }
    int64_t years = 0;
    int64_t months = 0;
    int64_t weeks = 0;
    int64_t days = 0;
    int64_t hours = 0;
    int64_t minutes = 0;
    int64_t seconds = 0;
    int64_t milliseconds = 0;
    int64_t microseconds = 0;
    int64_t nanoseconds = 0;
    if (argc > 0 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[0], &years, error_message))
        {
            return false;
        }
    }
    if (argc > 1 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[1], &months, error_message))
        {
            return false;
        }
    }
    if (argc > 2 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[2], &weeks, error_message))
        {
            return false;
        }
    }
    if (argc > 3 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[3], &days, error_message))
        {
            return false;
        }
    }
    if (argc > 4 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[4], &hours, error_message))
        {
            return false;
        }
    }
    if (argc > 5 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[5], &minutes, error_message))
        {
            return false;
        }
    }
    if (argc > 6 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[6], &seconds, error_message))
        {
            return false;
        }
    }
    if (argc > 7 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[7], &milliseconds, error_message))
        {
            return false;
        }
    }
    if (argc > 8 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[8], &microseconds, error_message))
        {
            return false;
        }
    }
    if (argc > 9 && argv)
    {
        if (!js_temporal_to_integer_if_integral(rt, &argv[9], &nanoseconds, error_message))
        {
            return false;
        }
    }
    bool has_pos = false;
    bool has_neg = false;
    int64_t fields[10] =
    {
        years, months, weeks, days, hours, minutes, seconds, milliseconds, microseconds, nanoseconds
    };
    for (size_t i = 0; i < 10; ++i)
    {
        if (fields[i] > 0)
        {
            has_pos = true;
        }
        else if (fields[i] < 0)
        {
            has_neg = true;
        }
    }
    if (has_pos && has_neg)
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal duration");
        }
        return false;
    }
    if (js_temporal_int64_abs(years) > JS_TEMPORAL_MAX_YMW ||
        js_temporal_int64_abs(months) > JS_TEMPORAL_MAX_YMW ||
        js_temporal_int64_abs(weeks) > JS_TEMPORAL_MAX_YMW ||
        js_temporal_int64_abs(days) > JS_TEMPORAL_MAX_YMW)
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal duration");
        }
        return false;
    }
    __int128 total_ns = 0;
    total_ns += (__int128)days * 86400LL * 1000000000LL;
    total_ns += (__int128)hours * 3600LL * 1000000000LL;
    total_ns += (__int128)minutes * 60LL * 1000000000LL;
    total_ns += (__int128)seconds * 1000000000LL;
    total_ns += (__int128)milliseconds * 1000000LL;
    total_ns += (__int128)microseconds * 1000LL;
    total_ns += (__int128)nanoseconds;
    if (total_ns > JS_TEMPORAL_MAX_TOTAL_NS || total_ns < -JS_TEMPORAL_MAX_TOTAL_NS)
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal duration");
        }
        return false;
    }
    return js_temporal_duration_create(rt,
                                       years,
                                       months,
                                       weeks,
                                       days,
                                       hours,
                                       minutes,
                                       seconds,
                                       milliseconds,
                                       microseconds,
                                       nanoseconds,
                                       out,
                                       error_message);
}

bool js_builtin_temporal_instant(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool constructing = rt && rt->constructing && rt->constructing_fn == js_builtin_temporal_instant;
    if (!constructing)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.Instant must be called with new");
        }
        return false;
    }
    if (argc == 0 || !argv)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.Instant requires a value");
        }
        return false;
    }
    if (argv[0].type != JS_VALUE_BIGINT)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.Instant requires a BigInt");
        }
        return false;
    }
    js_bigint_t *epoch_ns = js_bigint_clone(argv[0].as.bigint);
    if (!epoch_ns)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_temporal_instant_in_range(epoch_ns, error_message))
    {
        js_bigint_destroy(epoch_ns);
        return false;
    }
    return js_temporal_instant_create(rt, epoch_ns, out, error_message);
}

bool js_temporal_duration_getter(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_temporal_duration_t *duration = NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    const char *field = (const char *)user_data;
    if (field == JS_TEMPORAL_DURATION_FIELD_SIGN)
    {
        *out = js_value_make_number((double)js_temporal_duration_sign(duration));
        return true;
    }
    if (field == JS_TEMPORAL_DURATION_FIELD_BLANK)
    {
        *out = js_value_make_bool(js_temporal_duration_is_zero(duration));
        return true;
    }
    int64_t value = 0;
    if (field == JS_TEMPORAL_DURATION_FIELD_YEARS)
    {
        value = duration->years;
    }
    else if (field == JS_TEMPORAL_DURATION_FIELD_MONTHS)
    {
        value = duration->months;
    }
    else if (field == JS_TEMPORAL_DURATION_FIELD_WEEKS)
    {
        value = duration->weeks;
    }
    else if (field == JS_TEMPORAL_DURATION_FIELD_DAYS)
    {
        value = duration->days;
    }
    else if (field == JS_TEMPORAL_DURATION_FIELD_HOURS)
    {
        value = duration->hours;
    }
    else if (field == JS_TEMPORAL_DURATION_FIELD_MINUTES)
    {
        value = duration->minutes;
    }
    else if (field == JS_TEMPORAL_DURATION_FIELD_SECONDS)
    {
        value = duration->seconds;
    }
    else if (field == JS_TEMPORAL_DURATION_FIELD_MILLISECONDS)
    {
        value = duration->milliseconds;
    }
    else if (field == JS_TEMPORAL_DURATION_FIELD_MICROSECONDS)
    {
        value = duration->microseconds;
    }
    else if (field == JS_TEMPORAL_DURATION_FIELD_NANOSECONDS)
    {
        value = duration->nanoseconds;
    }
    *out = js_value_make_number((double)value);
    return true;
}

bool js_temporal_duration_negated(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_temporal_duration_t *duration = NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    return js_temporal_duration_create(rt,
                                       -duration->years,
                                       -duration->months,
                                       -duration->weeks,
                                       -duration->days,
                                       -duration->hours,
                                       -duration->minutes,
                                       -duration->seconds,
                                       -duration->milliseconds,
                                       -duration->microseconds,
                                       -duration->nanoseconds,
                                       out,
                                       error_message);
}

bool js_temporal_duration_abs(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_temporal_duration_t *duration = NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    return js_temporal_duration_create(rt,
                                       js_temporal_int64_abs(duration->years),
                                       js_temporal_int64_abs(duration->months),
                                       js_temporal_int64_abs(duration->weeks),
                                       js_temporal_int64_abs(duration->days),
                                       js_temporal_int64_abs(duration->hours),
                                       js_temporal_int64_abs(duration->minutes),
                                       js_temporal_int64_abs(duration->seconds),
                                       js_temporal_int64_abs(duration->milliseconds),
                                       js_temporal_int64_abs(duration->microseconds),
                                       js_temporal_int64_abs(duration->nanoseconds),
                                       out,
                                       error_message);
}

bool js_temporal_duration_to_string(js_runtime_t *rt,
                                    size_t argc,
                                    const js_value_t *argv,
                                    void *user_data,
                                    js_value_t *out,
                                    char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_temporal_duration_t *duration = NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    if (js_temporal_duration_is_zero(duration))
    {
        return js_value_make_cstring(out, "PT0S");
    }
    int sign = js_temporal_duration_sign(duration);
    int64_t years = js_temporal_int64_abs(duration->years);
    int64_t months = js_temporal_int64_abs(duration->months);
    int64_t weeks = js_temporal_int64_abs(duration->weeks);
    int64_t days = js_temporal_int64_abs(duration->days);
    int64_t hours = js_temporal_int64_abs(duration->hours);
    int64_t minutes = js_temporal_int64_abs(duration->minutes);
    int64_t seconds = js_temporal_int64_abs(duration->seconds);
    int64_t milliseconds = js_temporal_int64_abs(duration->milliseconds);
    int64_t microseconds = js_temporal_int64_abs(duration->microseconds);
    int64_t nanoseconds = js_temporal_int64_abs(duration->nanoseconds);
    bool has_time = hours || minutes || seconds || milliseconds || microseconds || nanoseconds;
    size_t cap = 512;
    char *buf = (char *)js_malloc(cap);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    size_t pos = 0;
    if (sign < 0)
    {
        buf[pos++] = '-';
    }
    buf[pos++] = 'P';
#define JS_APPEND_FMT(fmt, ...)                                                         \
    do                                                                                  \
    {                                                                                   \
        int written = snprintf(buf + pos, cap - pos, fmt, __VA_ARGS__);                 \
        if (written < 0 || (size_t)written >= cap - pos)                                \
        {                                                                               \
            js_free(buf);                                                                  \
            if (error_message)                                                          \
            {                                                                           \
                *error_message = js_strdup("allocation failed");                        \
            }                                                                           \
            return false;                                                               \
        }                                                                               \
        pos += (size_t)written;                                                         \
    } while (0)
    if (years)
    {
        JS_APPEND_FMT("%lldY", (long long)years);
    }
    if (months)
    {
        JS_APPEND_FMT("%lldM", (long long)months);
    }
    if (weeks)
    {
        JS_APPEND_FMT("%lldW", (long long)weeks);
    }
    if (days)
    {
        JS_APPEND_FMT("%lldD", (long long)days);
    }
    if (has_time)
    {
        buf[pos++] = 'T';
        if (hours)
        {
            JS_APPEND_FMT("%lldH", (long long)hours);
        }
        if (minutes)
        {
            JS_APPEND_FMT("%lldM", (long long)minutes);
        }
        int64_t frac_ns = milliseconds * 1000000LL + microseconds * 1000LL + nanoseconds;
        if (seconds || frac_ns)
        {
            if (frac_ns)
            {
                char frac_buf[16];
                (void)snprintf(frac_buf, sizeof(frac_buf), "%09lld", (long long)frac_ns);
                size_t frac_len = 9;
                while (frac_len > 0 && frac_buf[frac_len - 1] == '0')
                {
                    frac_len--;
                }
                JS_APPEND_FMT("%lld", (long long)seconds);
                if (frac_len > 0)
                {
                    if (pos + 1 + frac_len >= cap)
                    {
                        js_free(buf);
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        return false;
                    }
                    buf[pos++] = '.';
                    memcpy(buf + pos, frac_buf, frac_len);
                    pos += frac_len;
                }
                if (pos + 1 >= cap)
                {
                    js_free(buf);
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    return false;
                }
                buf[pos++] = 'S';
            }
            else
            {
                JS_APPEND_FMT("%lldS", (long long)seconds);
            }
        }
    }
#undef JS_APPEND_FMT
    bool ok = js_value_make_string(out, buf, pos);
    js_free(buf);
    return ok;
}

bool js_temporal_duration_to_json(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    return js_temporal_duration_to_string(rt, argc, argv, user_data, out, error_message);
}

bool js_temporal_duration_to_locale_string(js_runtime_t *rt,
                                           size_t argc,
                                           const js_value_t *argv,
                                           void *user_data,
                                           js_value_t *out,
                                           char **error_message)
{
    return js_temporal_duration_to_string(rt, argc, argv, user_data, out, error_message);
}

bool js_temporal_duration_value_of(js_runtime_t *rt,
                                   size_t argc,
                                   const js_value_t *argv,
                                   void *user_data,
                                   js_value_t *out,
                                   char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_duration_t *duration = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Duration.prototype.valueOf is not supported");
    }
    return false;
}

bool js_temporal_duration_with(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_duration_t *duration = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Duration.prototype.with not implemented");
    }
    return false;
}

bool js_temporal_duration_add(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_duration_t *duration = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Duration.prototype.add not implemented");
    }
    return false;
}

bool js_temporal_duration_subtract(js_runtime_t *rt,
                                   size_t argc,
                                   const js_value_t *argv,
                                   void *user_data,
                                   js_value_t *out,
                                   char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_duration_t *duration = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Duration.prototype.subtract not implemented");
    }
    return false;
}

bool js_temporal_duration_round(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_duration_t *duration = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Duration.prototype.round not implemented");
    }
    return false;
}

bool js_temporal_duration_total(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_duration_t *duration = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_duration(this_val, &duration, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Duration.prototype.total not implemented");
    }
    return false;
}

bool js_temporal_instant_getter(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_temporal_instant_t *instant = NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    const char *field = (const char *)user_data;
    if (field == JS_TEMPORAL_INSTANT_FIELD_EPOCH_NANOSECONDS)
    {
        out->type = JS_VALUE_BIGINT;
        out->as.bigint = js_bigint_clone(instant->epoch_nanoseconds);
        if (!out->as.bigint)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        return true;
    }
    if (field == JS_TEMPORAL_INSTANT_FIELD_EPOCH_MILLISECONDS)
    {
        js_value_t divisor;
        if (!js_value_make_bigint_from_int64(&divisor, 1000000))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        js_bigint_t *quot = NULL;
        js_bigint_t *rem = NULL;
        char *err = NULL;
        bool ok = js_bigint_divmod(instant->epoch_nanoseconds,
                                   divisor.as.bigint,
                                   &quot,
                                   &rem,
                                   &err);
        js_value_destroy(&divisor);
        if (!ok)
        {
            js_bigint_destroy(quot);
            js_bigint_destroy(rem);
            if (error_message)
            {
                *error_message = err ? err : js_strdup("RangeError: invalid Temporal instant");
            }
            else
            {
                js_free(err);
            }
            return false;
        }
        double ms = js_bigint_to_double(quot);
        js_bigint_destroy(quot);
        js_bigint_destroy(rem);
        *out = js_value_make_number(ms);
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

bool js_temporal_instant_to_string(js_runtime_t *rt,
                                   size_t argc,
                                   const js_value_t *argv,
                                   void *user_data,
                                   js_value_t *out,
                                   char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    js_temporal_instant_t *instant = NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    js_value_t divisor;
    if (!js_value_make_bigint_from_int64(&divisor, 1000000))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_bigint_t *quot = NULL;
    js_bigint_t *rem = NULL;
    char *err = NULL;
    bool ok = js_bigint_divmod(instant->epoch_nanoseconds,
                               divisor.as.bigint,
                               &quot,
                               &rem,
                               &err);
    js_value_destroy(&divisor);
    if (!ok)
    {
        if (error_message)
        {
            *error_message = err ? err : js_strdup("RangeError: invalid Temporal instant");
        }
        else
        {
            js_free(err);
        }
        js_bigint_destroy(quot);
        js_bigint_destroy(rem);
        return false;
    }
    int64_t rem_ns = (int64_t)js_bigint_to_double(rem);
    double ms = js_bigint_to_double(quot);
    if (rem_ns < 0)
    {
        rem_ns += 1000000;
        ms -= 1.0;
    }
    js_bigint_destroy(quot);
    js_bigint_destroy(rem);
    js_date_parts_t parts;
    if (!js_date_breakdown(ms, &parts))
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal instant");
        }
        return false;
    }
    int64_t frac_ns = (int64_t)parts.millisecond * 1000000LL + rem_ns;
    char year_buf[32];
    js_date_format_iso_year(parts.year, year_buf, sizeof(year_buf));
    size_t cap = 256;
    char *buf = (char *)js_malloc(cap);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    int len = snprintf(buf,
                       cap,
                       "%s-%02d-%02dT%02d:%02d:%02d",
                       year_buf,
                       parts.month,
                       parts.day,
                       parts.hour,
                       parts.minute,
                       parts.second);
    if (len < 0 || (size_t)len >= cap)
    {
        js_free(buf);
        return false;
    }
    size_t pos = (size_t)len;
    if (frac_ns > 0)
    {
        char frac_buf[16];
        (void)snprintf(frac_buf, sizeof(frac_buf), "%09lld", (long long)frac_ns);
        size_t frac_len = 9;
        while (frac_len > 0 && frac_buf[frac_len - 1] == '0')
        {
            frac_len--;
        }
        if (pos + 1 + frac_len >= cap)
        {
            js_free(buf);
            return false;
        }
        buf[pos++] = '.';
        memcpy(buf + pos, frac_buf, frac_len);
        pos += frac_len;
    }
    if (pos + 1 >= cap)
    {
        js_free(buf);
        return false;
    }
    buf[pos++] = 'Z';
    ok = js_value_make_string(out, buf, pos);
    js_free(buf);
    return ok;
}

bool js_temporal_instant_to_json(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    return js_temporal_instant_to_string(rt, argc, argv, user_data, out, error_message);
}

bool js_temporal_instant_to_locale_string(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message)
{
    return js_temporal_instant_to_string(rt, argc, argv, user_data, out, error_message);
}

bool js_temporal_instant_value_of(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_instant_t *instant = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Instant.prototype.valueOf is not supported");
    }
    return false;
}

bool js_temporal_instant_add(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_instant_t *instant = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Instant.prototype.add not implemented");
    }
    return false;
}

bool js_temporal_instant_subtract(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_instant_t *instant = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Instant.prototype.subtract not implemented");
    }
    return false;
}

bool js_temporal_instant_since(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_instant_t *instant = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Instant.prototype.since not implemented");
    }
    return false;
}

bool js_temporal_instant_until(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_instant_t *instant = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Instant.prototype.until not implemented");
    }
    return false;
}

bool js_temporal_instant_round(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_instant_t *instant = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Instant.prototype.round not implemented");
    }
    return false;
}

bool js_temporal_instant_equals(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_instant_t *instant = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    const js_value_t *other_val = (argc > 1 && argv) ? &argv[1] : NULL;
    if (!other_val || other_val->type != JS_VALUE_OBJECT || !other_val->as.object ||
        other_val->as.object->get_fn != js_temporal_instant_get)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.Instant expected");
        }
        return false;
    }
    js_temporal_instant_t *other = (js_temporal_instant_t *)other_val->as.object->user_data;
    if (!other || !other->epoch_nanoseconds)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.Instant expected");
        }
        return false;
    }
    int cmp = js_bigint_compare(instant->epoch_nanoseconds, other->epoch_nanoseconds);
    *out = js_value_make_bool(cmp == 0);
    return true;
}

bool js_temporal_instant_to_zoned_date_time_iso(js_runtime_t *rt,
                                                size_t argc,
                                                const js_value_t *argv,
                                                void *user_data,
                                                js_value_t *out,
                                                char **error_message)
{
    (void)rt;
    (void)argv;
    (void)argc;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temporal_instant_t *instant = NULL;
    const js_value_t *this_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temporal_require_instant(this_val, &instant, error_message))
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Instant.prototype.toZonedDateTimeISO not implemented");
    }
    return false;
}

bool js_temporal_now_instant(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    double now_ms = js_date_now_ms();
    if (js_is_nan(now_ms))
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: invalid Temporal instant");
        }
        return false;
    }
    int64_t ms_int = (int64_t)js_date_trunc(now_ms);
    int64_t ns_int = ms_int * 1000000LL;
    js_value_t tmp;
    if (!js_value_make_bigint_from_int64(&tmp, ns_int))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_bigint_t *epoch_ns = js_bigint_clone(tmp.as.bigint);
    js_value_destroy(&tmp);
    if (!epoch_ns)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_temporal_instant_in_range(epoch_ns, error_message))
    {
        js_bigint_destroy(epoch_ns);
        return false;
    }
    return js_temporal_instant_create(rt, epoch_ns, out, error_message);
}

bool js_temporal_now_plain_date_iso(js_runtime_t *rt,
                                    size_t argc,
                                    const js_value_t *argv,
                                    void *user_data,
                                    js_value_t *out,
                                    char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Now.plainDateISO not implemented");
    }
    return false;
}

bool js_temporal_now_plain_time_iso(js_runtime_t *rt,
                                    size_t argc,
                                    const js_value_t *argv,
                                    void *user_data,
                                    js_value_t *out,
                                    char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Now.plainTimeISO not implemented");
    }
    return false;
}

bool js_temporal_now_plain_date_time_iso(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Now.plainDateTimeISO not implemented");
    }
    return false;
}

bool js_temporal_now_zoned_date_time_iso(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: Temporal.Now.zonedDateTimeISO not implemented");
    }
    return false;
}

bool js_temporal_now_time_zone_id(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    return js_value_make_cstring(out, "UTC");
}

bool js_builtin_temporal_plain_date(js_runtime_t *rt,
                                    size_t argc,
                                    const js_value_t *argv,
                                    void *user_data,
                                    js_value_t *out,
                                    char **error_message)
{
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool constructing = rt && rt->constructing && rt->constructing_fn == js_builtin_temporal_plain_date;
    if (!constructing)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.PlainDate must be called with new");
        }
        return false;
    }
    if (!js_value_make_host_object(out, js_temporal_plain_date_get, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_temporal_plain_date_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

bool js_builtin_temporal_plain_time(js_runtime_t *rt,
                                    size_t argc,
                                    const js_value_t *argv,
                                    void *user_data,
                                    js_value_t *out,
                                    char **error_message)
{
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool constructing = rt && rt->constructing && rt->constructing_fn == js_builtin_temporal_plain_time;
    if (!constructing)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.PlainTime must be called with new");
        }
        return false;
    }
    if (!js_value_make_host_object(out, js_temporal_plain_time_get, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_temporal_plain_time_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

bool js_builtin_temporal_plain_date_time(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool constructing = rt && rt->constructing && rt->constructing_fn == js_builtin_temporal_plain_date_time;
    if (!constructing)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.PlainDateTime must be called with new");
        }
        return false;
    }
    if (!js_value_make_host_object(out, js_temporal_plain_date_time_get, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_temporal_plain_date_time_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

bool js_builtin_temporal_zoned_date_time(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool constructing = rt && rt->constructing && rt->constructing_fn == js_builtin_temporal_zoned_date_time;
    if (!constructing)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.ZonedDateTime must be called with new");
        }
        return false;
    }
    if (!js_value_make_host_object(out, js_temporal_zoned_date_time_get, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_temporal_zoned_date_time_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

bool js_builtin_temporal_plain_year_month(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message)
{
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool constructing = rt && rt->constructing && rt->constructing_fn == js_builtin_temporal_plain_year_month;
    if (!constructing)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.PlainYearMonth must be called with new");
        }
        return false;
    }
    if (!js_value_make_host_object(out, js_temporal_plain_year_month_get, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_temporal_plain_year_month_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

bool js_builtin_temporal_plain_month_day(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    bool constructing = rt && rt->constructing && rt->constructing_fn == js_builtin_temporal_plain_month_day;
    if (!constructing)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Temporal.PlainMonthDay must be called with new");
        }
        return false;
    }
    if (!js_value_make_host_object(out, js_temporal_plain_month_day_get, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_object_t *proto = js_get_temporal_plain_month_day_proto(rt);
    if (proto)
    {
        js_value_t proto_val;
        memset(&proto_val, 0, sizeof(proto_val));
        proto_val.type = JS_VALUE_OBJECT;
        proto_val.as.object = proto;
        (void)js_object_set_slot(out->as.object, "__proto__", &proto_val);
    }
    return true;
}

typedef enum
{
    JS_PROMISE_PENDING = 0,
    JS_PROMISE_FULFILLED,
    JS_PROMISE_REJECTED
} js_promise_state_t;

typedef struct js_promise js_promise_t;
typedef struct js_promise_reaction js_promise_reaction_t;
typedef struct js_promise_task js_promise_task_t;

struct js_promise_reaction
{
    js_value_t on_fulfilled;
    js_value_t on_rejected;
    js_promise_t *next_promise;
    js_promise_reaction_t *next;
};

struct js_promise
{
    int refcount;
    js_promise_state_t state;
    js_value_t value;
    js_promise_reaction_t *reactions;
};

struct js_promise_task
{
    js_promise_state_t state;
    js_value_t value;
    js_value_t on_fulfilled;
    js_value_t on_rejected;
    js_promise_t *next_promise;
};

typedef struct
{
    int refcount;
    js_runtime_t *rt;
    js_promise_t *promise;
    js_value_t results;
    size_t remaining;
    bool done;
} js_promise_all_state_t;

typedef struct
{
    js_promise_all_state_t *state;
    size_t index;
} js_promise_all_entry_t;

static void js_promise_retain(js_promise_t *promise)
{
    if (!promise)
    {
        return;
    }
    promise->refcount++;
}

static void js_promise_release(js_promise_t *promise)
{
    if (!promise)
    {
        return;
    }
    if (promise->refcount <= 0)
    {
        return;
    }
    promise->refcount--;
    if (promise->refcount > 0)
    {
        return;
    }
    js_value_destroy(&promise->value);
    js_promise_reaction_t *reaction = promise->reactions;
    while (reaction)
    {
        js_promise_reaction_t *next = reaction->next;
        js_value_destroy(&reaction->on_fulfilled);
        js_value_destroy(&reaction->on_rejected);
        if (reaction->next_promise)
        {
            js_promise_release(reaction->next_promise);
        }
        js_free(reaction);
        reaction = next;
    }
    js_free(promise);
}

static void js_promise_finalize(void *user_data)
{
    js_promise_release((js_promise_t *)user_data);
}

static bool js_promise_is_callable(const js_value_t *value)
{
    if (!value)
    {
        return false;
    }
    return value->type == JS_VALUE_FUNCTION || value->type == JS_VALUE_NATIVE_FN;
}

static js_promise_t *js_promise_from_value(const js_value_t *value);
static bool js_promise_get(js_runtime_t *rt,
                           void *user_data,
                           const char *name,
                           js_value_t *out,
                           char **error_message);

static bool js_promise_task_run(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message);

static bool js_promise_schedule_reaction(js_runtime_t *rt,
                                         js_promise_t *promise,
                                         js_promise_reaction_t *reaction)
{
    if (!promise || !reaction)
    {
        return false;
    }
    js_promise_task_t *task = (js_promise_task_t *)js_calloc(1, sizeof(*task));
    if (!task)
    {
        return false;
    }
    task->state = promise->state;
    task->value = js_value_make_undefined_internal();
    task->on_fulfilled = js_value_make_undefined_internal();
    task->on_rejected = js_value_make_undefined_internal();
    if (!js_value_copy(&task->value, &promise->value) ||
        !js_value_copy(&task->on_fulfilled, &reaction->on_fulfilled) ||
        !js_value_copy(&task->on_rejected, &reaction->on_rejected))
    {
        js_value_destroy(&task->value);
        js_value_destroy(&task->on_fulfilled);
        js_value_destroy(&task->on_rejected);
        js_free(task);
        return false;
    }
    task->next_promise = reaction->next_promise;
    js_promise_retain(task->next_promise);

    js_value_t callback;
    memset(&callback, 0, sizeof(callback));
    callback.type = JS_VALUE_NATIVE_FN;
    callback.as.native.fn = js_promise_task_run;
    callback.as.native.user_data = task;
    if (!js_runtime_queue_microtask(rt, &callback, 0, NULL))
    {
        js_promise_release(task->next_promise);
        js_value_destroy(&task->value);
        js_value_destroy(&task->on_fulfilled);
        js_value_destroy(&task->on_rejected);
        js_free(task);
        return false;
    }
    return true;
}

static bool js_promise_settle(js_runtime_t *rt,
                              js_promise_t *promise,
                              js_promise_state_t state,
                              const js_value_t *value)
{
    if (!promise || promise->state != JS_PROMISE_PENDING)
    {
        return true;
    }
    promise->state = state;
    js_value_destroy(&promise->value);
    promise->value = js_value_make_undefined_internal();
    if (value && !js_value_copy(&promise->value, value))
    {
        return false;
    }
    js_promise_reaction_t *reaction = promise->reactions;
    promise->reactions = NULL;
    while (reaction)
    {
        js_promise_reaction_t *next = reaction->next;
        (void)js_promise_schedule_reaction(rt, promise, reaction);
        js_value_destroy(&reaction->on_fulfilled);
        js_value_destroy(&reaction->on_rejected);
        if (reaction->next_promise)
        {
            js_promise_release(reaction->next_promise);
        }
        js_free(reaction);
        reaction = next;
    }
    return true;
}

static bool js_promise_reject_value(js_runtime_t *rt,
                                    js_promise_t *promise,
                                    const js_value_t *value)
{
    return js_promise_settle(rt, promise, JS_PROMISE_REJECTED, value);
}

static bool js_promise_link(js_runtime_t *rt, js_promise_t *source, js_promise_t *target)
{
    if (!source || !target)
    {
        return false;
    }
    js_promise_reaction_t *reaction = (js_promise_reaction_t *)js_calloc(1, sizeof(*reaction));
    if (!reaction)
    {
        return false;
    }
    reaction->on_fulfilled = js_value_make_undefined_internal();
    reaction->on_rejected = js_value_make_undefined_internal();
    reaction->next_promise = target;
    js_promise_retain(target);
    if (source->state == JS_PROMISE_PENDING)
    {
        reaction->next = source->reactions;
        source->reactions = reaction;
        return true;
    }
    bool ok = js_promise_schedule_reaction(rt, source, reaction);
    js_value_destroy(&reaction->on_fulfilled);
    js_value_destroy(&reaction->on_rejected);
    js_promise_release(reaction->next_promise);
    js_free(reaction);
    return ok;
}

static bool js_promise_resolve_value(js_runtime_t *rt,
                                     js_promise_t *promise,
                                     const js_value_t *value)
{
    if (!promise || promise->state != JS_PROMISE_PENDING)
    {
        return true;
    }
    js_promise_t *other = js_promise_from_value(value);
    if (other)
    {
        if (other == promise)
        {
            js_value_t err;
            if (!js_value_make_cstring(&err, "TypeError: promise cycle"))
            {
                return false;
            }
            bool ok = js_promise_reject_value(rt, promise, &err);
            js_value_destroy(&err);
            return ok;
        }
        if (other->state == JS_PROMISE_PENDING)
        {
            return js_promise_link(rt, other, promise);
        }
        if (other->state == JS_PROMISE_FULFILLED)
        {
            return js_promise_settle(rt, promise, JS_PROMISE_FULFILLED, &other->value);
        }
        return js_promise_settle(rt, promise, JS_PROMISE_REJECTED, &other->value);
    }
    return js_promise_settle(rt, promise, JS_PROMISE_FULFILLED, value);
}

static js_promise_t *js_promise_from_value(const js_value_t *value)
{
    if (!value || value->type != JS_VALUE_OBJECT || !value->as.object)
    {
        return NULL;
    }
    if (value->as.object->get_fn != js_promise_get)
    {
        return NULL;
    }
    return (js_promise_t *)value->as.object->user_data;
}

static bool js_promise_create_value(js_runtime_t *rt, js_value_t *out, js_promise_t **promise_out)
{
    (void)rt;
    if (!out)
    {
        return false;
    }
    js_promise_t *promise = (js_promise_t *)js_calloc(1, sizeof(*promise));
    if (!promise)
    {
        return false;
    }
    promise->refcount = 1;
    promise->state = JS_PROMISE_PENDING;
    promise->value = js_value_make_undefined_internal();
    promise->reactions = NULL;
    if (!js_value_make_host_object(out, js_promise_get, NULL, js_promise_finalize, promise))
    {
        js_free(promise);
        return false;
    }
    if (promise_out)
    {
        *promise_out = promise;
    }
    return true;
}

static bool js_promise_task_run(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (out)
    {
        *out = js_value_make_undefined_internal();
    }
    js_promise_task_t *task = (js_promise_task_t *)user_data;
    if (!task)
    {
        return true;
    }
    js_value_t *handler = (task->state == JS_PROMISE_FULFILLED) ? &task->on_fulfilled : &task->on_rejected;
    bool handled = js_promise_is_callable(handler);
    if (!handled)
    {
        if (task->state == JS_PROMISE_FULFILLED)
        {
            (void)js_promise_resolve_value(rt, task->next_promise, &task->value);
        }
        else
        {
            (void)js_promise_reject_value(rt, task->next_promise, &task->value);
        }
    }
    else
    {
        js_value_t result = js_value_make_undefined_internal();
        char *err = NULL;
        bool ok = js_call_value(rt, handler, 1, &task->value, &result, &err);
        if (ok)
        {
            (void)js_promise_resolve_value(rt, task->next_promise, &result);
        }
        else
        {
            js_value_t err_val = js_value_make_undefined_internal();
            if (err && !js_value_make_cstring(&err_val, err))
            {
                js_value_destroy(&result);
                js_free(err);
                return false;
            }
            if (!err)
            {
                (void)js_value_make_cstring(&err_val, "promise rejection");
            }
            (void)js_promise_reject_value(rt, task->next_promise, &err_val);
            js_value_destroy(&err_val);
        }
        js_free(err);
        js_value_destroy(&result);
    }
    js_value_destroy(&task->value);
    js_value_destroy(&task->on_fulfilled);
    js_value_destroy(&task->on_rejected);
    js_promise_release(task->next_promise);
    js_free(task);
    return true;
}

static bool js_promise_then_impl(js_runtime_t *rt,
                                 js_promise_t *promise,
                                 const js_value_t *on_fulfilled,
                                 const js_value_t *on_rejected,
                                 js_value_t *out)
{
    if (!promise || !out)
    {
        return false;
    }
    js_value_t next_value = js_value_make_undefined_internal();
    js_promise_t *next_promise = NULL;
    if (!js_promise_create_value(rt, &next_value, &next_promise))
    {
        return false;
    }
    js_promise_reaction_t *reaction = (js_promise_reaction_t *)js_calloc(1, sizeof(*reaction));
    if (!reaction)
    {
        js_value_destroy(&next_value);
        return false;
    }
    reaction->on_fulfilled = js_value_make_undefined_internal();
    reaction->on_rejected = js_value_make_undefined_internal();
    if (on_fulfilled && js_promise_is_callable(on_fulfilled))
    {
        if (!js_value_copy(&reaction->on_fulfilled, on_fulfilled))
        {
            js_value_destroy(&next_value);
            js_free(reaction);
            return false;
        }
    }
    if (on_rejected && js_promise_is_callable(on_rejected))
    {
        if (!js_value_copy(&reaction->on_rejected, on_rejected))
        {
            js_value_destroy(&reaction->on_fulfilled);
            js_value_destroy(&next_value);
            js_free(reaction);
            return false;
        }
    }
    reaction->next_promise = next_promise;
    js_promise_retain(next_promise);
    if (promise->state == JS_PROMISE_PENDING)
    {
        reaction->next = promise->reactions;
        promise->reactions = reaction;
    }
    else
    {
        (void)js_promise_schedule_reaction(rt, promise, reaction);
        js_value_destroy(&reaction->on_fulfilled);
        js_value_destroy(&reaction->on_rejected);
        js_promise_release(reaction->next_promise);
        js_free(reaction);
    }
    *out = next_value;
    return true;
}

static bool js_promise_then(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_promise_t *promise = (js_promise_t *)user_data;
    size_t arg_start = 0;
    if (!promise && argc > 0)
    {
        promise = js_promise_from_value(&argv[0]);
        if (promise)
        {
            arg_start = 1;
        }
    }
    if (!promise)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    const js_value_t *on_fulfilled = (argc > arg_start) ? &argv[arg_start] : NULL;
    const js_value_t *on_rejected = (argc > arg_start + 1) ? &argv[arg_start + 1] : NULL;
    if (!js_promise_then_impl(rt, promise, on_fulfilled, on_rejected, out))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static bool js_promise_catch(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    return js_promise_then(rt, argc, argv, user_data, out, error_message);
}

static bool js_promise_finally(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    return js_promise_then(rt, argc, argv, user_data, out, error_message);
}

static bool js_promise_get(js_runtime_t *rt,
                           void *user_data,
                           const char *name,
                           js_value_t *out,
                           char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !name)
    {
        return false;
    }
    if (strcmp(name, "then") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_promise_then;
        out->as.native.user_data = user_data;
        return true;
    }
    if (strcmp(name, "catch") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_promise_catch;
        out->as.native.user_data = user_data;
        return true;
    }
    if (strcmp(name, "finally") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_promise_finally;
        out->as.native.user_data = user_data;
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

bool js_promise_await(js_runtime_t *rt,
                      const js_value_t *value,
                      js_value_t *out,
                      char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!value)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    js_promise_t *promise = js_promise_from_value(value);
    if (!promise)
    {
        return js_value_copy(out, value);
    }
    if (promise->state == JS_PROMISE_PENDING)
    {
        js_runtime_run_microtasks(rt);
    }
    if (promise->state == JS_PROMISE_PENDING)
    {
        return js_value_copy(out, value);
    }
    if (promise->state == JS_PROMISE_FULFILLED)
    {
        return js_value_copy(out, &promise->value);
    }
    js_temp_string_t temp = {0};
    char *err = NULL;
    if (!js_temp_string_from_value(rt, &promise->value, &temp, &err))
    {
        if (err)
        {
            if (error_message)
            {
                *error_message = err;
            }
            else
            {
                js_free(err);
            }
            return false;
        }
        if (error_message)
        {
            *error_message = js_strdup("promise rejected");
        }
        return false;
    }
    char *msg = js_strdup_len(temp.data ? temp.data : "", temp.len);
    js_temp_string_release(&temp);
    if (!msg)
    {
        if (error_message)
        {
            *error_message = js_strdup("promise rejected");
        }
        return false;
    }
    if (error_message)
    {
        *error_message = msg;
    }
    else
    {
        js_free(msg);
    }
    return false;
}

static bool js_promise_resolve_native(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    js_promise_t *promise = (js_promise_t *)user_data;
    if (!promise)
    {
        return true;
    }
    const js_value_t *value = (argc > 0) ? &argv[0] : NULL;
    (void)js_promise_resolve_value(rt, promise, value);
    return true;
}

static bool js_promise_reject_native(js_runtime_t *rt,
                                     size_t argc,
                                     const js_value_t *argv,
                                     void *user_data,
                                     js_value_t *out,
                                     char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    js_promise_t *promise = (js_promise_t *)user_data;
    if (!promise)
    {
        return true;
    }
    const js_value_t *value = (argc > 0) ? &argv[0] : NULL;
    (void)js_promise_reject_value(rt, promise, value);
    return true;
}

bool js_builtin_promise(js_runtime_t *rt,
                        size_t argc,
                        const js_value_t *argv,
                        void *user_data,
                        js_value_t *out,
                        char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_promise_t *promise = NULL;
    if (!js_promise_create_value(rt, out, &promise))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!argv || argc < 1 || !js_promise_is_callable(&argv[0]))
    {
        return true;
    }
    js_value_t resolve_fn;
    memset(&resolve_fn, 0, sizeof(resolve_fn));
    resolve_fn.type = JS_VALUE_NATIVE_FN;
    resolve_fn.as.native.fn = js_promise_resolve_native;
    resolve_fn.as.native.user_data = promise;
    js_value_t reject_fn;
    memset(&reject_fn, 0, sizeof(reject_fn));
    reject_fn.type = JS_VALUE_NATIVE_FN;
    reject_fn.as.native.fn = js_promise_reject_native;
    reject_fn.as.native.user_data = promise;
    js_value_t call_args[2] = { resolve_fn, reject_fn };
    js_value_t result = js_value_make_undefined_internal();
    char *err = NULL;
    bool ok = js_call_value(rt, &argv[0], 2, call_args, &result, &err);
    js_value_destroy(&result);
    if (!ok)
    {
        js_value_t err_val = js_value_make_undefined_internal();
        if (err && !js_value_make_cstring(&err_val, err))
        {
            js_free(err);
            return true;
        }
        if (!err)
        {
            (void)js_value_make_cstring(&err_val, "promise executor failed");
        }
        (void)js_promise_reject_value(rt, promise, &err_val);
        js_value_destroy(&err_val);
    }
    js_free(err);
    return true;
}

bool js_builtin_promise_resolve(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc > 0)
    {
        js_promise_t *existing = js_promise_from_value(&argv[0]);
        if (existing)
        {
            return js_value_copy(out, &argv[0]);
        }
    }
    js_promise_t *promise = NULL;
    if (!js_promise_create_value(rt, out, &promise))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    const js_value_t *value = (argc > 0) ? &argv[0] : NULL;
    (void)js_promise_resolve_value(rt, promise, value);
    return true;
}

bool js_builtin_promise_reject(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_promise_t *promise = NULL;
    if (!js_promise_create_value(rt, out, &promise))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    const js_value_t *value = (argc > 0) ? &argv[0] : NULL;
    (void)js_promise_reject_value(rt, promise, value);
    return true;
}

static void js_promise_all_state_retain(js_promise_all_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->refcount++;
}

static void js_promise_all_state_release(js_promise_all_state_t *state)
{
    if (!state || state->refcount <= 0)
    {
        return;
    }
    state->refcount--;
    if (state->refcount > 0)
    {
        return;
    }
    js_value_destroy(&state->results);
    if (state->promise)
    {
        js_promise_release(state->promise);
    }
    js_free(state);
}

static bool js_promise_all_fulfill(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (out)
    {
        *out = js_value_make_undefined_internal();
    }
    js_promise_all_entry_t *entry = (js_promise_all_entry_t *)user_data;
    if (!entry || !entry->state)
    {
        return true;
    }
    js_promise_all_state_t *state = entry->state;
    if (!state->done && state->results.type == JS_VALUE_ARRAY)
    {
        const js_value_t *value = (argc > 0) ? &argv[0] : NULL;
        if (value)
        {
            (void)js_value_array_set(&state->results, entry->index, value);
        }
        if (state->remaining > 0)
        {
            state->remaining--;
        }
        if (state->remaining == 0 && !state->done)
        {
            state->done = true;
            (void)js_promise_resolve_value(rt, state->promise, &state->results);
        }
    }
    js_promise_all_state_release(state);
    js_free(entry);
    return true;
}

static bool js_promise_all_reject(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (out)
    {
        *out = js_value_make_undefined_internal();
    }
    js_promise_all_state_t *state = (js_promise_all_state_t *)user_data;
    if (!state)
    {
        return true;
    }
    if (!state->done)
    {
        state->done = true;
        const js_value_t *value = (argc > 0) ? &argv[0] : NULL;
        (void)js_promise_reject_value(rt, state->promise, value);
    }
    js_promise_all_state_release(state);
    return true;
}

bool js_builtin_promise_all(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_promise_t *result_promise = NULL;
    if (!js_promise_create_value(rt, out, &result_promise))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!argv || argc < 1 || argv[0].type != JS_VALUE_ARRAY || !argv[0].as.array)
    {
        js_value_t empty;
        if (!js_value_make_array(&empty))
        {
            return true;
        }
        (void)js_promise_resolve_value(rt, result_promise, &empty);
        js_value_destroy(&empty);
        return true;
    }
    size_t length = argv[0].as.array->length;
    js_value_t results;
    if (!js_value_make_array(&results))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (length == 0)
    {
        (void)js_promise_resolve_value(rt, result_promise, &results);
        js_value_destroy(&results);
        return true;
    }
    js_promise_all_state_t *state = (js_promise_all_state_t *)js_calloc(1, sizeof(*state));
    if (!state)
    {
        js_value_destroy(&results);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    state->refcount = 1;
    state->rt = rt;
    state->promise = result_promise;
    js_promise_retain(result_promise);
    state->results = results;
    state->remaining = length;
    state->done = false;

    for (size_t i = 0; i < length; ++i)
    {
        js_value_t item = js_value_make_undefined_internal();
        if (!js_array_get(argv[0].as.array, i, &item))
        {
            continue;
        }
        js_promise_t *item_promise = js_promise_from_value(&item);
        if (item_promise)
        {
            js_promise_all_entry_t *entry = (js_promise_all_entry_t *)js_calloc(1, sizeof(*entry));
            if (!entry)
            {
                js_value_destroy(&item);
                continue;
            }
            entry->state = state;
            entry->index = i;
            js_promise_all_state_retain(state);

            js_value_t on_fulfilled;
            memset(&on_fulfilled, 0, sizeof(on_fulfilled));
            on_fulfilled.type = JS_VALUE_NATIVE_FN;
            on_fulfilled.as.native.fn = js_promise_all_fulfill;
            on_fulfilled.as.native.user_data = entry;

            js_value_t on_rejected;
            memset(&on_rejected, 0, sizeof(on_rejected));
            on_rejected.type = JS_VALUE_NATIVE_FN;
            on_rejected.as.native.fn = js_promise_all_reject;
            on_rejected.as.native.user_data = state;
            js_promise_all_state_retain(state);

            js_value_t chained = js_value_make_undefined_internal();
            (void)js_promise_then_impl(rt, item_promise, &on_fulfilled, &on_rejected, &chained);
            js_value_destroy(&chained);
        }
        else
        {
            (void)js_value_array_set(&state->results, i, &item);
            if (state->remaining > 0)
            {
                state->remaining--;
            }
        }
        js_value_destroy(&item);
    }
    if (state->remaining == 0 && !state->done)
    {
        state->done = true;
        (void)js_promise_resolve_value(rt, result_promise, &state->results);
    }
    js_promise_all_state_release(state);
    return true;
}

bool js_builtin_queue_microtask(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined_internal();
    if (argc < 1 || !argv || !js_promise_is_callable(&argv[0]))
    {
        return true;
    }
    (void)js_runtime_queue_microtask(rt, &argv[0], 0, NULL);
    return true;
}

void js_release_bound_functions(js_runtime_t *rt)
{
    if (!rt)
    {
        return;
    }
    js_bound_fn_t *bound = rt->bound_functions;
    while (bound)
    {
        js_bound_fn_t *next = bound->next;
        js_bound_fn_release(bound);
        bound = next;
    }
    rt->bound_functions = NULL;
}
