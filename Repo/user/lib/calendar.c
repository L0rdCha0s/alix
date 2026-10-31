#include "time.h"
#include "errno.h"
#include "limits.h"
#include "stdint.h"
#include "string.h"

/* Signed, proleptic Gregorian UTC conversion. No current-zone offset is used
 * here: localtime/mktime require transition-aware timezone state separately. */
static int64_t calendar_floor_div(int64_t value, int64_t divisor)
{
    int64_t quotient = value / divisor;
    return quotient - (value % divisor < 0);
}

static int calendar_leap(int64_t year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int64_t calendar_year_start(int64_t year)
{
    int64_t previous = year - 1;
    return 365 * (year - 1970) + calendar_floor_div(previous, 4) - 492
           - calendar_floor_div(previous, 100) + 19
           + calendar_floor_div(previous, 400) - 4;
}

static int calendar_breakdown(time_t value, struct tm *result)
{
    static char utc_name[] = "UTC";
    static const unsigned short month_start[12] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    int64_t days = calendar_floor_div(value, 86400);
    if (days < calendar_year_start((int64_t)INT_MIN + 1900) ||
        days >= calendar_year_start((int64_t)INT_MAX + 1901))
    {
        errno = EOVERFLOW;
        return 0;
    }

    /* A March-based 400-year era has 146097 days. Leap days then occur at
     * the end of the year, allowing bounded arithmetic for negative dates. */
    int64_t shifted = days + 719468;
    int64_t era = calendar_floor_div(shifted, 146097);
    unsigned day_of_era = (unsigned)(shifted - era * 146097);
    unsigned year_of_era = (day_of_era - day_of_era / 1460 +
                            day_of_era / 36524 - day_of_era / 146096) / 365;
    unsigned march_day = day_of_era -
                          (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    unsigned march_month = (5 * march_day + 2) / 153;
    unsigned day = march_day - (153 * march_month + 2) / 5 + 1;
    int month = (int)march_month + (march_month < 10 ? 3 : -9);
    int64_t year = era * 400 + year_of_era + (month <= 2);
    int64_t seconds = value % 86400;
    if (seconds < 0) seconds += 86400;
    int weekday = (int)((days + 4) % 7);
    if (weekday < 0) weekday += 7;

    struct tm converted = {0};
    converted.tm_year = (int)(year - 1900);
    converted.tm_mon = month - 1;
    converted.tm_mday = (int)day;
    converted.tm_hour = (int)(seconds / 3600);
    converted.tm_min = (int)(seconds / 60 % 60);
    converted.tm_sec = (int)(seconds % 60);
    converted.tm_wday = weekday;
    converted.tm_yday = month_start[month - 1] + (int)day - 1 +
                        (month > 2 && calendar_leap(year));
    converted.tm_isdst = 0;
    converted.tm_gmtoff = 0;
    converted.tm_zone = utc_name;
    *result = converted;
    return 1;
}

struct tm *gmtime_r(const time_t *value, struct tm *result)
{
    if (!value || !result)
    {
        errno = EINVAL;
        return NULL;
    }
    return calendar_breakdown(*value, result) ? result : NULL;
}

struct tm *gmtime(const time_t *value)
{
    static _Thread_local struct tm result;
    return gmtime_r(value, &result);
}

time_t timegm(struct tm *value)
{
    static const unsigned short month_start[12] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    if (!value)
    {
        errno = EINVAL;
        return (time_t)-1;
    }
    int64_t month_eras = calendar_floor_div(value->tm_mon, 12);
    int month = (int)((int64_t)value->tm_mon - month_eras * 12);
    int64_t year = (int64_t)value->tm_year + 1900 + month_eras;
    int64_t days = calendar_year_start(year) + month_start[month] +
                   (month >= 2 && calendar_leap(year)) + (int64_t)value->tm_mday - 1;
    /* All source fields are int; their normalized sum fits signed time_t even
     * at the int extrema. Breakdown checks whether tm_year can represent it. */
    time_t result = days * 86400 + (int64_t)value->tm_hour * 3600 +
                    (int64_t)value->tm_min * 60 + value->tm_sec;
    struct tm normalized;
    if (!calendar_breakdown(result, &normalized)) return (time_t)-1;
    *value = normalized;
    return result;
}

static void calendar_two_digits(char *output, int value)
{
    output[0] = (char)('0' + value / 10);
    output[1] = (char)('0' + value % 10);
}

char *asctime_r(const struct tm *value, char *output)
{
    static const char weekdays[] = "SunMonTueWedThuFriSat";
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    if (!value || !output || value->tm_wday < 0 || value->tm_wday > 6 ||
        value->tm_mon < 0 || value->tm_mon > 11 || value->tm_mday < 1 ||
        value->tm_mday > 31 || value->tm_hour < 0 || value->tm_hour > 23 ||
        value->tm_min < 0 || value->tm_min > 59 || value->tm_sec < 0 || value->tm_sec > 60)
    {
        errno = EINVAL;
        return NULL;
    }
    int64_t year = (int64_t)value->tm_year + 1900;
    if (year < 0 || year > 9999)
    {
        errno = EOVERFLOW;
        return NULL;
    }
    memcpy(output, weekdays + value->tm_wday * 3, 3);
    output[3] = ' ';
    memcpy(output + 4, months + value->tm_mon * 3, 3);
    output[7] = ' ';
    calendar_two_digits(output + 8, value->tm_mday);
    if (output[8] == '0') output[8] = ' ';
    output[10] = ' ';
    calendar_two_digits(output + 11, value->tm_hour);
    output[13] = ':';
    calendar_two_digits(output + 14, value->tm_min);
    output[16] = ':';
    calendar_two_digits(output + 17, value->tm_sec);
    output[19] = ' ';
    calendar_two_digits(output + 20, (int)(year / 100));
    calendar_two_digits(output + 22, (int)(year % 100));
    for (unsigned i = 20; i < 23 && output[i] == '0'; ++i) output[i] = ' ';
    output[24] = '\n';
    output[25] = '\0';
    return output;
}

char *asctime(const struct tm *value)
{
    static _Thread_local char output[26];
    return asctime_r(value, output);
}
