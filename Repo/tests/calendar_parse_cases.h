#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define PARSE_CHECK(c) do { if (!(c)) return __LINE__; } while (0)
static int calendar_parse_cases(unsigned worker)
{
    static const char *const formats[] = {"%F %T", "%Y %j %T", "%G-W%V-%u %T", "%Y %U %w %T", "%Y %W %w %T", "%c"};
    char text[128];
    for (unsigned i = 0; i < 1024; ++i)
    {
        time_t value = 946684800 + (time_t)(i * 8 + worker) * 1609073;
        struct tm reference, parsed;
        PARSE_CHECK(gmtime_r(&value, &reference));
        for (unsigned f = 0; f < sizeof(formats) / sizeof(formats[0]); ++f)
        {
            PARSE_CHECK(strftime(text, sizeof(text), formats[f], &reference));
            memset(&parsed, 0, sizeof(parsed)); parsed.tm_isdst = -1;
            char *end = strptime(text, formats[f], &parsed);
            PARSE_CHECK(end && !*end);
            PARSE_CHECK(parsed.tm_year == reference.tm_year && parsed.tm_mon == reference.tm_mon &&
                parsed.tm_mday == reference.tm_mday && parsed.tm_hour == reference.tm_hour &&
                parsed.tm_min == reference.tm_min && parsed.tm_sec == reference.tm_sec &&
                parsed.tm_yday == reference.tm_yday && parsed.tm_wday == reference.tm_wday);
        }
    }
    struct tm parsed = {.tm_year = 70, .tm_mon = 0, .tm_mday = 1, .tm_sec = 37, .tm_yday = 77};
    errno = EDOM;
    char *end = strptime("11rest", "%m", &parsed);
    PARSE_CHECK(end && !strcmp(end, "rest") && parsed.tm_mon == 10 && parsed.tm_year == 70 &&
                parsed.tm_sec == 37 && parsed.tm_yday == 77 && errno == EDOM);
    end = strptime("PM 12:34:56", "%p %I:%M:%S", &parsed);
    PARSE_CHECK(end && !*end && parsed.tm_hour == 12 && parsed.tm_min == 34 && parsed.tm_sec == 56);
    end = strptime("12:00:00 am", "%r", &parsed);
    PARSE_CHECK(end && !*end && parsed.tm_hour == 0);
    end = strptime("20 24-02-29", "%C %y-%m-%d", &parsed);
    PARSE_CHECK(end && !*end && parsed.tm_year == 124 && parsed.tm_yday == 59 && parsed.tm_wday == 4);
    end = strptime("69", "%y", &parsed); PARSE_CHECK(end && !*end && parsed.tm_year == 69);
    end = strptime("68", "%y", &parsed); PARSE_CHECK(end && !*end && parsed.tm_year == 168);
    end = strptime(" 2024/02/29\t23:59:60", "%EY/%Om/%Od%n%OH:%OM:%OS", &parsed);
    PARSE_CHECK(end == NULL); /* Leading input space requires a format space. */
    end = strptime(" 2024/02/29\t23:59:60", " %EY/%Om/%Od%n%OH:%OM:%OS", &parsed);
    PARSE_CHECK(end && !*end && parsed.tm_sec == 60);
    static const struct { const char *text; long offset; } zones[] = {
        {"Z",0}, {"+00",0}, {"-0530",-19800}, {"+10:30",37800}, {"+00:12:21",741}, {"+23:59",86340}
    };
    for (unsigned i = 0; i < sizeof(zones) / sizeof(zones[0]); ++i)
    {
        end = strptime(zones[i].text, "%z", &parsed);
        PARSE_CHECK(end && !*end && parsed.tm_gmtoff == zones[i].offset && parsed.tm_isdst == 0);
    }
    static const struct { const char *text, *format; } invalid[] = {
        {"", "%"}, {"", "%z"}, {"+", "%z"}, {"+0", "%z"}, {"+01:", "%z"},
        {"+01:2", "%z"}, {"+01:23:", "%z"}, {"+24:00", "%z"}, {"-0060", "%z"},
        {"+12345", "%z"}, {"13", "%m"}, {"00", "%d"}, {"24", "%H"}, {"61", "%S"},
        {"2023-02-29", "%F"}, {"2023 366", "%Y %j"}, {"2021-W53-1", "%G-W%V-%u"},
        {"9223372036854775808", "%s"}, {"-9223372036854775809", "%s"}, {"x", "%Q"},
        {"", "%E"}, {"1", "%Em"}, {"invalid", "%Z"}
    };
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        struct tm original = parsed;
        PARSE_CHECK(!strptime(invalid[i].text, invalid[i].format, &parsed));
        PARSE_CHECK(!memcmp(&parsed, &original, sizeof(parsed)));
    }
    end = strptime("-1", "%s", &parsed);
    PARSE_CHECK(end && !*end && parsed.tm_year == 69 && parsed.tm_mon == 11 && parsed.tm_mday == 31 && parsed.tm_sec == 59);
    end = strptime("UTC", "%Z", &parsed);
    PARSE_CHECK(end && !*end && parsed.tm_gmtoff == 0 && parsed.tm_isdst == 0 && !strcmp(parsed.tm_zone, "UTC"));
    return 0;
}
#undef PARSE_CHECK
