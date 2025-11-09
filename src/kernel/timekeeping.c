#include "timekeeping.h"

#include "libc.h"
#include "serial.h"
#include "timer.h"
#include "vfs.h"

#define TIMEKEEPING_TZ_NAME_MAX 32
#define TIMEKEEPING_CONFIG_PATH "/etc/timezone/current"
#define TIMEKEEPING_DAY_SECONDS (24 * 60 * 60)

static const uint8_t TIMEKEEPING_MONTH_DAYS[12] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static uint64_t g_time_base_ms = 0;
static uint64_t g_tick_base = 0;
static uint32_t g_tick_frequency = 1000;
typedef struct
{
    char name[TIMEKEEPING_TZ_NAME_MAX];
    int standard_offset_minutes;
    bool dst_enabled;
    int dst_offset_minutes;
    timekeeping_dst_rule_t dst_start;
    timekeeping_dst_rule_t dst_end;
} timekeeping_timezone_state_t;

static timekeeping_timezone_state_t g_timezone = {
    .name = "UTC",
    .standard_offset_minutes = 0,
    .dst_enabled = false,
    .dst_offset_minutes = 0,
    .dst_start = { 0 },
    .dst_end = { 0 }
};

typedef struct
{
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    int weekday;
    int day_of_year;
} timekeeping_calendar_t;

static void timekeeping_log(const char *msg)
{
    serial_write_string("[time] ");
    if (msg)
    {
        serial_write_string(msg);
    }
    serial_write_string("\r\n");
}

static void timekeeping_set_timezone_internal(const char *name,
                                              int standard_offset,
                                              bool dst_enabled,
                                              int dst_offset,
                                              const timekeeping_dst_rule_t *start,
                                              const timekeeping_dst_rule_t *end)
{
    if (!name || *name == '\0')
    {
        name = "UTC";
    }
    size_t len = strlen(name);
    if (len >= TIMEKEEPING_TZ_NAME_MAX)
    {
        len = TIMEKEEPING_TZ_NAME_MAX - 1;
    }
    memcpy(g_timezone.name, name, len);
    g_timezone.name[len] = '\0';

    g_timezone.standard_offset_minutes = standard_offset;
    g_timezone.dst_enabled = dst_enabled;
    g_timezone.dst_offset_minutes = dst_enabled ? dst_offset : standard_offset;

    if (dst_enabled && start && end)
    {
        g_timezone.dst_start = *start;
        g_timezone.dst_end = *end;
    }
    else
    {
        memset(&g_timezone.dst_start, 0, sizeof(g_timezone.dst_start));
        memset(&g_timezone.dst_end, 0, sizeof(g_timezone.dst_end));
    }
}

static bool timekeeping_parse_int(const char *text, size_t len, int *value)
{
    if (!text || len == 0 || !value)
    {
        return false;
    }
    size_t idx = 0;
    bool negative = false;
    if (text[idx] == '+' || text[idx] == '-')
    {
        negative = (text[idx] == '-');
        idx++;
    }
    if (idx >= len)
    {
        return false;
    }
    int result = 0;
    for (; idx < len; ++idx)
    {
        char c = text[idx];
        if (c < '0' || c > '9')
        {
            return false;
        }
        result = result * 10 + (c - '0');
    }
    if (negative)
    {
        result = -result;
    }
    *value = result;
    return true;
}

static size_t timekeeping_format_int(char *buffer, size_t capacity, int value)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }
    char tmp[16];
    size_t tmp_len = 0;
    int64_t magnitude = value;
    bool negative = false;
    if (magnitude < 0)
    {
        negative = true;
        magnitude = -magnitude;
    }
    uint32_t abs_value = (uint32_t)magnitude;
    do
    {
        tmp[tmp_len++] = (char)('0' + (abs_value % 10));
        abs_value /= 10;
    } while (abs_value > 0 && tmp_len < sizeof(tmp));

    size_t out_len = 0;
    if (negative)
    {
        if (out_len + 1 >= capacity)
        {
            return 0;
        }
        buffer[out_len++] = '-';
    }
    while (tmp_len > 0)
    {
        if (out_len + 1 >= capacity)
        {
            return 0;
        }
        buffer[out_len++] = tmp[--tmp_len];
    }
    buffer[out_len] = '\0';
    return out_len;
}

static bool timekeeping_read_line(const char *data,
                                  size_t size,
                                  size_t *pos,
                                  char *buffer,
                                  size_t buffer_cap)
{
    if (!data || !pos || !buffer || buffer_cap == 0 || *pos >= size)
    {
        return false;
    }

    size_t write = 0;
    size_t cursor = *pos;
    while (cursor < size && data[cursor] != '\n' && data[cursor] != '\r')
    {
        if (write + 1 < buffer_cap)
        {
            buffer[write++] = data[cursor];
        }
        cursor++;
    }
    buffer[write] = '\0';
    while (cursor < size && (data[cursor] == '\n' || data[cursor] == '\r'))
    {
        cursor++;
    }
    *pos = cursor;
    return true;
}

static bool timekeeping_parse_rule_line(const char *line, timekeeping_dst_rule_t *rule)
{
    if (!line || !rule)
    {
        return false;
    }
    int values[4] = { 0, 0, 0, 0 };
    size_t len = strlen(line);
    size_t cursor = 0;
    for (int i = 0; i < 4; ++i)
    {
        while (cursor < len && (line[cursor] == ' ' || line[cursor] == '\t'))
        {
            cursor++;
        }
        size_t start = cursor;
        while (cursor < len && line[cursor] != ' ' && line[cursor] != '\t')
        {
            cursor++;
        }
        if (start == cursor)
        {
            return false;
        }
        if (!timekeeping_parse_int(line + start, cursor - start, &values[i]))
        {
            return false;
        }
    }

    if (values[0] < 0 || values[1] < 0 || values[2] < 0 || values[3] < 0)
    {
        return false;
    }
    rule->month = (uint8_t)values[0];
    rule->week = (uint8_t)values[1];
    rule->weekday = (uint8_t)values[2];
    rule->minute = (uint16_t)values[3];
    return true;
}

static bool timekeeping_rule_valid(const timekeeping_dst_rule_t *rule)
{
    if (!rule)
    {
        return false;
    }
    if (rule->month < 1 || rule->month > 12)
    {
        return false;
    }
    if (rule->week < 1 || rule->week > 5)
    {
        return false;
    }
    if (rule->weekday > 6)
    {
        return false;
    }
    if (rule->minute >= 24 * 60)
    {
        return false;
    }
    return true;
}

static bool timekeeping_is_leap_year(int year)
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

static int timekeeping_days_in_month(int year, int month)
{
    if (month < 1 || month > 12)
    {
        return 0;
    }
    int days = TIMEKEEPING_MONTH_DAYS[month - 1];
    if (month == 2 && timekeeping_is_leap_year(year))
    {
        days = 29;
    }
    return days;
}

static int64_t timekeeping_days_before_year(int year)
{
    int64_t days = 0;
    if (year >= 1970)
    {
        for (int y = 1970; y < year; ++y)
        {
            days += timekeeping_is_leap_year(y) ? 366 : 365;
        }
    }
    else
    {
        for (int y = year; y < 1970; ++y)
        {
            days -= timekeeping_is_leap_year(y) ? 366 : 365;
        }
    }
    return days;
}

static int64_t timekeeping_days_before_month(int year, int month)
{
    int64_t days = 0;
    for (int m = 1; m < month; ++m)
    {
        days += timekeeping_days_in_month(year, m);
    }
    return days;
}

static int timekeeping_day_of_week(int year, int month, int day)
{
    if (month < 3)
    {
        month += 12;
        year -= 1;
    }
    int k = year % 100;
    int j = year / 100;
    int h = (day + (13 * (month + 1)) / 5 + k + (k / 4) + (j / 4) + (5 * j)) % 7;
    int dow = ((h + 6) % 7); /* convert to 0=Sunday */
    return dow;
}

static int timekeeping_resolve_rule_day(int year, const timekeeping_dst_rule_t *rule)
{
    if (!timekeeping_rule_valid(rule))
    {
        return 0;
    }
    int dim = timekeeping_days_in_month(year, rule->month);
    if (dim <= 0)
    {
        return 0;
    }
    int dow_first = timekeeping_day_of_week(year, rule->month, 1);
    int day = 1 + ((rule->weekday + 7 - dow_first) % 7);
    day += (rule->week - 1) * 7;
    while (day > dim)
    {
        day -= 7;
    }
    if (day < 1 || day > dim)
    {
        return 0;
    }
    return day;
}

static uint64_t timekeeping_seconds_from_ymd(int year, int month, int day)
{
    int64_t days = timekeeping_days_before_year(year);
    days += timekeeping_days_before_month(year, month);
    days += (day - 1);
    if (days < 0)
    {
        return 0;
    }
    return (uint64_t)days * TIMEKEEPING_DAY_SECONDS;
}

static void timekeeping_breakdown_utc(uint64_t seconds, timekeeping_calendar_t *out)
{
    if (!out)
    {
        return;
    }
    uint64_t total_days = seconds / TIMEKEEPING_DAY_SECONDS;
    uint32_t rem = (uint32_t)(seconds % TIMEKEEPING_DAY_SECONDS);

    out->hour = (int)(rem / 3600U);
    rem %= 3600U;
    out->minute = (int)(rem / 60U);
    out->second = (int)(rem % 60U);

    out->weekday = (int)((total_days + 4) % 7); /* 1970-01-01 was Thursday (4) */

    int year = 1970;
    uint64_t day_counter = total_days;
    while (true)
    {
        uint32_t year_days = timekeeping_is_leap_year(year) ? 366U : 365U;
        if (day_counter < year_days)
        {
            break;
        }
        day_counter -= year_days;
        year++;
    }
    out->year = year;
    out->day_of_year = (int)day_counter;

    int month = 1;
    while (month <= 12)
    {
        int dim = timekeeping_days_in_month(year, month);
        if ((int)day_counter < dim)
        {
            break;
        }
        day_counter -= (uint64_t)dim;
        month++;
    }
    out->month = month;
    out->day = (int)day_counter + 1;
}

static uint64_t timekeeping_dst_transition_seconds(int year,
                                                   const timekeeping_dst_rule_t *rule,
                                                   bool is_start)
{
    if (!timekeeping_rule_valid(rule))
    {
        return 0;
    }
    int day = timekeeping_resolve_rule_day(year, rule);
    if (day <= 0)
    {
        return 0;
    }
    uint64_t local_seconds = timekeeping_seconds_from_ymd(year, rule->month, day);
    local_seconds += (uint64_t)rule->minute * 60ULL;

    int before_offset = is_start ? g_timezone.standard_offset_minutes
                                 : g_timezone.dst_offset_minutes;
    int64_t utc_seconds = (int64_t)local_seconds - (int64_t)before_offset * 60LL;
    if (utc_seconds < 0)
    {
        return 0;
    }
    return (uint64_t)utc_seconds;
}

static bool timekeeping_is_dst_active(uint64_t utc_seconds)
{
    if (!g_timezone.dst_enabled)
    {
        return false;
    }
    timekeeping_calendar_t cal;
    timekeeping_breakdown_utc(utc_seconds, &cal);
    uint64_t start = timekeeping_dst_transition_seconds(cal.year, &g_timezone.dst_start, true);
    uint64_t end = timekeeping_dst_transition_seconds(cal.year, &g_timezone.dst_end, false);
    if (start == 0 || end == 0)
    {
        return false;
    }
    if (start < end)
    {
        return (utc_seconds >= start && utc_seconds < end);
    }
    return (utc_seconds >= start || utc_seconds < end);
}

static int timekeeping_effective_offset_minutes(uint64_t utc_seconds)
{
    if (g_timezone.dst_enabled && timekeeping_is_dst_active(utc_seconds))
    {
        return g_timezone.dst_offset_minutes;
    }
    return g_timezone.standard_offset_minutes;
}

static bool timekeeping_parse_timezone(const char *data,
                                       size_t size,
                                       timekeeping_timezone_state_t *state_out)
{
    if (!data || size == 0 || !state_out)
    {
        return false;
    }

    size_t pos = 0;
    char line[128];
    timekeeping_timezone_state_t parsed = { 0 };

    if (!timekeeping_read_line(data, size, &pos, line, sizeof(line)))
    {
        return false;
    }
    size_t name_len = strlen(line);
    if (name_len == 0)
    {
        return false;
    }
    if (name_len >= TIMEKEEPING_TZ_NAME_MAX)
    {
        name_len = TIMEKEEPING_TZ_NAME_MAX - 1;
    }
    memcpy(parsed.name, line, name_len);
    parsed.name[name_len] = '\0';

    if (!timekeeping_read_line(data, size, &pos, line, sizeof(line)))
    {
        return false;
    }
    if (!timekeeping_parse_int(line, strlen(line), &parsed.standard_offset_minutes))
    {
        return false;
    }
    if (!timekeeping_is_valid_timezone_offset(parsed.standard_offset_minutes))
    {
        return false;
    }

    parsed.dst_enabled = false;
    parsed.dst_offset_minutes = parsed.standard_offset_minutes;
    memset(&parsed.dst_start, 0, sizeof(parsed.dst_start));
    memset(&parsed.dst_end, 0, sizeof(parsed.dst_end));

    size_t saved_pos = pos;
    if (timekeeping_read_line(data, size, &pos, line, sizeof(line)))
    {
        int dst_offset = 0;
        if (timekeeping_parse_int(line, strlen(line), &dst_offset) &&
            timekeeping_is_valid_timezone_offset(dst_offset) &&
            timekeeping_read_line(data, size, &pos, line, sizeof(line)))
        {
            timekeeping_dst_rule_t start_rule;
            if (timekeeping_parse_rule_line(line, &start_rule) &&
                timekeeping_read_line(data, size, &pos, line, sizeof(line)))
            {
                timekeeping_dst_rule_t end_rule;
                if (timekeeping_parse_rule_line(line, &end_rule) &&
                    timekeeping_rule_valid(&start_rule) &&
                    timekeeping_rule_valid(&end_rule))
                {
                    parsed.dst_enabled = (dst_offset != parsed.standard_offset_minutes);
                    parsed.dst_offset_minutes = parsed.dst_enabled ? dst_offset : parsed.standard_offset_minutes;
                    if (parsed.dst_enabled)
                    {
                        parsed.dst_start = start_rule;
                        parsed.dst_end = end_rule;
                    }
                }
            }
        }
    }
    else
    {
        pos = saved_pos;
    }

    *state_out = parsed;
    return true;
}

static bool timekeeping_write_string_line(vfs_node_t *file, const char *text)
{
    if (!file || !text)
    {
        return false;
    }
    size_t len = strlen(text);
    if (!vfs_append(file, text, len))
    {
        return false;
    }
    return vfs_append(file, "\n", 1);
}

static bool timekeeping_write_int_line(vfs_node_t *file, int value)
{
    char number[16];
    size_t len = timekeeping_format_int(number, sizeof(number), value);
    if (len == 0)
    {
        return false;
    }
    if (!vfs_append(file, number, len))
    {
        return false;
    }
    return vfs_append(file, "\n", 1);
}

static bool timekeeping_append_rule_value(char *buffer,
                                          size_t capacity,
                                          size_t *pos,
                                          int value,
                                          bool leading_space)
{
    if (!buffer || !pos || *pos >= capacity)
    {
        return false;
    }
    if (leading_space)
    {
        if (*pos + 1 >= capacity)
        {
            return false;
        }
        buffer[(*pos)++] = ' ';
    }
    size_t remaining = capacity - *pos;
    size_t written = timekeeping_format_int(buffer + *pos, remaining, value);
    if (written == 0)
    {
        return false;
    }
    *pos += written;
    return true;
}

static bool timekeeping_write_rule_line(vfs_node_t *file, const timekeeping_dst_rule_t *rule)
{
    if (!file || !rule)
    {
        return false;
    }
    char line[64];
    size_t pos = 0;
    if (!timekeeping_append_rule_value(line, sizeof(line), &pos, rule->month, false)) return false;
    if (!timekeeping_append_rule_value(line, sizeof(line), &pos, rule->week, true)) return false;
    if (!timekeeping_append_rule_value(line, sizeof(line), &pos, rule->weekday, true)) return false;
    if (!timekeeping_append_rule_value(line, sizeof(line), &pos, rule->minute, true)) return false;
    if (pos + 1 >= sizeof(line))
    {
        return false;
    }
    line[pos++] = '\n';
    return vfs_append(file, line, pos);
}

void timekeeping_init(void)
{
    g_tick_frequency = timer_frequency();
    if (g_tick_frequency == 0)
    {
        g_tick_frequency = 1000;
    }
    g_tick_base = timer_ticks();
    g_time_base_ms = 0;
    timekeeping_set_timezone_internal("UTC", 0, false, 0, NULL, NULL);
    if (!timekeeping_ensure_timezone_config())
    {
        timekeeping_log("failed to ensure timezone config");
    }
    if (!timekeeping_reload_timezone())
    {
        timekeeping_log("using default timezone");
    }
}

uint64_t timekeeping_now_millis(void)
{
    uint64_t ticks = timer_ticks();
    uint64_t delta_ticks = ticks - g_tick_base;
    uint64_t delta_ms = 0;
    if (g_tick_frequency > 0)
    {
        delta_ms = (delta_ticks * 1000ULL) / g_tick_frequency;
    }
    return g_time_base_ms + delta_ms;
}

uint64_t timekeeping_now_seconds(void)
{
    return timekeeping_now_millis() / 1000ULL;
}

bool timekeeping_set_utc_seconds(uint64_t seconds)
{
    g_time_base_ms = seconds * 1000ULL;
    g_tick_base = timer_ticks();
    return true;
}

bool timekeeping_save_timezone_spec(const timekeeping_timezone_spec_t *spec)
{
    if (!spec || !spec->name || *spec->name == '\0')
    {
        return false;
    }
    if (!timekeeping_is_valid_timezone_offset(spec->standard_offset_minutes))
    {
        return false;
    }

    bool dst_enabled = spec->dst_enabled;
    int dst_offset = spec->dst_offset_minutes;
    timekeeping_dst_rule_t start_rule = spec->dst_start;
    timekeeping_dst_rule_t end_rule = spec->dst_end;

    if (!dst_enabled ||
        !timekeeping_is_valid_timezone_offset(dst_offset) ||
        dst_offset == spec->standard_offset_minutes ||
        !timekeeping_rule_valid(&start_rule) ||
        !timekeeping_rule_valid(&end_rule))
    {
        dst_enabled = false;
    }

    vfs_node_t *file = vfs_open_file(vfs_root(), TIMEKEEPING_CONFIG_PATH, true, true);
    if (!file)
    {
        return false;
    }

    if (!timekeeping_write_string_line(file, spec->name))
    {
        return false;
    }
    if (!timekeeping_write_int_line(file, spec->standard_offset_minutes))
    {
        return false;
    }
    if (dst_enabled)
    {
        if (!timekeeping_write_int_line(file, dst_offset)) return false;
        if (!timekeeping_write_rule_line(file, &start_rule)) return false;
        if (!timekeeping_write_rule_line(file, &end_rule)) return false;
    }

    timekeeping_set_timezone_internal(spec->name,
                                      spec->standard_offset_minutes,
                                      dst_enabled,
                                      dst_enabled ? dst_offset : spec->standard_offset_minutes,
                                      dst_enabled ? &start_rule : NULL,
                                      dst_enabled ? &end_rule : NULL);
    return true;
}

bool timekeeping_save_timezone(const char *name, int offset_minutes)
{
    timekeeping_timezone_spec_t spec = {
        .name = name,
        .standard_offset_minutes = offset_minutes,
        .dst_enabled = false,
        .dst_offset_minutes = offset_minutes,
        .dst_start = { 0 },
        .dst_end = { 0 }
    };
    return timekeeping_save_timezone_spec(&spec);
}

bool timekeeping_reload_timezone(void)
{
    vfs_node_t *file = vfs_open_file(vfs_root(), TIMEKEEPING_CONFIG_PATH, false, false);
    if (!file)
    {
        return false;
    }
    size_t size = 0;
    const char *data = vfs_data(file, &size);
    if (!data || size == 0)
    {
        return false;
    }
    timekeeping_timezone_state_t parsed;
    if (!timekeeping_parse_timezone(data, size, &parsed))
    {
        return false;
    }
    timekeeping_set_timezone_internal(parsed.name,
                                      parsed.standard_offset_minutes,
                                      parsed.dst_enabled,
                                      parsed.dst_offset_minutes,
                                      parsed.dst_enabled ? &parsed.dst_start : NULL,
                                      parsed.dst_enabled ? &parsed.dst_end : NULL);
    return true;
}

bool timekeeping_ensure_timezone_config(void)
{
    vfs_node_t *file = vfs_open_file(vfs_root(), TIMEKEEPING_CONFIG_PATH, false, false);
    if (file)
    {
        return true;
    }
    return timekeeping_save_timezone("UTC", 0);
}

const char *timekeeping_timezone_name(void)
{
    return g_timezone.name;
}

int timekeeping_timezone_offset_minutes(void)
{
    return timekeeping_effective_offset_minutes(timekeeping_now_seconds());
}

bool timekeeping_local_time(timekeeping_time_of_day_t *out)
{
    if (!out)
    {
        return false;
    }
    uint64_t utc_seconds = timekeeping_now_seconds();
    int offset = timekeeping_effective_offset_minutes(utc_seconds);
    int64_t local_seconds = (int64_t)utc_seconds + (int64_t)offset * 60;
    int64_t day = TIMEKEEPING_DAY_SECONDS;
    int64_t normalized = local_seconds % day;
    if (normalized < 0)
    {
        normalized += day;
    }
    out->hour = (int)(normalized / 3600);
    out->minute = (int)((normalized % 3600) / 60);
    out->second = (int)(normalized % 60);
    return true;
}

void timekeeping_format_time(char *buffer, size_t length)
{
    if (!buffer || length == 0)
    {
        return;
    }
    timekeeping_time_of_day_t tod;
    if (!timekeeping_local_time(&tod))
    {
        buffer[0] = '\0';
        return;
    }
    if (length < 6)
    {
        buffer[0] = '\0';
        return;
    }

    int hour = tod.hour;
    int minute = tod.minute;
    if (hour < 0) hour = 0;
    if (hour > 23) hour = 23;
    if (minute < 0) minute = 0;
    if (minute > 59) minute = 59;

    buffer[0] = (char)('0' + (hour / 10));
    buffer[1] = (char)('0' + (hour % 10));
    buffer[2] = ':';
    buffer[3] = (char)('0' + (minute / 10));
    buffer[4] = (char)('0' + (minute % 10));
    buffer[5] = '\0';
}

bool timekeeping_is_valid_timezone_offset(int offset_minutes)
{
    return offset_minutes >= -720 && offset_minutes <= 840;
}
