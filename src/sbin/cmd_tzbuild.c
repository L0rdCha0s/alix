#include "shell_commands.h"

#include "libc.h"
#include "shell.h"
#include "timezone_paths.h"
#include "tz_format.h"
#include "timekeeping.h"
#include "vfs.h"

#ifndef INT64_MIN
#define INT64_MIN (-9223372036854775807LL - 1)
#endif
#ifndef INT64_MAX
#define INT64_MAX (9223372036854775807LL)
#endif
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
#endif

static int tzbuild_strncasecmp(const char *s1, const char *s2, size_t n);
static int tzbuild_strcasecmp(const char *s1, const char *s2);
static char *tzbuild_strstr(const char *haystack, const char *needle);
static char *tzbuild_strchr(const char *s, int c);
static void tzbuild_qsort(void *base, size_t nitems, size_t size, int (*compar)(const void *, const void *));

#define strncasecmp tzbuild_strncasecmp
#define strcasecmp tzbuild_strcasecmp
#define strstr tzbuild_strstr
#define strchr tzbuild_strchr
#define qsort tzbuild_qsort

#define TZBUILD_HEADER_MAGIC   TZDB_FILE_MAGIC
#define TZBUILD_VERSION        TZDB_FILE_VERSION
#define TZBUILD_NAME_MAX       96
#define TZBUILD_RULE_NAME_MAX  48
#define TZBUILD_FORMAT_MAX     32
#define TZBUILD_RELEASE_MAX    64
#define TZBUILD_YEAR_MIN       1900
#define TZBUILD_YEAR_MAX       2150
#define TZBUILD_RANGE_START    0                     /* 1970-01-01 */
#define TZBUILD_RANGE_END      7258118400LL          /* 2200-01-01 */
#define TZBUILD_UTC_MARGIN     (10LL * 365 * 86400)
#define TZBUILD_EVENTS_PER_YEAR 16

typedef enum
{
    TZ_DAY_RULE_DOM = 0,
    TZ_DAY_RULE_LAST,
    TZ_DAY_RULE_GE,
    TZ_DAY_RULE_LE
} tz_day_rule_kind_t;

typedef struct
{
    tz_day_rule_kind_t kind;
    int weekday; /* 0 = Sunday */
    int day;
} tz_day_rule_t;

typedef enum
{
    TZ_TIME_WALL = 0,
    TZ_TIME_STANDARD,
    TZ_TIME_UTC
} tz_time_type_t;

typedef struct
{
    int seconds;
    tz_time_type_t type;
} tz_time_spec_t;

typedef struct
{
    char name[TZBUILD_RULE_NAME_MAX];
    int from_year;
    int to_year;
    int in_month;
    tz_day_rule_t day_rule;
    tz_time_spec_t at;
    int save_minutes;
} tz_rule_t;

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
} tz_calendar_t;

typedef struct
{
    int year;
    int month;
    int day;
    tz_time_spec_t time;
    bool defined;
} tz_until_t;

typedef struct
{
    int gmtoff_minutes;
    bool has_rule_name;
    char rule_name[TZBUILD_RULE_NAME_MAX];
    bool fixed_save;
    int fixed_save_minutes;
    tz_until_t until;
} tz_zone_span_t;

typedef struct
{
    char name[TZBUILD_NAME_MAX];
    tz_zone_span_t *spans;
    size_t span_count;
    size_t span_capacity;
} tz_zone_t;

typedef struct
{
    char target[TZBUILD_NAME_MAX];
    char link[TZBUILD_NAME_MAX];
} tz_link_t;

typedef struct
{
    tz_rule_t *rules;
    size_t rule_count;
    size_t rule_capacity;
    tz_zone_t *zones;
    size_t zone_count;
    size_t zone_capacity;
    tz_link_t *links;
    size_t link_count;
    size_t link_capacity;
    char release[TZBUILD_RELEASE_MAX];
} tz_database_t;

typedef struct
{
    int64_t utc_seconds;
    int offset_minutes;
    bool is_dst;
} tz_transition_t;

typedef struct
{
    int64_t local_seconds;
    tz_time_type_t type;
    int save_minutes;
} tz_rule_event_t;

static bool tz_read_line(const char **cursor, const char *end, char *buffer, size_t cap);
static bool tz_parse(tz_database_t *db, const char *data, size_t size);
static bool tz_emit_database(shell_state_t *shell, tz_database_t *db);
static bool tz_parse_manifest_release(char *buffer, size_t capacity);
static int tz_month_from_name(const char *text);
static int tz_weekday_from_name(const char *text);
static bool tz_parse_offset_minutes(const char *text, int *minutes_out);
static bool tz_parse_time_spec(const char *text, tz_time_spec_t *spec_out);
static bool tz_parse_day_rule(const char *text, tz_day_rule_t *rule_out);
static int tz_compare_transitions(const void *a, const void *b);
static bool tz_rule_applies(const tz_rule_t *rule, int year);
static size_t tz_split_tokens(char *line, char *tokens[], size_t max_tokens);
static void tz_copy_string(char *dest, size_t capacity, const char *src);
static int tz_days_in_month(int year, int month);
static int tz_day_of_week(int year, int month, int day);
static int tz_resolve_day_rule(int year, const tz_rule_t *rule);
static bool tz_append_span(tz_zone_t *zone, const tz_zone_span_t *span);
static tz_zone_t *tz_find_zone(tz_database_t *db, const char *name);
static bool tz_collect_transitions(const tz_database_t *db,
                                   const tz_zone_t *zone,
                                   tz_transition_t **out_list,
                                   size_t *out_count,
                                   size_t *out_capacity,
                                   int *initial_offset,
                                   bool *initial_is_dst);
static bool tz_parse_rule_entry(tz_database_t *db, char *tokens[], size_t count);
static bool tz_parse_zone_entry(tz_database_t *db,
                                char *tokens[],
                                size_t count,
                                tz_zone_t **zone_out);
static bool tz_parse_zone_span_tokens(tz_zone_t *zone, char *tokens[], size_t count);
static bool tz_parse_link_entry(tz_database_t *db, char *tokens[], size_t count);

bool shell_cmd_tzbuild(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)args;
    if (!shell || !out)
    {
        return false;
    }

    vfs_node_t *tzdata_file = vfs_open_file(vfs_root(), TZDB_TZDATA_PATH, false, false);
    if (!tzdata_file)
    {
        return shell_output_error(out, "tzdata.zi missing, run tzsync first");
    }
    size_t data_size = 0;
    const char *data = vfs_data(tzdata_file, &data_size);
    if (!data || data_size == 0)
    {
        return shell_output_error(out, "tzdata.zi empty");
    }

    tz_database_t db;
    memset(&db, 0, sizeof(db));

    shell_output_write(out, "Parsing tzdata...\n");
    if (!tz_parse(&db, data, data_size))
    {
        return shell_output_error(out, "tzbuild parse failed");
    }

    shell_output_write(out, "Writing database...\n");
    if (!tz_emit_database(shell, &db))
    {
        return shell_output_error(out, "failed to write timezone database");
    }

    shell_output_write(out, "tzbuild complete.\n");
    return true;
}

static const char *tz_skip_spaces(const char *s)
{
    while (s && (*s == ' ' || *s == '\t'))
    {
        ++s;
    }
    return s;
}

static void tz_trim(char *text)
{
    if (!text)
    {
        return;
    }
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t'))
    {
        text[--len] = '\0';
    }
    char *cursor = text;
    cursor = (char *)tz_skip_spaces(cursor);
    if (cursor != text)
    {
        memmove(text, cursor, strlen(cursor) + 1);
    }
}

static void tz_strip_comment(char *line)
{
    if (!line)
    {
        return;
    }
    for (size_t i = 0; line[i]; ++i)
    {
        if (line[i] == '#')
        {
            line[i] = '\0';
            break;
        }
    }
}

static void tz_copy_string(char *dest, size_t capacity, const char *src)
{
    if (!dest || capacity == 0)
    {
        return;
    }
    if (!src)
    {
        dest[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= capacity)
    {
        len = capacity - 1;
    }
    memcpy(dest, src, len);
    dest[len] = '\0';
}

static bool tz_read_line(const char **cursor, const char *end, char *buffer, size_t cap)
{
    if (!cursor || !*cursor || !buffer || cap == 0 || *cursor >= end)
    {
        return false;
    }
    const char *start = *cursor;
    const char *line_end = start;
    while (line_end < end && *line_end != '\n' && *line_end != '\r')
    {
        ++line_end;
    }
    size_t len = (size_t)(line_end - start);
    if (len >= cap)
    {
        len = cap - 1;
    }
    memcpy(buffer, start, len);
    buffer[len] = '\0';
    while (line_end < end && (*line_end == '\n' || *line_end == '\r'))
    {
        ++line_end;
    }
    *cursor = line_end;
    return true;
}

static bool tz_parse_manifest_release(char *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return false;
    }
    vfs_node_t *file = vfs_open_file(vfs_root(), TZDB_MANIFEST_PATH, false, false);
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
    const char *cursor = data;
    const char *end = data + size;
    char line[128];
    while (tz_read_line(&cursor, end, line, sizeof(line)))
    {
        tz_trim(line);
        if (strncmp(line, "version=", 8) == 0)
        {
            tz_copy_string(buffer, capacity, line + 8);
            buffer[capacity - 1] = '\0';
            return true;
        }
    }
    return false;
}

static bool tz_parse_int(const char *text, int *out, bool allow_sign)
{
    if (!text || !out || *text == '\0')
    {
        return false;
    }
    bool negative = false;
    const char *cursor = text;
    if (allow_sign && (*cursor == '-' || *cursor == '+'))
    {
        negative = (*cursor == '-');
        ++cursor;
    }
    if (*cursor == '\0')
    {
        return false;
    }
    int value = 0;
    while (*cursor)
    {
        if (*cursor < '0' || *cursor > '9')
        {
            return false;
        }
        value = value * 10 + (*cursor - '0');
        ++cursor;
    }
    *out = negative ? -value : value;
    return true;
}

static bool tz_parse_offset_minutes(const char *text, int *minutes_out)
{
    if (!text || !minutes_out || *text == '\0')
    {
        return false;
    }
    bool negative = false;
    const char *cursor = text;
    if (*cursor == '+' || *cursor == '-')
    {
        negative = (*cursor == '-');
        ++cursor;
    }
    if (*cursor == '\0')
    {
        return false;
    }

    int parts[3] = { 0, 0, 0 };
    int part_index = 0;
    while (*cursor && part_index < 3)
    {
        const char *start = cursor;
        while (*cursor && *cursor != ':' && *cursor != '\0')
        {
            ++cursor;
        }
        char buf[8];
        size_t len = (size_t)(cursor - start);
        if (len == 0 || len >= sizeof(buf))
        {
            return false;
        }
        memcpy(buf, start, len);
        buf[len] = '\0';
        if (!tz_parse_int(buf, &parts[part_index], false))
        {
            return false;
        }
        ++part_index;
        if (*cursor == ':')
        {
            ++cursor;
        }
    }

    int hours = parts[0];
    int minutes = (part_index > 1) ? parts[1] : 0;
    int seconds = (part_index > 2) ? parts[2] : 0;
    int total_seconds = hours * 3600 + minutes * 60 + seconds;
    if (total_seconds % 60 != 0)
    {
        return false;
    }
    int total_minutes = total_seconds / 60;
    *minutes_out = negative ? -total_minutes : total_minutes;
    return true;
}

static tz_time_type_t tz_parse_time_suffix(char suffix)
{
    switch (suffix)
    {
        case 'u':
        case 'g':
        case 'z':
        case 'U':
        case 'G':
        case 'Z':
            return TZ_TIME_UTC;
        case 's':
        case 'S':
            return TZ_TIME_STANDARD;
        case 'w':
        case 'W':
        default:
            return TZ_TIME_WALL;
    }
}

static bool tz_parse_time_spec(const char *text, tz_time_spec_t *spec_out)
{
    if (!text || !spec_out || *text == '\0')
    {
        return false;
    }
    size_t len = strlen(text);
    tz_time_type_t type = TZ_TIME_WALL;
    if (len > 0)
    {
        char last = text[len - 1];
        if (last == 'u' || last == 'U' || last == 'g' || last == 'G' ||
            last == 'z' || last == 'Z' || last == 's' || last == 'S' ||
            last == 'w' || last == 'W')
        {
            type = tz_parse_time_suffix(last);
            len--;
        }
    }

    int parts[3] = { 0, 0, 0 };
    int part_index = 0;
    size_t idx = 0;
    while (idx < len && part_index < 3)
    {
        size_t start = idx;
        while (idx < len && text[idx] != ':')
        {
            idx++;
        }
        if (idx == start)
        {
            return false;
        }
        char buf[8];
        size_t chunk = idx - start;
        if (chunk >= sizeof(buf))
        {
            return false;
        }
        memcpy(buf, text + start, chunk);
        buf[chunk] = '\0';
        if (!tz_parse_int(buf, &parts[part_index], true))
        {
            return false;
        }
        ++part_index;
        if (idx < len && text[idx] == ':')
        {
            idx++;
        }
    }

    int hours = parts[0];
    int minutes = (part_index > 1) ? parts[1] : 0;
    int seconds = (part_index > 2) ? parts[2] : 0;
    int total_seconds = hours * 3600 + minutes * 60 + seconds;
    spec_out->seconds = total_seconds;
    spec_out->type = type;
    return true;
}

static bool tz_parse_day_rule(const char *text, tz_day_rule_t *rule_out)
{
    if (!text || !rule_out || *text == '\0')
    {
        return false;
    }
    if (text[0] >= '0' && text[0] <= '9')
    {
        int day = 0;
        if (!tz_parse_int(text, &day, false))
        {
            return false;
        }
        rule_out->kind = TZ_DAY_RULE_DOM;
        rule_out->day = day;
        rule_out->weekday = 0;
        return true;
    }

    if (strncmp(text, "last", 4) == 0)
    {
        int weekday = tz_weekday_from_name(text + 4);
        if (weekday < 0)
        {
            return false;
        }
        rule_out->kind = TZ_DAY_RULE_LAST;
        rule_out->weekday = weekday;
        rule_out->day = 0;
        return true;
    }

    const char *ge_ptr = strstr(text, ">=");
    if (ge_ptr)
    {
        int weekday_len = (int)(ge_ptr - text);
        char buf[16];
        if (weekday_len <= 0 || weekday_len >= (int)sizeof(buf))
        {
            return false;
        }
        memcpy(buf, text, (size_t)weekday_len);
        buf[weekday_len] = '\0';
        int weekday = tz_weekday_from_name(buf);
        if (weekday < 0)
        {
            return false;
        }
        int day = 0;
        if (!tz_parse_int(ge_ptr + 2, &day, false))
        {
            return false;
        }
        rule_out->kind = TZ_DAY_RULE_GE;
        rule_out->weekday = weekday;
        rule_out->day = day;
        return true;
    }

    const char *le_ptr = strstr(text, "<=");
    if (le_ptr)
    {
        int weekday_len = (int)(le_ptr - text);
        char buf[16];
        if (weekday_len <= 0 || weekday_len >= (int)sizeof(buf))
        {
            return false;
        }
        memcpy(buf, text, (size_t)weekday_len);
        buf[weekday_len] = '\0';
        int weekday = tz_weekday_from_name(buf);
        if (weekday < 0)
        {
            return false;
        }
        int day = 0;
        if (!tz_parse_int(le_ptr + 2, &day, false))
        {
            return false;
        }
        rule_out->kind = TZ_DAY_RULE_LE;
        rule_out->weekday = weekday;
        rule_out->day = day;
        return true;
    }

    return false;
}

static int tz_month_from_name(const char *text)
{
    static const char *kMonths[] = {
        "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
    };
    if (!text || *text == '\0')
    {
        return -1;
    }
    for (int i = 0; i < 12; ++i)
    {
        if (strncasecmp(text, kMonths[i], 3) == 0)
        {
            return i + 1;
        }
    }
    return -1;
}

static int tz_weekday_from_name(const char *text)
{
    static const char *kDays[] = {
        "Sun","Mon","Tue","Wed","Thu","Fri","Sat"
    };
    if (!text || *text == '\0')
    {
        return -1;
    }
    for (int i = 0; i < 7; ++i)
    {
        if (strncasecmp(text, kDays[i], 3) == 0)
        {
            return i;
        }
    }
    return -1;
}

static int tz_resolve_day_rule(int year, const tz_rule_t *rule)
{
    int month = rule->in_month;
    const tz_day_rule_t *dr = &rule->day_rule;
    int dim = tz_days_in_month(year, month);
    switch (dr->kind)
    {
        case TZ_DAY_RULE_DOM:
            if (dr->day < 1) return 1;
            if (dr->day > dim) return dim;
            return dr->day;
        case TZ_DAY_RULE_LAST:
        {
            int day = dim;
            while (day > 0)
            {
                if (tz_day_of_week(year, month, day) == dr->weekday)
                {
                    return day;
                }
                --day;
            }
            return dim;
        }
        case TZ_DAY_RULE_GE:
        {
            int day = dr->day;
            if (day < 1) day = 1;
            if (day > dim) day = dim;
            while (day <= dim)
            {
                if (tz_day_of_week(year, month, day) == dr->weekday)
                {
                    return day;
                }
                ++day;
            }
            return dim;
        }
        case TZ_DAY_RULE_LE:
        {
            int day = dr->day;
            if (day > dim) day = dim;
            if (day < 1) day = 1;
            while (day >= 1)
            {
                if (tz_day_of_week(year, month, day) == dr->weekday)
                {
                    return day;
                }
                --day;
            }
            return 1;
        }
        default:
            return dr->day;
    }
}

static bool tz_is_leap_year(int year)
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

static int tz_days_in_month(int year, int month)
{
    static const int days[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    if (month < 1 || month > 12)
    {
        return 30;
    }
    if (month == 2 && tz_is_leap_year(year))
    {
        return 29;
    }
    return days[month - 1];
}

static int tz_day_of_week(int year, int month, int day)
{
    int y = year;
    int m = month;
    if (m < 3)
    {
        m += 12;
        y -= 1;
    }
    int K = y % 100;
    int J = y / 100;
    int h = (day + (13 * (m + 1)) / 5 + K + (K / 4) + (J / 4) + (5 * J)) % 7;
    int d = ((h + 6) % 7);
    return d;
}

static int64_t tz_seconds_from_ymd(int year, int month, int day)
{
    int64_t days = 0;
    if (year >= 1970)
    {
        for (int y = 1970; y < year; ++y)
        {
            days += tz_is_leap_year(y) ? 366 : 365;
        }
    }
    else
    {
        for (int y = year; y < 1970; ++y)
        {
            days -= tz_is_leap_year(y) ? 366 : 365;
        }
    }
    for (int m = 1; m < month; ++m)
    {
        days += tz_days_in_month(year, m);
    }
    days += (day - 1);
    return days * 86400LL;
}

static int64_t tz_seconds_from_ymd_hms(int year, int month, int day, int hour, int minute, int second)
{
    return tz_seconds_from_ymd(year, month, day) + hour * 3600LL + minute * 60LL + second;
}

static bool tz_reserve(void **ptr, size_t elem_size, size_t *capacity, size_t required)
{
    if (*capacity >= required)
    {
        return true;
    }
    size_t new_cap = (*capacity == 0) ? 8 : *capacity;
    while (new_cap < required)
    {
        new_cap *= 2;
    }
    void *new_mem = realloc(*ptr, elem_size * new_cap);
    if (!new_mem)
    {
        return false;
    }
    *ptr = new_mem;
    *capacity = new_cap;
    return true;
}

static bool tz_append_span(tz_zone_t *zone, const tz_zone_span_t *span)
{
    if (!zone || !span)
    {
        return false;
    }
    if (!tz_reserve((void **)&zone->spans,
                    sizeof(tz_zone_span_t),
                    &zone->span_capacity,
                    zone->span_count + 1))
    {
        return false;
    }
    zone->spans[zone->span_count++] = *span;
    return true;
}

static tz_zone_t *tz_find_zone(tz_database_t *db, const char *name)
{
    if (!db || !name)
    {
        return NULL;
    }
    for (size_t i = 0; i < db->zone_count; ++i)
    {
        if (strcmp(db->zones[i].name, name) == 0)
        {
            return &db->zones[i];
        }
    }
    if (!tz_reserve((void **)&db->zones,
                    sizeof(tz_zone_t),
                    &db->zone_capacity,
                    db->zone_count + 1))
    {
        return NULL;
    }
    tz_zone_t *zone = &db->zones[db->zone_count++];
    memset(zone, 0, sizeof(*zone));
    tz_copy_string(zone->name, sizeof(zone->name), name);
    return zone;
}

static bool tz_rule_applies(const tz_rule_t *rule, int year)
{
    if (!rule)
    {
        return false;
    }
    if (year < rule->from_year)
    {
        return false;
    }
    if (year > rule->to_year)
    {
        return false;
    }
    return true;
}

static int tz_compare_transitions(const void *a, const void *b)
{
    const tz_transition_t *ta = (const tz_transition_t *)a;
    const tz_transition_t *tb = (const tz_transition_t *)b;
    if (ta->utc_seconds < tb->utc_seconds) return -1;
    if (ta->utc_seconds > tb->utc_seconds) return 1;
    return 0;
}

static int tz_compare_rule_events(const void *a, const void *b)
{
    const tz_rule_event_t *ea = (const tz_rule_event_t *)a;
    const tz_rule_event_t *eb = (const tz_rule_event_t *)b;
    if (ea->local_seconds < eb->local_seconds) return -1;
    if (ea->local_seconds > eb->local_seconds) return 1;
    return 0;
}

static size_t tz_split_tokens(char *line, char *tokens[], size_t max_tokens)
{
    size_t count = 0;
    char *cursor = line;
    while (cursor && *cursor && count < max_tokens)
    {
        cursor = (char *)tz_skip_spaces(cursor);
        if (*cursor == '\0')
        {
            break;
        }
        tokens[count++] = cursor;
        while (*cursor && *cursor != ' ' && *cursor != '\t')
        {
            ++cursor;
        }
        if (*cursor)
        {
            *cursor = '\0';
            ++cursor;
        }
    }
    return count;
}

static int tzbuild_strncasecmp(const char *s1, const char *s2, size_t n)
{
    while (n > 0)
    {
        char c1 = *s1++;
        char c2 = *s2++;
        if (c1 >= 'a' && c1 <= 'z') c1 = (char)(c1 - ('a' - 'A'));
        if (c2 >= 'a' && c2 <= 'z') c2 = (char)(c2 - ('a' - 'A'));
        if (c1 != c2 || c1 == '\0' || c2 == '\0')
        {
            return (int)(unsigned char)c1 - (int)(unsigned char)c2;
        }
        --n;
    }
    return 0;
}

static int tzbuild_strcasecmp(const char *s1, const char *s2)
{
    while (*s1 || *s2)
    {
        char c1 = *s1++;
        char c2 = *s2++;
        if (c1 >= 'a' && c1 <= 'z') c1 = (char)(c1 - ('a' - 'A'));
        if (c2 >= 'a' && c2 <= 'z') c2 = (char)(c2 - ('a' - 'A'));
        if (c1 != c2)
        {
            return (int)(unsigned char)c1 - (int)(unsigned char)c2;
        }
    }
    return 0;
}

static char *tzbuild_strstr(const char *haystack, const char *needle)
{
    if (!haystack || !needle || *needle == '\0')
    {
        return (char *)haystack;
    }
    size_t needle_len = strlen(needle);
    while (*haystack)
    {
        if (strncmp(haystack, needle, needle_len) == 0)
        {
            return (char *)haystack;
        }
        ++haystack;
    }
    return NULL;
}

static char *tzbuild_strchr(const char *s, int c)
{
    char target = (char)c;
    while (*s)
    {
        if (*s == target)
        {
            return (char *)s;
        }
        ++s;
    }
    return (target == '\0') ? (char *)s : NULL;
}

static void tzbuild_qsort(void *base, size_t nitems, size_t size, int (*compar)(const void *, const void *))
{
    if (!base || nitems < 2 || size == 0 || !compar)
    {
        return;
    }
    char *data = (char *)base;
    char *tmp = (char *)malloc(size);
    if (!tmp)
    {
        return;
    }
    for (size_t i = 0; i < nitems - 1; ++i)
    {
        for (size_t j = i + 1; j < nitems; ++j)
        {
            char *a = data + i * size;
            char *b = data + j * size;
            if (compar(a, b) > 0)
            {
                memcpy(tmp, a, size);
                memcpy(a, b, size);
                memcpy(b, tmp, size);
            }
        }
    }
    free(tmp);
}

static bool tz_parse_rule_entry(tz_database_t *db, char *tokens[], size_t count)
{
    if (!db || count < 10)
    {
        return false;
    }
    const char *name = tokens[1];
    const char *from_field = tokens[2];
    const char *to_field = tokens[3];
    const char *type_field = tokens[4];
    const char *month_field = tokens[5];
    const char *on_field = tokens[6];
    const char *at_field = tokens[7];
    const char *save_field = tokens[8];

    (void)type_field; /* currently ignored */

    int from_year = TZBUILD_YEAR_MIN;
    int to_year = TZBUILD_YEAR_MAX;

    if (strcasecmp(from_field, "min") == 0 || strcasecmp(from_field, "minimum") == 0)
    {
        from_year = TZBUILD_YEAR_MIN;
    }
    else
    {
        if (!tz_parse_int(from_field, &from_year, true))
        {
            return false;
        }
    }

    if (strcasecmp(to_field, "max") == 0 || strcasecmp(to_field, "maximum") == 0)
    {
        to_year = TZBUILD_YEAR_MAX;
    }
    else if (strcasecmp(to_field, "only") == 0)
    {
        to_year = from_year;
    }
    else
    {
        if (!tz_parse_int(to_field, &to_year, true))
        {
            return false;
        }
    }

    int month = tz_month_from_name(month_field);
    if (month <= 0)
    {
        return false;
    }

    tz_day_rule_t day_rule;
    if (!tz_parse_day_rule(on_field, &day_rule))
    {
        return false;
    }

    tz_time_spec_t at_spec;
    if (!tz_parse_time_spec(at_field, &at_spec))
    {
        return false;
    }

    int save_minutes = 0;
    if (!tz_parse_offset_minutes(save_field, &save_minutes))
    {
        return false;
    }

    if (!tz_reserve((void **)&db->rules,
                    sizeof(tz_rule_t),
                    &db->rule_capacity,
                    db->rule_count + 1))
    {
        return false;
    }

    tz_rule_t *rule = &db->rules[db->rule_count++];
    memset(rule, 0, sizeof(*rule));
    tz_copy_string(rule->name, sizeof(rule->name), name);
    rule->from_year = from_year;
    rule->to_year = to_year;
    rule->in_month = month;
    rule->day_rule = day_rule;
    rule->at = at_spec;
    rule->save_minutes = save_minutes;
    return true;
}

static bool tz_parse_zone_span_tokens(tz_zone_t *zone, char *tokens[], size_t count)
{
    if (!zone || !tokens || count < 3)
    {
        return false;
    }

    tz_zone_span_t span;
    memset(&span, 0, sizeof(span));

    if (!tz_parse_offset_minutes(tokens[0], &span.gmtoff_minutes))
    {
        return false;
    }

    const char *rule_field = tokens[1];
    if (strcmp(rule_field, "-") == 0)
    {
        span.has_rule_name = false;
        span.fixed_save = true;
        span.fixed_save_minutes = 0;
    }
    else if (strchr(rule_field, ':') || rule_field[0] == '+' || rule_field[0] == '-' ||
             (rule_field[0] >= '0' && rule_field[0] <= '9'))
    {
        int save = 0;
        if (!tz_parse_offset_minutes(rule_field, &save))
        {
            return false;
        }
        span.fixed_save = true;
        span.fixed_save_minutes = save;
    }
    else
    {
        span.has_rule_name = true;
        tz_copy_string(span.rule_name, sizeof(span.rule_name), rule_field);
    }

    size_t index = 3;
    span.until.defined = false;
    if (count > index)
    {
        span.until.defined = true;
        if (!tz_parse_int(tokens[index++], &span.until.year, true))
        {
            return false;
        }
        if (count > index)
        {
            int month = tz_month_from_name(tokens[index]);
            if (month > 0)
            {
                span.until.month = month;
                ++index;
            }
            else
            {
                span.until.month = 1;
            }
        }
        else
        {
            span.until.month = 1;
        }

        if (count > index)
        {
            int day = 0;
            if (tz_parse_int(tokens[index], &day, false))
            {
                span.until.day = day;
                ++index;
            }
            else
            {
                span.until.day = 1;
            }
        }
        else
        {
            span.until.day = 1;
        }

        if (count > index)
        {
            if (!tz_parse_time_spec(tokens[index], &span.until.time))
            {
                return false;
            }
        }
        else
        {
            span.until.time.seconds = 0;
            span.until.time.type = TZ_TIME_WALL;
        }
    }

    return tz_append_span(zone, &span);
}

static bool tz_parse_zone_entry(tz_database_t *db,
                                char *tokens[],
                                size_t count,
                                tz_zone_t **zone_out)
{
    if (!db || count < 5)
    {
        return false;
    }
    const char *name = tokens[1];
    tz_zone_t *zone = tz_find_zone(db, name);
    if (!zone)
    {
        return false;
    }
    if (!tz_parse_zone_span_tokens(zone, &tokens[2], count - 2))
    {
        return false;
    }
    if (zone_out)
    {
        *zone_out = zone;
    }
    return true;
}

static bool tz_parse_link_entry(tz_database_t *db, char *tokens[], size_t count)
{
    if (!db || count < 3)
    {
        return false;
    }
    if (!tz_reserve((void **)&db->links,
                    sizeof(tz_link_t),
                    &db->link_capacity,
                    db->link_count + 1))
    {
        return false;
    }
    tz_link_t *link = &db->links[db->link_count++];
    memset(link, 0, sizeof(*link));
    tz_copy_string(link->target, sizeof(link->target), tokens[1]);
    tz_copy_string(link->link, sizeof(link->link), tokens[2]);
    return true;
}

static bool tz_parse(tz_database_t *db, const char *data, size_t size)
{
    if (!db || !data || size == 0)
    {
        return false;
    }
    const char *cursor = data;
    const char *end = data + size;
    char line[512];
    tz_zone_t *current_zone = NULL;

    while (tz_read_line(&cursor, end, line, sizeof(line)))
    {
        tz_strip_comment(line);
        tz_trim(line);
        if (line[0] == '\0')
        {
            current_zone = NULL;
            continue;
        }

        if (line[0] == ' ' || line[0] == '\t')
        {
            if (!current_zone)
            {
                continue;
            }
            char *tokens[16];
            size_t count = tz_split_tokens(line, tokens, 16);
            if (count == 0)
            {
                continue;
            }
            if (!tz_parse_zone_span_tokens(current_zone, tokens, count))
            {
                return false;
            }
            continue;
        }

        char *tokens[16];
        size_t count = tz_split_tokens(line, tokens, 16);
        if (count == 0)
        {
            continue;
        }

        if (strcmp(tokens[0], "Rule") == 0)
        {
            current_zone = NULL;
            if (!tz_parse_rule_entry(db, tokens, count))
            {
                return false;
            }
        }
        else if (strcmp(tokens[0], "Zone") == 0)
        {
            if (!tz_parse_zone_entry(db, tokens, count, &current_zone))
            {
                return false;
            }
        }
        else if (strcmp(tokens[0], "Link") == 0)
        {
            current_zone = NULL;
            if (!tz_parse_link_entry(db, tokens, count))
            {
                return false;
            }
        }
        else
        {
            current_zone = NULL;
        }
    }
    return true;
}

static bool tz_collect_transitions(const tz_database_t *db,
                                   const tz_zone_t *zone,
                                   tz_transition_t **out_list,
                                   size_t *out_count,
                                   size_t *out_capacity,
                                   int *initial_offset,
                                   bool *initial_is_dst)
{
    if (!db || !zone || !out_list || !out_count || !out_capacity)
    {
        return false;
    }

    tz_transition_t *list = *out_list;
    size_t count = *out_count;
    size_t capacity = *out_capacity;

    bool initial_set = false;
    int current_save = 0;
    int64_t span_start_local = INT64_MIN / 2;

    for (size_t si = 0; si < zone->span_count; ++si)
    {
        const tz_zone_span_t *span = &zone->spans[si];
        int gmtoff = span->gmtoff_minutes;
        int64_t span_end_local;
        if (span->until.defined)
        {
            int month = span->until.month ? span->until.month : 1;
            int day = span->until.day ? span->until.day : 1;
            int secs = span->until.time.seconds;
            int hour = secs / 3600;
            int minute = (secs % 3600) / 60;
            int second = secs % 60;
            span_end_local = tz_seconds_from_ymd_hms(span->until.year, month, day,
                                                     hour, minute, second);
        }
        else
        {
            span_end_local = INT64_MAX / 2;
        }

        if (!initial_set)
        {
            int base_save = span->fixed_save ? span->fixed_save_minutes : current_save;
            if (initial_offset) *initial_offset = gmtoff + base_save;
            if (initial_is_dst) *initial_is_dst = (base_save != 0);
            initial_set = true;
        }

        if (span->fixed_save)
        {
            current_save = span->fixed_save_minutes;
        }
        else if (span->has_rule_name)
        {
            for (int year = TZBUILD_YEAR_MIN; year <= TZBUILD_YEAR_MAX; ++year)
            {
                int64_t year_start_seconds = tz_seconds_from_ymd(year, 1, 1);
                if (year_start_seconds >= span_end_local)
                {
                    break;
                }
                tz_rule_event_t events[TZBUILD_EVENTS_PER_YEAR];
                size_t event_count = 0;
                for (size_t ri = 0; ri < db->rule_count; ++ri)
                {
                    const tz_rule_t *rule = &db->rules[ri];
                    if (strcmp(rule->name, span->rule_name) != 0)
                    {
                        continue;
                    }
                    if (!tz_rule_applies(rule, year))
                    {
                        continue;
                    }
                    if (event_count >= TZBUILD_EVENTS_PER_YEAR)
                    {
                        return false;
                    }
                    int day = tz_resolve_day_rule(year, rule);
                    int64_t local_seconds = tz_seconds_from_ymd(year, rule->in_month, day);
                    local_seconds += rule->at.seconds;
                    events[event_count].local_seconds = local_seconds;
                    events[event_count].type = rule->at.type;
                    events[event_count].save_minutes = rule->save_minutes;
                    event_count++;
                }

                if (event_count == 0)
                {
                    continue;
                }

                qsort(events, event_count, sizeof(tz_rule_event_t), tz_compare_rule_events);

                for (size_t ei = 0; ei < event_count; ++ei)
                {
                    const tz_rule_event_t *event = &events[ei];
                    int offset_before = 0;
                    switch (event->type)
                    {
                        case TZ_TIME_WALL:
                            offset_before = gmtoff + current_save;
                            break;
                        case TZ_TIME_STANDARD:
                            offset_before = gmtoff;
                            break;
                        case TZ_TIME_UTC:
                            offset_before = 0;
                            break;
                    }
                    int64_t utc_seconds = event->local_seconds - (int64_t)offset_before * 60LL;

                    if (event->local_seconds >= span_start_local && event->local_seconds < span_end_local)
                    {
                        if (utc_seconds >= (TZBUILD_RANGE_START - TZBUILD_UTC_MARGIN) &&
                            utc_seconds <= (TZBUILD_RANGE_END + TZBUILD_UTC_MARGIN))
                        {
                            if (!tz_reserve((void **)&list,
                                            sizeof(tz_transition_t),
                                            &capacity,
                                            count + 1))
                            {
                                return false;
                            }
                            tz_transition_t *tr = &list[count++];
                            tr->utc_seconds = utc_seconds;
                            tr->offset_minutes = gmtoff + event->save_minutes;
                            tr->is_dst = (event->save_minutes != 0);
                        }
                    }

                    current_save = event->save_minutes;
                }
            }
        }

        span_start_local = span_end_local;
    }

    *out_list = list;
    *out_count = count;
    *out_capacity = capacity;
    return true;
}

static bool tz_add_name(char **table, size_t *size, size_t *capacity, const char *name, uint32_t *offset_out)
{
    if (!table || !size || !capacity || !name || !offset_out)
    {
        return false;
    }
    size_t len = strlen(name) + 1;
    if (!tz_reserve((void **)table, sizeof(char), capacity, *size + len))
    {
        return false;
    }
    uint32_t offset = (uint32_t)(*size);
    memcpy(*table + *size, name, len);
    *size += len;
    *offset_out = offset;
    return true;
}

static bool tz_emit_database(shell_state_t *shell, tz_database_t *db)
{
    (void)shell;
    if (!db)
    {
        return false;
    }

    tz_transition_t *transitions = NULL;
    size_t transition_count = 0;
    size_t transition_capacity = 0;

    tzdb_zone_record_t *zone_records = NULL;
    size_t zone_count = 0;
    size_t zone_capacity = 0;

    typedef struct
    {
        const char *name;
        size_t record_index;
    } zone_index_entry_t;

    zone_index_entry_t *zone_index = NULL;
    size_t zone_index_count = 0;
    size_t zone_index_capacity = 0;

    char *name_table = NULL;
    size_t name_table_size = 0;
    size_t name_table_capacity = 0;

    for (size_t i = 0; i < db->zone_count; ++i)
    {
        const tz_zone_t *zone = &db->zones[i];
        size_t start_index = transition_count;
        int initial_offset = 0;
        bool initial_is_dst = false;
        if (!tz_collect_transitions(db,
                                    zone,
                                    &transitions,
                                    &transition_count,
                                    &transition_capacity,
                                    &initial_offset,
                                    &initial_is_dst))
        {
            return false;
        }

        size_t zone_transition_count = transition_count - start_index;
        if (zone_transition_count > 1)
        {
            qsort(transitions + start_index,
                  zone_transition_count,
                  sizeof(tz_transition_t),
                  tz_compare_transitions);
        }

        if (!tz_reserve((void **)&zone_records,
                        sizeof(tzdb_zone_record_t),
                        &zone_capacity,
                        zone_count + 1))
        {
            return false;
        }
        tzdb_zone_record_t *record = &zone_records[zone_count];
        memset(record, 0, sizeof(*record));
        uint32_t name_offset = 0;
        if (!tz_add_name(&name_table, &name_table_size, &name_table_capacity, zone->name, &name_offset))
        {
            return false;
        }
        record->name_offset = name_offset;
        record->transition_index = (uint32_t)start_index;
        record->transition_count = (uint32_t)zone_transition_count;
        record->initial_offset = initial_offset;
        record->initial_is_dst = initial_is_dst ? 1 : 0;

        if (!tz_reserve((void **)&zone_index,
                        sizeof(zone_index_entry_t),
                        &zone_index_capacity,
                        zone_index_count + 1))
        {
            return false;
        }
        zone_index[zone_index_count].name = zone->name;
        zone_index[zone_index_count].record_index = zone_count;
        zone_index_count++;
        zone_count++;
    }

    for (size_t li = 0; li < db->link_count; ++li)
    {
        const tz_link_t *link = &db->links[li];
        size_t target_index = SIZE_MAX;
        for (size_t zi = 0; zi < zone_index_count; ++zi)
        {
            if (strcmp(zone_index[zi].name, link->target) == 0)
            {
                target_index = zone_index[zi].record_index;
                break;
            }
        }
        if (target_index == SIZE_MAX)
        {
            continue;
        }
        if (!tz_reserve((void **)&zone_records,
                        sizeof(tzdb_zone_record_t),
                        &zone_capacity,
                        zone_count + 1))
        {
            return false;
        }
        tzdb_zone_record_t *alias = &zone_records[zone_count];
        *alias = zone_records[target_index];
        uint32_t alias_offset = 0;
        if (!tz_add_name(&name_table, &name_table_size, &name_table_capacity, link->link, &alias_offset))
        {
            return false;
        }
        alias->name_offset = alias_offset;
        zone_count++;
    }

    tzdb_transition_record_t *transition_records = NULL;
    if (transition_count > 0)
    {
        transition_records = malloc(sizeof(tzdb_transition_record_t) * transition_count);
        if (!transition_records)
        {
            return false;
        }
        for (size_t i = 0; i < transition_count; ++i)
        {
            transition_records[i].utc_seconds = transitions[i].utc_seconds;
            transition_records[i].offset_minutes = transitions[i].offset_minutes;
            transition_records[i].is_dst = transitions[i].is_dst ? 1 : 0;
            memset(transition_records[i].reserved, 0, sizeof(transition_records[i].reserved));
        }
    }

    tzdb_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, TZBUILD_HEADER_MAGIC, 4);
    header.version = TZBUILD_VERSION;
    header.flags = 0;
    header.zone_count = (uint32_t)zone_count;
    header.transition_count = (uint32_t)transition_count;
    header.name_table_size = (uint32_t)name_table_size;
    header.range_start = TZBUILD_RANGE_START;
    header.range_end = TZBUILD_RANGE_END;
    if (!tz_parse_manifest_release(header.release, sizeof(header.release)))
    {
        tz_copy_string(header.release, sizeof(header.release), "unknown");
    }

    vfs_node_t *file = vfs_open_file(vfs_root(), TZDB_DATABASE_PATH, true, true);
    if (!file)
    {
        free(transition_records);
        return false;
    }
    vfs_truncate(file);

    if (!vfs_append(file, (const char *)&header, sizeof(header)))
    {
        free(transition_records);
        return false;
    }
    if (zone_count > 0)
    {
        if (!vfs_append(file, (const char *)zone_records, zone_count * sizeof(tzdb_zone_record_t)))
        {
            free(transition_records);
            return false;
        }
    }
    if (transition_count > 0)
    {
        if (!vfs_append(file,
                        (const char *)transition_records,
                        transition_count * sizeof(tzdb_transition_record_t)))
        {
            free(transition_records);
            return false;
        }
    }
    free(transition_records);

    if (name_table_size > 0)
    {
        if (!vfs_append(file, name_table, name_table_size))
        {
            return false;
        }
    }

    free(zone_records);
    free(zone_index);
    free(name_table);
    free(transitions);
    return true;
}
