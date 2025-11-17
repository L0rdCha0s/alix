#include "shell_commands.h"

#include "libc.h"
#include "timekeeping.h"
#include "tzdb.h"

typedef struct
{
    const char *name;
    int offset_minutes;
    const char *description;
    bool dst_enabled;
    int dst_offset_minutes;
    timekeeping_dst_rule_t dst_start;
    timekeeping_dst_rule_t dst_end;
} tzset_option_t;

static const timekeeping_dst_rule_t TZ_DST_START_US = { 3, 2, 0, 120 };
static const timekeeping_dst_rule_t TZ_DST_END_US   = { 11, 1, 0, 120 };

static const tzset_option_t g_tz_options[] = {
    { "UTC-8",  -480, "Pacific Time", true,  -420, TZ_DST_START_US, TZ_DST_END_US },
    { "UTC-7",  -420, "Mountain Time", true, -360, TZ_DST_START_US, TZ_DST_END_US },
    { "UTC-6",  -360, "Central Time", true,  -300, TZ_DST_START_US, TZ_DST_END_US },
    { "UTC-5",  -300, "Eastern Time", true,  -240, TZ_DST_START_US, TZ_DST_END_US },
    { "UTC-4",  -240, "Atlantic Time", false, -240, {0}, {0} },
    { "UTC",       0, "Coordinated Universal Time", false, 0, {0}, {0} },
    { "UTC+1",   60, "Central European Time", false, 60, {0}, {0} },
    { "UTC+2",  120, "Eastern European Time", false, 120, {0}, {0} },
    { "UTC+3",  180, "Moscow Time", false, 180, {0}, {0} },
    { "UTC+5:30", 330, "India Standard Time", false, 330, {0}, {0} },
    { "UTC+8",  480, "China Standard Time", false, 480, {0}, {0} },
    { "UTC+9",  540, "Japan Standard Time", false, 540, {0}, {0} },
    { "UTC+10", 600, "Australian Eastern Time", false, 600, {0}, {0} }
};

static const char *tzset_skip_spaces(const char *text)
{
    if (!text)
    {
        return "";
    }
    while (*text == ' ' || *text == '\t')
    {
        ++text;
    }
    return text;
}

static bool tzset_equal_ignore_case(const char *a, const char *b)
{
    if (!a || !b)
    {
        return false;
    }
    while (*a && *b)
    {
        char ca = *a;
        char cb = *b;
        if (ca >= 'a' && ca <= 'z')
        {
            ca = (char)(ca - ('a' - 'A'));
        }
        if (cb >= 'a' && cb <= 'z')
        {
            cb = (char)(cb - ('a' - 'A'));
        }
        if (ca != cb)
        {
            return false;
        }
        ++a;
        ++b;
    }
    return (*a == '\0' && *b == '\0');
}

static bool tzset_prefix_ignore_case(const char *text, const char *prefix)
{
    if (!text || !prefix)
    {
        return false;
    }
    while (*prefix)
    {
        char ct = *text;
        char cp = *prefix;
        if (ct >= 'a' && ct <= 'z') ct = (char)(ct - ('a' - 'A'));
        if (cp >= 'a' && cp <= 'z') cp = (char)(cp - ('a' - 'A'));
        if (ct != cp)
        {
            return false;
        }
        ++text;
        ++prefix;
    }
    return true;
}

static bool tzset_contains_ignore_case(const char *text, const char *needle)
{
    if (!text || !needle || *needle == '\0')
    {
        return true;
    }
    size_t needle_len = strlen(needle);
    for (const char *cursor = text; *cursor; ++cursor)
    {
        if ((size_t)(text + strlen(text) - cursor) < needle_len)
        {
            break;
        }
        bool match = true;
        for (size_t i = 0; i < needle_len; ++i)
        {
            char ct = cursor[i];
            char cn = needle[i];
            if (ct >= 'a' && ct <= 'z') ct = (char)(ct - ('a' - 'A'));
            if (cn >= 'a' && cn <= 'z') cn = (char)(cn - ('a' - 'A'));
            if (ct != cn)
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            return true;
        }
    }
    return false;
}

static bool tzset_parse_int(const char *text, int *value)
{
    if (!text || !value || *text == '\0')
    {
        return false;
    }
    int sign = 1;
    size_t idx = 0;
    if (text[idx] == '+' || text[idx] == '-')
    {
        sign = (text[idx] == '-') ? -1 : 1;
        idx++;
    }
    if (text[idx] == '\0')
    {
        return false;
    }
    int result = 0;
    for (; text[idx]; ++idx)
    {
        char c = text[idx];
        if (c < '0' || c > '9')
        {
            return false;
        }
        result = result * 10 + (c - '0');
    }
    *value = result * sign;
    return true;
}

static void tzset_copy_string(char *dest, size_t capacity, const char *src)
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

static const tzset_option_t *tzset_find_option(const char *name)
{
    if (!name || *name == '\0')
    {
        return NULL;
    }
    for (size_t i = 0; i < sizeof(g_tz_options) / sizeof(g_tz_options[0]); ++i)
    {
        if (tzset_equal_ignore_case(name, g_tz_options[i].name))
        {
            return &g_tz_options[i];
        }
    }
    return NULL;
}

static size_t tzset_format_unsigned(char *buffer, size_t capacity, unsigned value)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }
    char tmp[16];
    size_t tmp_len = 0;
    do
    {
        tmp[tmp_len++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value > 0 && tmp_len < sizeof(tmp));

    size_t out_len = 0;
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

static void tzset_write_offset(shell_output_t *out, int offset_minutes)
{
    char tmp[16];
    size_t pos = 0;
    tmp[pos++] = (offset_minutes >= 0) ? '+' : '-';
    int hours = offset_minutes / 60;
    if (hours < 0)
    {
        hours = -hours;
    }
    pos += tzset_format_unsigned(tmp + pos, sizeof(tmp) - pos, (unsigned)hours);
    int minutes = offset_minutes % 60;
    if (minutes < 0)
    {
        minutes = -minutes;
    }
    if (offset_minutes % 60 != 0 && pos + 3 < sizeof(tmp))
    {
        tmp[pos++] = ':';
        tmp[pos++] = (char)('0' + (minutes / 10));
        tmp[pos++] = (char)('0' + (minutes % 10));
    }
    tmp[pos] = '\0';
    shell_output_write(out, tmp);
}

static void tzset_print_current(shell_output_t *out)
{
    shell_output_write(out, "Current timezone: ");
    shell_output_write(out, timekeeping_timezone_name());
    if (timekeeping_timezone_has_zone())
    {
        shell_output_write(out, " (tzdb ");
        shell_output_write(out, timekeeping_timezone_zone());
        shell_output_write(out, ")");
    }
    shell_output_write(out, " (UTC offset ");
    int offset = timekeeping_timezone_offset_minutes();
    tzset_write_offset(out, offset);
    shell_output_write(out, ")\n");
}

static void tzset_print_legacy_options(shell_output_t *out);

static void tzset_list_zones(shell_output_t *out, const char *filter)
{
    if (!tzdb_load())
    {
        shell_output_write(out, "tzdb database not available. Showing legacy presets.\n");
        tzset_print_legacy_options(out);
        return;
    }
    size_t count = 0;
    const tzdb_zone_t *zones = tzdb_zones(&count);
    shell_output_write(out, "Available tzdb zones");
    if (filter && *filter)
    {
        shell_output_write(out, " matching '");
        shell_output_write(out, filter);
        shell_output_write(out, "'");
    }
    shell_output_write(out, ":\n");
    size_t matches = 0;
    for (size_t i = 0; i < count; ++i)
    {
        if (!filter || *filter == '\0' || tzset_contains_ignore_case(zones[i].name, filter))
        {
            shell_output_write(out, "  ");
            shell_output_write(out, zones[i].name);
            shell_output_write(out, "\n");
            matches++;
        }
    }
    if (matches == 0)
    {
        shell_output_write(out, "  (no matches)\n");
    }
}

static void tzset_print_legacy_options(shell_output_t *out)
{
    shell_output_write(out, "Legacy timezone presets:\n");
    for (size_t i = 0; i < sizeof(g_tz_options) / sizeof(g_tz_options[0]); ++i)
    {
        const tzset_option_t *opt = &g_tz_options[i];
        shell_output_write(out, "  ");
        shell_output_write(out, opt->name);
        if (opt->dst_enabled)
        {
            shell_output_write(out, " (DST)");
        }
        shell_output_write(out, " - ");
        shell_output_write(out, opt->description);
        shell_output_write(out, "\n");
    }
    shell_output_write(out, "Usage: tzset <name>, tzset list [filter], or tzset legacy <preset> [dst_offset_minutes]\n");
}

bool shell_cmd_tzset(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    const char *trimmed = tzset_skip_spaces(args);
    if (*trimmed == '\0')
    {
        tzset_print_current(out);
        shell_output_write(out, "Use 'tzset list [filter]' to browse tzdb zones or 'tzset legacy <name>' for presets.\n");
        return true;
    }

    if (tzset_equal_ignore_case(trimmed, "list") ||
        (tzset_prefix_ignore_case(trimmed, "list") &&
         (trimmed[4] == ' ' || trimmed[4] == '\t')))
    {
        const char *filter = trimmed + 4;
        if (tzset_prefix_ignore_case(trimmed, "list") &&
            (trimmed[4] == ' ' || trimmed[4] == '\t'))
        {
            filter = tzset_skip_spaces(trimmed + 4);
        }
        else
        {
            filter = "";
        }
        tzset_list_zones(out, filter);
        return true;
    }

    bool legacy_mode = false;
    if (tzset_equal_ignore_case(trimmed, "legacy") ||
        (tzset_prefix_ignore_case(trimmed, "legacy") &&
         (trimmed[6] == ' ' || trimmed[6] == '\t')))
    {
        legacy_mode = true;
        trimmed = tzset_skip_spaces(trimmed + 6);
        if (*trimmed == '\0')
        {
            tzset_print_legacy_options(out);
            return true;
        }
    }

    const char *name_start = trimmed;
    const char *name_end = name_start;
    while (*name_end && *name_end != ' ' && *name_end != '\t')
    {
        ++name_end;
    }
    if (name_end == name_start)
    {
        shell_output_write(out, "Usage: tzset <name> [dst_offset_minutes]\n");
        return false;
    }

    char tz_name[TIMEKEEPING_TZ_NAME_MAX];
    size_t name_len = (size_t)(name_end - name_start);
    if (name_len >= sizeof(tz_name))
    {
        name_len = sizeof(tz_name) - 1;
    }
    memcpy(tz_name, name_start, name_len);
    tz_name[name_len] = '\0';

    const char *dst_arg = tzset_skip_spaces(name_end);
    bool has_dst_override = (*dst_arg != '\0');
    int dst_override_minutes = 0;
    if (has_dst_override)
    {
        if (!tzset_parse_int(dst_arg, &dst_override_minutes) ||
            !timekeeping_is_valid_timezone_offset(dst_override_minutes))
        {
            shell_output_write(out, "Invalid DST offset. Provide minutes relative to UTC (e.g., -240).\n");
            return false;
        }
    }

    if (!legacy_mode && tzdb_load())
    {
        const tzdb_zone_t *zone = tzdb_find_zone(tz_name);
        if (zone)
        {
            if (has_dst_override)
            {
                shell_output_write(out, "DST offset overrides are only supported for legacy presets.\n");
                return false;
            }
            timekeeping_timezone_spec_t spec;
            memset(&spec, 0, sizeof(spec));
            tzset_copy_string(spec.name, sizeof(spec.name), zone->name);
            spec.standard_offset_minutes = zone->initial_offset_minutes;
            spec.dst_enabled = false;
            spec.dst_offset_minutes = spec.standard_offset_minutes;
            spec.use_zone = true;
            tzset_copy_string(spec.zone_name, sizeof(spec.zone_name), zone->name);
            if (!timekeeping_save_timezone_spec(&spec))
            {
                shell_output_write(out, "Failed to update timezone.\n");
                return false;
            }
            shell_output_write(out, "Timezone updated to ");
            shell_output_write(out, zone->name);
            shell_output_write(out, " via tzdb.\n");
            return true;
        }
    }

    const tzset_option_t *option = tzset_find_option(tz_name);
    if (!option)
    {
        shell_output_write(out, "Unknown timezone. Use 'tzset list' or 'tzset legacy <name>'.\n");
        return false;
    }

    timekeeping_timezone_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    tzset_copy_string(spec.name, sizeof(spec.name), option->name);
    spec.standard_offset_minutes = option->offset_minutes;
    spec.dst_enabled = option->dst_enabled;
    spec.dst_offset_minutes = option->dst_offset_minutes;
    spec.dst_start = option->dst_start;
    spec.dst_end = option->dst_end;
    spec.use_zone = false;
    if (has_dst_override)
    {
        if (!option->dst_enabled)
        {
            shell_output_write(out, "DST offset overrides require a preset with DST rules.\n");
            return false;
        }
        if (dst_override_minutes == spec.standard_offset_minutes)
        {
            shell_output_write(out, "DST offset must differ from the standard offset.\n");
            return false;
        }
        spec.dst_offset_minutes = dst_override_minutes;
        spec.dst_enabled = true;
    }
    if (!timekeeping_save_timezone_spec(&spec))
    {
        shell_output_write(out, "Failed to update timezone.\n");
        return false;
    }

    shell_output_write(out, "Timezone updated to ");
    shell_output_write(out, option->name);
    if (has_dst_override && spec.dst_enabled)
    {
        shell_output_write(out, " (DST offset ");
        tzset_write_offset(out, spec.dst_offset_minutes);
        shell_output_write(out, ")");
    }
    shell_output_write(out, ".\n");
    return true;
}
