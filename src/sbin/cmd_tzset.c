#include "shell_commands.h"

#include "libc.h"
#include "timekeeping.h"

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
    shell_output_write(out, " (UTC offset ");
    int offset = timekeeping_timezone_offset_minutes();
    tzset_write_offset(out, offset);
    shell_output_write(out, ")\n");
}

static void tzset_print_options(shell_output_t *out)
{
    shell_output_write(out, "Available timezones:\n");
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
    shell_output_write(out, "Usage: tzset <name> or tzset list\n");
}

bool shell_cmd_tzset(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    const char *trimmed = tzset_skip_spaces(args);
    if (*trimmed == '\0' || tzset_equal_ignore_case(trimmed, "list"))
    {
        tzset_print_current(out);
        tzset_print_options(out);
        return true;
    }

    const tzset_option_t *option = tzset_find_option(trimmed);
    if (!option)
    {
        shell_output_write(out, "Unknown timezone. Run 'tzset list' for options.\n");
        return false;
    }

    timekeeping_timezone_spec_t spec = {
        .name = option->name,
        .standard_offset_minutes = option->offset_minutes,
        .dst_enabled = option->dst_enabled,
        .dst_offset_minutes = option->dst_offset_minutes,
        .dst_start = option->dst_start,
        .dst_end = option->dst_end
    };
    if (!timekeeping_save_timezone_spec(&spec))
    {
        shell_output_write(out, "Failed to update timezone.\n");
        return false;
    }

    shell_output_write(out, "Timezone updated to ");
    shell_output_write(out, option->name);
    shell_output_write(out, ".\n");
    return true;
}
