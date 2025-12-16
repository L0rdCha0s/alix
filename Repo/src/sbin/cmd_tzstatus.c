#include "shell_commands.h"

#include "libc.h"
#include "timekeeping.h"
#include "tzdb.h"

static void tzstatus_write_unsigned(shell_output_t *out, size_t value)
{
    char buf[32];
    size_t pos = 0;
    if (value == 0)
    {
        buf[pos++] = '0';
    }
    else
    {
        while (value > 0 && pos < sizeof(buf))
        {
            buf[pos++] = (char)('0' + (value % 10));
            value /= 10;
        }
    }
    for (size_t i = 0; i < pos; ++i)
    {
        char c = buf[pos - 1 - i];
        shell_output_write(out, (char[]){ c, '\0' });
    }
}

static void tzstatus_write_signed(shell_output_t *out, int value)
{
    if (value < 0)
    {
        shell_output_write(out, "-");
        tzstatus_write_unsigned(out, (size_t)(-value));
    }
    else
    {
        tzstatus_write_unsigned(out, (size_t)value);
    }
}

bool shell_cmd_tzstatus(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;
    bool tzdb_available = tzdb_load();
    shell_output_write(out, "tzdb: ");
    if (tzdb_available)
    {
        size_t count = 0;
        tzdb_zones(&count);
        const char *release = tzdb_release();
        shell_output_write(out, "loaded");
        if (release && *release)
        {
            shell_output_write(out, " (");
            shell_output_write(out, release);
            shell_output_write(out, ")");
        }
        shell_output_write(out, ", ");
        tzstatus_write_unsigned(out, count);
        shell_output_write(out, " zones\n");
    }
    else
    {
        shell_output_write(out, "not available\n");
    }

    shell_output_write(out, "Current timezone: ");
    shell_output_write(out, timekeeping_timezone_name());
    if (timekeeping_timezone_has_zone())
    {
        shell_output_write(out, " (tzdb ");
        shell_output_write(out, timekeeping_timezone_zone());
        shell_output_write(out, ")");
    }
    shell_output_write(out, "\n");

    int offset = timekeeping_timezone_offset_minutes();
    shell_output_write(out, "UTC offset: ");
    tzstatus_write_signed(out, offset);
    shell_output_write(out, " minutes\n");
    return true;
}
