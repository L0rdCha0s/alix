#include "shell.h"

#include "process.h"
#include "serial.h"
#include "libc.h"

static void write_decimal(shell_output_t *out, uint64_t value)
{
    char digits[32];
    size_t count = 0;
    if (value == 0)
    {
        digits[count++] = '0';
    }
    else
    {
        while (value > 0 && count < sizeof(digits))
        {
            digits[count++] = (char)('0' + (value % 10ULL));
            value /= 10ULL;
        }
    }

    char buffer[32];
    size_t idx = 0;
    while (count > 0 && idx < sizeof(buffer) - 1)
    {
        buffer[idx++] = digits[--count];
    }
    buffer[idx] = '\0';
    shell_output_write(out, buffer);
}

static void write_hex(shell_output_t *out, uint64_t value)
{
    char buffer[17];
    for (int i = 15; i >= 0; --i)
    {
        uint8_t nibble = (uint8_t)(value & 0xFULL);
        buffer[i] = (char)(nibble < 10 ? ('0' + nibble) : ('A' + (nibble - 10)));
        value >>= 4;
    }
    buffer[16] = '\0';
    shell_output_write(out, buffer);
}

static bool spawn_user_demo(shell_output_t *out, const char *name_tag)
{
    process_t *proc = process_create_user_dummy(name_tag, -1);
    if (!proc)
    {
        return shell_output_error(out, "userdemo: failed to create user process");
    }

    process_user_layout_t layout;
    bool have_layout = process_query_user_layout(proc, &layout);

    shell_output_write(out, "userdemo: spawned pid=");
    write_decimal(out, process_get_pid(proc));
    shell_output_write(out, " entry=0x");
    write_hex(out, have_layout ? layout.entry_point : 0);
    shell_output_write(out, " stack_top=0x");
    write_hex(out, have_layout ? layout.stack_top : 0);
    shell_output_write(out, " stack_size=");
    write_decimal(out, have_layout ? layout.stack_size : 0);
    shell_output_write(out, " cr3=0x");
    write_hex(out, have_layout ? layout.cr3 : 0);
    shell_output_write(out, "\n");

    serial_write_string("userdemo: pid=");
    serial_write_hex64(process_get_pid(proc));
    serial_write_string(" entry=0x");
    serial_write_hex64(have_layout ? layout.entry_point : 0);
    serial_write_string(" stack_top=0x");
    serial_write_hex64(have_layout ? layout.stack_top : 0);
    serial_write_string(" cr3=0x");
    serial_write_hex64(have_layout ? layout.cr3 : 0);
    serial_write_string("\r\n");

    return true;
}

static const char *skip_spaces(const char *text)
{
    while (text && *text == ' ')
    {
        ++text;
    }
    return text;
}

static bool parse_count(const char *args, size_t *count_out)
{
    if (!count_out)
    {
        return false;
    }
    *count_out = 1;

    args = skip_spaces(args);
    if (!args || *args == '\0')
    {
        return true;
    }

    size_t value = 0;
    while (*args)
    {
        char c = *args++;
        if (c < '0' || c > '9')
        {
            return false;
        }
        value = value * 10 + (size_t)(c - '0');
        if (value > 32)
        {
            value = 32;
            break;
        }
    }

    if (value == 0)
    {
        value = 1;
    }
    *count_out = value;
    return true;
}

bool shell_cmd_userdemo(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;

    size_t count = 1;
    if (!parse_count(args ? args : "", &count))
    {
        return shell_output_error(out, "userdemo: invalid count (expected positive integer)");
    }

    for (size_t i = 0; i < count; ++i)
    {
        if (!spawn_user_demo(out, "user_demo_cli"))
        {
            return false;
        }
    }

    return true;
}
