#include "shell_commands.h"

#include "libc.h"
#include "types.h"

static const char *skip_spaces(const char *text)
{
    while (text && *text == ' ')
    {
        ++text;
    }
    return text;
}

static bool parse_hex_ptr(const char *text, uintptr_t *out_value)
{
    if (!text || !out_value)
    {
        return false;
    }

    text = skip_spaces(text);
    if (*text == '\0')
    {
        return false;
    }

    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
    {
        text += 2;
    }

    uintptr_t result = 0;
    size_t digits = 0;

    while (*text)
    {
        char c = *text++;
        uint8_t value;
        if (c >= '0' && c <= '9')
        {
            value = (uint8_t)(c - '0');
        }
        else if (c >= 'a' && c <= 'f')
        {
            value = (uint8_t)(10 + c - 'a');
        }
        else if (c >= 'A' && c <= 'F')
        {
            value = (uint8_t)(10 + c - 'A');
        }
        else if (c == ' ')
        {
            break;
        }
        else
        {
            return false;
        }

        if (digits >= sizeof(uintptr_t) * 2)
        {
            return false;
        }

        result = (result << 4) | value;
        digits++;
    }

    if (digits == 0)
    {
        return false;
    }

    *out_value = result;
    return true;
}

static void format_hex_ptr(uintptr_t value, char *buffer, size_t capacity)
{
    static const char hex_digits[] = "0123456789ABCDEF";
    if (capacity < 19)
    {
        if (capacity > 0)
        {
            buffer[0] = '\0';
        }
        return;
    }

    buffer[0] = '0';
    buffer[1] = 'x';
    for (int i = 0; i < 16; ++i)
    {
        int shift = (15 - i) * 4;
        uint8_t nibble = (uint8_t)((value >> shift) & 0xF);
        buffer[2 + i] = hex_digits[nibble];
    }
    buffer[18] = '\0';
}

bool shell_cmd_free(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;

    uintptr_t address = 0;
    if (!parse_hex_ptr(args, &address))
    {
        shell_output_write(out, "usage: free <address>\n");
        return false;
    }

    void *ptr = (void *)address;
    free(ptr);

    char addr_buffer[32];
    format_hex_ptr(address, addr_buffer, sizeof(addr_buffer));
    shell_output_write(out, "Freed block at ");
    shell_output_write(out, addr_buffer);
    shell_output_write(out, "\n");
    return true;
}
