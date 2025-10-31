#include "shell_commands.h"

#include "libc.h"
#include "types.h"

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

bool shell_cmd_alloc1m(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    const size_t block_size = 1024 * 1024;
    void *ptr = malloc(block_size);
    if (!ptr)
    {
        shell_output_write(out, "allocation failed\n");
        return false;
    }

    char addr_buffer[32];
    format_hex_ptr((uintptr_t)ptr, addr_buffer, sizeof(addr_buffer));

    shell_output_write(out, "Allocated 1 MiB at ");
    shell_output_write(out, addr_buffer);
    shell_output_write(out, "\n");
    return true;
}
