#include "shell.h"
#include "process.h"
#include "libc.h"

static void u64_to_str(uint64_t value, char *buffer, size_t buffer_len)
{
    if (!buffer || buffer_len == 0)
    {
        return;
    }
    char tmp[21];
    size_t pos = 0;
    do
    {
        tmp[pos++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value != 0 && pos < sizeof(tmp));

    size_t out = 0;
    while (out < pos && out + 1 < buffer_len)
    {
        buffer[out] = tmp[pos - 1 - out];
        out++;
    }
    buffer[out] = '\0';
}

bool shell_cmd_top(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    process_info_t infos[32];
    size_t count = process_snapshot(infos, sizeof(infos) / sizeof(infos[0]));

    shell_output_write(out, "PID  STATE     THR  CUR OUT NAME             THREAD           REM\n");

    for (size_t i = 0; i < count; ++i)
    {
        const process_info_t *info = &infos[i];
        char pid_buf[32];
        u64_to_str(info->pid, pid_buf, sizeof(pid_buf));

        char rem_buf[32];
        u64_to_str(info->time_slice_remaining, rem_buf, sizeof(rem_buf));

        char out_buf[16];
        if (info->stdout_fd < 0)
        {
            out_buf[0] = '-';
            out_buf[1] = '\0';
        }
        else
        {
            u64_to_str((uint64_t)info->stdout_fd, out_buf, sizeof(out_buf));
        }

        shell_output_write(out, info->is_current ? "* " : "  ");
        shell_output_write(out, pid_buf);
        shell_output_write(out, "  ");
        shell_output_write(out, process_state_name(info->state));
        shell_output_write(out, "  ");
        shell_output_write(out, thread_state_name(info->thread_state));
        shell_output_write(out, "  ");
        shell_output_write(out, info->is_idle ? "idle " : "     ");
        shell_output_write(out, "  ");
        shell_output_write(out, out_buf);
        shell_output_write(out, "  ");
        shell_output_write(out, info->name);
        shell_output_write(out, "  ");
        shell_output_write(out, info->thread_name);
        shell_output_write(out, "  ");
        shell_output_write(out, rem_buf);
        shell_output_write(out, "\n");
    }

    return true;
}
