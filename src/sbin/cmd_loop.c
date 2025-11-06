#include "shell.h"
#include "timer.h"
#include "process.h"
#include "libc.h"

static const char loop1_sequence[] = { '0','1','2','3','4','5','6','7','8','9' };
static const char loop2_sequence[] = { 'A','B','C','D','E','F','G','H','I','J' };

typedef struct loop_context
{
    const char *sequence;
    size_t length;
} loop_context_t;

static void shell_output_write_u64(shell_output_t *out, uint64_t value)
{
    char buf[21];
    size_t pos = 0;
    if (value == 0)
    {
        buf[pos++] = '0';
    }
    else
    {
        char tmp[21];
        size_t tpos = 0;
        while (value && tpos < sizeof(tmp))
        {
            tmp[tpos++] = (char)('0' + (value % 10));
            value /= 10;
        }
        while (tpos > 0)
        {
            buf[pos++] = tmp[--tpos];
        }
    }
    shell_output_write_len(out, buf, pos);
}

static void loop_process_entry(void *arg)
{
    loop_context_t *ctx = (loop_context_t *)arg;
    if (!ctx || !ctx->sequence || ctx->length == 0)
    {
        process_exit(0);
    }

    const char *seq = ctx->sequence;
    size_t length = ctx->length;
    free(ctx);

    uint64_t freq = timer_frequency();
    uint64_t delay_ticks = (freq * 500 + 999) / 1000;
    if (delay_ticks == 0)
    {
        delay_ticks = 1;
    }

    size_t index = 0;
    while (1)
    {
        char c = seq[index];
        char line[2] = { c, '\n' };
        process_stdout_write(line, sizeof(line));

        index = (index + 1) % length;

        uint64_t target = timer_ticks() + delay_ticks;
        while (timer_ticks() < target)
        {
            process_yield();
        }
    }
}

static bool start_loop(shell_state_t *shell,
                       shell_output_t *out,
                       const char *name,
                       const char *sequence,
                       size_t length)
{
    loop_context_t *ctx = (loop_context_t *)malloc(sizeof(loop_context_t));
    if (!ctx)
    {
        return shell_output_error(out, "loop: allocation failed");
    }
    ctx->sequence = sequence;
    ctx->length = length;

    process_t *proc = process_create_kernel(name,
                                            loop_process_entry,
                                            ctx,
                                            0,
                                            shell ? shell->stdout_fd : -1);
    if (!proc)
    {
        free(ctx);
        return shell_output_error(out, "loop: failed to start process");
    }

    shell_output_write(out, "Started ");
    shell_output_write(out, name);
    shell_output_write(out, " (pid ");
    uint64_t loop_pid_val = process_get_pid(proc);
    if (loop_pid_val == 0)
    {
        shell_output_write(out, "?");
    }
    else
    {
        shell_output_write_u64(out, loop_pid_val);
    }
    shell_output_write(out, ")\n");
    return true;
}

bool shell_cmd_loop1(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)args;
    return start_loop(shell, out, "loop1", loop1_sequence, sizeof(loop1_sequence));
}

bool shell_cmd_loop2(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)args;
    return start_loop(shell, out, "loop2", loop2_sequence, sizeof(loop2_sequence));
}
