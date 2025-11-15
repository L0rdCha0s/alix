#include "shell.h"
#include "timer.h"
#include "process.h"
#include "libc.h"

static const char loop1_sequence[] = { '0','1','2','3','4','5','6','7','8','9' };
static const char loop2_sequence[] = { 'A','B','C','D','E','F','G','H','I','J' };
static const char letters_sequence[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static bool start_loop(shell_state_t *shell,
                       shell_output_t *out,
                       const char *name,
                       const char *sequence,
                       size_t length,
                       uint64_t delay_ms)
{
    (void)shell;

    if (!sequence || length == 0)
    {
        return shell_output_error(out, "loop: empty sequence");
    }

    static const char prefix[] = "Starting ";
    static const char suffix[] = " (Ctrl-C to stop)\n";
    process_stdout_write(prefix, sizeof(prefix) - 1);
    process_stdout_write(name, strlen(name));
    process_stdout_write(suffix, sizeof(suffix) - 1);

    uint64_t freq = timer_frequency();
    uint64_t delay_ticks = (freq * delay_ms + 999) / 1000;
    if (delay_ticks == 0)
    {
        delay_ticks = 1;
    }

    size_t index = 0;
    while (1)
    {
        char c = sequence[index];
        char line[2] = { c, '\n' };
        process_stdout_write(line, sizeof(line));
        index = (index + 1) % length;

        uint64_t target = timer_ticks() + delay_ticks;
        while (timer_ticks() < target)
        {
            process_yield();
        }
    }

    return true;
}

bool shell_cmd_loop1(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)args;
    return start_loop(shell,
                      out,
                      "loop1",
                      loop1_sequence,
                      sizeof(loop1_sequence),
                      500);
}

bool shell_cmd_loop2(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)args;
    return start_loop(shell,
                      out,
                      "loop2",
                      loop2_sequence,
                      sizeof(loop2_sequence),
                      500);
}

bool shell_cmd_letters(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)args;
    return start_loop(shell,
                      out,
                      "letters",
                      letters_sequence,
                      sizeof(letters_sequence) - 1,
                      200);
}
