#include "shell.h"
#include "timer.h"
#include "process.h"
#include "libc.h"
#include "serial.h"

static const char loop1_sequence[] = { '0','1','2','3','4','5','6','7','8','9' };
static const char loop2_sequence[] = { 'A','B','C','D','E','F','G','H','I','J' };
static const char letters_sequence[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static void letters_handle_char(char c);
static void *g_letters_alloc = NULL;
static const size_t g_letters_alloc_size = (size_t)(1536 * 1024); /* ~1.5 MiB */

static bool start_loop(shell_state_t *shell,
                       shell_output_t *out,
                       const char *name,
                       const char *sequence,
                       size_t length,
                       uint64_t delay_ms,
                       void (*on_char)(char c))
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
        if (on_char)
        {
            on_char(c);
        }
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
                      500,
                      NULL);
}

bool shell_cmd_loop2(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)args;
    return start_loop(shell,
                      out,
                      "loop2",
                      loop2_sequence,
                      sizeof(loop2_sequence),
                      500,
                      NULL);
}

bool shell_cmd_letters(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)args;
    return start_loop(shell,
                      out,
                      "letters",
                      letters_sequence,
                      sizeof(letters_sequence) - 1,
                      200,
                      letters_handle_char);
}

static void letters_child_thread(void *arg)
{
    (void)arg;
    serial_printf("%s", "<Child>\r\n");
    process_sleep_ms(2000);
    serial_printf("%s", "<EndChild>\r\n");
    process_exit(0);
}

static void letters_handle_char(char c)
{
    switch (c)
    {
        case 'J':
        {
            process_t *child = process_create_kernel("letters_child",
                                                     letters_child_thread,
                                                     NULL,
                                                     PROCESS_DEFAULT_STACK_SIZE,
                                                     process_current_stdout_fd());
            (void)child;
            break;
        }
        case 'M':
        {
            if (!g_letters_alloc)
            {
                g_letters_alloc = malloc(g_letters_alloc_size);
                if (g_letters_alloc)
                {
                    memset(g_letters_alloc, 0x5A, g_letters_alloc_size);
                }
            }
            break;
        }
        case 'Q':
        {
            if (g_letters_alloc)
            {
                free(g_letters_alloc);
                g_letters_alloc = NULL;
            }
            break;
        }
        default:
            break;
    }
}
