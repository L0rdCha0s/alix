#include "userlib.h"
#include "usyscall.h"

static const char loop1_sequence[] = { '0','1','2','3','4','5','6','7','8','9' };
static const char loop2_sequence[] = { 'A','B','C','D','E','F','G','H','I','J' };
static const char letters_sequence[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static void *g_letters_alloc = NULL;
static const size_t g_letters_alloc_size = (size_t)(1536 * 1024); /* ~1.5 MiB */

static void delay_yield(uint64_t iterations)
{
    for (uint64_t i = 0; i < iterations; ++i)
    {
        int rc = sys_yield();
        if (rc != 0)
        {
            /* Fallback to a short busy pause if the syscall fails. */
            for (volatile int j = 0; j < 1000; ++j)
            {
            }
            const char msg[] = "[loop] sys_yield failed\n";
            sys_serial_write(msg, sizeof(msg) - 1);
        }
    }
}

static void letters_handle_char(char c)
{
    switch (c)
    {
        case 'J':
        {
            const char msg[] = "<user_loop child stub>\n";
            sys_serial_write(msg, sizeof(msg) - 1);
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

static void usage(void)
{
    const char msg[] = "usage: loop [loop1|loop2|letters]\n";
    write(1, msg, sizeof(msg) - 1);
}

int main(int argc, char **argv)
{
    const char *mode = (argc >= 2) ? argv[1] : "loop1";
    const char *seq = loop1_sequence;
    size_t seq_len = sizeof(loop1_sequence);
    void (*on_char)(char) = NULL;
    int serial_budget = 16; /* limit serial spam to first few iterations */

    if (strcmp(mode, "loop1") == 0)
    {
        seq = loop1_sequence;
        seq_len = sizeof(loop1_sequence);
    }
    else if (strcmp(mode, "loop2") == 0)
    {
        seq = loop2_sequence;
        seq_len = sizeof(loop2_sequence);
    }
    else if (strcmp(mode, "letters") == 0)
    {
        seq = letters_sequence;
        seq_len = sizeof(letters_sequence) - 1;
        on_char = letters_handle_char;
    }
    else
    {
        usage();
        return 1;
    }

    const char *prefix = "Starting loop (Ctrl-C to stop)\n";
    write(1, prefix, strlen(prefix));

    size_t index = 0;
    while (1)
    {
        char c = seq[index];
        char line[2] = { c, '\n' };
        sys_serial_write(line, sizeof(line));
        write(1, line, sizeof(line));
        if (serial_budget > 0) serial_budget--;
        if (on_char)
        {
            on_char(c);
        }
        index = (index + 1) % seq_len;

        delay_yield(1);
    }
}
