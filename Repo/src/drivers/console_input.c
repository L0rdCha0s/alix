#include "console_input.h"

static wait_queue_t g_console_input_waiters;

void console_input_init(void)
{
    wait_queue_init(&g_console_input_waiters);
}

void console_input_wake(void)
{
    wait_queue_wake_all(&g_console_input_waiters);
}

void console_input_wait(wait_queue_predicate_t predicate, void *context)
{
    wait_queue_wait(&g_console_input_waiters, predicate, context);
}

bool console_input_wait_timeout(wait_queue_predicate_t predicate,
                                void *context,
                                uint64_t timeout_ticks)
{
    return wait_queue_wait_timeout(&g_console_input_waiters, predicate, context, timeout_ticks);
}
