#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "libc.h"
#include "usyscall.h"
#include "errno.h"

size_t strspn(const char *text, const char *accept)
{
    size_t length = 0;
    while (text[length] && strchr(accept, (unsigned char)text[length])) ++length;
    return length;
}
size_t strcspn(const char *text, const char *reject)
{
    size_t length = 0;
    while (text[length] && !strchr(reject, (unsigned char)text[length])) ++length;
    return length;
}
char *strpbrk(const char *text, const char *accept)
{
    text += strcspn(text, accept);
    return *text ? (char *)text : NULL;
}
char *strtok_r(char *text, const char *delimiters, char **saved)
{
    if (!text) text = *saved;
    if (!text) return NULL;
    text += strspn(text, delimiters);
    if (!*text) { *saved = NULL; return NULL; }
    char *end = text + strcspn(text, delimiters);
    if (*end) { *end = 0; *saved = end + 1; } else *saved = NULL;
    return text;
}
char *strtok(char *text, const char *delimiters)
{
    static _Thread_local char *saved;
    return strtok_r(text, delimiters, &saved);
}

typedef struct quick_handler { struct quick_handler *next; void (*function)(void); } quick_handler_t;
static quick_handler_t *quick_handlers;
static alix_mutex_t quick_mutex;
static uint64_t quick_owner;
static volatile uint32_t quick_active;

int at_quick_exit(void (*function)(void))
{
    quick_handler_t *handler = malloc(sizeof(*handler));
    if (!handler) return -1;
    handler->function = function;
    alix_mutex_lock(&quick_mutex);
    handler->next = quick_handlers;
    quick_handlers = handler;
    alix_mutex_unlock(&quick_mutex);
    return 0;
}
void quick_exit(int status)
{
    uint64_t expected = 0, self = alix_thread_self();
    if (!__atomic_compare_exchange_n(&quick_owner, &expected, self, false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) && expected != self)
    {
        __atomic_store_n(&quick_active, 1, __ATOMIC_RELEASE);
        for (;;) (void)sys_futex_wait(&quick_active, 1, SYSCALL_FUTEX_WAIT_FOREVER);
    }
    for (;;)
    {
        alix_mutex_lock(&quick_mutex);
        quick_handler_t *handler = quick_handlers;
        if (handler) quick_handlers = handler->next;
        alix_mutex_unlock(&quick_mutex);
        if (!handler) break;
        void (*function)(void) = handler->function;
        free(handler);
        function();
    }
    _Exit(status);
}

int system(const char *command)
{
    int shell = sys_shell_open();
    if (!command)
    {
        if (shell >= 0) (void)sys_shell_close(shell);
        return shell >= 0;
    }
    if (shell < 0) { errno = EAGAIN; return -1; }
    char *output = malloc(4096);
    if (!output) { (void)sys_shell_close(shell); errno = ENOMEM; return -1; }
    int status = -1, running = 1;
    if (sys_shell_exec(shell, command, strlen(command)) < 0) running = 0;
    while (running)
    {
        ssize_t count = sys_shell_poll(shell, output, 4096, &status, &running);
        if (count < 0) { status = -1; break; }
        if (count) (void)fwrite(output, 1, (size_t)count, stdout);
        if (running) (void)sys_sleep_ms(1);
    }
    (void)sys_shell_close(shell);
    free(output);
    return status < 0 ? -1 : (status & 255) << 8;
}
