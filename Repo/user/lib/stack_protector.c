#include "types.h"
#include "unistd.h"
#include "usyscall.h"

/* Clang's native Alix target uses this process-wide guard, not an offset in
 * another OS's thread control block. This object is linked only when an
 * instrumented object references the guard or failure handler. */
uintptr_t __stack_chk_guard __attribute__((visibility("hidden")));

__attribute__((noreturn, no_stack_protector))
static void stack_protector_abort(const char *message, size_t length)
{
    /* A damaged stack must not enter allocation, stdio locks or exit handlers. */
    sys_serial_write(message, length);
    sys_exit(127);
}

__attribute__((no_stack_protector))
static void stack_protector_initialize(void)
{
    for (unsigned attempt = 0; attempt < 8; ++attempt)
    {
        if (getentropy(&__stack_chk_guard, sizeof(__stack_chk_guard)) != 0)
        {
            break;
        }
        if (__stack_chk_guard != 0)
        {
            return;
        }
    }
    static const char message[] = "ALIX_STACK_PROTECTOR: entropy unavailable\n";
    stack_protector_abort(message, sizeof(message) - 1);
}

__attribute__((noreturn, no_stack_protector, visibility("hidden")))
void __stack_chk_fail(void)
{
    static const char message[] = "ALIX_STACK_PROTECTOR: stack corruption\n";
    stack_protector_abort(message, sizeof(message) - 1);
}

typedef void (*runtime_hook_t)(void);
/* The linker puts this before every ordinary preinit and constructor entry.
 * crt0 and this object themselves are compiled without instrumentation. */
__attribute__((section(".preinit_array.alix_runtime"), used))
static runtime_hook_t stack_protector_hook = stack_protector_initialize;
