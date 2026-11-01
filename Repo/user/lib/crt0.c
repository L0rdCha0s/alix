#include "types.h"
#include "usyscall.h"
#include "libc.h"

extern int main(int argc, char **argv);
extern int __alix_environment_initialize(char **environment);
extern char __bss_start[];
extern char __bss_end[];
/* This statically linked executable is its own C++ destructor registration
 * domain; no host crtbegin.o is linked into an Alix application. */
void *__dso_handle __attribute__((visibility("hidden"))) = &__dso_handle;

typedef void (*runtime_hook_t)(void);
extern runtime_hook_t __preinit_array_start[];
extern runtime_hook_t __preinit_array_end[];
extern runtime_hook_t __init_array_start[];
extern runtime_hook_t __init_array_end[];

void _start(uint64_t argc, char **argv, char **environment)
{
    /* Zero BSS so globals start in a known state (Doom depends on this). */
    for (char *p = __bss_start; p < __bss_end; ++p)
    {
        *p = 0;
    }

    if (__alix_environment_initialize(environment) != 0) sys_exit(127);
    /* ELF constructors run only after BSS and libc globals are initialized. */
    for (runtime_hook_t *hook = __preinit_array_start; hook < __preinit_array_end; ++hook)
    {
        (*hook)();
    }
    for (runtime_hook_t *hook = __init_array_start; hook < __init_array_end; ++hook)
    {
        (*hook)();
    }

    int status = main((int)argc, argv);

    /* libc centralizes TLS destructors, exit callbacks and finalizer arrays
     * so both returning from main and explicit exit() have the same contract. */
    exit(status);
}
