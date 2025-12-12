#include "types.h"
#include "usyscall.h"

extern int main(int argc, char **argv);
extern char __bss_start[];
extern char __bss_end[];

void _start(uint64_t argc, char **argv)
{
    /* Zero BSS so globals start in a known state (Doom depends on this). */
    for (char *p = __bss_start; p < __bss_end; ++p)
    {
        *p = 0;
    }

    int status = main((int)argc, argv);
    sys_exit(status);
}
