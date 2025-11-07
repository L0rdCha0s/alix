#include "types.h"

extern int main(int argc, char **argv);
extern void sys_exit(int status);

void _start(uint64_t argc, char **argv)
{
    int status = main((int)argc, argv);
    sys_exit(status);
}
