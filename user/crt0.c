#include "types.h"
#include "usyscall.h"

extern int main(int argc, char **argv);

void _start(uint64_t argc, char **argv)
{
    int status = main((int)argc, argv);
    sys_exit(status);
}
