#include "types.h"
#include "usyscall.h"

extern int main(int argc, char **argv);

void _start(void)
{
    int status = main(0, NULL);
    sys_exit(status);
}
