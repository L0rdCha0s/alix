#include "sys/ioctl.h"
#include "usyscall.h"
#include "errno.h"
#include <stdarg.h>

int ioctl(int fd, unsigned long request, ...)
{
#ifndef ALIX_OWNED_FDS
    (void)fd; (void)request; errno = ENOTSUP; return -1;
#else
    void *argument = NULL;
    size_t bytes = 0;
    if (request == FIONREAD || request == FIONBIO)
    {
        va_list arguments; va_start(arguments, request);
        argument = va_arg(arguments, void *); va_end(arguments);
        bytes = sizeof(int32_t);
    }
    int64_t result = sys_file_io(SYSCALL_FILE_IOCTL, (uint64_t)(int64_t)fd,
                                  request, (uintptr_t)argument, bytes);
    if (result < 0) { errno = (int)-result; return -1; }
    return (int)result;
#endif
}
