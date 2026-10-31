#include "unistd.h"
#include "usyscall.h"
#include "errno.h"

ssize_t readlink(const char *path, char *buffer, size_t capacity)
{
    ssize_t result = sys_readlink(path, buffer, capacity);
    if (result < 0)
    {
        errno = (int)-result;
        return -1;
    }
    return result;
}
