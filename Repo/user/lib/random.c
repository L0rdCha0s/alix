#include "sys/random.h"
#include "usyscall.h"
#include "errno.h"

ssize_t getrandom(void *buffer, size_t length, unsigned int flags)
{
    ssize_t result = sys_getrandom(buffer, length, flags);
    if (result < 0)
    {
        errno = (int)-result;
        return -1;
    }
    return result;
}

int getentropy(void *buffer, size_t length)
{
    if (length > 256u)
    {
        errno = EIO;
        return -1;
    }
    if (length != 0 && !buffer)
    {
        errno = EFAULT;
        return -1;
    }
    size_t filled = 0;
    while (filled < length)
    {
        ssize_t count = getrandom((uint8_t *)buffer + filled, length - filled, 0);
        if (count < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (count == 0 || (size_t)count > length - filled)
        {
            errno = EIO;
            return -1;
        }
        filled += (size_t)count;
    }
    return 0;
}
