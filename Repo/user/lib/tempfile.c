#include "errno.h"
#include "fcntl.h"
#include "limits.h"
#include "stdlib.h"
#include "string.h"
#include "sys/random.h"
#include "sys/stat.h"

static int temporary_object(char *path, int suffix, int flags, bool directory)
{
    if (!path || suffix < 0 || (flags & ~(O_CLOEXEC | O_APPEND | O_SYNC)))
    { errno = EINVAL; return -1; }
    size_t length = strnlen(path, PATH_MAX);
    if (length == PATH_MAX) { errno = ENAMETOOLONG; return -1; }
    if ((size_t)suffix > length || length - (size_t)suffix < 6 ||
        memcmp(path + length - (size_t)suffix - 6, "XXXXXX", 6))
    { errno = EINVAL; return -1; }
    char *name = path + length - (size_t)suffix - 6;
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int saved = errno;
    for (unsigned attempt = 0; attempt < 256; ++attempt)
    {
        uint64_t value;
        if (getentropy(&value, sizeof(value))) return -1;
        for (unsigned index = 0; index < 6; ++index)
        { name[index] = alphabet[value % 62]; value /= 62; }
        int result = directory ? mkdir(path, 0700u) :
            open(path, O_RDWR | O_CREAT | O_EXCL | (uint32_t)flags, 0600u);
        if (result >= 0) { errno = saved; return result; }
        if (errno != EEXIST) return -1;
    }
    errno = EEXIST;
    return -1;
}

int mkostemps(char *path, int suffix, int flags)
{ return temporary_object(path, suffix, flags, false); }
int mkstemps(char *path, int suffix) { return mkostemps(path, suffix, 0); }
int mkostemp(char *path, int flags) { return mkostemps(path, 0, flags); }
int mkstemp(char *path) { return mkostemps(path, 0, 0); }
char *mkdtemp(char *path)
{ return temporary_object(path, 0, 0, true) < 0 ? NULL : path; }
