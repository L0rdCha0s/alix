#include "stdio.h"
#include "unistd.h"
#include "stdlib.h"
#include "errno.h"
#include "sys/stat.h"
#include "usyscall.h"

static uint64_t temporary_sequence;

char *tmpnam(char *output)
{
    static _Thread_local char internal[L_tmpnam];
    if (!output) output = internal;
    for (;;)
    {
        uint64_t sequence = __atomic_add_fetch(&temporary_sequence, 1, __ATOMIC_RELAXED);
        if (sequence > TMP_MAX) { errno = EEXIST; return NULL; }
        int length = snprintf(output, L_tmpnam, "/tmp/alix-%ld-%llu.tmp",
                              (long)getpid(), (unsigned long long)sequence);
        if (length < 0 || length >= L_tmpnam) { errno = ENAMETOOLONG; return NULL; }
        struct stat metadata;
        if (stat(output, &metadata))
        {
            if (errno == ENOENT) return output;
            return NULL;
        }
    }
}

FILE *tmpfile(void)
{
    char *path = malloc(L_tmpnam);
    if (!path) { errno = ENOMEM; return NULL; }
    FILE *stream = NULL;
    for (;;)
    {
        if (!tmpnam(path)) break;
        stream = fopen(path, "w+bx");
        if (!stream)
        {
            if (errno == EEXIST) continue;
            break;
        }
        /* The retained open node survives removal; no cleanup callback or
         * pointer into this call's storage is needed at process termination. */
        if (remove(path))
        {
            int error = errno;
            (void)fclose(stream);
            errno = error;
            stream = NULL;
        }
        break;
    }
    free(path);
    return stream;
}

int rename(const char *old_path, const char *new_path)
{
    int64_t result = sys_file_io(SYSCALL_FILE_RENAME, (uintptr_t)old_path, (uintptr_t)new_path, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
