#include "sys/mman.h"
#include "usyscall.h"
#include "errno.h"

void *mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset)
{
    if (!(flags & MAP_ANONYMOUS) || fd != -1 || offset != 0)
    {
        errno = ENOTSUP;
        return MAP_FAILED;
    }
    int64_t result = sys_vm_map((uintptr_t)address, length, (uint32_t)protection, (uint32_t)flags);
    if (result < 0)
    {
        errno = (int)-result;
        return MAP_FAILED;
    }
    return (void *)(uintptr_t)result;
}

int mprotect(void *address, size_t length, int protection)
{
    int result = sys_vm_protect((uintptr_t)address, length, (uint32_t)protection);
    if (result < 0)
    {
        errno = -result;
        return -1;
    }
    return 0;
}

int munmap(void *address, size_t length)
{
    int result = sys_vm_unmap((uintptr_t)address, length);
    if (result < 0)
    {
        errno = -result;
        return -1;
    }
    return 0;
}

int madvise(void *address, size_t length, int advice)
{
    if (advice != MADV_DONTNEED)
    {
        errno = EINVAL;
        return -1;
    }
    int result = sys_vm_advise((uintptr_t)address, length, (uint32_t)advice);
    if (result < 0)
    {
        errno = -result;
        return -1;
    }
    return 0;
}

int posix_madvise(void *address, size_t length, int advice)
{
    /* POSIX_MADV_DONTNEED must not discard contents. The separate syscall
     * namespace validates the range without applying destructive advice. */
    if (advice < POSIX_MADV_NORMAL || advice > POSIX_MADV_DONTNEED)
    {
        return EINVAL;
    }
    int result = sys_vm_advise((uintptr_t)address, length,
                                SYSCALL_VM_ADVICE_POSIX | (uint32_t)advice);
    return result < 0 ? -result : 0;
}
