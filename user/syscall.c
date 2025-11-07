#include "usyscall.h"

static inline long syscall0(long id)
{
    long ret;
    __asm__ volatile ("int $0x80"
                      : "=a"(ret)
                      : "a"(id)
                      : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall1(long id, long a0)
{
    long ret;
    __asm__ volatile ("int $0x80"
                      : "=a"(ret)
                      : "a"(id), "D"(a0)
                      : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall2(long id, long a0, long a1)
{
    long ret;
    __asm__ volatile ("int $0x80"
                      : "=a"(ret)
                      : "a"(id), "D"(a0), "S"(a1)
                      : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall3(long id, long a0, long a1, long a2)
{
    long ret;
    __asm__ volatile ("int $0x80"
                      : "=a"(ret)
                      : "a"(id), "D"(a0), "S"(a1), "d"(a2)
                      : "rcx", "r11", "memory");
    return ret;
}

ssize_t sys_write(int fd, const void *buffer, size_t count)
{
    return (ssize_t)syscall3(SYSCALL_WRITE, fd, (long)buffer, (long)count);
}

ssize_t sys_read(int fd, void *buffer, size_t count)
{
    return (ssize_t)syscall3(SYSCALL_READ, fd, (long)buffer, (long)count);
}

int sys_close(int fd)
{
    return (int)syscall1(SYSCALL_CLOSE, fd);
}

int sys_open(const char *path, uint64_t flags)
{
    return (int)syscall2(SYSCALL_OPEN, (long)path, (long)flags);
}

void *sys_sbrk(int64_t increment)
{
    long ret = syscall1(SYSCALL_SBRK, (long)increment);
    if (ret < 0)
    {
        return (void *)-1;
    }
    return (void *)ret;
}

void sys_exit(int status)
{
    syscall1(SYSCALL_EXIT, status);
    for (;;)
    {
        syscall0(SYSCALL_EXIT);
    }
}
