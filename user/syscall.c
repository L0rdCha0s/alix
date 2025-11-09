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

int sys_ui_create(const user_atk_window_desc_t *desc)
{
    return (int)syscall1(SYSCALL_UI_CREATE, (long)desc);
}

int sys_ui_present(uint32_t handle, const void *pixels, size_t byte_len)
{
    return (int)syscall3(SYSCALL_UI_PRESENT, (long)handle, (long)pixels, (long)byte_len);
}

int sys_ui_poll_event(uint32_t handle, user_atk_event_t *event, uint32_t flags)
{
    return (int)syscall3(SYSCALL_UI_POLL_EVENT, (long)handle, (long)event, (long)flags);
}

int sys_ui_close(uint32_t handle)
{
    return (int)syscall1(SYSCALL_UI_CLOSE, (long)handle);
}

int sys_yield(void)
{
    return (int)syscall0(SYSCALL_YIELD);
}

int sys_serial_write(const char *buffer, size_t length)
{
    return (int)syscall2(SYSCALL_SERIAL_WRITE, (long)buffer, (long)length);
}
