#include "usyscall.h"
#include "libc.h"

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

static inline long syscall4(long id, long a0, long a1, long a2, long a3)
{
    long ret;
    register long r10 __asm__("r10") = a3;
    __asm__ volatile ("int $0x80"
                      : "=a"(ret)
                      : "a"(id), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                      : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall5(long id, long a0, long a1, long a2, long a3, long a4)
{
    long ret;
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    __asm__ volatile ("int $0x80"
                      : "=a"(ret)
                      : "a"(id), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8)
                      : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall6(long id, long a0, long a1, long a2, long a3, long a4, long a5)
{
    long ret;
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    __asm__ volatile ("int $0x80"
                      : "=a"(ret)
                      : "a"(id), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
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

int sys_shell_open(void)
{
    return (int)syscall0(SYSCALL_SHELL_OPEN);
}

int sys_shell_exec(int handle, const char *command, size_t command_len)
{
    if (!command)
    {
        return -1;
    }
    if (command_len == 0)
    {
        command_len = strlen(command);
    }
    return (int)syscall3(SYSCALL_SHELL_EXEC,
                         handle,
                         (long)command,
                         (long)command_len);
}

ssize_t sys_shell_poll(int handle,
                       char *output,
                       size_t output_len,
                       int *status_out,
                       int *running_out)
{
    return (ssize_t)syscall5(SYSCALL_SHELL_POLL,
                              handle,
                              (long)output,
                              (long)output_len,
                              (long)status_out,
                              (long)running_out);
}

int sys_shell_interrupt(int handle)
{
    return (int)syscall1(SYSCALL_SHELL_INTERRUPT, handle);
}

int sys_shell_close(int handle)
{
    return (int)syscall1(SYSCALL_SHELL_CLOSE, handle);
}

ssize_t sys_proc_snapshot(syscall_process_info_t *buffer, size_t capacity)
{
    return (ssize_t)syscall2(SYSCALL_PROC_SNAPSHOT, (long)buffer, (long)capacity);
}

ssize_t sys_net_snapshot(syscall_net_stats_t *buffer, size_t capacity)
{
    return (ssize_t)syscall2(SYSCALL_NET_SNAPSHOT, (long)buffer, (long)capacity);
}
