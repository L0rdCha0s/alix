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

int sys_ui_poll_event_timeout(uint32_t handle, user_atk_event_t *event, uint32_t timeout_ms)
{
    return (int)syscall3(SYSCALL_UI_POLL_EVENT_TIMEOUT, (long)handle, (long)event, (long)timeout_ms);
}

int sys_ui_close(uint32_t handle)
{
    return (int)syscall1(SYSCALL_UI_CLOSE, (long)handle);
}

int sys_ui_capture(uint32_t handle, uint32_t flags)
{
    return (int)syscall2(SYSCALL_UI_CAPTURE, (long)handle, (long)flags);
}

int sys_yield(void)
{
    return (int)syscall0(SYSCALL_YIELD);
}

int sys_sleep_ms(uint32_t ms)
{
    return (int)syscall1(SYSCALL_SLEEP_MS, (long)ms);
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

ssize_t sys_shell_get_cwd(int handle, char *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return -1;
    }
    return (ssize_t)syscall3(SYSCALL_SHELL_CWD, handle, (long)buffer, (long)capacity);
}

ssize_t sys_shell_prompt(int handle, char *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return -1;
    }
    return (ssize_t)syscall3(SYSCALL_SHELL_PROMPT, handle, (long)buffer, (long)capacity);
}

ssize_t sys_proc_snapshot(syscall_process_info_t *buffer, size_t capacity)
{
    return (ssize_t)syscall2(SYSCALL_PROC_SNAPSHOT, (long)buffer, (long)capacity);
}

ssize_t sys_net_snapshot(syscall_net_stats_t *buffer, size_t capacity)
{
    return (ssize_t)syscall2(SYSCALL_NET_SNAPSHOT, (long)buffer, (long)capacity);
}

ssize_t sys_cpu_snapshot(syscall_cpu_stats_t *buffer, size_t capacity)
{
    return (ssize_t)syscall2(SYSCALL_CPU_SNAPSHOT, (long)buffer, (long)capacity);
}

uint64_t sys_time_millis(void)
{
    return (uint64_t)syscall0(SYSCALL_TIME_MILLIS);
}

int sys_time_info(syscall_time_info_t *info)
{
    return (int)syscall1(SYSCALL_TIME_INFO, (long)info);
}

int sys_timezone_info(syscall_timezone_info_t *info, size_t size)
{
    return (int)syscall2(SYSCALL_TIMEZONE_INFO, (long)info, (long)size);
}

ssize_t sys_font_cache(void *buffer, size_t capacity)
{
    return (ssize_t)syscall2(SYSCALL_FONT_CACHE, (long)buffer, (long)capacity);
}

int64_t sys_lseek(int fd, int64_t offset, int whence)
{
    return (int64_t)syscall3(SYSCALL_LSEEK, fd, (long)offset, (long)whence);
}

int sys_fstat(int fd, syscall_stat_t *st)
{
    return (int)syscall2(SYSCALL_FSTAT, fd, (long)st);
}

ssize_t sys_pread(int fd, void *buffer, size_t count, size_t offset)
{
    return (ssize_t)syscall4(SYSCALL_PREAD, fd, (long)buffer, (long)count, (long)offset);
}

int sys_socket_open(const char *iface_name)
{
    return (int)syscall2(SYSCALL_SOCKET_OPEN, (long)iface_name, 0);
}

int sys_socket_connect(int fd, const char *ipv4_text, uint16_t port)
{
    return (int)syscall3(SYSCALL_SOCKET_CONNECT, fd, (long)ipv4_text, (long)port);
}

ssize_t sys_list_dir(const char *path, syscall_dirent_t *entries, size_t capacity)
{
    return (ssize_t)syscall3(SYSCALL_LIST_DIR, (long)path, (long)entries, (long)capacity);
}

uint32_t sys_getuid(void)
{
    return (uint32_t)syscall0(SYSCALL_GETUID);
}

int sys_mkdir(const char *path)
{
    return (int)syscall1(SYSCALL_MKDIR, (long)path);
}

ssize_t sys_socket_available(int fd)
{
    return (ssize_t)syscall1(SYSCALL_SOCKET_AVAILABLE, fd);
}

uint64_t sys_thread_self(void)
{
    return (uint64_t)syscall0(SYSCALL_THREAD_SELF);
}

int sys_thread_set_tls(uintptr_t base)
{
    return (int)syscall1(SYSCALL_THREAD_SET_TLS, (long)base);
}

uint64_t sys_monotonic_millis(void)
{
    return (uint64_t)syscall0(SYSCALL_MONOTONIC_MILLIS);
}

uintptr_t sys_thread_get_tls(void)
{
    return (uintptr_t)syscall0(SYSCALL_THREAD_GET_TLS);
}

int sys_thread_set_affinity(uint32_t cpu_index)
{
    return (int)syscall1(SYSCALL_THREAD_SET_AFFINITY, (long)cpu_index);
}

uint32_t sys_thread_cpu(void)
{
    return (uint32_t)syscall0(SYSCALL_THREAD_CPU);
}

int sys_futex_wait(volatile uint32_t *address, uint32_t expected, uint32_t timeout_ms)
{
    return (int)syscall3(SYSCALL_FUTEX_WAIT, (long)address, (long)expected, (long)timeout_ms);
}

int sys_futex_wake(volatile uint32_t *address, uint32_t max_waiters)
{
    return (int)syscall2(SYSCALL_FUTEX_WAKE, (long)address, (long)max_waiters);
}

int64_t sys_vm_map(uintptr_t hint, size_t length, uint32_t protection, uint32_t flags)
{
    return (int64_t)syscall4(SYSCALL_VM_MAP, (long)hint, (long)length, protection, flags);
}

int sys_vm_protect(uintptr_t address, size_t length, uint32_t protection)
{
    return (int)syscall3(SYSCALL_VM_PROTECT, (long)address, (long)length, protection);
}

int sys_vm_unmap(uintptr_t address, size_t length)
{
    return (int)syscall2(SYSCALL_VM_UNMAP, (long)address, (long)length);
}

int sys_vm_advise(uintptr_t address, size_t length, uint32_t advice)
{
    return (int)syscall3(SYSCALL_VM_ADVISE, (long)address, (long)length, advice);
}

int sys_thread_detach(uint64_t tid)
{
    return (int)syscall1(SYSCALL_THREAD_DETACH, (long)tid);
}

ssize_t sys_getrandom(void *buffer, size_t length, uint32_t flags)
{
    return (ssize_t)syscall3(SYSCALL_GETRANDOM, (long)buffer, (long)length, (long)flags);
}

int sys_thread_info(uint64_t tid, syscall_thread_info_t *info)
{
    return (int)syscall2(SYSCALL_THREAD_INFO, (long)tid, (long)info);
}

int sys_thread_set_name(uint64_t tid, const char *name)
{
    return (int)syscall2(SYSCALL_THREAD_SET_NAME, (long)tid, (long)name);
}

int sys_thread_prepare_exit(void)
{
    return (int)syscall0(SYSCALL_THREAD_PREPARE_EXIT);
}

int32_t sys_getpid(void)
{
    return (int32_t)syscall0(SYSCALL_GETPID);
}

int64_t sys_thread_create(uintptr_t entry,
                          uintptr_t arg,
                          size_t stack_size,
                          const char *name)
{
    return (int64_t)syscall4(SYSCALL_THREAD_CREATE,
                             (long)entry,
                             (long)arg,
                             (long)stack_size,
                             (long)name);
}

int sys_thread_join(uint64_t tid, int *status_out)
{
    return (int)syscall2(SYSCALL_THREAD_JOIN, (long)tid, (long)status_out);
}

void sys_thread_exit(int status)
{
    syscall1(SYSCALL_THREAD_EXIT, status);
    for (;;)
    {
        syscall0(SYSCALL_THREAD_EXIT);
    }
}

int sys_sigaction(int number,const alix_sigaction_t *action,alix_sigaction_t *old,size_t size)
{ return (int)syscall4(SYSCALL_SIGACTION,number,(long)action,(long)old,(long)size); }
int sys_sigprocmask(int how,const alix_sigset_t *set,alix_sigset_t *old)
{ return (int)syscall3(SYSCALL_SIGPROCMASK,how,(long)set,(long)old); }
int sys_sigaltstack(const alix_stack_t *stack,alix_stack_t *old,size_t size)
{ return (int)syscall3(SYSCALL_SIGALTSTACK,(long)stack,(long)old,(long)size); }
int sys_sigreturn(uintptr_t frame) { return (int)syscall1(SYSCALL_SIGRETURN,(long)frame); }
int sys_raise(int number,uint64_t thread) { return (int)syscall2(SYSCALL_RAISE,number,(long)thread); }
int sys_kill(int32_t pid,int number) { return (int)syscall2(SYSCALL_KILL,pid,number); }
int sys_sleep_interruptible(uint32_t milliseconds,uint32_t *remaining)
{ return (int)syscall2(SYSCALL_SLEEP_INTERRUPTIBLE,milliseconds,(long)remaining); }
