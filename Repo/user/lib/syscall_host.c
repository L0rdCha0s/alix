#ifdef TTF_HOST_BUILD

#include "usyscall.h"

#include <dirent.h>
#include "errno.h"
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif

#define HOST_SBRK_RESERVE_BYTES (512u * 1024u * 1024u)

static uint8_t *g_host_heap_base = NULL;
static size_t g_host_heap_size = 0;
static size_t g_host_heap_offset = 0;

static bool host_heap_init(void)
{
    if (g_host_heap_base)
    {
        return true;
    }
    void *base = mmap(NULL,
                      HOST_SBRK_RESERVE_BYTES,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON,
                      -1,
                      0);
    if (base == MAP_FAILED)
    {
        return false;
    }
    g_host_heap_base = (uint8_t *)base;
    g_host_heap_size = HOST_SBRK_RESERVE_BYTES;
    g_host_heap_offset = 0;
    return true;
}

ssize_t sys_write(int fd, const void *buffer, size_t count)
{
    return (ssize_t)syscall(SYS_write, fd, buffer, count);
}

ssize_t sys_read(int fd, void *buffer, size_t count)
{
    return (ssize_t)syscall(SYS_read, fd, buffer, count);
}

int sys_close(int fd)
{
    return (int)syscall(SYS_close, fd);
}

int sys_open(const char *path, uint64_t flags)
{
    int oflags = 0;
    if ((flags & SYSCALL_OPEN_READ) && (flags & SYSCALL_OPEN_WRITE))
    {
        oflags |= O_RDWR;
    }
    else if (flags & SYSCALL_OPEN_WRITE)
    {
        oflags |= O_WRONLY;
    }
    else
    {
        oflags |= O_RDONLY;
    }
    if (flags & SYSCALL_OPEN_CREATE)
    {
        oflags |= O_CREAT;
    }
    if (flags & SYSCALL_OPEN_TRUNCATE)
    {
        oflags |= O_TRUNC;
    }
    return (int)syscall(SYS_open, path, oflags, 0644);
}

void *sys_sbrk(int64_t increment)
{
    if (!host_heap_init())
    {
        return (void *)-1;
    }
    if (increment == 0)
    {
        return g_host_heap_base + g_host_heap_offset;
    }
    if (increment < 0)
    {
        size_t dec = (size_t)(-increment);
        if (dec > g_host_heap_offset)
        {
            return (void *)-1;
        }
        g_host_heap_offset -= dec;
        return g_host_heap_base + g_host_heap_offset;
    }
    size_t inc = (size_t)increment;
    if (g_host_heap_offset + inc > g_host_heap_size)
    {
        return (void *)-1;
    }
    void *prev = g_host_heap_base + g_host_heap_offset;
    g_host_heap_offset += inc;
    return prev;
}

void sys_exit(int status)
{
    (void)syscall(SYS_exit, status);
    for (;;)
    {
        (void)syscall(SYS_exit, status);
    }
}

int sys_ui_create(const user_atk_window_desc_t *desc)
{
    (void)desc;
    errno = ENOSYS;
    return -1;
}

int sys_ui_present(uint32_t handle, const void *pixels, size_t byte_len)
{
    (void)handle;
    (void)pixels;
    (void)byte_len;
    errno = ENOSYS;
    return -1;
}

int sys_ui_poll_event(uint32_t handle, user_atk_event_t *event, uint32_t flags)
{
    (void)handle;
    (void)event;
    (void)flags;
    errno = ENOSYS;
    return -1;
}

int sys_ui_poll_event_timeout(uint32_t handle, user_atk_event_t *event, uint32_t timeout_ms)
{
    (void)handle;
    (void)event;
    (void)timeout_ms;
    errno = ENOSYS;
    return -1;
}

int sys_ui_close(uint32_t handle)
{
    (void)handle;
    errno = ENOSYS;
    return -1;
}

int sys_ui_capture(uint32_t handle, uint32_t flags)
{
    (void)handle;
    (void)flags;
    errno = ENOSYS;
    return -1;
}

int sys_yield(void)
{
    return sched_yield();
}

int sys_sleep_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)((ms % 1000u) * 1000000u);
    (void)nanosleep(&ts, NULL);
    return 0;
}

int sys_serial_write(const char *buffer, size_t length)
{
    return (int)sys_write(2, buffer, length);
}

int sys_shell_open(void)
{
    errno = ENOSYS;
    return -1;
}

int sys_shell_exec(int handle, const char *command, size_t command_len)
{
    (void)handle;
    (void)command;
    (void)command_len;
    errno = ENOSYS;
    return -1;
}

ssize_t sys_shell_poll(int handle,
                       char *output,
                       size_t output_len,
                       int *status_out,
                       int *running_out)
{
    (void)handle;
    (void)output;
    (void)output_len;
    (void)status_out;
    (void)running_out;
    errno = ENOSYS;
    return -1;
}

ssize_t sys_shell_get_cwd(int handle, char *buffer, size_t capacity)
{
    (void)handle;
    (void)buffer;
    (void)capacity;
    errno = ENOSYS;
    return -1;
}

ssize_t sys_shell_prompt(int handle, char *buffer, size_t capacity)
{
    (void)handle;
    (void)buffer;
    (void)capacity;
    errno = ENOSYS;
    return -1;
}

int sys_shell_interrupt(int handle)
{
    (void)handle;
    errno = ENOSYS;
    return -1;
}

int sys_shell_close(int handle)
{
    (void)handle;
    errno = ENOSYS;
    return -1;
}

ssize_t sys_proc_snapshot(syscall_process_info_t *buffer, size_t capacity)
{
    (void)buffer;
    (void)capacity;
    errno = ENOSYS;
    return -1;
}

ssize_t sys_net_snapshot(syscall_net_stats_t *buffer, size_t capacity)
{
    (void)buffer;
    (void)capacity;
    errno = ENOSYS;
    return -1;
}

ssize_t sys_cpu_snapshot(syscall_cpu_stats_t *buffer, size_t capacity)
{
    (void)buffer;
    (void)capacity;
    errno = ENOSYS;
    return -1;
}

uint64_t sys_time_millis(void)
{
    struct timespec ts = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
        return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
    }
    return 0;
}

int sys_time_info(syscall_time_info_t *info)
{
    (void)info;
    errno = ENOSYS;
    return -1;
}

__attribute__((weak)) ssize_t sys_font_cache(void *buffer, size_t capacity)
{
    (void)buffer;
    (void)capacity;
    errno = ENOSYS;
    return -1;
}

int64_t sys_lseek(int fd, int64_t offset, int whence)
{
    int host_whence = SEEK_SET;
    if (whence == SYSCALL_SEEK_CUR)
    {
        host_whence = SEEK_CUR;
    }
    else if (whence == SYSCALL_SEEK_END)
    {
        host_whence = SEEK_END;
    }
    return (int64_t)syscall(SYS_lseek, fd, offset, host_whence);
}

int sys_fstat(int fd, syscall_stat_t *st)
{
    if (!st)
    {
        errno = EINVAL;
        return -1;
    }
    struct stat host;
    if (syscall(SYS_fstat, fd, &host) != 0)
    {
        return -1;
    }
    st->size_bytes = (uint64_t)host.st_size;
    st->type = S_ISDIR(host.st_mode) ? SYSCALL_NODE_TYPE_DIR : SYSCALL_NODE_TYPE_FILE;
    st->atime = (uint64_t)host.st_atime * 1000u;
    st->mtime = (uint64_t)host.st_mtime * 1000u;
    st->ctime = (uint64_t)host.st_ctime * 1000u;
    return 0;
}

ssize_t sys_pread(int fd, void *buffer, size_t count, size_t offset)
{
    return (ssize_t)syscall(SYS_pread, fd, buffer, count, offset);
}

int sys_socket_open(const char *iface_name)
{
    (void)iface_name;
    errno = ENOSYS;
    return -1;
}

int sys_socket_connect(int fd, const char *ipv4_text, uint16_t port)
{
    (void)fd;
    (void)ipv4_text;
    (void)port;
    errno = ENOSYS;
    return -1;
}

ssize_t sys_socket_available(int fd)
{
    (void)fd;
    errno = ENOSYS;
    return -1;
}

uint64_t sys_thread_self(void)
{
    return 1;
}

int64_t sys_thread_create(uintptr_t entry,
                          uintptr_t arg,
                          size_t stack_size,
                          const char *name)
{
    (void)entry;
    (void)arg;
    (void)stack_size;
    (void)name;
    errno = ENOSYS;
    return -1;
}

int sys_thread_join(uint64_t tid, int *status_out)
{
    (void)tid;
    (void)status_out;
    errno = ENOSYS;
    return -1;
}

void sys_thread_exit(int status)
{
    sys_exit(status);
}

ssize_t sys_list_dir(const char *path, syscall_dirent_t *entries, size_t capacity)
{
    if (!path || !entries || capacity == 0)
    {
        errno = EINVAL;
        return -1;
    }
    DIR *dir = opendir(path);
    if (!dir)
    {
        return -1;
    }
    size_t count = 0;
    struct dirent *ent = NULL;
    while (count < capacity && (ent = readdir(dir)) != NULL)
    {
        syscall_dirent_t *out = &entries[count++];
        memset(out, 0, sizeof(*out));
        out->type = SYSCALL_NODE_TYPE_FILE;
        if (ent->d_type == DT_DIR)
        {
            out->type = SYSCALL_NODE_TYPE_DIR;
        }
        strncpy(out->name, ent->d_name, SYSCALL_DIR_NAME_MAX - 1u);
        out->name[SYSCALL_DIR_NAME_MAX - 1u] = '\0';
    }
    closedir(dir);
    return (ssize_t)count;
}

uint32_t sys_getuid(void)
{
    return (uint32_t)syscall(SYS_getuid);
}

int sys_mkdir(const char *path)
{
    if (!path || path[0] == '\0')
    {
        errno = EINVAL;
        return -1;
    }
    return (int)syscall(SYS_mkdir, path, 0755);
}

#endif
