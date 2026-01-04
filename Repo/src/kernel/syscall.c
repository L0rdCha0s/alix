#include "syscall.h"

#include "syscall_defs.h"
#include "process.h"
#include "serial.h"
#include "fd.h"
#include "heap.h"
#include "vfs.h"
#include "libc.h"
#include "user_atk_host.h"
#include "shell_service.h"
#include "net/interface.h"
#include "net/dns.h"
#include "net/tcp.h"
#include "user_copy.h"
#include "timekeeping.h"
#include "font_cache.h"

/*
 * src/kernel/syscall.c
 *
 * Syscall dispatcher and implementations.
 *
 * Entry/ABI:
 * - User code executes `int 0x80`.
 * - The x86 stub (`src/arch/x86/syscall_entry.S`) saves registers and calls
 *   `syscall_dispatch(syscall_frame_t*, vector)`.
 *
 * Resource model:
 * - Files and sockets are returned as integer FDs backed by `fd.c` entries.
 * - VFS files use a `file_handle_t` context holding { vfs_node, offset, flags }.
 * - TCP sockets integrate with the same FD layer via `net_tcp_socket_fd`.
 *
 * See docs/kernel/syscalls.md.
 */

static process_info_t *g_proc_snapshot_buf = NULL;
static size_t g_proc_snapshot_cap = 0;
static syscall_process_info_t *g_proc_snapshot_user_buf = NULL;
static size_t g_proc_snapshot_user_cap = 0;
static process_cpu_info_t *g_cpu_snapshot_buf = NULL;
static size_t g_cpu_snapshot_cap = 0;
static syscall_cpu_stats_t *g_cpu_snapshot_user_buf = NULL;
static size_t g_cpu_snapshot_user_cap = 0;
static net_interface_stats_t *g_net_snapshot_buf = NULL;
static size_t g_net_snapshot_cap = 0;
static syscall_net_stats_t *g_net_snapshot_user_buf = NULL;
static size_t g_net_snapshot_user_cap = 0;

typedef struct
{
    vfs_node_t *node;
    size_t offset;
    bool readable;
    bool writable;
} file_handle_t;

#define SYSCALL_MAX_PATH_LEN     4096u
#define SYSCALL_MAX_COMMAND_LEN  4096u
#define SYSCALL_MAX_SERIAL_BYTES 4096u
#define SYSCALL_MAX_IP_TEXT_LEN  256u
#define SYSCALL_MAX_PROMPT_LEN   256u

typedef struct
{
    syscall_dirent_t *entries;
    size_t capacity;
    size_t count;
} syscall_dir_enum_t;

static ssize_t syscall_file_read(void *ctx, void *buffer, size_t count)
{
    file_handle_t *handle = (file_handle_t *)ctx;
    if (!handle || !handle->readable || (!buffer && count > 0))
    {
        return -1;
    }
    if (count == 0)
    {
        return 0;
    }
    ssize_t bytes = vfs_read_at(handle->node, handle->offset, buffer, count);
    if (bytes > 0)
    {
        handle->offset += (size_t)bytes;
    }
    return bytes;
}

static void syscall_copy_string(char *dst, size_t capacity, const char *src)
{
    if (!dst || capacity == 0)
    {
        return;
    }
    if (!src)
    {
        dst[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= capacity)
    {
        len = capacity - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static bool syscall_dir_collect(const vfs_node_t *child, void *context)
{
    if (!child || !context)
    {
        return false;
    }
    syscall_dir_enum_t *ctx = (syscall_dir_enum_t *)context;
    if (!ctx->entries || ctx->capacity == 0)
    {
        return false;
    }
    if (ctx->count >= ctx->capacity)
    {
        return false;
    }

    syscall_dirent_t *dst = &ctx->entries[ctx->count];
    size_t size_bytes = 0;
    vfs_node_type_t node_type = VFS_NODE_FILE;
    if (!vfs_stat(child, &size_bytes, &node_type, NULL, NULL, NULL))
    {
        return false;
    }

    dst->type = (uint32_t)node_type;
    dst->size_bytes = size_bytes;
    dst->reserved = 0;
    const char *name = vfs_name(child);
    size_t len = name ? strlen(name) : 0;
    if (len >= SYSCALL_DIR_NAME_MAX)
    {
        len = SYSCALL_DIR_NAME_MAX - 1;
    }
    if (len > 0 && name)
    {
        memcpy(dst->name, name, len);
    }
    dst->name[len] = '\0';
    ctx->count++;
    return ctx->count < ctx->capacity;
}

static int64_t syscall_do_proc_snapshot(syscall_process_info_t *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return -1;
    }

    size_t bytes = 0;
    if (__builtin_mul_overflow(capacity, sizeof(*buffer), &bytes))
    {
        return -1;
    }

    if (!user_ptr_range_valid(buffer, bytes))
    {
        return -1;
    }

    if (capacity > g_proc_snapshot_cap)
    {
        size_t snap_bytes = sizeof(process_info_t) * capacity;
        process_info_t *new_buf = (process_info_t *)realloc(g_proc_snapshot_buf, snap_bytes);
        if (!new_buf)
        {
            return -1;
        }
        g_proc_snapshot_buf = new_buf;
        g_proc_snapshot_cap = capacity;
    }

    if (capacity > g_proc_snapshot_user_cap)
    {
        syscall_process_info_t *new_out = (syscall_process_info_t *)realloc(g_proc_snapshot_user_buf,
                                                                            bytes);
        if (!new_out)
        {
            return -1;
        }
        g_proc_snapshot_user_buf = new_out;
        g_proc_snapshot_user_cap = capacity;
    }

    process_info_t *tmp = g_proc_snapshot_buf;
    syscall_process_info_t *out_buf = g_proc_snapshot_user_buf;
    if (!tmp || !out_buf)
    {
        return -1;
    }

    size_t count = process_snapshot(tmp, capacity);
    for (size_t i = 0; i < count; ++i)
    {
        const process_info_t *info = &tmp[i];
        syscall_process_info_t *out = &out_buf[i];
        out->pid = info->pid;
        out->process_state = (uint32_t)info->state;
        out->thread_state = (uint32_t)info->thread_state;
        out->time_slice_remaining = info->time_slice_remaining;
        out->stdout_fd = info->stdout_fd;
        out->is_idle = info->is_idle ? 1u : 0u;
        out->heap_used_bytes = info->heap_used_bytes;
        out->heap_committed_bytes = info->heap_committed_bytes;
        out->runtime_ticks = info->runtime_ticks;
        out->last_cpu_index = info->last_cpu_index;

        const char *proc_name = info->name ? info->name : "";
        const char *thread_name = info->thread_name ? info->thread_name : "";
        syscall_copy_string(out->process_name, SYSCALL_PROCESS_NAME_MAX, proc_name);
        syscall_copy_string(out->thread_name, SYSCALL_PROCESS_NAME_MAX, thread_name);
    }

    if (count > 0)
    {
        size_t copy_bytes = sizeof(syscall_process_info_t) * count;
        if (!user_copy_to_user(buffer, out_buf, copy_bytes))
        {
            return -1;
        }
    }

    return (int64_t)count;
}

static int64_t syscall_do_net_snapshot(syscall_net_stats_t *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return -1;
    }

    size_t bytes = 0;
    if (__builtin_mul_overflow(capacity, sizeof(*buffer), &bytes))
    {
        return -1;
    }

    if (!user_ptr_range_valid(buffer, bytes))
    {
        return -1;
    }

    if (capacity > g_net_snapshot_cap)
    {
        size_t snap_bytes = sizeof(net_interface_stats_t) * capacity;
        net_interface_stats_t *new_buf = (net_interface_stats_t *)realloc(g_net_snapshot_buf,
                                                                          snap_bytes);
        if (!new_buf)
        {
            return -1;
        }
        g_net_snapshot_buf = new_buf;
        g_net_snapshot_cap = capacity;
    }

    if (capacity > g_net_snapshot_user_cap)
    {
        syscall_net_stats_t *new_out = (syscall_net_stats_t *)realloc(g_net_snapshot_user_buf,
                                                                      bytes);
        if (!new_out)
        {
            return -1;
        }
        g_net_snapshot_user_buf = new_out;
        g_net_snapshot_user_cap = capacity;
    }

    net_interface_stats_t *tmp = g_net_snapshot_buf;
    syscall_net_stats_t *out_buf = g_net_snapshot_user_buf;
    if (!tmp || !out_buf)
    {
        return -1;
    }

    size_t count = net_if_snapshot(tmp, capacity);
    for (size_t i = 0; i < count; ++i)
    {
        const net_interface_stats_t *stats = &tmp[i];
        syscall_net_stats_t *out = &out_buf[i];
        memset(out, 0, sizeof(*out));
        syscall_copy_string(out->name, SYSCALL_NET_IF_NAME_MAX, stats->name);
        out->present = stats->present ? 1u : 0u;
        out->link_up = stats->link_up ? 1u : 0u;
        memcpy(out->mac, stats->mac, sizeof(out->mac));
        out->ipv4_addr = stats->ipv4_addr;
        out->ipv4_netmask = stats->ipv4_netmask;
        out->ipv4_gateway = stats->ipv4_gateway;
        out->rx_bytes = stats->rx_bytes;
        out->tx_bytes = stats->tx_bytes;
        out->rx_packets = stats->rx_packets;
        out->tx_packets = stats->tx_packets;
        out->rx_errors = stats->rx_errors;
        out->tx_errors = stats->tx_errors;
    }

    if (count > 0)
    {
        size_t copy_bytes = sizeof(syscall_net_stats_t) * count;
        if (!user_copy_to_user(buffer, out_buf, copy_bytes))
        {
            return -1;
        }
    }

    return (int64_t)count;
}

static int64_t syscall_do_cpu_snapshot(syscall_cpu_stats_t *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return -1;
    }

    size_t bytes = 0;
    if (__builtin_mul_overflow(capacity, sizeof(*buffer), &bytes))
    {
        return -1;
    }

    if (!user_ptr_range_valid(buffer, bytes))
    {
        return -1;
    }

    size_t capped_capacity = capacity;
    if (capped_capacity > SYSCALL_CPU_MAX)
    {
        capped_capacity = SYSCALL_CPU_MAX;
    }

    if (capped_capacity > g_cpu_snapshot_cap)
    {
        size_t snap_bytes = sizeof(process_cpu_info_t) * capped_capacity;
        process_cpu_info_t *new_buf = (process_cpu_info_t *)realloc(g_cpu_snapshot_buf,
                                                                    snap_bytes);
        if (!new_buf)
        {
            return -1;
        }
        g_cpu_snapshot_buf = new_buf;
        g_cpu_snapshot_cap = capped_capacity;
    }

    if (capacity > g_cpu_snapshot_user_cap)
    {
        syscall_cpu_stats_t *new_out = (syscall_cpu_stats_t *)realloc(g_cpu_snapshot_user_buf,
                                                                      bytes);
        if (!new_out)
        {
            return -1;
        }
        g_cpu_snapshot_user_buf = new_out;
        g_cpu_snapshot_user_cap = capacity;
    }

    process_cpu_info_t *tmp = g_cpu_snapshot_buf;
    syscall_cpu_stats_t *out_buf = g_cpu_snapshot_user_buf;
    if (!tmp || !out_buf)
    {
        return -1;
    }

    size_t count = process_cpu_snapshot(tmp, capped_capacity);
    if (count > capacity)
    {
        count = capacity;
    }

    for (size_t i = 0; i < count; ++i)
    {
        const process_cpu_info_t *info = &tmp[i];
        syscall_cpu_stats_t *out = &out_buf[i];
        out->cpu_index = info->cpu_index;
        out->online = info->online;
        out->run_queue_depth = info->run_queue_depth;
        out->current_thread_state = info->current_thread_state;
        out->total_ticks = info->total_ticks;
        out->idle_ticks = info->idle_ticks;
        out->switch_count = info->switch_count;
        out->current_pid = info->current_pid;
        syscall_copy_string(out->current_process_name,
                            SYSCALL_PROCESS_NAME_MAX,
                            info->current_process_name);
        syscall_copy_string(out->current_thread_name,
                            SYSCALL_PROCESS_NAME_MAX,
                            info->current_thread_name);
    }

    if (count > 0)
    {
        size_t copy_bytes = sizeof(syscall_cpu_stats_t) * count;
        if (!user_copy_to_user(buffer, out_buf, copy_bytes))
        {
            return -1;
        }
    }

    return (int64_t)count;
}

/*
 * Select a network interface for socket syscalls.
 *
 * If `iface_name_user` is non-NULL, this attempts to open that specific
 * interface name; otherwise it picks the first present interface and prefers
 * one with link-up.
 */
static net_interface_t *syscall_pick_interface(const char *iface_name_user)
{
    net_interface_t *iface = NULL;
    char *name_buf = NULL;

    if (iface_name_user)
    {
        name_buf = (char *)malloc(NET_IF_NAME_MAX);
        if (!name_buf)
        {
            return NULL;
        }
        size_t copied = 0;
        if (!user_copy_string_from_user(name_buf, NET_IF_NAME_MAX, iface_name_user, &copied))
        {
            free(name_buf);
            return NULL;
        }
        iface = net_if_by_name(name_buf);
    }

    if (!iface)
    {
        size_t count = net_if_count();
        for (size_t i = 0; i < count; ++i)
        {
            net_interface_t *candidate = net_if_at(i);
            if (!candidate || !candidate->present)
            {
                continue;
            }
            iface = candidate;
            if (candidate->link_up)
            {
                break;
            }
        }
    }

    free(name_buf);
    return iface;
}

/*
 * Create a TCP socket bound to a chosen interface and return its FD.
 */
static int64_t syscall_do_socket_open(const char *iface_name_user)
{
    net_interface_t *iface = syscall_pick_interface(iface_name_user);
    if (!iface)
    {
        return -1;
    }

    net_tcp_socket_t *socket = net_tcp_socket_open(iface);
    if (!socket)
    {
        return -1;
    }

    int fd = net_tcp_socket_fd(socket);
    if (fd < 0)
    {
        net_tcp_socket_release(socket);
        return -1;
    }
    return (int64_t)fd;
}

/*
 * Connect a TCP socket FD to a remote IPv4 address/port (or hostname via DNS).
 *
 * This currently uses a simple poll/sleep loop waiting for ESTABLISHED.
 */
static int64_t syscall_do_socket_connect(int fd,
                                         const char *ipv4_text_user,
                                         uint16_t port)
{
    if (!ipv4_text_user || port == 0)
    {
        return -1;
    }

    char *ip_text = (char *)malloc(SYSCALL_MAX_IP_TEXT_LEN);
    if (!ip_text)
    {
        return -1;
    }
    size_t copied = 0;
    if (!user_copy_string_from_user(ip_text, SYSCALL_MAX_IP_TEXT_LEN, ipv4_text_user, &copied))
    {
        free(ip_text);
        return -1;
    }
    serial_printf("[sock_connect] start host=%s port=%u",
                  ip_text[0] ? ip_text : "<none>",
                  (unsigned)port);

    uint32_t ipv4 = 0;
    bool parsed = net_parse_ipv4(ip_text, &ipv4);
    if ((!parsed || ipv4 == 0) && ip_text[0] != '\0')
    {
        uint32_t resolved = 0;
        if (net_dns_resolve_ipv4(ip_text, NULL, &resolved))
        {
            ipv4 = resolved;
            parsed = true;
        }
    }
    if (parsed && ipv4 != 0)
    {
        uint8_t a = (uint8_t)((ipv4 >> 24) & 0xFF);
        uint8_t b = (uint8_t)((ipv4 >> 16) & 0xFF);
        uint8_t c = (uint8_t)((ipv4 >> 8) & 0xFF);
        uint8_t d = (uint8_t)(ipv4 & 0xFF);
        serial_printf("[sock_connect] resolved host=%s ip=%u.%u.%u.%u",
                      ip_text[0] ? ip_text : "<none>",
                      (unsigned)a,
                      (unsigned)b,
                      (unsigned)c,
                      (unsigned)d);
    }
    free(ip_text);
    if (!parsed || ipv4 == 0)
    {
        serial_printf("%s", "[sock_connect] resolve failed");
        return -1;
    }

    net_tcp_socket_t *socket = net_tcp_socket_from_fd(fd);
    if (!socket)
    {
        serial_printf("[sock_connect] socket missing fd=%d", fd);
        return -1;
    }
    if (!net_tcp_socket_connect(socket, ipv4, port))
    {
        serial_printf("[sock_connect] connect failed ip=0x%08X port=%u",
                      (unsigned)ipv4,
                      (unsigned)port);
        return -1;
    }
    serial_printf("[sock_connect] connect issued state=%s",
                  net_tcp_socket_state(socket));

    const uint32_t step_ms = 10;
    const uint32_t timeout_ms = 15000;
    uint32_t waited = 0;
    while (!net_tcp_socket_is_established(socket))
    {
        if (net_tcp_socket_has_error(socket) || net_tcp_socket_remote_closed(socket))
        {
            return -1;
        }
        if (waited >= timeout_ms)
        {
            return -1;
        }
        process_sleep_ms(step_ms);
        waited += step_ms;
    }
    return 0;
}

/*
 * Return the number of readable bytes currently buffered for a TCP socket FD.
 */
static int64_t syscall_do_socket_available(int fd)
{
    net_tcp_socket_t *socket = net_tcp_socket_from_fd(fd);
    if (!socket)
    {
        return -1;
    }
    return (int64_t)net_tcp_socket_available(socket);
}

static int64_t syscall_do_thread_create(uintptr_t entry,
                                        uintptr_t arg,
                                        size_t stack_size,
                                        const char *name_user)
{
    char name_buf[PROCESS_NAME_MAX];
    const char *name = NULL;
    if (name_user)
    {
        size_t copied = 0;
        if (!user_copy_string_from_user(name_buf, sizeof(name_buf), name_user, &copied))
        {
            return -1;
        }
        name = name_buf;
    }
    return process_user_thread_create(name, entry, arg, stack_size);
}

static ssize_t syscall_file_write(void *ctx, const void *buffer, size_t count)
{
    file_handle_t *handle = (file_handle_t *)ctx;
    if (!handle || !handle->writable || (!buffer && count > 0))
    {
        return -1;
    }
    if (count == 0)
    {
        return 0;
    }
    ssize_t bytes = vfs_write_at(handle->node, handle->offset, buffer, count);
    if (bytes > 0)
    {
        handle->offset += (size_t)bytes;
    }
    return bytes;
}

static int syscall_file_close(void *ctx)
{
    if (ctx)
    {
        file_handle_t *handle = (file_handle_t *)ctx;
        if (handle->node)
        {
            vfs_node_release(handle->node);
        }
        free(handle);
    }
    return 0;
}

static ssize_t syscall_file_pread(void *ctx, void *buffer, size_t count, size_t offset)
{
    file_handle_t *handle = (file_handle_t *)ctx;
    if (!handle || !handle->readable || (!buffer && count > 0))
    {
        return -1;
    }
    return vfs_read_at(handle->node, offset, buffer, count);
}

static int64_t syscall_file_lseek(void *ctx, int64_t offset, int whence)
{
    file_handle_t *handle = (file_handle_t *)ctx;
    if (!handle || !handle->node)
    {
        return -1;
    }

    size_t size = 0;
    vfs_node_type_t type = VFS_NODE_FILE;
    vfs_stat(handle->node, &size, &type, NULL, NULL, NULL);

    int64_t base = 0;
    switch (whence)
    {
        case SYSCALL_SEEK_SET: base = 0; break;
        case SYSCALL_SEEK_CUR: base = (int64_t)handle->offset; break;
        case SYSCALL_SEEK_END: base = (int64_t)size; break;
        default: return -1;
    }

    int64_t target = 0;
    if (__builtin_add_overflow(base, offset, &target) || target < 0)
    {
        return -1;
    }

    handle->offset = (size_t)target;
    return target;
}

static int syscall_file_fstat(void *ctx, syscall_stat_t *out)
{
    file_handle_t *handle = (file_handle_t *)ctx;
    if (!handle || !handle->node || !out)
    {
        return -1;
    }

    size_t size = 0;
    vfs_node_type_t type = VFS_NODE_FILE;
    uint64_t atime = 0;
    uint64_t mtime = 0;
    uint64_t ctime = 0;
    if (!vfs_stat(handle->node, &size, &type, &atime, &mtime, &ctime))
    {
        return -1;
    }
    out->size_bytes = size;
    out->type = (uint32_t)type;
    out->reserved = 0;
    out->atime = atime;
    out->mtime = mtime;
    out->ctime = ctime;
    return 0;
}

static const fd_ops_t g_syscall_file_ops = {
    .read = syscall_file_read,
    .write = syscall_file_write,
    .close = syscall_file_close,
    .pread = syscall_file_pread,
    .lseek = syscall_file_lseek,
    .fstat = syscall_file_fstat,
};

static int64_t syscall_do_write(uint64_t fd, const void *buffer, size_t count)
{
    if (count == 0)
    {
        return 0;
    }
    if (!buffer)
    {
        return -1;
    }
    if (!user_ptr_range_valid(buffer, count))
    {
        return -1;
    }

    uint8_t *tmp = (uint8_t *)malloc(count);
    if (!tmp)
    {
        return -1;
    }
    if (!user_copy_from_user(tmp, buffer, count))
    {
        free(tmp);
        return -1;
    }
    ssize_t bytes = fd_write((int)fd, tmp, count);
    free(tmp);
    return (int64_t)bytes;
}

static int64_t syscall_do_read(uint64_t fd, void *buffer, size_t count)
{
    if (count == 0)
    {
        return 0;
    }
    if (!buffer)
    {
        return -1;
    }
    if (!user_ptr_range_valid(buffer, count))
    {
        return -1;
    }

    uint8_t *tmp = (uint8_t *)malloc(count);
    if (!tmp)
    {
        return -1;
    }
    ssize_t bytes = fd_read((int)fd, tmp, count);
    if (bytes > 0)
    {
        if (!user_copy_to_user(buffer, tmp, (size_t)bytes))
        {
            bytes = -1;
        }
    }
    free(tmp);
    return (int64_t)bytes;
}

static int64_t syscall_do_pread(uint64_t fd, void *buffer, size_t count, size_t offset)
{
    if (count == 0)
    {
        return 0;
    }
    if (!buffer)
    {
        return -1;
    }
    if (!user_ptr_range_valid(buffer, count))
    {
        return -1;
    }

    uint8_t *tmp = (uint8_t *)malloc(count);
    if (!tmp)
    {
        return -1;
    }
    ssize_t bytes = fd_pread((int)fd, tmp, count, offset);
    if (bytes > 0)
    {
        if (!user_copy_to_user(buffer, tmp, (size_t)bytes))
        {
            bytes = -1;
        }
    }
    free(tmp);
    return (int64_t)bytes;
}

static int64_t syscall_do_lseek(uint64_t fd, int64_t offset, int whence)
{
    return fd_lseek((int)fd, offset, whence);
}

static int64_t syscall_do_fstat(uint64_t fd, syscall_stat_t *out)
{
    if (!out)
    {
        return -1;
    }
    if (!user_ptr_range_valid(out, sizeof(*out)))
    {
        return -1;
    }
    syscall_stat_t tmp;
    if (fd_fstat((int)fd, &tmp) != 0)
    {
        return -1;
    }
    if (!user_copy_to_user(out, &tmp, sizeof(tmp)))
    {
        return -1;
    }
    return 0;
}

static int64_t syscall_do_close(uint64_t fd)
{
    return (int64_t)fd_close((int)fd);
}

static int64_t syscall_do_list_dir(const char *path, syscall_dirent_t *out_entries, size_t capacity)
{
    if (!out_entries || capacity == 0)
    {
        return -1;
    }

    size_t bytes = 0;
    if (__builtin_mul_overflow(capacity, sizeof(*out_entries), &bytes))
    {
        return -1;
    }

    if (!user_ptr_range_valid(out_entries, bytes))
    {
        return -1;
    }

    char *path_buf = (char *)malloc(SYSCALL_MAX_PATH_LEN);
    if (!path_buf)
    {
        return -1;
    }
    size_t copied_len = 0;
    if (!user_copy_string_from_user(path_buf, SYSCALL_MAX_PATH_LEN, path ? path : "", &copied_len))
    {
        free(path_buf);
        return -1;
    }
    (void)copied_len;

    vfs_node_t *cwd = process_current_cwd();
    if (!cwd)
    {
        cwd = vfs_root();
    }
    vfs_node_t *dir = vfs_resolve(cwd, path_buf);
    free(path_buf);
    if (!dir || !vfs_is_dir(dir))
    {
        return -1;
    }

    syscall_dirent_t *entries = (syscall_dirent_t *)malloc(bytes);
    if (!entries)
    {
        return -1;
    }
    syscall_dir_enum_t ctx = {
        .entries = entries,
        .capacity = capacity,
        .count = 0
    };
    vfs_enum_children(dir, syscall_dir_collect, &ctx);

    if (ctx.count > 0)
    {
        size_t copy_bytes = ctx.count * sizeof(syscall_dirent_t);
        if (!user_copy_to_user(out_entries, entries, copy_bytes))
        {
            free(entries);
            return -1;
        }
    }

    free(entries);
    return (int64_t)ctx.count;
}

static int64_t syscall_do_mkdir(const char *path)
{
    if (!path)
    {
        return -1;
    }

    char *path_buf = (char *)malloc(SYSCALL_MAX_PATH_LEN);
    if (!path_buf)
    {
        return -1;
    }
    size_t copied_len = 0;
    if (!user_copy_string_from_user(path_buf, SYSCALL_MAX_PATH_LEN, path, &copied_len))
    {
        free(path_buf);
        return -1;
    }
    if (copied_len == 0 || path_buf[0] == '\0')
    {
        free(path_buf);
        return -1;
    }

    vfs_node_t *cwd = process_current_cwd();
    if (!cwd)
    {
        cwd = vfs_root();
    }
    vfs_node_t *dir = vfs_mkdir(cwd, path_buf);
    free(path_buf);
    if (!dir || !vfs_is_dir(dir))
    {
        return -1;
    }
    return 0;
}

/*
 * Open a VFS file and return an FD.
 *
 * This allocates a `file_handle_t` (node + current offset + access flags),
 * retains the underlying `vfs_node_t`, and installs the handle into the global
 * FD table with `g_syscall_file_ops`.
 */
static int64_t syscall_do_open(const char *path, uint64_t flags)
{
    if (!path)
    {
        return -1;
    }

    bool readable = (flags & SYSCALL_OPEN_READ) != 0;
    bool writable = (flags & SYSCALL_OPEN_WRITE) != 0;
    if (!readable && !writable)
    {
        return -1;
    }
    bool create = (flags & SYSCALL_OPEN_CREATE) != 0;
    bool truncate = (flags & SYSCALL_OPEN_TRUNCATE) != 0;

    char *path_buf = (char *)malloc(SYSCALL_MAX_PATH_LEN);
    if (!path_buf)
    {
        return -1;
    }
    size_t copied_len = 0;
    if (!user_copy_string_from_user(path_buf, SYSCALL_MAX_PATH_LEN, path, &copied_len))
    {
        // serial_printf("%s", "[sys_open] copy failed\n");
        free(path_buf);
        return -1;
    }
    // serial_printf("[sys_open] path=%s len=0x%016llX flags=0x%016llX\n",
    //               path_buf,
    //               (unsigned long long)copied_len,
    //               (unsigned long long)flags);

    file_handle_t *handle = (file_handle_t *)malloc(sizeof(file_handle_t));
    if (!handle)
    {
        free(path_buf);
        return -1;
    }

    vfs_node_t *cwd = process_current_cwd();
    if (!cwd)
    {
        cwd = vfs_root();
    }

    bool proc_devices_path = (path_buf && strncmp(path_buf, "/proc/devices", 13) == 0);
    bool trace_doom_wad = (path_buf && strcmp(path_buf, "/usr/share/games/doom/doom1.wad") == 0);
    if (proc_devices_path)
    {
        serial_printf("%s", "[sys_open] attempt ");
        serial_printf("%s", path_buf);
        serial_printf("%s", " flags=0x");
        serial_printf("%016llX", (unsigned long long)flags);
        serial_printf("%s", "\r\n");
    }

    if (trace_doom_wad)
    {
        serial_printf("[sys_open] doom pre vfs_open_file cwd=0x%016llX create=%d truncate=%d",
                      (unsigned long long)(uintptr_t)cwd,
                      create ? 1 : 0,
                      (truncate && writable) ? 1 : 0);
    }

    vfs_node_t *node = vfs_open_file(cwd, path_buf, create, truncate && writable);
    if (trace_doom_wad)
    {
        serial_printf("[sys_open] doom vfs_open_file node=0x%016llX",
                      (unsigned long long)(uintptr_t)node);
    }
    if (!node && proc_devices_path)
    {
        serial_printf("%s", "[sys_open] fail ");
        serial_printf("%s", path_buf);
        serial_printf("%s", " flags=");
        serial_printf("%016llX", (unsigned long long)flags);
        serial_printf("%s", "\r\n");
    }
    if (node && proc_devices_path)
    {
        serial_printf("%s", "[sys_open] ok ");
        serial_printf("%s", path_buf);
        serial_printf("%s", "\r\n");
    }
    free(path_buf);
    if (!node)
    {
        free(handle);
        return -1;
    }

    vfs_node_retain(node);
    handle->node = node;
    handle->offset = 0;
    handle->readable = readable;
    handle->writable = writable;

    int fd = fd_allocate(&g_syscall_file_ops, handle);
    if (fd < 0)
    {
        vfs_node_release(node);
        free(handle);
        return -1;
    }
    if (trace_doom_wad)
    {
        serial_printf("[sys_open] doom fd=%d", fd);
    }
    return (int64_t)fd;
}

/*
 * Syscall dispatch entrypoint called from the x86 0x80 stub.
 *
 * - `frame` contains the saved user register state; `frame->rax` is the syscall id.
 * - The handler writes the return value back to `frame->rax`.
 * - Some syscalls (notably `SYSCALL_YIELD` when invoked from the user preempt
 *   stub) return additional information via RAX (resume RIP).
 */
uint64_t syscall_dispatch(syscall_frame_t *frame, uint64_t vector)
{
    (void)vector;

    if (!frame)
    {
        return 0;
    }

    uint64_t syscall_id = frame->rax;
    int64_t result = -1;

    switch (syscall_id)
    {
        case SYSCALL_EXIT:
            process_exit((int)frame->rdi);
            return 0;
        case SYSCALL_WRITE:
            result = syscall_do_write(frame->rdi,
                                      (const void *)frame->rsi,
                                      (size_t)frame->rdx);
            break;
        case SYSCALL_READ:
            result = syscall_do_read(frame->rdi,
                                     (void *)frame->rsi,
                                     (size_t)frame->rdx);
            break;
        case SYSCALL_PREAD:
            result = syscall_do_pread(frame->rdi,
                                      (void *)frame->rsi,
                                      (size_t)frame->rdx,
                                      (size_t)frame->r10);
            break;
        case SYSCALL_OPEN:
            result = syscall_do_open((const char *)frame->rdi, frame->rsi);
            break;
        case SYSCALL_CLOSE:
            result = syscall_do_close(frame->rdi);
            break;
        case SYSCALL_LSEEK:
            result = syscall_do_lseek(frame->rdi, (int64_t)frame->rsi, (int)frame->rdx);
            break;
        case SYSCALL_FSTAT:
            result = syscall_do_fstat(frame->rdi, (syscall_stat_t *)frame->rsi);
            break;
        case SYSCALL_LIST_DIR:
            result = syscall_do_list_dir((const char *)frame->rdi,
                                         (syscall_dirent_t *)frame->rsi,
                                         (size_t)frame->rdx);
            break;
        case SYSCALL_MKDIR:
            result = syscall_do_mkdir((const char *)frame->rdi);
            break;
        case SYSCALL_YIELD:
            process_preempt_hook();
            {
                uint64_t resume = process_take_preempt_resume_rip();
                if (resume)
                {
                    /* Return the resume RIP to the user preempt stub so it can
                     * restore the interrupted register state before resuming.
                     *
                     * NOTE: We intentionally do NOT overwrite frame->rip here.
                     * The preempt stub will `ret` to this address. */
                    result = (int64_t)resume;
                    break;
                }
            }
            result = 0;
            break;
        case SYSCALL_SLEEP_MS:
        {
            uint32_t ms = (uint32_t)frame->rdi;
            if (ms == 0)
            {
                process_yield();
            }
            else
            {
                process_sleep_ms(ms);
            }
            result = 0;
            break;
        }
        case SYSCALL_SBRK:
            result = process_user_sbrk(process_current(), (int64_t)frame->rdi);
            break;
        case SYSCALL_UI_CREATE:
            result = user_atk_sys_create((const user_atk_window_desc_t *)frame->rdi);
            break;
        case SYSCALL_UI_PRESENT:
            result = user_atk_sys_present((uint32_t)frame->rdi,
                                          (const video_color_t *)frame->rsi,
                                          (size_t)frame->rdx);
            break;
        case SYSCALL_UI_POLL_EVENT:
            result = user_atk_sys_poll_event((uint32_t)frame->rdi,
                                             (user_atk_event_t *)frame->rsi,
                                             (uint32_t)frame->rdx);
            break;
        case SYSCALL_UI_POLL_EVENT_TIMEOUT:
            result = user_atk_sys_poll_event_timeout((uint32_t)frame->rdi,
                                                     (user_atk_event_t *)frame->rsi,
                                                     (uint32_t)frame->rdx);
            break;
        case SYSCALL_UI_CLOSE:
            result = user_atk_sys_close((uint32_t)frame->rdi);
            break;
        case SYSCALL_UI_CAPTURE:
            result = user_atk_sys_capture((uint32_t)frame->rdi, (uint32_t)frame->rsi);
            break;
        case SYSCALL_FONT_CACHE:
            result = font_cache_copy_to_user((void *)frame->rdi, (size_t)frame->rsi);
            break;
        case SYSCALL_SERIAL_WRITE:
        {
            const char *msg = (const char *)frame->rdi;
            size_t len = (size_t)frame->rsi;
            if (!msg)
            {
                result = -1;
                break;
            }

            if (len == 0)
            {
                if (SYSCALL_MAX_SERIAL_BYTES == 0)
                {
                    result = -1;
                    break;
                }
                char *tmp = (char *)malloc(SYSCALL_MAX_SERIAL_BYTES);
                if (!tmp)
                {
                    result = -1;
                    break;
                }
                size_t copied = 0;
                if (!user_copy_string_from_user(tmp, SYSCALL_MAX_SERIAL_BYTES, msg, &copied))
                {
                    free(tmp);
                    result = -1;
                    break;
                }
                serial_output_bytes(tmp, copied);
                result = (int64_t)copied;
                free(tmp);
                break;
            }

            if (len > SYSCALL_MAX_SERIAL_BYTES)
            {
                result = -1;
                break;
            }
            char *tmp = (char *)malloc(len);
            if (!tmp)
            {
                result = -1;
                break;
            }
            if (!user_copy_from_user(tmp, msg, len))
            {
                free(tmp);
                result = -1;
                break;
            }
            serial_output_bytes(tmp, len);
            free(tmp);
            result = (int64_t)len;
            break;
        }
        case SYSCALL_SHELL_OPEN:
            result = shell_service_open_session();
            break;
        case SYSCALL_SHELL_CLOSE:
            result = shell_service_close_session((uint32_t)frame->rdi) ? 0 : -1;
            break;
        case SYSCALL_SHELL_EXEC:
        {
            const char *command_user = (const char *)frame->rsi;
            size_t command_len = (size_t)frame->rdx;
            if (!command_user)
            {
                result = -1;
                break;
            }
            if (command_len > (size_t)(SYSCALL_MAX_COMMAND_LEN - 1))
            {
                result = -1;
                break;
            }
            size_t buffer_len = (command_len > 0) ? (command_len + 1) : SYSCALL_MAX_COMMAND_LEN;
            char *command = (char *)malloc(buffer_len);
            if (!command)
            {
                result = -1;
                break;
            }
            if (command_len == 0)
            {
                size_t copied = 0;
                if (!user_copy_string_from_user(command, buffer_len, command_user, &copied))
                {
                    free(command);
                    result = -1;
                    break;
                }
                command_len = copied;
            }
            else
            {
                if (!user_copy_from_user(command, command_user, command_len))
                {
                    free(command);
                    result = -1;
                    break;
                }
                command[command_len] = '\0';
            }
            result = shell_service_exec((uint32_t)frame->rdi, command, command_len);
            free(command);
            break;
        }
        case SYSCALL_SHELL_POLL:
        {
            char *output_user = (char *)frame->rsi;
            size_t output_capacity = (size_t)frame->rdx;
            int *status_user = (int *)frame->r10;
            int *running_user = (int *)frame->r8;
            if (output_user && output_capacity > 0 &&
                !user_ptr_range_valid(output_user, output_capacity))
            {
                result = -1;
                break;
            }

            int status_tmp = 0;
            int running_tmp = 0;
            ssize_t poll_res = shell_service_poll((uint32_t)frame->rdi,
                                                  output_user,
                                                  output_capacity,
                                                  status_user ? &status_tmp : NULL,
                                                  running_user ? &running_tmp : NULL);
            if (poll_res >= 0)
            {
                if (poll_res >= 0 && status_user)
                {
                    if (!user_copy_to_user(status_user, &status_tmp, sizeof(status_tmp)))
                    {
                        poll_res = -1;
                    }
                }
                if (poll_res >= 0 && running_user)
                {
                    if (!user_copy_to_user(running_user, &running_tmp, sizeof(running_tmp)))
                    {
                        poll_res = -1;
                    }
                }
            }

            result = (poll_res >= 0) ? (int64_t)poll_res : -1;
            break;
        }
        case SYSCALL_SHELL_CWD:
        {
            char *output_user = (char *)frame->rsi;
            size_t output_capacity = (size_t)frame->rdx;
            if (!output_user || output_capacity == 0 ||
                !user_ptr_range_valid(output_user, output_capacity))
            {
                result = -1;
                break;
            }
            char path_buf[256];
            ssize_t written = shell_service_get_cwd((uint32_t)frame->rdi,
                                                    path_buf,
                                                    sizeof(path_buf));
            if (written < 0 || (size_t)written + 1 > output_capacity)
            {
                result = -1;
                break;
            }
            if (!user_copy_to_user(output_user, path_buf, (size_t)written + 1))
            {
                result = -1;
                break;
            }
            result = written;
            break;
        }
        case SYSCALL_SHELL_PROMPT:
        {
            char *output_user = (char *)frame->rsi;
            size_t output_capacity = (size_t)frame->rdx;
            if (!output_user || output_capacity == 0 ||
                !user_ptr_range_valid(output_user, output_capacity))
            {
                result = -1;
                break;
            }

            size_t buffer_cap = output_capacity;
            if (buffer_cap > SYSCALL_MAX_PROMPT_LEN)
            {
                buffer_cap = SYSCALL_MAX_PROMPT_LEN;
            }

            char *prompt_buf = (char *)malloc(buffer_cap);
            if (!prompt_buf)
            {
                result = -1;
                break;
            }

            ssize_t written = shell_service_get_prompt((uint32_t)frame->rdi,
                                                       prompt_buf,
                                                       buffer_cap);
            if (written < 0 || (size_t)written + 1 > output_capacity)
            {
                free(prompt_buf);
                result = -1;
                break;
            }
            if (!user_copy_to_user(output_user, prompt_buf, (size_t)written + 1))
            {
                free(prompt_buf);
                result = -1;
                break;
            }
            free(prompt_buf);
            result = written;
            break;
        }
        case SYSCALL_SHELL_INTERRUPT:
            result = shell_service_interrupt((uint32_t)frame->rdi);
            break;
        case SYSCALL_PROC_SNAPSHOT:
            result = syscall_do_proc_snapshot((syscall_process_info_t *)frame->rdi,
                                              (size_t)frame->rsi);
            break;
        case SYSCALL_NET_SNAPSHOT:
            result = syscall_do_net_snapshot((syscall_net_stats_t *)frame->rdi,
                                             (size_t)frame->rsi);
            break;
        case SYSCALL_CPU_SNAPSHOT:
            result = syscall_do_cpu_snapshot((syscall_cpu_stats_t *)frame->rdi,
                                             (size_t)frame->rsi);
            break;
        case SYSCALL_TIME_INFO:
        {
            syscall_time_info_t *user_info = (syscall_time_info_t *)frame->rdi;
            if (!user_info || !user_ptr_range_valid(user_info, sizeof(*user_info)))
            {
                result = -1;
                break;
            }
            syscall_time_info_t info = { 0 };
            info.offset_minutes = timekeeping_timezone_offset_minutes();
            const char *tz_name = timekeeping_timezone_name();
            syscall_copy_string(info.timezone_name, sizeof(info.timezone_name), tz_name);
            result = user_copy_to_user(user_info, &info, sizeof(info)) ? 0 : -1;
            break;
        }
        case SYSCALL_TIME_MILLIS:
            result = (int64_t)timekeeping_now_millis();
            break;
        case SYSCALL_GETUID:
            result = (int64_t)process_get_uid(process_current());
            break;
        case SYSCALL_SOCKET_OPEN:
            result = syscall_do_socket_open((const char *)frame->rdi);
            break;
        case SYSCALL_SOCKET_CONNECT:
            result = syscall_do_socket_connect((int)frame->rdi,
                                               (const char *)frame->rsi,
                                               (uint16_t)frame->rdx);
            break;
        case SYSCALL_SOCKET_AVAILABLE:
            result = syscall_do_socket_available((int)frame->rdi);
            break;
        case SYSCALL_THREAD_SELF:
            result = (int64_t)thread_current_tid();
            break;
        case SYSCALL_THREAD_CREATE:
            result = syscall_do_thread_create((uintptr_t)frame->rdi,
                                              (uintptr_t)frame->rsi,
                                              (size_t)frame->rdx,
                                              (const char *)frame->r10);
            break;
        case SYSCALL_THREAD_JOIN:
        {
            int *status_user = (int *)frame->rsi;
            if (status_user && !user_ptr_range_valid(status_user, sizeof(*status_user)))
            {
                result = -1;
                break;
            }
            int status_tmp = 0;
            int join_res = process_user_thread_join(frame->rdi, status_user ? &status_tmp : NULL);
            if (join_res >= 0 && status_user)
            {
                if (!user_copy_to_user(status_user, &status_tmp, sizeof(status_tmp)))
                {
                    result = -1;
                    break;
                }
            }
            result = (int64_t)join_res;
            break;
        }
        case SYSCALL_THREAD_EXIT:
            process_user_thread_exit((int)frame->rdi);
            return 0;
        default:
            serial_printf("%s", "syscall: unhandled id=");
            serial_printf("%016llX", (unsigned long long)(syscall_id));
            serial_printf("%s", "\r\n");
            result = -1;
            break;
    }

    frame->rax = (uint64_t)result;
    return (uint64_t)result;
}
