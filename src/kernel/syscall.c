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

static process_info_t *g_proc_snapshot_buf = NULL;
static size_t g_proc_snapshot_cap = 0;
static net_interface_stats_t *g_net_snapshot_buf = NULL;
static size_t g_net_snapshot_cap = 0;

typedef struct
{
    vfs_node_t *node;
    size_t offset;
    bool readable;
    bool writable;
} file_handle_t;

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

static int64_t syscall_do_proc_snapshot(syscall_process_info_t *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return -1;
    }

    if (capacity > g_proc_snapshot_cap)
    {
        size_t bytes = sizeof(process_info_t) * capacity;
        process_info_t *new_buf = (process_info_t *)realloc(g_proc_snapshot_buf, bytes);
        if (!new_buf)
        {
            return -1;
        }
        g_proc_snapshot_buf = new_buf;
        g_proc_snapshot_cap = capacity;
    }

    process_info_t *tmp = g_proc_snapshot_buf;
    if (!tmp)
    {
        return -1;
    }

    size_t count = process_snapshot(tmp, capacity);
    for (size_t i = 0; i < count; ++i)
    {
        const process_info_t *info = &tmp[i];
        syscall_process_info_t *out = &buffer[i];
        out->pid = info->pid;
        out->process_state = (uint32_t)info->state;
        out->thread_state = (uint32_t)info->thread_state;
        out->time_slice_remaining = info->time_slice_remaining;
        out->stdout_fd = info->stdout_fd;
        out->is_idle = info->is_idle ? 1u : 0u;
        out->heap_used_bytes = info->heap_used_bytes;
        out->heap_committed_bytes = info->heap_committed_bytes;

        const char *proc_name = info->name ? info->name : "";
        const char *thread_name = info->thread_name ? info->thread_name : "";
        syscall_copy_string(out->process_name, SYSCALL_PROCESS_NAME_MAX, proc_name);
        syscall_copy_string(out->thread_name, SYSCALL_PROCESS_NAME_MAX, thread_name);
    }

    return (int64_t)count;
}

static int64_t syscall_do_net_snapshot(syscall_net_stats_t *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return -1;
    }

    if (capacity > g_net_snapshot_cap)
    {
        size_t bytes = sizeof(net_interface_stats_t) * capacity;
        net_interface_stats_t *new_buf = (net_interface_stats_t *)realloc(g_net_snapshot_buf, bytes);
        if (!new_buf)
        {
            return -1;
        }
        g_net_snapshot_buf = new_buf;
        g_net_snapshot_cap = capacity;
    }

    net_interface_stats_t *tmp = g_net_snapshot_buf;
    if (!tmp)
    {
        return -1;
    }

    size_t count = net_if_snapshot(tmp, capacity);
    for (size_t i = 0; i < count; ++i)
    {
        const net_interface_stats_t *stats = &tmp[i];
        syscall_net_stats_t *out = &buffer[i];
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

    return (int64_t)count;
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
            vfs_flush_node(handle->node);
        }
        free(handle);
    }
    return 0;
}

static const fd_ops_t g_syscall_file_ops = {
    .read = syscall_file_read,
    .write = syscall_file_write,
    .close = syscall_file_close,
};

static int64_t syscall_do_write(uint64_t fd, const void *buffer, size_t count)
{
    if (!buffer && count > 0)
    {
        return -1;
    }
    return (int64_t)fd_write((int)fd, buffer, count);
}

static int64_t syscall_do_read(uint64_t fd, void *buffer, size_t count)
{
    if (!buffer && count > 0)
    {
        return -1;
    }
    return (int64_t)fd_read((int)fd, buffer, count);
}

static int64_t syscall_do_close(uint64_t fd)
{
    return (int64_t)fd_close((int)fd);
}

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

    vfs_node_t *cwd = process_current_cwd();
    if (!cwd)
    {
        cwd = vfs_root();
    }
    vfs_node_t *node = vfs_open_file(cwd, path, create, truncate && writable);
    if (!node)
    {
        return -1;
    }

    file_handle_t *handle = (file_handle_t *)malloc(sizeof(file_handle_t));
    if (!handle)
    {
        return -1;
    }
    handle->node = node;
    handle->offset = 0;
    handle->readable = readable;
    handle->writable = writable;

    int fd = fd_allocate(&g_syscall_file_ops, handle);
    if (fd < 0)
    {
        free(handle);
        return -1;
    }
    return (int64_t)fd;
}

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
        case SYSCALL_OPEN:
            result = syscall_do_open((const char *)frame->rdi, frame->rsi);
            break;
        case SYSCALL_CLOSE:
            result = syscall_do_close(frame->rdi);
            break;
        case SYSCALL_YIELD:
            process_preempt_hook();
            {
                uint64_t resume = process_take_preempt_resume_rip();
                if (resume)
                {
                    frame->rip = resume;
                }
            }
            result = 0;
            break;
        case SYSCALL_SBRK:
            result = process_user_sbrk(process_current(), (int64_t)frame->rdi);
            break;
        case SYSCALL_UI_CREATE:
            result = user_atk_sys_create((const user_atk_window_desc_t *)frame->rdi);
            break;
        case SYSCALL_UI_PRESENT:
            result = user_atk_sys_present((uint32_t)frame->rdi,
                                          (const uint16_t *)frame->rsi,
                                          (size_t)frame->rdx);
            break;
        case SYSCALL_UI_POLL_EVENT:
            result = user_atk_sys_poll_event((uint32_t)frame->rdi,
                                             (user_atk_event_t *)frame->rsi,
                                             (uint32_t)frame->rdx);
            break;
        case SYSCALL_UI_CLOSE:
            result = user_atk_sys_close((uint32_t)frame->rdi);
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
                len = strlen(msg);
            }
            serial_output_bytes(msg, len);
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
            result = shell_service_exec((uint32_t)frame->rdi,
                                        (const char *)frame->rsi,
                                        (size_t)frame->rdx);
            break;
        case SYSCALL_SHELL_POLL:
            result = shell_service_poll((uint32_t)frame->rdi,
                                        (char *)frame->rsi,
                                        (size_t)frame->rdx,
                                        (int *)frame->r10,
                                        (int *)frame->r8);
            break;
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
