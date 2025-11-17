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
#include "user_copy.h"

static process_info_t *g_proc_snapshot_buf = NULL;
static size_t g_proc_snapshot_cap = 0;
static syscall_process_info_t *g_proc_snapshot_user_buf = NULL;
static size_t g_proc_snapshot_user_cap = 0;
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

    char *path_buf = (char *)malloc(SYSCALL_MAX_PATH_LEN);
    if (!path_buf)
    {
        return -1;
    }
    if (!user_copy_string_from_user(path_buf, SYSCALL_MAX_PATH_LEN, path, NULL))
    {
        free(path_buf);
        return -1;
    }

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
    vfs_node_t *node = vfs_open_file(cwd, path_buf, create, truncate && writable);
    free(path_buf);
    if (!node)
    {
        free(handle);
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
            if (output_user && !user_ptr_range_valid(output_user, output_capacity))
            {
                result = -1;
                break;
            }

            char *output = NULL;
            if (output_capacity > 0 && output_user)
            {
                output = (char *)malloc(output_capacity);
                if (!output)
                {
                    result = -1;
                    break;
                }
            }

            int status_tmp = 0;
            int running_tmp = 0;
            ssize_t poll_res = shell_service_poll((uint32_t)frame->rdi,
                                                  output,
                                                  output_capacity,
                                                  status_user ? &status_tmp : NULL,
                                                  running_user ? &running_tmp : NULL);
            if (poll_res >= 0)
            {
                if (output && output_capacity > 0)
                {
                    size_t to_copy = (size_t)poll_res + 1;
                    if (to_copy > output_capacity)
                    {
                        to_copy = output_capacity;
                    }
                    if (!user_copy_to_user(output_user, output, to_copy))
                    {
                        poll_res = -1;
                    }
                }
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

            free(output);
            result = (poll_res >= 0) ? (int64_t)poll_res : -1;
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
