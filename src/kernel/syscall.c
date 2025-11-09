#include "syscall.h"

#include "syscall_defs.h"
#include "process.h"
#include "serial.h"
#include "fd.h"
#include "heap.h"
#include "vfs.h"
#include "libc.h"
#include "user_atk_host.h"

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
            for (size_t i = 0; i < len; ++i)
            {
                serial_write_char(msg[i]);
            }
            result = (int64_t)len;
            break;
        }
        default:
            serial_write_string("syscall: unhandled id=");
            serial_write_hex64(syscall_id);
            serial_write_string("\r\n");
            result = -1;
            break;
    }

    frame->rax = (uint64_t)result;
    return (uint64_t)result;
}
