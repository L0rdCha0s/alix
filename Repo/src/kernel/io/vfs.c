#include "io_vfs.h"
#include "vfs.h"
#include "process.h"
#include "heap.h"
#include "errno.h"

typedef struct
{
    vfs_node_t *node;
    uint64_t offset;
    bool readable, writable;
    bool offset_owned;
    wait_queue_t offset_waiters;
} io_vfs_file_t;

static bool io_vfs_offset_ready(void *context)
{
    io_vfs_file_t *file = context;
    bool expected = false;
    return __atomic_compare_exchange_n(&file->offset_owned, &expected, true, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static void io_vfs_offset_lock(io_vfs_file_t *file)
{
    wait_queue_wait(&file->offset_waiters, io_vfs_offset_ready, file);
}

static void io_vfs_offset_unlock(io_vfs_file_t *file)
{
    __atomic_store_n(&file->offset_owned, false, __ATOMIC_RELEASE);
    wait_queue_wake_all(&file->offset_waiters);
}

static ssize_t io_vfs_file_read(void *context, void *buffer, size_t count)
{
    io_vfs_file_t *file = context;
    if (!file || !file->readable) return -EBADF;
    if (!buffer && count) return -EINVAL;
    io_vfs_offset_lock(file);
    ssize_t result = count > 0x7fffffffffffffffULL - file->offset ? -EOVERFLOW :
        vfs_read_data_at(file->node, (size_t)file->offset, buffer, count);
    if (result > 0 && (size_t)result <= count) file->offset += (uint64_t)result;
    else if (result > 0) result = -EIO;
    io_vfs_offset_unlock(file);
    return result == -1 ? -EIO : result;
}

static ssize_t io_vfs_file_write(void *context, const void *buffer, size_t count)
{
    io_vfs_file_t *file = context;
    if (!file || !file->writable) return -EBADF;
    if (!buffer && count) return -EINVAL;
    io_vfs_offset_lock(file);
    ssize_t result = count > 0x7fffffffffffffffULL - file->offset ? -EFBIG :
        vfs_write_data_at(file->node, (size_t)file->offset, buffer, count);
    if (result > 0 && (size_t)result <= count) file->offset += (uint64_t)result;
    else if (result > 0) result = -EIO;
    io_vfs_offset_unlock(file);
    return result == -1 ? -EIO : result;
}

static ssize_t io_vfs_file_pread(void *context, void *buffer, size_t count, size_t offset)
{
    io_vfs_file_t *file = context;
    if (!file || !file->readable) return -EBADF;
    if ((!buffer && count) || offset > 0x7fffffffffffffffULL ||
        count > 0x7fffffffffffffffULL - offset) return -EINVAL;
    ssize_t result = vfs_read_data_at(file->node, offset, buffer, count);
    if (result > 0 && (size_t)result > count) return -EIO;
    return result == -1 ? -EIO : result;
}

static int64_t io_vfs_file_seek(void *context, int64_t offset, int whence)
{
    io_vfs_file_t *file = context;
    if (!file) return -EBADF;
    io_vfs_offset_lock(file);
    uint64_t base = 0;
    int64_t result = -EINVAL;
    if (whence == SYSCALL_SEEK_CUR) base = file->offset;
    else if (whence == SYSCALL_SEEK_END)
    {
        size_t size = 0;
        if (!vfs_stat(file->node, &size, NULL, NULL, NULL, NULL))
        {
            result = -EIO;
            goto done;
        }
        base = size;
    }
    else if (whence != SYSCALL_SEEK_SET) goto done;
    if (base > 0x7fffffffffffffffULL)
    {
        result = -EOVERFLOW;
        goto done;
    }
    int64_t target;
    if (__builtin_add_overflow((int64_t)base, offset, &target) || target < 0) goto done;
    file->offset = (uint64_t)target;
    result = target;
done:
    io_vfs_offset_unlock(file);
    return result;
}

static int io_vfs_file_stat(void *context, syscall_stat_t *out)
{
    io_vfs_file_t *file = context;
    if (!file || !out) return -EINVAL;
    size_t size = 0;
    vfs_node_type_t type;
    if (!vfs_stat(file->node, &size, &type, &out->atime, &out->mtime, &out->ctime)) return -EIO;
    out->size_bytes = size;
    out->type = (uint32_t)type;
    out->reserved = 0;
    return 0;
}

static int io_vfs_file_close(void *context)
{
    io_vfs_file_t *file = context;
    if (file)
    {
        if (file->node) vfs_node_release(file->node);
        free(file);
    }
    return 0;
}

static const fd_ops_t io_vfs_ops = {
    .read = io_vfs_file_read,
    .write = io_vfs_file_write,
    .pread = io_vfs_file_pread,
    .lseek = io_vfs_file_seek,
    .fstat = io_vfs_file_stat,
    .close = io_vfs_file_close,
};

void io_vfs_execute(io_request_t *request, io_service_result_t *result,
                     fd_retirement_queue_t *retirement)
{
    if (!result) return;
    result->result = -EINVAL;
    result->description_owned = NULL;
    if (!request || io_request_buffer_size(request) < sizeof(io_vfs_operation_t)) return;
    io_vfs_operation_t *operation = io_request_buffer(request);
    size_t available = io_request_buffer_size(request) - sizeof(*operation);
    if (!operation || operation->reserved) return;
    fd_description_t *description = io_request_description(request);
    if (operation->opcode == IO_VFS_RESOLVE_CWD)
    {
        if (description || !io_request_cwd(request)) return;
        size_t length = 0;
        while (length < available && length < 4096u && operation->data[length]) ++length;
        if (length == available || length == 4096u) { result->result = -ENAMETOOLONG; return; }
        vfs_node_t *node = NULL;
        result->result = vfs_resolve_owned(io_request_cwd(request), (const char *)operation->data, &node);
        if (result->result) return;
        if (!vfs_is_dir(node))
        {
            vfs_node_release(node);
            result->result = -ENOTDIR;
            return;
        }
        result->description_owned = process_cwd_description_create_owned(node);
        if (!result->description_owned)
        {
            vfs_node_release(node);
            result->result = -ENOMEM;
        }
        return;
    }
    if (operation->opcode == IO_VFS_READLINK)
    {
        if (description || !io_request_cwd(request) || !operation->count || operation->count > available) return;
        size_t length = 0;
        while (length < available && length < 4096u && operation->data[length]) ++length;
        if (length == available || length == 4096u) { result->result = -ENAMETOOLONG; return; }
        result->result = vfs_readlink_snapshot(io_request_cwd(request), (const char *)operation->data,
                                               operation->data, (size_t)operation->count,
                                               io_request_uid(request), io_request_gid(request));
        return;
    }
    if (operation->opcode == IO_VFS_OPEN)
    {
        uint32_t known = SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE;
        if (!retirement || description || !io_request_cwd(request) ||
            (operation->flags & ~known) || !(operation->flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)) ||
            ((operation->flags & SYSCALL_OPEN_TRUNCATE) && !(operation->flags & SYSCALL_OPEN_WRITE))) return;
        size_t length = 0;
        while (length < available && length < 4096u && operation->data[length]) ++length;
        if (!length) return;
        if (length == available || length == 4096u) { result->result = -ENAMETOOLONG; return; }
        io_vfs_file_t *file = calloc(1, sizeof(*file));
        if (!file) { result->result = -ENOMEM; return; }
        wait_queue_init(&file->offset_waiters);
        file->readable = (operation->flags & SYSCALL_OPEN_READ) != 0;
        file->writable = (operation->flags & SYSCALL_OPEN_WRITE) != 0;
        description = fd_description_create_deferred(&io_vfs_ops, file, retirement);
        if (!description) { free(file); result->result = -ENOMEM; return; }
        result->result = vfs_open_data_owned(io_request_cwd(request), (const char *)operation->data,
                                            (operation->flags & SYSCALL_OPEN_CREATE) != 0,
                                            (operation->flags & SYSCALL_OPEN_TRUNCATE) != 0,
                                            io_request_uid(request), io_request_gid(request), &file->node);
        if (result->result) fd_description_put(description);
        else result->description_owned = description;
        return;
    }
    if (!description || fd_description_ops(description)->close != io_vfs_file_close)
    {
        result->result = -EBADF;
        return;
    }
    io_vfs_file_t *file = fd_description_context(description);
    if (operation->count > available) return;
    switch (operation->opcode)
    {
        case IO_VFS_READ:
            result->result = io_vfs_file_read(file, operation->data, (size_t)operation->count);
            break;
        case IO_VFS_WRITE:
            result->result = io_vfs_file_write(file, operation->data, (size_t)operation->count);
            break;
        case IO_VFS_PREAD:
            if (operation->offset >= 0)
                result->result = io_vfs_file_pread(file, operation->data, (size_t)operation->count, (size_t)operation->offset);
            break;
        case IO_VFS_SEEK:
            result->result = io_vfs_file_seek(file, operation->offset, operation->whence);
            break;
        case IO_VFS_STAT:
            result->result = io_vfs_file_stat(file, &operation->stat);
            break;
        case IO_VFS_SYNC:
            io_vfs_offset_lock(file);
            result->result = vfs_flush_node(file->node) ? 0 : -EIO;
            io_vfs_offset_unlock(file);
            break;
        default:
            result->result = -ENOSYS;
            break;
    }
}
