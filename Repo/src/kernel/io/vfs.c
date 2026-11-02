#include "io_vfs.h"
#include "vfs.h"
#include "process.h"
#include "heap.h"
#include "errno.h"
#include "libc.h"
#include "io_stream.h"
#include "io_tcp.h"
#include "io_pipe.h"
#include "io_audio.h"
#include "system_identity.h"

typedef struct
{
    vfs_node_t *node;
    uint64_t offset;
    bool readable, writable;
    fd_description_t *description; /* self, used only during a pinned callback */
    bool offset_owned;
    wait_queue_t offset_waiters;
    io_flock_state_t flock;
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
    uint32_t status = fd_description_status_flags(file->description);
    bool append = (status & FD_STATUS_APPEND) != 0;
    ssize_t result = append ? vfs_write_append(file->node, buffer, count, false, &file->offset) :
        count > 0x7fffffffffffffffULL - file->offset ? -EFBIG :
        vfs_write_data_at(file->node, (size_t)file->offset, buffer, count);
    if (result > 0)
    {
        if ((size_t)result > count) result = -EIO;
        else if (!append) file->offset += (uint64_t)result;
    }
    /* The protected worker retains this open description and its node through
     * data/metadata commit and the device cache flush. Failed persistence is
     * reported even though the in-memory write and offset may have advanced. */
    if (result > 0 && (status & FD_STATUS_SYNC) && !vfs_flush_node(file->node)) result = -EIO;
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

static int64_t io_vfs_file_available(io_vfs_file_t *file)
{
    io_vfs_offset_lock(file);
    size_t size = 0;
    int64_t result = -EIO;
    if (vfs_stat(file->node, &size, NULL, NULL, NULL, NULL))
    {
        uint64_t available = size > file->offset ? (uint64_t)size - file->offset : 0;
        result = available > INT64_MAX ? INT64_MAX : (int64_t)available;
    }
    io_vfs_offset_unlock(file);
    return result;
}

static int io_vfs_file_close(void *context)
{
    io_vfs_file_t *file = context;
    if (file)
    {
        io_flock_state_close(&file->flock);
        if (file->node) vfs_node_release_owned(file->node);
        free(file);
    }
    return 0;
}

static uint32_t io_vfs_poll(void *context)
{
    (void)context;
    /* Owned data nodes exclude device callbacks. Regular files and directories
     * have no readiness wait; EOF and an invalid direction return immediately. */
    return SYSCALL_POLL_IN | SYSCALL_POLL_OUT;
}
static const fd_ops_t io_vfs_ops = {
    .read = io_vfs_file_read,
    .write = io_vfs_file_write,
    .pread = io_vfs_file_pread,
    .lseek = io_vfs_file_seek,
    .fstat = io_vfs_file_stat,
    .close = io_vfs_file_close,
    .poll = io_vfs_poll,
};

bool io_vfs_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_vfs_file_close;
}

io_flock_state_t *io_vfs_flock_state(const fd_description_t *description)
{
    return io_vfs_description_valid(description) ?
        &((io_vfs_file_t *)fd_description_context(description))->flock : NULL;
}

int io_vfs_open_owned(vfs_node_t *cwd, const char *path, uint32_t flags,
                       uint32_t uid, uint32_t gid, fd_retirement_queue_t *retirement,
                       fd_description_t **output)
{
    if (!output) return -EINVAL;
    *output = NULL;
    uint32_t known = SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE |
                     SYSCALL_OPEN_TRUNCATE | SYSCALL_OPEN_EXCLUSIVE | SYSCALL_OPEN_APPEND | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_SYNC;
    if (!retirement || !cwd || !path || (flags & ~known) || !(flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)) ||
        ((flags & SYSCALL_OPEN_TRUNCATE) && !(flags & SYSCALL_OPEN_WRITE))) return -EINVAL;
    io_vfs_file_t *file = calloc(1, sizeof(*file));
    if (!file) return -ENOMEM;
    wait_queue_init(&file->offset_waiters);
    file->readable = (flags & SYSCALL_OPEN_READ) != 0;
    file->writable = (flags & SYSCALL_OPEN_WRITE) != 0;
    fd_description_t *description = fd_description_create_deferred(&io_vfs_ops, file, retirement);
    if (!description) { free(file); return -ENOMEM; }
    file->description = description;
    (void)fd_description_initialize_status(description, flags &
        (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_APPEND | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_SYNC));
    int result = vfs_open_data_flags_owned(cwd, path, (flags & SYSCALL_OPEN_CREATE) != 0,
                                           (flags & SYSCALL_OPEN_TRUNCATE) != 0,
                                           (flags & SYSCALL_OPEN_EXCLUSIVE) != 0, uid, gid, &file->node);
    if (result) fd_description_put(description);
    else
    {
        io_flock_state_init(&file->flock, file->node, description);
        *output = description;
    }
    return result;
}

typedef struct
{
    vfs_node_t *node;
    vfs_directory_snapshot_t snapshot;
    size_t cursor, index;
    bool cursor_owned;
    wait_queue_t cursor_waiters;
} io_vfs_directory_t;

static bool io_vfs_directory_ready(void *context)
{
    io_vfs_directory_t *directory = context;
    bool expected = false;
    return __atomic_compare_exchange_n(&directory->cursor_owned, &expected, true, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static int io_vfs_directory_close(void *context)
{
    io_vfs_directory_t *directory = context;
    if (directory)
    {
        vfs_directory_snapshot_release(&directory->snapshot);
        if (directory->node) vfs_node_release_owned(directory->node);
        free(directory);
    }
    return 0;
}

static const fd_ops_t io_vfs_directory_ops = { .close = io_vfs_directory_close, .poll = io_vfs_poll };

static int io_vfs_directory_next(io_vfs_directory_t *directory, void *output, bool rewind)
{
    wait_queue_wait(&directory->cursor_waiters, io_vfs_directory_ready, directory);
    int result = 0;
    if (rewind)
    {
        /* POSIX rewind refreshes the directory state. A failed refresh keeps
         * the old snapshot/cursor intact. The protected worker owns this heap
         * record across any VFS wait. */
        vfs_directory_snapshot_t *fresh = calloc(1, sizeof(*fresh));
        if (!fresh) result = -ENOMEM;
        else
        {
            result = vfs_directory_snapshot(directory->node, fresh);
            if (!result)
            {
                vfs_directory_snapshot_release(&directory->snapshot);
                directory->snapshot = *fresh;
                directory->cursor = directory->index = 0;
            }
            free(fresh);
        }
    }
    else if (directory->index < directory->snapshot.count)
    {
        size_t remaining = directory->cursor <= directory->snapshot.bytes ?
                           directory->snapshot.bytes - directory->cursor : 0;
        if (remaining < sizeof(vfs_directory_record_t)) result = -EIO;
        else
        {
            const vfs_directory_record_t *record = (const void *)(directory->snapshot.data + directory->cursor);
            size_t record_bytes = (sizeof(*record) + (size_t)record->name_length + 1u + 7u) & ~(size_t)7u;
            if (!record->inode || record->name_length > SYSCALL_DIRENT_NAME_MAX ||
                record_bytes > remaining || record->name[record->name_length]) result = -EIO;
            else
            {
                syscall_directory_entry_t *entry = output;
                entry->version = SYSCALL_DIRENT_VERSION;
                entry->size = sizeof(*entry);
                entry->inode = record->inode;
                entry->type = record->type;
                entry->name_length = record->name_length;
                memcpy(entry->name, record->name, record->name_length + 1u);
                directory->cursor += record_bytes;
                ++directory->index;
                result = 1;
            }
        }
    }
    __atomic_store_n(&directory->cursor_owned, false, __ATOMIC_RELEASE);
    wait_queue_wake_all(&directory->cursor_waiters);
    return result;
}

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
    if (operation->opcode == IO_VFS_OPEN_DIR)
    {
        if (!retirement || description || !io_request_cwd(request)) return;
        size_t length = 0;
        while (length < available && length < VFS_PATH_MAX && operation->data[length]) ++length;
        if (length == available || length == VFS_PATH_MAX) { result->result = -ENAMETOOLONG; return; }
        io_vfs_directory_t *directory = calloc(1, sizeof(*directory));
        if (!directory) { result->result = -ENOMEM; return; }
        wait_queue_init(&directory->cursor_waiters);
        description = fd_description_create_deferred(&io_vfs_directory_ops, directory, retirement);
        if (!description) { free(directory); result->result = -ENOMEM; return; }
        (void)fd_description_initialize_status(description, FD_STATUS_READ);
        result->result = vfs_resolve_owned(io_request_cwd(request), (const char *)operation->data, &directory->node);
        if (!result->result) result->result = vfs_directory_snapshot(directory->node, &directory->snapshot);
        if (result->result) fd_description_put(description);
        else result->description_owned = description;
        return;
    }
    if (operation->opcode == IO_VFS_READ_DIR || operation->opcode == IO_VFS_REWIND_DIR)
    {
        if (!description || fd_description_ops(description)->close != io_vfs_directory_close)
        { result->result = -EBADF; return; }
        if (operation->opcode == IO_VFS_READ_DIR &&
            (operation->count != sizeof(syscall_directory_entry_t) || operation->count > available)) return;
        result->result = io_vfs_directory_next(fd_description_context(description), operation->data,
                                                operation->opcode == IO_VFS_REWIND_DIR);
        return;
    }
    if (operation->opcode == IO_VFS_RESOLVE_CWD)
    {
        /* Optional input description is solely a caller-lifetime pin. Workers
         * never inspect its context or derive authority from it. */
        if (!io_request_cwd(request)) return;
        size_t length = 0;
        while (length < available && length < 4096u && operation->data[length]) ++length;
        if (length == available || length == 4096u) { result->result = -ENAMETOOLONG; return; }
        vfs_node_t *node = NULL;
        result->result = vfs_resolve_owned(io_request_cwd(request), (const char *)operation->data, &node);
        if (result->result) return;
        if (!vfs_is_dir(node))
        {
            vfs_node_release_owned(node);
            result->result = -ENOTDIR;
            return;
        }
        result->description_owned = process_cwd_description_create_owned(node);
        if (!result->description_owned)
        {
            vfs_node_release_owned(node);
            result->result = -ENOMEM;
        }
        return;
    }
    if (operation->opcode == IO_VFS_SYSTEM_INFO)
    {
        if (description || !io_request_cwd(request) || operation->flags ||
            operation->count != sizeof(syscall_utsname_t) || available != sizeof(syscall_utsname_t)) return;
        result->result = system_identity_snapshot(io_request_cwd(request), io_request_uid(request),
                                                     io_request_gid(request), (void *)operation->data);
        return;
    }
    if (operation->opcode == IO_VFS_GETCWD)
    {
        if (description || !io_request_cwd(request) || operation->flags ||
            !operation->count || operation->count > available) return;
        result->result = vfs_path_snapshot(io_request_cwd(request), (char *)operation->data, (size_t)operation->count);
        return;
    }
    if (operation->opcode == IO_VFS_MKDIR)
    {
        if (description || !io_request_cwd(request) || operation->flags || available < VFS_PATH_MAX) return;
        if (strnlen((const char *)operation->data, VFS_PATH_MAX) == VFS_PATH_MAX) { result->result = -ENAMETOOLONG; return; }
        result->result = vfs_mkdir_exclusive(io_request_cwd(request), (const char *)operation->data,
                                             io_request_uid(request), io_request_gid(request));
        return;
    }
    if (operation->opcode == IO_VFS_REMOVE || operation->opcode == IO_VFS_RENAME)
    {
        if (description || !io_request_cwd(request) || available < VFS_PATH_MAX || operation->flags > SYSCALL_REMOVE_DIRECTORY_ONLY ||
            (operation->opcode == IO_VFS_RENAME && operation->flags)) return;
        const char *path = (const char *)operation->data;
        if (strnlen(path, VFS_PATH_MAX) == VFS_PATH_MAX) { result->result = -ENAMETOOLONG; return; }
        if (operation->opcode == IO_VFS_REMOVE)
            result->result = operation->flags == SYSCALL_REMOVE_DIRECTORY_ONLY ?
                vfs_remove_directory_path(io_request_cwd(request), path) :
                vfs_remove_path(io_request_cwd(request), path, operation->flags != 0);
        else
        {
            if (available < 2 * VFS_PATH_MAX) return;
            const char *new_path = path + VFS_PATH_MAX;
            if (strnlen(new_path, VFS_PATH_MAX) == VFS_PATH_MAX) { result->result = -ENAMETOOLONG; return; }
            result->result = vfs_rename_path(io_request_cwd(request), path, new_path);
        }
        return;
    }
    if (operation->opcode == IO_VFS_REALPATH)
    {
        if (description || !io_request_cwd(request) || operation->flags || !operation->count ||
            operation->count > available) return;
        if (strnlen((const char *)operation->data, available) == available) { result->result = -ENAMETOOLONG; return; }
        result->result = vfs_realpath_snapshot(io_request_cwd(request), (const char *)operation->data,
                                               (char *)operation->data, (size_t)operation->count);
        return;
    }
    if (operation->opcode == IO_VFS_STAT_PATH)
    {
        if (description || !io_request_cwd(request) || operation->count ||
            (operation->flags & ~SYSCALL_STAT_NOFOLLOW)) return;
        size_t length = 0;
        while (length < available && length < VFS_PATH_MAX && operation->data[length]) ++length;
        if (length == available || length == VFS_PATH_MAX) { result->result = -ENAMETOOLONG; return; }
        vfs_stat_snapshot_t metadata;
        result->result = vfs_path_stat_snapshot(io_request_cwd(request), (const char *)operation->data,
                                                 !(operation->flags & SYSCALL_STAT_NOFOLLOW),
                                                 io_request_uid(request), io_request_gid(request), &metadata);
        if (!result->result)
            operation->stat = (syscall_stat_t){ .size_bytes = metadata.size_bytes, .type = (uint32_t)metadata.type,
                                               .atime = metadata.atime, .mtime = metadata.mtime, .ctime = metadata.ctime };
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
        uint32_t known = SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE | SYSCALL_OPEN_EXCLUSIVE | SYSCALL_OPEN_APPEND | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_SYNC;
        if (!retirement || (description && !fd_table_reservation_valid(description)) || !io_request_cwd(request) ||
            (operation->flags & ~known) || !(operation->flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)) ||
            ((operation->flags & SYSCALL_OPEN_TRUNCATE) && !(operation->flags & SYSCALL_OPEN_WRITE))) return;
        size_t length = 0;
        while (length < available && length < 4096u && operation->data[length]) ++length;
        if (!length) return;
        if (length == available || length == 4096u) { result->result = -ENAMETOOLONG; return; }
        result->result = io_vfs_open_owned(io_request_cwd(request), (const char *)operation->data,
                                             operation->flags, io_request_uid(request), io_request_gid(request),
                                             retirement, &result->description_owned);
        return;
    }
    if (io_stream_description_valid(description))
    {
        io_stream_execute(request, result);
        return;
    }
    if (io_tcp_description_valid(description))
    {
        if (operation->opcode == IO_VFS_STAT)
        {
            operation->stat = (syscall_stat_t){ .type = SYSCALL_NODE_TYPE_SOCKET };
            result->result = 0;
        }
        else result->result = operation->opcode == IO_VFS_SYNC || operation->opcode == IO_VFS_TRUNCATE ? -EINVAL : -ESPIPE;
        return;
    }
    if (io_pipe_description_valid(description))
    {
        result->result = operation->opcode == IO_VFS_STAT ? io_pipe_stat(description, &operation->stat) :
                            operation->opcode == IO_VFS_SYNC || operation->opcode == IO_VFS_TRUNCATE ? -EINVAL : -ESPIPE;
        return;
    }
    if (io_audio_description_valid(description))
    {
        result->result = operation->opcode == IO_VFS_STAT ? io_audio_stat(description, &operation->stat) :
                            operation->opcode == IO_VFS_SYNC || operation->opcode == IO_VFS_TRUNCATE ? -EINVAL : -ESPIPE;
        return;
    }
    if (!io_vfs_description_valid(description))
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
        case IO_VFS_AVAILABLE:
            if (operation->flags || operation->count || operation->offset || operation->whence) break;
            result->result = io_vfs_file_available(file);
            break;
        case IO_VFS_SYNC:
            io_vfs_offset_lock(file);
            result->result = vfs_flush_node(file->node) ? 0 : -EIO;
            io_vfs_offset_unlock(file);
            break;
        case IO_VFS_TRUNCATE:
            if (!file->writable) { result->result = -EBADF; break; }
            if (operation->offset < 0) break;
            io_vfs_offset_lock(file);
            result->result = vfs_resize_data(file->node, (uint64_t)operation->offset);
            io_vfs_offset_unlock(file);
            break;
        default:
            result->result = -ENOSYS;
            break;
    }
}
