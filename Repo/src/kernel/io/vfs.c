#include "io_vfs.h"
#include "vfs.h"
#include "process.h"
#include "heap.h"
#include "errno.h"
#include "libc.h"
#include "io_stream.h"
#include "io_tcp.h"
#include "io_udp.h"
#include "io_pipe.h"
#include "io_audio.h"
#include "system_identity.h"
#include "vfs_mapping.h"
#include "io_record_lock.h"

typedef struct {
    vfs_file_mapping_t *mapping;
    bool writable;
} io_vfs_mapping_t;
static int io_vfs_mapping_close(void *context)
{
    io_vfs_mapping_t *m = context;
    if (m) { vfs_mapping_release(m->mapping); free(m); }
    return 0;
}
static const fd_ops_t io_vfs_mapping_ops = { .close = io_vfs_mapping_close };
static bool io_vfs_mapping_valid(const fd_description_t *description)
{ return description && fd_description_ops(description)->close == io_vfs_mapping_close; }
bool io_vfs_mapping_writable(const fd_description_t *description)
{ return io_vfs_mapping_valid(description) && ((io_vfs_mapping_t *)fd_description_context(description))->writable; }
paddr_t io_vfs_mapping_page(const fd_description_t *description, size_t index)
{
    return io_vfs_mapping_valid(description) ?
        vfs_mapping_page(((io_vfs_mapping_t *)fd_description_context(description))->mapping, index) : 0;
}
typedef struct {
    size_t count, capacity;
    fd_description_t *mappings[];
} io_vfs_sync_bundle_t;
static int io_vfs_sync_bundle_close(void *context)
{
    io_vfs_sync_bundle_t *b = context;
    if (b) { for (size_t i = 0; i < b->count; ++i) fd_description_put(b->mappings[i]); free(b); }
    return 0;
}
static const fd_ops_t io_vfs_sync_bundle_ops = { .close = io_vfs_sync_bundle_close };
fd_description_t *io_vfs_sync_bundle_create(size_t capacity)
{
    if (capacity > (SIZE_MAX-sizeof(io_vfs_sync_bundle_t))/sizeof(fd_description_t *)) return NULL;
    io_vfs_sync_bundle_t *b = calloc(1, sizeof(*b) + capacity * sizeof(*b->mappings));
    if (!b) return NULL;
    b->capacity = capacity;
    fd_description_t *description = fd_description_create_deferred(&io_vfs_sync_bundle_ops,b,process_fd_retirement_queue());
    if (!description) free(b);
    return description;
}
bool io_vfs_sync_bundle_add(fd_description_t *description, fd_description_t *mapping)
{
    io_vfs_sync_bundle_t *b = fd_description_context(description);
    for (size_t i=0; i<b->count; ++i) if (b->mappings[i]==mapping) return true;
    if (b->count == b->capacity || !fd_description_get(mapping)) return false;
    b->mappings[b->count++] = mapping;
    return true;
}

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

const void *io_vfs_record_key(const fd_description_t *description)
{
    return io_vfs_description_valid(description) ?
        ((io_vfs_file_t *)fd_description_context(description))->node : NULL;
}

int io_vfs_record_base(const fd_description_t *description, int whence, int64_t *base)
{
    if (!base || !io_vfs_description_valid(description)) return -EINVAL;
    io_vfs_file_t *file = fd_description_context(description);
    uint64_t value = 0;
    if (whence == SYSCALL_SEEK_CUR)
    {
        io_vfs_offset_lock(file); value = file->offset; io_vfs_offset_unlock(file);
    }
    else if (whence == SYSCALL_SEEK_END)
    {
        size_t size = 0;
        if (!vfs_stat(file->node, &size, NULL, NULL, NULL, NULL)) return -EIO;
        value = size;
    }
    else if (whence != SYSCALL_SEEK_SET) return -EINVAL;
    if (value > INT64_MAX) return -EOVERFLOW;
    *base = (int64_t)value;
    return 0;
}

io_flock_state_t *io_vfs_flock_state(const fd_description_t *description)
{
    return io_vfs_description_valid(description) ?
        &((io_vfs_file_t *)fd_description_context(description))->flock : NULL;
}

static int io_vfs_open_common(vfs_node_t *cwd, const char *path, uint32_t flags,
                       uint32_t uid, uint32_t gid, fd_retirement_queue_t *retirement,
                       fd_description_t **output, bool shared_memory, uint32_t mode)
{
    if (!output) return -EINVAL;
    *output = NULL;
    uint32_t known = SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE |
                     SYSCALL_OPEN_TRUNCATE | SYSCALL_OPEN_EXCLUSIVE | SYSCALL_OPEN_APPEND | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_SYNC;
    if (!retirement || (!shared_memory && !cwd) || !path || (flags & ~known) || !(flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)) ||
        ((flags & SYSCALL_OPEN_TRUNCATE) && !(flags & SYSCALL_OPEN_WRITE))) return -EINVAL;
    if (shared_memory && (!(flags & SYSCALL_OPEN_READ) ||
        (flags & (SYSCALL_OPEN_APPEND | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_SYNC)))) return -EINVAL;
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
    int result = shared_memory ?
        vfs_shm_open_owned(path, (flags & SYSCALL_OPEN_CREATE) != 0,
                           (flags & SYSCALL_OPEN_TRUNCATE) != 0,
                           (flags & SYSCALL_OPEN_EXCLUSIVE) != 0, uid, gid, mode,
                           file->writable ? 6u : 4u, &file->node) :
        vfs_open_data_mode_owned(cwd, path, (flags & SYSCALL_OPEN_CREATE) != 0,
                                           (flags & SYSCALL_OPEN_TRUNCATE) != 0,
                                           (flags & SYSCALL_OPEN_EXCLUSIVE) != 0, uid, gid,
                                           (file->readable ? 4u : 0) | (file->writable ? 2u : 0), mode, &file->node);
    if (result) fd_description_put(description);
    else
    {
        io_flock_state_init(&file->flock, file->node, description);
        *output = description;
    }
    return result;
}

int io_vfs_open_owned(vfs_node_t *cwd, const char *path, uint32_t flags,
                       uint32_t uid, uint32_t gid, fd_retirement_queue_t *retirement,
                       fd_description_t **output)
{
    return io_vfs_open_common(cwd, path, flags, uid, gid, retirement, output, false, 0666u);
}

int io_vfs_open_mode_owned(vfs_node_t *cwd, const char *path, uint32_t flags,
                            uint32_t mode, uint32_t uid, uint32_t gid,
                            fd_retirement_queue_t *retirement, fd_description_t **output)
{
    return io_vfs_open_common(cwd, path, flags, uid, gid, retirement, output, false, mode);
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

static uint32_t io_vfs_stat_mode(uint32_t type)
{
    switch (type)
    {
        case SYSCALL_NODE_TYPE_DIR: return 0040000u;
        case SYSCALL_NODE_TYPE_FILE: return 0100000u;
        case SYSCALL_NODE_TYPE_BLOCK: return 0060000u;
        case SYSCALL_NODE_TYPE_SYMLINK: return 0120000u;
        case SYSCALL_NODE_TYPE_SOCKET: return 0140000u;
        case SYSCALL_NODE_TYPE_CHARACTER: return 0020000u;
        case SYSCALL_NODE_TYPE_FIFO: return 0010000u;
        default: return 0;
    }
}

static void io_vfs_stat_info_encode(const vfs_stat_info_t *input, syscall_stat_info_t *output)
{
    const vfs_stat_snapshot_t *m = &input->metadata;
    *output = (syscall_stat_info_t){
        .size_bytes = m->size_bytes, .mode = io_vfs_stat_mode(m->type) | input->permissions, .type = m->type,
        .atime = m->atime, .mtime = m->mtime, .ctime = m->ctime,
        .device = input->device, .inode = input->inode, .links = input->links,
        .uid = input->uid, .gid = input->gid, .block_size = 4096,
        .blocks = m->size_bytes / 512 + (m->size_bytes % 512 != 0),
    };
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
    if (operation->opcode == IO_VFS_SET_TIMES)
    {
        if (description || !io_request_cwd(request) || operation->flags > 1 || operation->count || operation->offset ||
            operation->whence || available != VFS_PATH_MAX + sizeof(syscall_file_times_t)) return;
        if (strnlen((const char *)operation->data,VFS_PATH_MAX) == VFS_PATH_MAX)
        { result->result = -ENAMETOOLONG; return; }
        const syscall_file_times_t *times = (const void *)(operation->data + VFS_PATH_MAX);
        if (times->access_seconds < 0 || times->modify_seconds < 0 || times->access_microseconds < 0 ||
            times->access_microseconds > 999999 || times->modify_microseconds < 0 || times->modify_microseconds > 999999) return;
        vfs_node_t *node = NULL;
        result->result = vfs_resolve_owned(io_request_cwd(request), (const char *)operation->data, &node);
        if (!result->result)
        {
            result->result = vfs_set_times_owned(node, io_request_uid(request), io_request_gid(request),
                operation->flags != 0, (uint64_t)times->access_seconds, (uint64_t)times->modify_seconds);
            vfs_node_release_owned(node);
        }
        return;
    }
    if (operation->opcode == IO_VFS_LOCK_RESOLVE)
    {
        if (operation->flags || operation->count || operation->offset || operation->whence || available) return;
        result->result = io_record_lock_resolve(description);
        return;
    }
    if (operation->opcode == IO_VFS_STAT_INFO || operation->opcode == IO_VFS_PATH_INFO)
    {
        bool path = operation->opcode == IO_VFS_PATH_INFO;
        if (operation->count || operation->offset || operation->whence ||
            (operation->flags & ~(path ? SYSCALL_STAT_NOFOLLOW : 0u)) ||
            available < sizeof(syscall_stat_info_t)) return;
        if (path && (description || !io_request_cwd(request))) return;
        if (path && strnlen((const char *)operation->data, available) == available)
        { result->result = -ENAMETOOLONG; return; }
        if (path || io_vfs_description_valid(description))
        {
            vfs_stat_info_t *info = calloc(1, sizeof(*info));
            if (!info) { result->result = -ENOMEM; return; }
            result->result = path ? vfs_path_stat_info(io_request_cwd(request), (const char *)operation->data,
                !(operation->flags & SYSCALL_STAT_NOFOLLOW), io_request_uid(request), io_request_gid(request), info) :
                vfs_node_stat_info(((io_vfs_file_t *)fd_description_context(description))->node, info);
            if (!result->result) io_vfs_stat_info_encode(info, (void *)operation->data);
            free(info);
        }
        else
        {
            /* Reuse each descriptor adapter's original metadata path. The
             * bounded nested call uses the same owned request, never a caller
             * buffer. Anonymous descriptions have no filesystem inode/link. */
            operation->opcode = IO_VFS_STAT;
            io_vfs_execute(request, result, retirement);
            operation->opcode = IO_VFS_STAT_INFO;
            if (!result->result)
            {
                const syscall_stat_t *m = &operation->stat;
                *(syscall_stat_info_t *)operation->data = (syscall_stat_info_t){
                    .size_bytes = m->size_bytes, .mode = io_vfs_stat_mode(m->type), .type = m->type,
                    .atime = m->atime, .mtime = m->mtime, .ctime = m->ctime,
                    .block_size = 4096, .blocks = m->size_bytes / 512 + (m->size_bytes % 512 != 0),
                };
            }
        }
        return;
    }
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
    if (operation->opcode == IO_VFS_MKDIR || operation->opcode == IO_VFS_MKDIR_MODE)
    {
        if (description || !io_request_cwd(request) || operation->flags || available < VFS_PATH_MAX) return;
        if (strnlen((const char *)operation->data, VFS_PATH_MAX) == VFS_PATH_MAX) { result->result = -ENAMETOOLONG; return; }
        if (operation->opcode == IO_VFS_MKDIR_MODE)
        {
            if (operation->whence < 0 || operation->whence > 0777) return;
            result->result = vfs_mkdir_mode_exclusive(io_request_cwd(request), (const char *)operation->data,
                io_request_uid(request), io_request_gid(request), (uint32_t)operation->whence);
        }
        else result->result = vfs_mkdir_exclusive(io_request_cwd(request), (const char *)operation->data,
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
    if (operation->opcode == IO_VFS_SHM_UNLINK)
    {
        if (description || operation->flags || operation->count || operation->offset || operation->whence ||
            !available || strnlen((const char *)operation->data, available) == available) return;
        result->result = vfs_shm_unlink_owned((const char *)operation->data, io_request_uid(request));
        return;
    }
    if (operation->opcode == IO_VFS_OPEN || operation->opcode == IO_VFS_SHM_OPEN || operation->opcode == IO_VFS_OPEN_MODE)
    {
        uint32_t known = SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE | SYSCALL_OPEN_EXCLUSIVE | SYSCALL_OPEN_APPEND | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_SYNC;
        if (!retirement || (description && !fd_table_reservation_valid(description)) || !io_request_cwd(request) ||
            (operation->flags & ~known) || !(operation->flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)) ||
            ((operation->flags & SYSCALL_OPEN_TRUNCATE) && !(operation->flags & SYSCALL_OPEN_WRITE))) return;
        size_t length = 0;
        while (length < available && length < 4096u && operation->data[length]) ++length;
        if (!length) return;
        if (length == available || length == 4096u) { result->result = -ENAMETOOLONG; return; }
        if (operation->opcode == IO_VFS_SHM_OPEN)
        {
            if (operation->count || operation->offset || operation->whence < 0 || operation->whence > 0777) return;
            result->result = io_vfs_open_common(NULL, (const char *)operation->data,
                operation->flags, io_request_uid(request), io_request_gid(request),
                retirement, &result->description_owned, true, (uint32_t)operation->whence);
            return;
        }
        if (operation->opcode == IO_VFS_OPEN_MODE && (operation->whence < 0 || operation->whence > 0777)) return;
        result->result = io_vfs_open_mode_owned(io_request_cwd(request), (const char *)operation->data,
                                             operation->flags, operation->opcode == IO_VFS_OPEN_MODE ? (uint32_t)operation->whence : 0666u,
                                             io_request_uid(request), io_request_gid(request),
                                             retirement, &result->description_owned);
        return;
    }
    if (io_stream_description_valid(description))
    {
        io_stream_execute(request, result);
        return;
    }
    if (operation->opcode == IO_VFS_SYNC_MAPPINGS)
    {
        if (!description || fd_description_ops(description)->close != io_vfs_sync_bundle_close) return;
        io_vfs_sync_bundle_t *bundle = fd_description_context(description);
        result->result = 0;
        for (size_t i=0; i<bundle->count; ++i) {
            io_vfs_mapping_t *m = fd_description_context(bundle->mappings[i]);
            int error = vfs_mapping_sync(m->mapping);
            if (error && !result->result) result->result = error;
        }
        return;
    }
    if (io_tcp_description_valid(description) || io_udp_description_valid(description))
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
    if (operation->opcode != IO_VFS_MAP && operation->count > available) return;
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
        case IO_VFS_CHOWN:
            if (operation->count || operation->offset) break;
            result->result = vfs_chown_owned(file->node, io_request_uid(request), io_request_gid(request),
                                              operation->flags, (uint32_t)operation->whence);
            break;
        case IO_VFS_CHMOD:
            if (operation->count || operation->offset || operation->whence) break;
            result->result = vfs_chmod_owned(file->node, io_request_uid(request), operation->flags);
            break;
        case IO_VFS_AVAILABLE:
            if (operation->flags || operation->count || operation->offset || operation->whence) break;
            result->result = io_vfs_file_available(file);
            break;
        case IO_VFS_MAP:
        {
            bool shared = (operation->flags & SYSCALL_VM_MAP_SHARED) != 0;
            if (!file->readable) { result->result = -EACCES; break; }
            if (shared && (operation->whence & SYSCALL_VM_PROT_WRITE) && !file->writable) {
                result->result = -EACCES; break;
            }
            if (shared && (operation->whence & SYSCALL_VM_PROT_WRITE) && !vfs_mapping_write_allowed(file->node)) {
                result->result = -EROFS; break;
            }
            io_vfs_mapping_t *m = calloc(1,sizeof(*m));
            fd_description_t *owner = m ? fd_description_create_deferred(&io_vfs_mapping_ops,m,retirement) : NULL;
            if (!owner) { free(m); result->result = -ENOMEM; break; }
            m->writable = !shared || (file->writable && vfs_mapping_write_allowed(file->node));
            result->result = vfs_mapping_create(file->node,(uint64_t)operation->offset,
                (size_t)operation->count,shared,owner,&m->mapping);
            if (result->result) fd_description_put(owner);
            else result->description_owned = owner;
            break;
        }
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
