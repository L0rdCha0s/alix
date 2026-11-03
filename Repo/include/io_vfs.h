#ifndef IO_VFS_H
#define IO_VFS_H

#include "io_service.h"
#include "io_flock.h"

typedef enum
{
    IO_VFS_OPEN,
    IO_VFS_READ,
    IO_VFS_WRITE,
    IO_VFS_PREAD,
    IO_VFS_SEEK,
    IO_VFS_STAT,
    IO_VFS_SYNC,
    IO_VFS_READLINK,
    IO_VFS_RESOLVE_CWD,
    IO_VFS_OPEN_DIR,
    IO_VFS_READ_DIR,
    IO_VFS_REWIND_DIR,
    IO_VFS_STAT_PATH,
    IO_VFS_GETCWD,
    IO_VFS_REMOVE,
    IO_VFS_RENAME,
    IO_VFS_TRUNCATE,
    IO_VFS_REALPATH,
    IO_VFS_MKDIR,
    IO_VFS_AVAILABLE,
    IO_VFS_SYSTEM_INFO,
    IO_VFS_MAP,
    IO_VFS_SYNC_MAPPINGS,
    IO_VFS_STAT_INFO,
    IO_VFS_PATH_INFO,
    IO_VFS_CHOWN,
    IO_VFS_CHMOD,
    IO_VFS_LOCK_RESOLVE,
    IO_VFS_SET_TIMES,
    IO_VFS_SHM_OPEN,
    IO_VFS_SHM_UNLINK,
    IO_VFS_OPEN_MODE,
    IO_VFS_MKDIR_MODE,
    IO_VFS_CHMOD_PATH
} io_vfs_opcode_t;

/* The complete object lives in io_request_buffer(). All data/path bytes are
 * owned kernel storage; no process pointer or user address is retained.
 * READLINK consumes a NUL-terminated path in data, then overwrites data with
 * at most count non-NUL-terminated target bytes. No descriptor is required. */
typedef struct
{
    uint32_t opcode, flags;
    int32_t whence;
    uint32_t reserved;
    uint64_t count;
    int64_t offset;
    syscall_stat_t stat;
    unsigned char data[];
} io_vfs_operation_t;

/* Protected storage worker only, no caller-held locks/preemption guard.
 * retirement must remain owned for this call; OPEN constructs a deferred
 * description in that queue. The persistent service/controller owns the queue
 * reference, rather than storing its lifetime on a syscall caller's stack.
 * Callback-backed files and non-VFS descriptions require other adapters.
 * cwd is the retained request cwd and credentials are captured request values.
 * File offset gates sleep; their wait predicates receive heap-owned handles. */
void io_vfs_execute(io_request_t *request, io_service_result_t *result,
                     fd_retirement_queue_t *retirement);
/* Caller holds a description reference; regular-file backend identity only. */
bool io_vfs_description_valid(const fd_description_t *description);
/* Caller pins the description. Key is borrowed only while that pin lives. */
const void *io_vfs_record_key(const fd_description_t *description);
/* Protected storage worker only; synchronous output is owned lease storage. */
int io_vfs_record_base(const fd_description_t *description, int whence, int64_t *base);
bool io_vfs_mapping_writable(const fd_description_t *description);
paddr_t io_vfs_mapping_page(const fd_description_t *description, size_t index);
fd_description_t *io_vfs_sync_bundle_create(size_t capacity);
bool io_vfs_sync_bundle_add(fd_description_t *bundle, fd_description_t *mapping);
/* Caller pins a regular-file description through use of this embedded state. */
io_flock_state_t *io_vfs_flock_state(const fd_description_t *description);
struct vfs_node;
/* Protected worker, retained cwd; returns one owned deferred regular-file
 * description. No caller process, stack or user address is retained. */
int io_vfs_open_owned(struct vfs_node *cwd, const char *path, uint32_t flags,
                       uint32_t uid, uint32_t gid, fd_retirement_queue_t *retirement,
                       fd_description_t **output);
int io_vfs_open_mode_owned(struct vfs_node *cwd, const char *path, uint32_t flags,
                            uint32_t mode, uint32_t uid, uint32_t gid,
                            fd_retirement_queue_t *retirement, fd_description_t **output);

#endif
