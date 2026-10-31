#ifndef IO_VFS_SERVICE_H
#define IO_VFS_SERVICE_H

#include "io_vfs.h"

/* Boot controller only, after process resource cleanup and VFS are ready. The
 * protected service and its owner have kernel lifetime. */
bool io_vfs_service_start(void);
int io_vfs_service_snapshot(io_service_status_t *out);

ssize_t io_vfs_readlink_user(const char *path, void *buffer, size_t capacity);
/* Kernel caller owns path/output for the synchronous call; no pointer is
 * retained by a worker. This entry also supports native boot acceptance. */
ssize_t io_vfs_readlink_kernel(const char *path, void *buffer, size_t capacity);

/* Resolve on protected storage workers, then atomically install on the calling
 * process and optional live owner PID. Only the numeric PID crosses the wait.
 * The PID is supplied by trusted kernel shell state, not a user syscall. */
int io_vfs_change_cwd_kernel(const char *path, uint64_t owner_pid);
/* Internal result-guard operation; consumes description only on success. */
int process_apply_cwd_to_current_and_pid(fd_description_t *owner, uint64_t owner_pid);

#endif
