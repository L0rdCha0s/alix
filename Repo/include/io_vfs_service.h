#ifndef IO_VFS_SERVICE_H
#define IO_VFS_SERVICE_H

#include "io_vfs.h"

/* Boot controller only, after process resource cleanup and VFS are ready. The
 * protected service and its owner have kernel lifetime. */
bool io_vfs_service_start(void);
int io_vfs_service_snapshot(io_service_status_t *out);
/* Borrowed kernel-lifetime service for other native VFS entry points. */
io_service_t *io_vfs_service_current(void);
/* Finite kernel lazy-read continuation. Pins the file in a registered request;
 * no caller buffer or stack is retained by the protected storage worker. */
int io_vfs_prepare_data_kernel(struct vfs_node *node);
int64_t io_vfs_directory_user(uint32_t operation, int handle, void *argument, size_t bytes);

ssize_t io_vfs_readlink_user(const char *path, void *buffer, size_t capacity);
/* Kernel caller owns path/output for the synchronous call; no pointer is
 * retained by a worker. This entry also supports native boot acceptance. */
ssize_t io_vfs_readlink_kernel(const char *path, void *buffer, size_t capacity);

/* Resolve on protected storage workers, then atomically install on the calling
 * process and optional live owner PID. Only the numeric PID crosses the wait.
 * The PID is supplied by trusted kernel shell state, not a user syscall. */
int io_vfs_change_cwd_kernel(const char *path, uint64_t owner_pid);
struct shell_state;
/* Explicit base/lifetime are borrowed, protected references. Under the caller's
 * prep guard, this takes its own pins and registers/submits a CWD request; caller
 * retains both originals on every return. No wait occurs here. */
int io_vfs_prepare_cwd(const char *path, fd_description_t *base, fd_description_t *lifetime);
int io_vfs_change_shell_cwd_kernel(const char *path, struct shell_state *shell);
/* Result guard required; consumes owner on success only. */
int io_vfs_apply_shell_cwd_owned(struct shell_state *shell, fd_description_t *owner);
/* Internal result-guard operation; consumes description only on success. */
int process_apply_cwd_to_current_and_pid(fd_description_t *owner, uint64_t owner_pid);

#endif
