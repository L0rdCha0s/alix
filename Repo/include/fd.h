#ifndef FD_H
#define FD_H

#include "types.h"
#include "syscall_defs.h"

typedef struct fd_description fd_description_t;
typedef fd_description_t *(*fd_importer_t)(void *context);

typedef struct fd_ops
{
    ssize_t (*read)(void *ctx, void *buffer, size_t count);
    ssize_t (*write)(void *ctx, const void *buffer, size_t count);
    int (*close)(void *ctx);
    ssize_t (*pread)(void *ctx, void *buffer, size_t count, size_t offset);
    int64_t (*lseek)(void *ctx, int64_t offset, int whence);
    int (*fstat)(void *ctx, syscall_stat_t *out);
    /* Bounded readiness snapshot, never waits or performs storage I/O. Returns
     * SYSCALL_POLL_* flags; error/hangup are independent of requested events. */
    uint32_t (*poll)(void *ctx);
} fd_ops_t;

int fd_allocate(const fd_ops_t *ops, void *context);
int fd_install(int fd, const fd_ops_t *ops, void *context);
/* Kernel sources only. Importers run under the global slot lock and must only
 * acquire/create deferred ownership in a bounded preparation guard. A slot is
 * never imported by integer fallback after private lookup failure. */
int fd_allocate_importable(const fd_ops_t *ops, void *context, fd_importer_t importer);
int fd_install_importable(int fd, const fd_ops_t *ops, void *context, fd_importer_t importer);
fd_description_t *fd_import_owned(int fd);
void fd_release(int fd);
ssize_t fd_read(int fd, void *buffer, size_t count);
ssize_t fd_write(int fd, const void *buffer, size_t count);
int fd_close(int fd);
ssize_t fd_pread(int fd, void *buffer, size_t count, size_t offset);
int64_t fd_lseek(int fd, int64_t offset, int whence);
int fd_fstat(int fd, syscall_stat_t *out);

#endif
