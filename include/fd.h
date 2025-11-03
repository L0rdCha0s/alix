#ifndef FD_H
#define FD_H

#include "types.h"

typedef struct fd_ops
{
    ssize_t (*read)(void *ctx, void *buffer, size_t count);
    ssize_t (*write)(void *ctx, const void *buffer, size_t count);
    int (*close)(void *ctx);
} fd_ops_t;

int fd_allocate(const fd_ops_t *ops, void *context);
void fd_release(int fd);
ssize_t fd_read(int fd, void *buffer, size_t count);
ssize_t fd_write(int fd, const void *buffer, size_t count);
int fd_close(int fd);

#endif
