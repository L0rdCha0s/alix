#ifndef IO_PIPE_H
#define IO_PIPE_H

#include "io_event_service.h"

#define IO_PIPE_CAPACITY 16384u
#define IO_PIPE_ATOMIC 4096u
typedef enum { IO_PIPE_READ, IO_PIPE_WRITE, IO_PIPE_AVAILABLE, IO_PIPE_OPEN_WAIT } io_pipe_opcode_t;
typedef struct
{
    uint32_t opcode, reserved;
    uint64_t count;
    unsigned char data[];
} io_pipe_operation_t;

/* Protected worker or bounded preparation guard. On success the caller owns
 * two deferred descriptions; on failure neither output owns anything. */
int io_pipe_create_pair(fd_retirement_queue_t *retirement,
                         fd_description_t **reader, fd_description_t **writer);
bool io_pipe_description_valid(const fd_description_t *description);
int io_pipe_stat(const fd_description_t *description, syscall_stat_t *out);
/* Readiness step only, never a blocking wait. All state/data is request-owned. */
bool io_pipe_execute(io_request_t *request, io_service_result_t *result);

typedef struct io_pipe io_pipe_t;
struct vfs_node;
io_pipe_t *io_pipe_named_create(void);
void io_pipe_named_destroy(io_pipe_t *pipe);
/* Consumes the owned VFS node on every return. */
int io_pipe_named_open_owned(struct vfs_node *node, uint32_t flags,
                              fd_retirement_queue_t *retirement, fd_description_t **out);
struct vfs_node *io_pipe_node(const fd_description_t *description);
bool io_pipe_open_pending(const fd_description_t *description);
/* Consumes both descriptions on every return. Lease cleanup cancels an
 * uncommitted reservation and releases the endpoint on the protected worker. */
int io_pipe_open_lease_create(fd_description_t *endpoint, fd_description_t *reservation,
                               fd_retirement_queue_t *retirement, fd_description_t **out);
bool io_pipe_open_lease_valid(const fd_description_t *description);
fd_description_t *io_pipe_open_reservation(const fd_description_t *description);
bool io_pipe_open_execute(io_request_t *request, io_service_result_t *result);

#endif
