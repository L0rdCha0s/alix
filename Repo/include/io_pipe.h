#ifndef IO_PIPE_H
#define IO_PIPE_H

#include "io_event_service.h"

#define IO_PIPE_CAPACITY 16384u
#define IO_PIPE_ATOMIC 4096u
typedef enum { IO_PIPE_READ, IO_PIPE_WRITE, IO_PIPE_AVAILABLE } io_pipe_opcode_t;
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

#endif
