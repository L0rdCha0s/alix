#ifndef IO_SERVICE_H
#define IO_SERVICE_H

#include "io_request.h"

#define IO_SERVICE_MAX_WORKERS 16u

typedef struct io_service io_service_t;
typedef struct
{
    int64_t result;
    fd_description_t *description_owned;
} io_service_result_t;

/* Runs synchronously on one persistent protected storage worker. Both the
 * request operation buffer and result record are heap-owned. Return normally;
 * do not exit the worker or retain result beyond the callback. The callback
 * owns a complete blocking continuation, including every lock/DMA cleanup.
 * It must explicitly use request uid/gid/retained cwd for caller-sensitive
 * work, never the service process's identity. Indefinite TCP readiness waits
 * belong to an event-driven executor, not this finite storage pool. */
typedef void (*io_service_handler_t)(io_request_t *request, io_service_result_t *result);

typedef struct
{
    io_queue_status_t queue;
    uint32_t workers, active_workers;
    bool stopping, stopped;
} io_service_status_t;

/* Control-plane calls require a persistent, uncancellable kernel owner.
 * They must run without a preemption guard or any caller-held lock. Create
 * rejects guard-held entry with NULL; shutdown/destroy return -EINVAL before
 * changing state, because rollback and quiescent joins can block.
 * Create publishes no handle until all workers exist. Each process is retained
 * before it can run; constructor rollback joins every created process. */
io_service_t *io_service_create(size_t capacity, uint32_t workers, io_service_handler_t handler);

/* Caller holds only its bounded preemption guard through create/bind/register/
 * submit, then drops it before process_io_wait_current(). Successful creation
 * returns WAITER ownership; transfer it to process_io_register_current before
 * blocking. Submission publishes the queue entry before waking workers. */
int io_service_request_create(io_service_t *service, size_t bytes, uint32_t uid,
                              uint32_t gid, io_request_t **out);
int io_service_submit(io_service_t *service, io_request_t *request);

/* Cancel queued work, notify waiters, and wait for active continuations and
 * dedicated cleanup to finish. Callers must release their own waiter refs;
 * shutdown deliberately waits for remaining waiter ownership. One controller
 * performs joins; concurrent controllers get -EBUSY and may retry. Repeating
 * after completion succeeds. Calls from this service's workers get -EDEADLK.
 * Success consumes each retained process owner only after a quiescent join. */
int io_service_shutdown(io_service_t *service);

/* Separate from shutdown: the owner must first quiesce all external API users.
 * Never destroy a service while another caller can still enter its APIs. */
int io_service_destroy(io_service_t *service);
/* Queue fields are one coherent snapshot; worker fields may advance meanwhile. */
int io_service_snapshot(io_service_t *service, io_service_status_t *out);

#endif
