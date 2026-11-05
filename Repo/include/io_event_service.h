#ifndef IO_EVENT_SERVICE_H
#define IO_EVENT_SERVICE_H

#include "io_service.h"

typedef struct io_event_service io_event_service_t;
/* One bounded, nonblocking step on the protected event worker. Return true to
 * complete (transferring result ownership); false to keep the request pending.
 * A pending step must leave description_owned NULL. Receive/transmit buffers,
 * operation state and result are heap-owned. Never retain a caller stack/user
 * pointer, wait for readiness, or run a storage continuation here. */
typedef bool (*io_event_handler_t)(io_request_t *request, io_service_result_t *result);

typedef struct
{
    io_queue_status_t queue;
    size_t pending;
    bool worker_alive, stopping, stopped;
} io_event_service_status_t;

/* Persistent uncancellable controller, without locks or a preparation guard.
 * One event worker multiplexes all pending requests, with a separate cleanup
 * worker. Capacity bounds every request, including completed waiter owners.
 * Workers are retained before publication; failed construction joins them. */
io_event_service_t *io_event_service_create(size_t capacity, io_event_handler_t handler);
/* Current caller holds a bounded preparation guard through create/bind/register/
 * submit. The calling thread's I/O record must own WAITER before any wait. */
int io_event_service_request_create(io_event_service_t *service, size_t bytes,
                                    uint32_t uid, uint32_t gid, io_request_t **out);
int io_event_service_submit(io_event_service_t *service, io_request_t *request);
/* Publish a transport/IPC readiness transition after releasing its data locks.
 * The hub has permanent storage and retains no socket, caller or service owner. */
void io_event_service_notify(void);
/* One persistent controller cancels pending requests and joins both workers.
 * Caller-held WAITER references must be released separately. External API users
 * must be quiescent before destroy; shutdown is not an external lifetime pin. */
int io_event_service_shutdown(io_event_service_t *service);
int io_event_service_destroy(io_event_service_t *service);
int io_event_service_snapshot(io_event_service_t *service, io_event_service_status_t *out);

#endif
