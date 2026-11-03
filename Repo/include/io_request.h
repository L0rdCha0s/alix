#ifndef IO_REQUEST_H
#define IO_REQUEST_H

#include "fd_table.h"

#define IO_QUEUE_MAX_REQUESTS 1024u
#define IO_REQUEST_BUFFER_MAX (64u * 1024u)

typedef struct io_queue io_queue_t;
typedef struct io_request io_request_t;
typedef void (*io_cwd_release_t)(void *cwd);

typedef enum
{
    IO_REQUEST_NEW,
    IO_REQUEST_QUEUED,
    IO_REQUEST_RUNNING,
    IO_REQUEST_COMPLETED
} io_request_state_t;

typedef struct
{
    io_request_state_t state;
    bool cancelled;
    int64_t result;
} io_request_status_t;

typedef struct
{
    size_t capacity, live, queued, cleanup;
    bool closed;
} io_queue_status_t;

/* Independent primitives: no scheduler, process, user-VA or I/O callbacks.
 * Queue owners must quiesce all external API users before successful destroy.
 * Every request pointer must be protected by its WAITER or EXECUTOR ownership
 * (or by the queue while queued). No generic get/put or resurrection exists.
 * All return codes are zero/success or negative errno unless documented. */
io_queue_t *io_queue_create(size_t capacity);
void io_queue_shutdown(io_queue_t *queue);
/* Requires shutdown, no live requests/reservations and no active drainer. */
int io_queue_destroy(io_queue_t *queue);
int io_queue_snapshot(io_queue_t *queue, io_queue_status_t *out);

/* Creation returns WAITER ownership and a zeroed kernel buffer. Admission
 * counts NEW, queued, running, completed and cleanup-pending requests alike.
 * On failure no ownership is acquired, and *out is NULL. */
int io_request_create(io_queue_t *queue, size_t buffer_size, uint32_t uid,
                      uint32_t gid, io_request_t **out);
/* Bind once before submit. On success, transfer one already-owned description
 * reference and retained cwd reference; on error they remain with the caller.
 * Both inputs may be NULL. A cancelled, never-submitted request may still bind
 * its resources so preparation rollback also uses the cleanup worker. */
int io_request_bind(io_request_t *request, fd_description_t *description_owned,
                    void *cwd_owned, io_cwd_release_t release_cwd);
/* Alternative bind for a deferred cwd-owner description. Both inputs transfer
 * on success; if identical they require distinct owned references. cwd exposes
 * the description's immutable context while the separate owner keeps it alive.
 * Bind/register/submit still requires the caller's bounded preparation guard. */
int io_request_bind_cwd_owner(io_request_t *request, fd_description_t *description_owned,
                               fd_description_t *cwd_owner_owned);
bool io_request_uses_queue(const io_request_t *request, const io_queue_t *queue);
void *io_request_buffer(io_request_t *request);
size_t io_request_buffer_size(const io_request_t *request);
fd_description_t *io_request_description(const io_request_t *request);
void *io_request_cwd(const io_request_t *request);
uint32_t io_request_uid(const io_request_t *request);
uint32_t io_request_gid(const io_request_t *request);

/* Register WAITER ownership in the calling thread's heap-owned cleanup record
 * before submit/block. Successful submit adds EXECUTOR ownership; take moves
 * that same owner from the queue to the service worker. */
int io_request_submit(io_request_t *request);
/* Complete a bound NEW request without an executor/queue round trip. The live
 * caller owns its registered WAITER throughout a bounded nonblocking operation;
 * result bytes/resources remain request-owned and use ordinary waiter cleanup. */
int io_request_complete_inline(io_request_t *request, int64_t result);
io_request_t *io_queue_take(io_queue_t *queue);
/* Cancellation never frees resources or interrupts an active continuation.
 * NEW/QUEUED requests complete with -ECANCELED; RUNNING requests remain owned
 * by their worker. A caller needing wakeups performs them after unlocking. */
int io_request_cancel(io_request_t *request);
int io_request_status(io_request_t *request, io_request_status_t *out);
/* Completion retains EXECUTOR ownership so the worker can safely notify its
 * external completion queue, then release. Output ownership transfers only
 * on success; input and output require distinct references even if equal. */
int io_request_publish_complete(io_request_t *request, int64_t result,
                                fd_description_t *result_description_owned);
/* Only the live, noncancelled WAITER may take an OPEN result. Later process
 * glue must serialize this with caller cancellation and immediately transfer
 * the returned ref into another registered owner before allowing preemption. */
int io_request_take_result(io_request_t *request, fd_description_t **out);
int io_request_worker_release(io_request_t *request);
int io_request_waiter_release(io_request_t *request);
/* Call only after the waiter is no longer executing/using its request (or from
 * its own bounded preparation rollback). Combines cancellation and release. */
int io_request_waiter_abandon(io_request_t *request);

/* Last release only enqueues the request itself, without allocation or any
 * resource destructor. Only a persistent cleanup worker calls drain, with no
 * caller-held locks. At most budget requests are destroyed. Destructors run
 * outside all module locks and may reenter queue APIs. */
size_t io_queue_drain(io_queue_t *queue, size_t budget);

#endif
