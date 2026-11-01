#ifndef IO_FLOCK_H
#define IO_FLOCK_H
#include "io_event_service.h"

/* Embedded in the regular-file description context. The VFS node and this
 * state remain owned by that description. Its weak self pointer is examined
 * only under the registry lock, which also serializes unlink in final close. */
typedef struct io_flock_state {
    struct io_flock_state *next;
    const void *key;
    fd_description_t *description;
    void *active;
    uint32_t held, reserved;
    bool registered;
} io_flock_state_t;
void io_flock_state_init(io_flock_state_t *state, const void *key, fd_description_t *self);
void io_flock_state_close(io_flock_state_t *state);
bool io_flock_flags_valid(uint32_t flags);
/* Immediate, allocation-free release; supersedes an outstanding acquisition
 * on the same open description. Caller pins the owning file in its guard. */
int io_flock_unlock(io_flock_state_t *state);
/* Consume target_owned on all returns. Prepare under the caller's bounded
 * guard, then register the output lease in a request before blocking. */
int io_flock_create(fd_retirement_queue_t *retirement, fd_description_t *target_owned,
                     io_flock_state_t *state, uint32_t flags, fd_description_t **output);
bool io_flock_description_valid(const fd_description_t *description);
bool io_flock_execute(io_request_t *request, io_service_result_t *result);
/* Only the live guarded caller commits a successfully taken result lease.
 * Unclaimed/cancelled leases roll their reservation back on protected cleanup. */
int io_flock_commit(fd_description_t *lease);
/* Guarded live caller: discard a completed failed acquisition immediately,
 * including its target pin, instead of waiting for request finalization. */
void io_flock_abort(fd_description_t *lease);
#endif
