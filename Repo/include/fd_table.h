#ifndef FD_TABLE_H
#define FD_TABLE_H

#include "fd.h"

#define FD_TABLE_MAX_ENTRIES 256u
#define FD_TABLE_CLOEXEC 1u
#define FD_STATUS_READ (1u << 0)
#define FD_STATUS_WRITE (1u << 1)
#define FD_STATUS_APPEND (1u << 16)
#define FD_STATUS_NONBLOCK (1u << 18)
#define FD_STATUS_SYNC (1u << 19)

typedef struct fd_description fd_description_t;
typedef struct fd_table fd_table_t;
typedef struct fd_retirement_queue fd_retirement_queue_t;

#define FD_RETIREMENT_MAX_OBJECTS 65536u
typedef struct
{
    size_t capacity, live, pending, drainers;
    uint32_t references;
    bool closed;
} fd_retirement_status_t;

/* Opt-in deferred destruction. Admission counts every live table/description,
 * in-progress allocation and queued finalizer. Saturation only rejects new
 * objects; close, replacement and final put allocate nothing and cannot fail
 * from saturation. Deferred tables accept only descriptions of the same queue.
 * Constructors must run on a persistent protected worker or inside a bounded
 * preemption guard: allocation reservations cannot survive an abandoned caller.
 * Queue construction and successful reference acquisitions (get/pin) likewise
 * require caller protection until the new ownership is registered/published.
 * Deferred release/remove/replacement/shutdown operations internally guard the
 * whole detach-to-enqueue interval. Callers must still protect ownership
 * transfer into/out of their registered cleanup record (including pin outputs)
 * with their own guard; the module cannot register a caller's local references.
 * Final puts enqueue rather than calling close or freeing. Close returns zero
 * after detaching; asynchronous destructor return codes are not reported.
 * The existing constructors preserve synchronous destruction semantics.
 *
 * The creating owner retains the queue's base reference until destroy. Every
 * concurrent worker/API user must own a get reference or be protected by the
 * owner's external quiescence protocol. put releases only additional refs.
 * Objects and allocation reservations independently keep destroy busy. No raw
 * pointer may be resurrected. Shutdown stops admission, not finalization; after
 * all API users are quiescent, destroy requires shutdown, no objects/drainers
 * and only the creating owner's reference. */
fd_retirement_queue_t *fd_retirement_queue_create(size_t capacity);
bool fd_retirement_queue_get(fd_retirement_queue_t *queue);
int fd_retirement_queue_put(fd_retirement_queue_t *queue);
void fd_retirement_queue_shutdown(fd_retirement_queue_t *queue);
int fd_retirement_queue_snapshot(fd_retirement_queue_t *queue, fd_retirement_status_t *out);
int fd_retirement_queue_destroy(fd_retirement_queue_t *queue);
/* Only persistent protected cleanup workers may drain, without any caller-held
 * lock/preemption guard. Callbacks may block/reenter; detached finalizers must
 * never be abandoned. budget bounds the number of objects, not callback time. */
size_t fd_retirement_queue_drain(fd_retirement_queue_t *queue, size_t budget);
fd_description_t *fd_description_create_deferred(const fd_ops_t *ops, void *context,
                                                 fd_retirement_queue_t *queue);
fd_table_t *fd_table_create_deferred(size_t capacity, fd_retirement_queue_t *queue);

/* Standalone ownership primitives; the legacy global FD API is unchanged.
 * Every API caller must own a table/description reference, or acquire one
 * while the publishing owner's lock prevents its final release. A raw pointer
 * cannot be resurrected with get(). Successful get/install/pin/dup operations
 * retain independent references; overflow never wraps the reference count.
 *
 * Ops are copied into the description. On successful create the description
 * owns context until the final close callback; on failure the caller retains
 * context. Shared offsets and operation serialization belong to that context.
 * All callbacks run without module locks. Functions which release references
 * on synchronous objects must also run without caller-held locks, from an execution context
 * which cannot be abandoned during final cleanup (for example an owned I/O
 * worker). The module does not make an existing callback cancellation-safe.
 */
fd_description_t *fd_description_create(const fd_ops_t *ops, void *context);
bool fd_description_get(fd_description_t *description);
/* Borrowed finalization query: own a reference, or hold an external registry
 * lock whose unlink is performed by the close callback before freeing its
 * context. This does not acquire ownership or permit resurrection. */
bool fd_description_referenced(const fd_description_t *description);
/* Returns the close callback's result only on the final release, else zero. */
int fd_description_put(fd_description_t *description);
const fd_ops_t *fd_description_ops(const fd_description_t *description);
void *fd_description_context(const fd_description_t *description);
/* Initialize only before publication, with exclusive constructor ownership.
 * Status is shared by aliases/inherited slots. Mutation preserves access mode. */
int fd_description_initialize_status(fd_description_t *description, uint32_t flags);
uint32_t fd_description_status_flags(const fd_description_t *description);
int fd_description_set_status_flags(fd_description_t *description, uint32_t flags);
/* Change only selected mutable bits; other status/access bits remain intact. */
int fd_description_update_status_flags(fd_description_t *description, uint32_t mask, uint32_t flags);
/* Immutable identity query; caller holds a description reference. */
bool fd_description_is_deferred_to(const fd_description_t *description, const fd_retirement_queue_t *queue);

fd_table_t *fd_table_create(size_t capacity);
bool fd_table_get(fd_table_t *table);
/* Optional process-owned advisory-lock observer. Called synchronously outside
 * table locks while a removed description is still pinned. NULL means shutdown.
 * It must be bounded, allocation-free and must not wait or run storage I/O.
 * Register once (repeating the same pair is allowed) while owning this table. */
typedef void (*fd_table_close_observer_t)(void *context, fd_description_t *description);
int fd_table_observe_closes(fd_table_t *table, fd_table_close_observer_t observer, void *context);
bool fd_table_closed(fd_table_t *table);
/* Reserve a not-yet-visible OPEN slot before worker-side create/truncate. The
 * returned deferred description owns a table reference and cancels its ticket
 * on final cleanup. No table->reservation reference cycle exists. Caller holds
 * a preparation guard until registering this owner in a request. */
int fd_table_reserve_deferred(fd_table_t *table, fd_description_t **out);
bool fd_table_reservation_valid(const fd_description_t *description);
/* Caller owns the reservation. Clear only its matching ticket, before a failed
 * OPEN returns; later deferred cleanup still owns the table reference. */
int fd_table_reservation_cancel(fd_description_t *reservation);
/* Caller owns both references under its result guard. Commit retains target;
 * reservation remains request-owned until normal completion/cleanup. */
int fd_table_reservation_commit(fd_description_t *reservation, fd_description_t *target, uint32_t flags);
/* Snapshot an owned deferred table under its lock. The caller holds a bounded
 * preparation guard through the returned owner's publication. An exec snapshot
 * omits CLOEXEC entries; other entries retain shared open descriptions/offsets.
 * On failure out is NULL and deferred cleanup owns any partial snapshot. */
int fd_table_clone_deferred(fd_table_t *source, bool close_on_exec, fd_table_t **out);
void fd_table_put(fd_table_t *table);
size_t fd_table_capacity(const fd_table_t *table);
/* Limits constrain new allocation, preserving access to existing high slots.
 * Raising the hard limit requires caller authorization and cannot exceed the
 * immutable physical capacity. An admitted OPEN reservation may still commit
 * after a concurrent reduction. Clones inherit both limits and existing slots. */
int fd_table_get_limits(fd_table_t *table, uint64_t *soft, uint64_t *hard);
int fd_table_set_limits(fd_table_t *table, uint64_t soft, uint64_t hard, bool raise_allowed);
/* Atomically prevent further lookups/mutations, then drop slot references
 * outside the lock. Idempotent. Existing operation pins remain valid. The
 * caller's reference keeps the table alive through callbacks and draining.
 * A concurrent repeat can return while the first caller is still draining;
 * the first caller must retain its reference until this function returns. */
void fd_table_shutdown(fd_table_t *table);

/* Install retains description; it never consumes the caller's reference.
 * All integer APIs return a descriptor/success or a negative errno. */
int fd_table_install(fd_table_t *table, fd_description_t *description,
                     int minimum, uint32_t flags);
int fd_table_install_at(fd_table_t *table, int fd,
                        fd_description_t *description, uint32_t flags);
/* Publish two distinct lowest free slots atomically, or change nothing. Both
 * descriptions remain caller-owned; successful slots retain separate refs. */
int fd_table_install_pair(fd_table_t *table, fd_description_t *first,
                           fd_description_t *second, uint32_t flags, int output[2]);
/* pin's output is owned until put. The caller must register that ownership in
 * a heap-owned cancellation record BEFORE invoking an operation that can
 * block. Neither the description nor a pointer into it may outlive the pin. */
int fd_table_pin(fd_table_t *table, int fd, fd_description_t **description_out,
                 uint32_t *flags_out);
int fd_table_close(fd_table_t *table, int fd);
/* expected must remain pinned across the call. Its identity cannot be reused
 * while pinned; a replacement slot returns -EAGAIN and remains untouched. */
int fd_table_close_if(fd_table_t *table, int fd, fd_description_t *expected);
int fd_table_dup(fd_table_t *table, int source, int minimum, uint32_t flags);
/* F_DUPFD variants reject a minimum outside the current soft limit as EINVAL. */
int fd_table_dup_minimum(fd_table_t *table, int source, int minimum, uint32_t flags);
/* dup2(source, source) validates source and preserves its descriptor flags. */
int fd_table_dup2(fd_table_t *table, int source, int destination);
/* dup3 rejects identical descriptors; only FD_TABLE_CLOEXEC is supported. */
int fd_table_dup3(fd_table_t *table, int source, int destination, uint32_t flags);
int fd_table_get_flags(fd_table_t *table, int fd, uint32_t *flags_out);
int fd_table_set_flags(fd_table_t *table, int fd, uint32_t flags);

#endif
