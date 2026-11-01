#include "io_flock.h"
#include "heap.h"
#include "spinlock.h"
#include "errno.h"

typedef struct {
    fd_description_t *target, *self;
    io_flock_state_t *state;
    uint32_t mode;
    bool nonblock, begun, granted, revoked;
} io_flock_lease_t;

static spinlock_t flock_registry_lock;
static io_flock_state_t *flock_registry;

bool io_flock_flags_valid(uint32_t flags)
{
    uint32_t mode = flags & ~SYSCALL_FLOCK_NONBLOCK;
    return mode == SYSCALL_FLOCK_SHARED || mode == SYSCALL_FLOCK_EXCLUSIVE || mode == SYSCALL_FLOCK_UNLOCK;
}

void io_flock_state_init(io_flock_state_t *state, const void *key, fd_description_t *self)
{
    state->next = NULL; state->key = key; state->description = self;
    state->active = NULL; state->held = state->reserved = 0; state->registered = false;
}

void io_flock_state_close(io_flock_state_t *state)
{
    spinlock_lock(&flock_registry_lock);
    if (state->registered)
    {
        io_flock_state_t **link = &flock_registry;
        while (*link && *link != state) link = &(*link)->next;
        if (*link) *link = state->next;
    }
    state->next = NULL; state->held = state->reserved = 0;
    state->registered = false;
    /* Every active lease owns the file, so final close cannot race a lease. */
    state->active = NULL;
    spinlock_unlock(&flock_registry_lock);
}

int io_flock_unlock(io_flock_state_t *state)
{
    if (!state || !state->key || !state->description) return -EINVAL;
    spinlock_lock(&flock_registry_lock);
    state->held = state->reserved = 0;
    if (state->active) ((io_flock_lease_t *)state->active)->revoked = true;
    state->active = NULL;
    spinlock_unlock(&flock_registry_lock);
    return 0;
}

static void io_flock_lease_abort(io_flock_lease_t *lease)
{
    fd_description_t *target;
    spinlock_lock(&flock_registry_lock);
    if (lease->state)
    {
        if (lease->state->active == lease)
        {
            lease->state->active = NULL;
            lease->state->reserved = 0;
        }
    }
    lease->state = NULL; lease->revoked = true; lease->granted = false;
    target = lease->target; lease->target = NULL;
    spinlock_unlock(&flock_registry_lock);
    fd_description_put(target);
}

static int io_flock_close(void *context)
{
    io_flock_lease_t *lease = context;
    io_flock_lease_abort(lease);
    free(lease);
    return 0;
}
static const fd_ops_t io_flock_ops = { .close = io_flock_close };

bool io_flock_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_flock_close;
}

void io_flock_abort(fd_description_t *description)
{
    if (io_flock_description_valid(description))
        io_flock_lease_abort(fd_description_context(description));
}

int io_flock_create(fd_retirement_queue_t *retirement, fd_description_t *target,
                     io_flock_state_t *state, uint32_t flags, fd_description_t **output)
{
    int error = -EINVAL;
    if (output) *output = NULL;
    uint32_t mode = flags & ~SYSCALL_FLOCK_NONBLOCK;
    if (!output || !state || !state->key || state->description != target ||
        !fd_description_is_deferred_to(target, retirement) || !io_flock_flags_valid(flags) ||
        mode == SYSCALL_FLOCK_UNLOCK) goto failed;
    io_flock_lease_t *lease = calloc(1, sizeof(*lease));
    if (!lease) { error = -ENOMEM; goto failed; }
    lease->target = target; lease->state = state; lease->mode = mode;
    lease->nonblock = (flags & SYSCALL_FLOCK_NONBLOCK) != 0;
    fd_description_t *description = fd_description_create_deferred(&io_flock_ops, lease, retirement);
    if (!description) { free(lease); error = -ENOMEM; goto failed; }
    lease->self = description; *output = description;
    return 0;
failed:
    fd_description_put(target);
    return error;
}

bool io_flock_execute(io_request_t *request, io_service_result_t *result)
{
    if (!result) return true;
    result->result = -EINVAL; result->description_owned = NULL;
    fd_description_t *description = io_request_description(request);
    if (!io_flock_description_valid(description)) return true;
    io_flock_lease_t *lease = fd_description_context(description);
    spinlock_lock(&flock_registry_lock);
    io_flock_state_t *state = lease->state;
    if (!state || lease->revoked) { result->result = -ECANCELED; goto complete; }
    if (state->active && state->active != lease)
    {
        if (lease->nonblock) { result->result = -EWOULDBLOCK; goto complete; }
        spinlock_unlock(&flock_registry_lock); return false;
    }
    if (!state->registered)
    {
        state->next = flock_registry; flock_registry = state; state->registered = true;
    }
    state->active = lease;
    if (!lease->begun)
    {
        /* BSD-style conversion releases the old mode before waiting. Two
         * shared owners may both upgrade without retaining a mutual hold. */
        if (state->held != lease->mode) state->held = 0;
        lease->begun = true;
    }
    for (io_flock_state_t *other = flock_registry; other; other = other->next)
    {
        if (other == state || other->key != state->key ||
            !fd_description_referenced(other->description)) continue;
        uint32_t modes = other->held | other->reserved;
        if (modes && (lease->mode == SYSCALL_FLOCK_EXCLUSIVE || (modes & SYSCALL_FLOCK_EXCLUSIVE)))
        {
            if (lease->nonblock)
            {
                state->active = NULL; result->result = -EWOULDBLOCK; goto complete;
            }
            spinlock_unlock(&flock_registry_lock); return false;
        }
    }
    if (!fd_description_get(description))
    {
        state->active = NULL; result->result = -EOVERFLOW; goto complete;
    }
    state->reserved = lease->mode; lease->granted = true;
    result->description_owned = description; result->result = 0;
complete:
    spinlock_unlock(&flock_registry_lock);
    return true;
}

int io_flock_commit(fd_description_t *description)
{
    if (!io_flock_description_valid(description)) return -EINVAL;
    io_flock_lease_t *lease = fd_description_context(description);
    int result = -ECANCELED;
    fd_description_t *target = NULL;
    spinlock_lock(&flock_registry_lock);
    if (lease->state && lease->granted && !lease->revoked && lease->state->active == lease)
    {
        lease->state->held = lease->mode;
        lease->state->active = NULL; lease->state->reserved = 0;
        lease->state = NULL; target = lease->target; lease->target = NULL;
        lease->granted = false; result = 0;
    }
    spinlock_unlock(&flock_registry_lock);
    /* The committed lock belongs to the open description, not the completed
     * request. Releasing this pin now also makes final-close visibility prompt. */
    fd_description_put(target);
    return result;
}
