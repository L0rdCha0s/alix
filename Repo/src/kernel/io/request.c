#include "io_request.h"
#include "heap.h"
#include "spinlock.h"
#include "errno.h"

#define IO_OWNER_WAITER 1u
#define IO_OWNER_EXECUTOR 2u
#define IO_OWNER_CLEANUP 4u

struct io_request
{
    io_queue_t *queue;
    io_request_t *all_next, *all_previous;
    io_request_t *work_next, *work_previous;
    io_request_t *cleanup_next;
    unsigned owners;
    io_request_state_t state;
    bool cancelled, submitted, bound;
    int64_t result;
    void *buffer;
    size_t buffer_size;
    uint32_t uid, gid;
    fd_description_t *description, *result_description, *cwd_owner;
    void *cwd;
    io_cwd_release_t release_cwd;
};

struct io_queue
{
    spinlock_t lock;
    size_t capacity, live, queued, cleanup, drainers;
    bool closed;
    io_request_t *all, *head, *tail, *cleanup_head, *cleanup_tail;
};


static void io_enqueue_cleanup_locked(io_request_t *request)
{
    if (request->owners != 0) return;
    io_queue_t *queue = request->queue;
    request->owners = IO_OWNER_CLEANUP;
    request->cleanup_next = NULL;
    if (queue->cleanup_tail) queue->cleanup_tail->cleanup_next = request;
    else queue->cleanup_head = request;
    queue->cleanup_tail = request;
    ++queue->cleanup;
}

static void io_remove_work_locked(io_request_t *request)
{
    io_queue_t *queue = request->queue;
    if (request->work_previous) request->work_previous->work_next = request->work_next;
    else queue->head = request->work_next;
    if (request->work_next) request->work_next->work_previous = request->work_previous;
    else queue->tail = request->work_previous;
    request->work_previous = request->work_next = NULL;
    --queue->queued;
}

static void io_cancel_locked(io_request_t *request)
{
    request->cancelled = true;
    if (request->state == IO_REQUEST_QUEUED)
    {
        io_remove_work_locked(request);
        request->owners &= ~IO_OWNER_EXECUTOR;
        request->state = IO_REQUEST_COMPLETED;
        request->result = -ECANCELED;
    }
    else if (request->state == IO_REQUEST_NEW)
    {
        request->state = IO_REQUEST_COMPLETED;
        request->result = -ECANCELED;
    }
    io_enqueue_cleanup_locked(request);
}

io_queue_t *io_queue_create(size_t capacity)
{
    if (!capacity || capacity > IO_QUEUE_MAX_REQUESTS) return NULL;
    io_queue_t *queue = calloc(1, sizeof(*queue));
    if (!queue) return NULL;
    spinlock_init(&queue->lock);
    queue->capacity = capacity;
    return queue;
}

void io_queue_shutdown(io_queue_t *queue)
{
    if (!queue) return;
    spinlock_lock(&queue->lock);
    queue->closed = true;
    for (io_request_t *request = queue->all; request; request = request->all_next)
        io_cancel_locked(request);
    spinlock_unlock(&queue->lock);
}

int io_queue_destroy(io_queue_t *queue)
{
    if (!queue) return -EINVAL;
    spinlock_lock(&queue->lock);
    bool ready = queue->closed && queue->live == 0 && queue->drainers == 0;
    spinlock_unlock(&queue->lock);
    if (!ready) return -EBUSY;
    free(queue);
    return 0;
}

int io_queue_snapshot(io_queue_t *queue, io_queue_status_t *out)
{
    if (!queue || !out) return -EINVAL;
    spinlock_lock(&queue->lock);
    out->capacity = queue->capacity;
    out->live = queue->live;
    out->queued = queue->queued;
    out->cleanup = queue->cleanup;
    out->closed = queue->closed;
    spinlock_unlock(&queue->lock);
    return 0;
}

int io_request_create(io_queue_t *queue, size_t buffer_size, uint32_t uid,
                      uint32_t gid, io_request_t **out)
{
    if (!out) return -EINVAL;
    *out = NULL;
    if (!queue || buffer_size > IO_REQUEST_BUFFER_MAX) return -EINVAL;
    spinlock_lock(&queue->lock);
    int result = queue->closed ? -ECANCELED : queue->live == queue->capacity ? -EAGAIN : 0;
    if (!result) ++queue->live; /* Reservation protects queue lifetime across allocation. */
    spinlock_unlock(&queue->lock);
    if (result) return result;
    io_request_t *request = calloc(1, sizeof(*request));
    if (request && buffer_size) request->buffer = calloc(1, buffer_size);
    if (!request || (buffer_size && !request->buffer)) result = -ENOMEM;
    spinlock_lock(&queue->lock);
    if (!result && queue->closed) result = -ECANCELED;
    if (result)
    {
        --queue->live;
    }
    else
    {
        request->queue = queue;
        request->owners = IO_OWNER_WAITER;
        request->state = IO_REQUEST_NEW;
        request->buffer_size = buffer_size;
        request->uid = uid;
        request->gid = gid;
        request->all_next = queue->all;
        if (queue->all) queue->all->all_previous = request;
        queue->all = request;
        *out = request;
    }
    spinlock_unlock(&queue->lock);
    if (result && request)
    {
        free(request->buffer);
        free(request);
    }
    return result;
}

int io_request_bind(io_request_t *request, fd_description_t *description_owned,
                    void *cwd_owned, io_cwd_release_t release_cwd)
{
    if (!request || ((cwd_owned == NULL) != (release_cwd == NULL))) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    int result = 0;
    if (!(request->owners & IO_OWNER_WAITER) || request->submitted || request->bound)
        result = -EBUSY;
    else
    {
        request->description = description_owned;
        request->cwd = cwd_owned;
        request->release_cwd = release_cwd;
        request->bound = true;
    }
    spinlock_unlock(&queue->lock);
    return result;
}

int io_request_bind_cwd_owner(io_request_t *request, fd_description_t *description_owned,
                               fd_description_t *cwd_owner_owned)
{
    if (!request || !cwd_owner_owned || !fd_description_context(cwd_owner_owned)) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    int result = 0;
    if (!(request->owners & IO_OWNER_WAITER) || request->submitted || request->bound)
        result = -EBUSY;
    else
    {
        request->description = description_owned;
        request->cwd_owner = cwd_owner_owned;
        request->cwd = fd_description_context(cwd_owner_owned);
        request->bound = true;
    }
    spinlock_unlock(&queue->lock);
    return result;
}

bool io_request_uses_queue(const io_request_t *request, const io_queue_t *queue)
{ return request && queue && request->queue == queue; }

void *io_request_buffer(io_request_t *request) { return request ? request->buffer : NULL; }
size_t io_request_buffer_size(const io_request_t *request) { return request ? request->buffer_size : 0; }
fd_description_t *io_request_description(const io_request_t *request) { return request ? request->description : NULL; }
void *io_request_cwd(const io_request_t *request) { return request ? request->cwd : NULL; }
uint32_t io_request_uid(const io_request_t *request) { return request ? request->uid : 0; }
uint32_t io_request_gid(const io_request_t *request) { return request ? request->gid : 0; }

int io_request_submit(io_request_t *request)
{
    if (!request) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    int result = 0;
    if (!(request->owners & IO_OWNER_WAITER) || request->submitted) result = -EINVAL;
    else if (queue->closed || request->cancelled) result = -ECANCELED;
    else
    {
        request->submitted = true;
        request->state = IO_REQUEST_QUEUED;
        request->owners |= IO_OWNER_EXECUTOR;
        request->work_previous = queue->tail;
        if (queue->tail) queue->tail->work_next = request;
        else queue->head = request;
        queue->tail = request;
        ++queue->queued;
    }
    spinlock_unlock(&queue->lock);
    return result;
}

int io_request_complete_inline(io_request_t *request, int64_t result)
{
    if (!request) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    int status = 0;
    if (queue->closed || request->cancelled) status = -ECANCELED;
    else if (request->owners != IO_OWNER_WAITER || !request->bound ||
             request->submitted || request->state != IO_REQUEST_NEW) status = -EINVAL;
    else
    {
        request->submitted = true;
        request->result = result;
        request->state = IO_REQUEST_COMPLETED;
    }
    spinlock_unlock(&queue->lock);
    return status;
}

io_request_t *io_queue_take(io_queue_t *queue)
{
    if (!queue) return NULL;
    spinlock_lock(&queue->lock);
    io_request_t *request = queue->head;
    if (request)
    {
        io_remove_work_locked(request);
        request->state = IO_REQUEST_RUNNING;
    }
    spinlock_unlock(&queue->lock);
    return request;
}

int io_request_cancel(io_request_t *request)
{
    if (!request) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    int result = 0;
    if (!(request->owners & (IO_OWNER_WAITER | IO_OWNER_EXECUTOR))) result = -EINVAL;
    else io_cancel_locked(request);
    spinlock_unlock(&queue->lock);
    return result;
}

int io_request_status(io_request_t *request, io_request_status_t *out)
{
    if (!request || !out) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    out->state = request->state;
    out->cancelled = request->cancelled;
    out->result = request->result;
    spinlock_unlock(&queue->lock);
    return 0;
}

int io_request_publish_complete(io_request_t *request, int64_t result,
                                fd_description_t *result_description_owned)
{
    if (!request) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    int status = 0;
    if (request->state != IO_REQUEST_RUNNING || !(request->owners & IO_OWNER_EXECUTOR)) status = -EINVAL;
    else
    {
        request->result = result;
        request->result_description = result_description_owned;
        request->state = IO_REQUEST_COMPLETED;
    }
    spinlock_unlock(&queue->lock);
    return status;
}

int io_request_take_result(io_request_t *request, fd_description_t **out)
{
    if (!out) return -EINVAL;
    *out = NULL;
    if (!request) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    int result = 0;
    if (!(request->owners & IO_OWNER_WAITER)) result = -EINVAL;
    else if (request->cancelled) result = -ECANCELED;
    else if (request->state != IO_REQUEST_COMPLETED) result = -EAGAIN;
    else
    {
        *out = request->result_description;
        request->result_description = NULL;
    }
    spinlock_unlock(&queue->lock);
    return result;
}

int io_request_worker_release(io_request_t *request)
{
    if (!request) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    int result = 0;
    if (request->state != IO_REQUEST_COMPLETED || !(request->owners & IO_OWNER_EXECUTOR)) result = -EINVAL;
    else
    {
        request->owners &= ~IO_OWNER_EXECUTOR;
        io_enqueue_cleanup_locked(request);
    }
    spinlock_unlock(&queue->lock);
    return result;
}

static int io_release_waiter(io_request_t *request, bool abandon)
{
    if (!request) return -EINVAL;
    io_queue_t *queue = request->queue;
    spinlock_lock(&queue->lock);
    int result = 0;
    if (!(request->owners & IO_OWNER_WAITER)) result = -EINVAL;
    else
    {
        if (abandon) io_cancel_locked(request);
        request->owners &= ~IO_OWNER_WAITER;
        io_enqueue_cleanup_locked(request);
    }
    spinlock_unlock(&queue->lock);
    return result;
}

int io_request_waiter_release(io_request_t *request) { return io_release_waiter(request, false); }
int io_request_waiter_abandon(io_request_t *request) { return io_release_waiter(request, true); }

size_t io_queue_drain(io_queue_t *queue, size_t budget)
{
    if (!queue || !budget) return 0;
    spinlock_lock(&queue->lock);
    ++queue->drainers;
    spinlock_unlock(&queue->lock);
    size_t drained = 0;
    while (drained < budget)
    {
        spinlock_lock(&queue->lock);
        io_request_t *request = queue->cleanup_head;
        if (request)
        {
            queue->cleanup_head = request->cleanup_next;
            if (!queue->cleanup_head) queue->cleanup_tail = NULL;
            --queue->cleanup;
            if (request->all_previous) request->all_previous->all_next = request->all_next;
            else queue->all = request->all_next;
            if (request->all_next) request->all_next->all_previous = request->all_previous;
        }
        spinlock_unlock(&queue->lock);
        if (!request) break;
        /* Only this worker owns CLEANUP now. Keep live reserved until every
         * destructor returns, so reentrant shutdown/destroy cannot free queue. */
        fd_description_put(request->description);
        fd_description_put(request->result_description);
        fd_description_put(request->cwd_owner);
        if (request->release_cwd) request->release_cwd(request->cwd);
        free(request->buffer);
        free(request);
        spinlock_lock(&queue->lock);
        --queue->live;
        spinlock_unlock(&queue->lock);
        ++drained;
    }
    spinlock_lock(&queue->lock);
    --queue->drainers;
    spinlock_unlock(&queue->lock);
    return drained;
}
