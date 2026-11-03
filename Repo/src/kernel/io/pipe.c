#include "io_pipe.h"
#include "spinlock.h"
#include "heap.h"
#include "libc.h"
#include "errno.h"
#include "vfs.h"

struct io_pipe
{
    spinlock_t lock;
    size_t head, used;
    unsigned readers, writers, endpoints;
    uint64_t reader_epoch, writer_epoch;
    bool named;
    unsigned char data[IO_PIPE_CAPACITY];
};

typedef struct
{
    io_pipe_t *pipe;
    vfs_node_t *node;
    bool readable, writable, active, connected, writer_seen;
    uint64_t reader_epoch, writer_epoch;
} io_pipe_endpoint_t;

static int io_pipe_close(void *context)
{
    io_pipe_endpoint_t *endpoint = context;
    io_pipe_t *pipe = endpoint->pipe;
    spinlock_lock(&pipe->lock);
    if (endpoint->active)
    {
        if (endpoint->writable) --pipe->writers;
        if (endpoint->readable) --pipe->readers;
        --pipe->endpoints;
        if (!pipe->endpoints) pipe->head = pipe->used = 0;
    }
    bool last = !pipe->named && !pipe->endpoints;
    spinlock_unlock(&pipe->lock);
    if (endpoint->node) vfs_node_release_owned(endpoint->node);
    free(endpoint);
    if (last) free(pipe);
    return 0;
}

static uint32_t io_pipe_poll(void *context)
{
    io_pipe_endpoint_t *endpoint = context;
    io_pipe_t *pipe = endpoint->pipe;
    uint32_t flags = 0;
    spinlock_lock(&pipe->lock);
    if (endpoint->writable)
    {
        if (!pipe->readers) flags |= SYSCALL_POLL_ERR;
        if (IO_PIPE_CAPACITY - pipe->used >= IO_PIPE_ATOMIC) flags |= SYSCALL_POLL_OUT;
    }
    if (endpoint->readable)
    {
        if (pipe->used) flags |= SYSCALL_POLL_IN;
        if (pipe->writers || pipe->writer_epoch != endpoint->writer_epoch) endpoint->writer_seen = true;
        if (!pipe->writers && (!pipe->named || endpoint->writer_seen)) flags |= SYSCALL_POLL_HUP;
    }
    spinlock_unlock(&pipe->lock);
    return flags;
}
static const fd_ops_t io_pipe_ops = { .close = io_pipe_close, .poll = io_pipe_poll };

bool io_pipe_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_pipe_close;
}

struct vfs_node *io_pipe_node(const fd_description_t *description)
{
    return io_pipe_description_valid(description) ? ((io_pipe_endpoint_t *)fd_description_context(description))->node : NULL;
}

io_pipe_t *io_pipe_named_create(void)
{
    io_pipe_t *pipe = calloc(1, sizeof(*pipe));
    if (pipe) { spinlock_init(&pipe->lock); pipe->named = true; }
    return pipe;
}

void io_pipe_named_destroy(io_pipe_t *pipe)
{
    /* Every endpoint owns its VFS node, so the node cannot die with users. */
    if (pipe) free(pipe);
}

int io_pipe_named_open_owned(vfs_node_t *node, uint32_t flags,
                              fd_retirement_queue_t *retirement, fd_description_t **out)
{
    *out = NULL;
    io_pipe_t *pipe = vfs_fifo_state(node);
    if (!pipe) { vfs_node_release_owned(node); return -ENOMEM; }
    io_pipe_endpoint_t *endpoint = calloc(1, sizeof(*endpoint));
    if (!endpoint) { vfs_node_release_owned(node); return -ENOMEM; }
    *endpoint = (io_pipe_endpoint_t){.pipe = pipe, .node = node,
        .readable = (flags & SYSCALL_OPEN_READ) != 0, .writable = (flags & SYSCALL_OPEN_WRITE) != 0};
    fd_description_t *description = fd_description_create_deferred(&io_pipe_ops, endpoint, retirement);
    if (!description) { vfs_node_release_owned(node); free(endpoint); return -ENOMEM; }
    (void)fd_description_initialize_status(description, flags &
        (FD_STATUS_READ | FD_STATUS_WRITE | FD_STATUS_NONBLOCK | FD_STATUS_APPEND | FD_STATUS_SYNC));
    int result = 0;
    spinlock_lock(&pipe->lock);
    bool nonblocking = (flags & SYSCALL_OPEN_NONBLOCK) != 0;
    if (endpoint->writable && !endpoint->readable && nonblocking && !pipe->readers) result = -ENXIO;
    else if (pipe->endpoints == UINT32_MAX || pipe->reader_epoch == UINT64_MAX || pipe->writer_epoch == UINT64_MAX) result = -EOVERFLOW;
    else
    {
        endpoint->reader_epoch = pipe->reader_epoch; endpoint->writer_epoch = pipe->writer_epoch;
        endpoint->writer_seen = pipe->writers != 0;
        endpoint->connected = nonblocking || (endpoint->readable && endpoint->writable) ||
            (endpoint->readable ? pipe->writers != 0 : pipe->readers != 0);
        if (endpoint->readable) { ++pipe->readers; ++pipe->reader_epoch; }
        if (endpoint->writable) { ++pipe->writers; ++pipe->writer_epoch; }
        ++pipe->endpoints; endpoint->active = true;
    }
    spinlock_unlock(&pipe->lock);
    if (result) fd_description_put(description);
    else *out = description;
    return result;
}

bool io_pipe_open_pending(const fd_description_t *description)
{
    if (!io_pipe_description_valid(description)) return false;
    io_pipe_endpoint_t *endpoint = fd_description_context(description);
    io_pipe_t *pipe = endpoint->pipe;
    spinlock_lock(&pipe->lock);
    if (!endpoint->connected)
        endpoint->connected = endpoint->readable ? pipe->writers || pipe->writer_epoch != endpoint->writer_epoch :
                                                  pipe->readers || pipe->reader_epoch != endpoint->reader_epoch;
    bool pending = !endpoint->connected;
    spinlock_unlock(&pipe->lock);
    return pending;
}

typedef struct { fd_description_t *endpoint, *reservation; } io_pipe_open_lease_t;
static int io_pipe_open_lease_close(void *context)
{
    io_pipe_open_lease_t *lease = context;
    (void)fd_table_reservation_cancel(lease->reservation);
    fd_description_put(lease->endpoint); fd_description_put(lease->reservation);
    free(lease);
    return 0;
}
static const fd_ops_t io_pipe_open_lease_ops = {.close = io_pipe_open_lease_close};
bool io_pipe_open_lease_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_pipe_open_lease_close;
}
fd_description_t *io_pipe_open_reservation(const fd_description_t *description)
{
    return io_pipe_open_lease_valid(description) ? ((io_pipe_open_lease_t *)fd_description_context(description))->reservation : NULL;
}
int io_pipe_open_lease_create(fd_description_t *endpoint, fd_description_t *reservation,
                               fd_retirement_queue_t *retirement, fd_description_t **out)
{
    *out = NULL;
    io_pipe_open_lease_t *lease = calloc(1, sizeof(*lease));
    fd_description_t *description = lease ? fd_description_create_deferred(&io_pipe_open_lease_ops, lease, retirement) : NULL;
    if (!description)
    {
        free(lease); (void)fd_table_reservation_cancel(reservation);
        fd_description_put(endpoint); fd_description_put(reservation); return -ENOMEM;
    }
    *lease = (io_pipe_open_lease_t){.endpoint = endpoint, .reservation = reservation};
    *out = description;
    return 0;
}
bool io_pipe_open_execute(io_request_t *request, io_service_result_t *result)
{
    result->result = -EINVAL; result->description_owned = NULL;
    if (!io_pipe_open_lease_valid(io_request_description(request)) || io_request_buffer_size(request) != sizeof(io_pipe_operation_t)) return true;
    io_pipe_operation_t *operation = io_request_buffer(request);
    if (operation->opcode != IO_PIPE_OPEN_WAIT || operation->count || operation->reserved) return true;
    io_pipe_open_lease_t *lease = fd_description_context(io_request_description(request));
    if (io_pipe_open_pending(lease->endpoint)) return false;
    if (!fd_description_get(lease->endpoint)) { result->result = -EOVERFLOW; return true; }
    result->description_owned = lease->endpoint; result->result = 0;
    return true;
}

int io_pipe_create_pair(fd_retirement_queue_t *retirement,
                         fd_description_t **reader, fd_description_t **writer)
{
    if (!reader || !writer || reader == writer) return -EINVAL;
    *reader = NULL; *writer = NULL;
    if (!retirement) return -EINVAL;
    io_pipe_t *pipe = calloc(1, sizeof(*pipe));
    io_pipe_endpoint_t *input = pipe ? calloc(1, sizeof(*input)) : NULL;
    io_pipe_endpoint_t *output = input ? calloc(1, sizeof(*output)) : NULL;
    if (!output) { free(input); free(pipe); return -ENOMEM; }
    spinlock_init(&pipe->lock);
    pipe->readers = pipe->writers = 1;
    pipe->endpoints = 2;
    *input = (io_pipe_endpoint_t){ .pipe = pipe, .readable = true, .active = true, .connected = true };
    *output = (io_pipe_endpoint_t){ .pipe = pipe, .writable = true, .active = true, .connected = true };
    fd_description_t *read_description = fd_description_create_deferred(&io_pipe_ops, input, retirement);
    if (!read_description) { free(output); free(input); free(pipe); return -ENOMEM; }
    fd_description_t *write_description = fd_description_create_deferred(&io_pipe_ops, output, retirement);
    if (!write_description)
    {
        pipe->writers = 0; pipe->endpoints = 1;
        free(output);
        fd_description_put(read_description);
        return -ENOMEM;
    }
    *reader = read_description; *writer = write_description;
    (void)fd_description_initialize_status(read_description, FD_STATUS_READ);
    (void)fd_description_initialize_status(write_description, FD_STATUS_WRITE);
    return 0;
}

int io_pipe_stat(const fd_description_t *description, syscall_stat_t *out)
{
    if (!io_pipe_description_valid(description)) return -EBADF;
    if (!out) return -EINVAL;
    *out = (syscall_stat_t){ .type = SYSCALL_NODE_TYPE_FIFO };
    vfs_node_t *node = io_pipe_node(description);
    if (node && !vfs_stat(node, NULL, NULL, &out->atime, &out->mtime, &out->ctime)) return -EIO;
    return 0;
}

bool io_pipe_execute(io_request_t *request, io_service_result_t *result)
{
    if (!result) return true;
    result->result = -EINVAL; result->description_owned = NULL;
    if (!request || io_request_buffer_size(request) < sizeof(io_pipe_operation_t)) return true;
    io_pipe_operation_t *operation = io_request_buffer(request);
    if (operation->reserved || operation->count > io_request_buffer_size(request) - sizeof(*operation)) return true;
    fd_description_t *description = io_request_description(request);
    if (!io_pipe_description_valid(description)) { result->result = -EBADF; return true; }
    io_pipe_endpoint_t *endpoint = fd_description_context(description);
    if (operation->opcode == IO_PIPE_AVAILABLE)
    {
        if (operation->count) return true;
        spinlock_lock(&endpoint->pipe->lock);
        result->result = (int64_t)endpoint->pipe->used;
        spinlock_unlock(&endpoint->pipe->lock);
        return true;
    }
    bool writing = operation->opcode == IO_PIPE_WRITE;
    if ((operation->opcode != IO_PIPE_READ && !writing)) return true;
    if ((writing && !endpoint->writable) || (!writing && !endpoint->readable)) { result->result = -EBADF; return true; }
    if (!operation->count) { result->result = 0; return true; }
    io_pipe_t *pipe = endpoint->pipe;
    bool complete = true;
    spinlock_lock(&pipe->lock);
    size_t bytes = (size_t)operation->count;
    if (writing)
    {
        size_t space = IO_PIPE_CAPACITY - pipe->used;
        if (!pipe->readers) result->result = -EPIPE;
        else if (!space || (bytes <= IO_PIPE_ATOMIC && space < bytes)) complete = false;
        else
        {
            if (bytes > space) bytes = space;
            size_t tail = (pipe->head + pipe->used) % IO_PIPE_CAPACITY;
            size_t first = bytes < IO_PIPE_CAPACITY - tail ? bytes : IO_PIPE_CAPACITY - tail;
            memcpy(pipe->data + tail, operation->data, first);
            memcpy(pipe->data, operation->data + first, bytes - first);
            pipe->used += bytes;
            result->result = (int64_t)bytes;
        }
    }
    else if (!pipe->used)
    {
        if (pipe->writers) complete = false;
        else result->result = 0;
    }
    else
    {
        if (bytes > pipe->used) bytes = pipe->used;
        size_t first = bytes < IO_PIPE_CAPACITY - pipe->head ? bytes : IO_PIPE_CAPACITY - pipe->head;
        memcpy(operation->data, pipe->data + pipe->head, first);
        memcpy(operation->data + first, pipe->data, bytes - first);
        pipe->head = (pipe->head + bytes) % IO_PIPE_CAPACITY;
        pipe->used -= bytes;
        result->result = (int64_t)bytes;
    }
    spinlock_unlock(&pipe->lock);
    if (!complete && (fd_description_status_flags(description) & FD_STATUS_NONBLOCK))
    { result->result = -EAGAIN; complete = true; }
    return complete;
}
