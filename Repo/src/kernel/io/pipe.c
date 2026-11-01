#include "io_pipe.h"
#include "spinlock.h"
#include "heap.h"
#include "libc.h"
#include "errno.h"

typedef struct
{
    spinlock_t lock;
    size_t head, used;
    bool reader, writer;
    unsigned char data[IO_PIPE_CAPACITY];
} io_pipe_t;

typedef struct
{
    io_pipe_t *pipe;
    bool writing;
} io_pipe_endpoint_t;

static int io_pipe_close(void *context)
{
    io_pipe_endpoint_t *endpoint = context;
    io_pipe_t *pipe = endpoint->pipe;
    spinlock_lock(&pipe->lock);
    if (endpoint->writing) pipe->writer = false;
    else pipe->reader = false;
    bool last = !pipe->reader && !pipe->writer;
    spinlock_unlock(&pipe->lock);
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
    if (endpoint->writing)
    {
        if (!pipe->reader) flags |= SYSCALL_POLL_ERR;
        if (IO_PIPE_CAPACITY - pipe->used >= IO_PIPE_ATOMIC) flags |= SYSCALL_POLL_OUT;
    }
    else
    {
        if (pipe->used) flags |= SYSCALL_POLL_IN;
        if (!pipe->writer) flags |= SYSCALL_POLL_HUP;
    }
    spinlock_unlock(&pipe->lock);
    return flags;
}
static const fd_ops_t io_pipe_ops = { .close = io_pipe_close, .poll = io_pipe_poll };

bool io_pipe_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_pipe_close;
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
    pipe->reader = pipe->writer = true;
    *input = (io_pipe_endpoint_t){ .pipe = pipe };
    *output = (io_pipe_endpoint_t){ .pipe = pipe, .writing = true };
    fd_description_t *read_description = fd_description_create_deferred(&io_pipe_ops, input, retirement);
    if (!read_description) { free(output); free(input); free(pipe); return -ENOMEM; }
    fd_description_t *write_description = fd_description_create_deferred(&io_pipe_ops, output, retirement);
    if (!write_description)
    {
        pipe->writer = false;
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
    bool writing = operation->opcode == IO_PIPE_WRITE;
    if ((operation->opcode != IO_PIPE_READ && !writing)) return true;
    if (writing != endpoint->writing) { result->result = -EBADF; return true; }
    if (!operation->count) { result->result = 0; return true; }
    io_pipe_t *pipe = endpoint->pipe;
    bool complete = true;
    spinlock_lock(&pipe->lock);
    size_t bytes = (size_t)operation->count;
    if (writing)
    {
        size_t space = IO_PIPE_CAPACITY - pipe->used;
        if (!pipe->reader) result->result = -EPIPE;
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
        if (pipe->writer) complete = false;
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
