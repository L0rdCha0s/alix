#include "io_stream.h"
#include "process.h"
#include "console.h"
#include "serial.h"
#include "heap.h"
#include "errno.h"

typedef struct
{
    fd_ops_t ops;
    void *context;
    fd_description_t *owner;
} io_stream_t;

static int io_stream_close(void *context)
{
    io_stream_t *stream = context;
    int result = stream->ops.close ? stream->ops.close(stream->context) : 0;
    fd_description_put(stream->owner);
    free(stream);
    return result;
}

static uint32_t io_stream_poll(void *context)
{
    io_stream_t *stream = context;
    return stream->ops.poll ? stream->ops.poll(stream->context) : SYSCALL_POLL_ERR;
}
static const fd_ops_t io_stream_ops = { .close = io_stream_close, .poll = io_stream_poll };

fd_description_t *io_stream_create(const fd_ops_t *ops, void *context,
                                   fd_description_t *owner, fd_retirement_queue_t *retirement)
{
    if (!ops || !retirement || (owner && !fd_description_is_deferred_to(owner, retirement))) return NULL;
    io_stream_t *stream = calloc(1, sizeof(*stream));
    if (!stream) return NULL;
    stream->ops = *ops;
    stream->context = context;
    stream->owner = owner;
    fd_description_t *description = fd_description_create_deferred(&io_stream_ops, stream, retirement);
    if (!description) free(stream);
    else (void)fd_description_initialize_status(description,
        (ops->read ? FD_STATUS_READ : 0) | (ops->write ? FD_STATUS_WRITE : 0));
    return description;
}

bool io_stream_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_stream_close;
}

void io_stream_execute(io_request_t *request, io_service_result_t *result)
{
    if (!result) return;
    result->result = -EINVAL;
    result->description_owned = NULL;
    if (!request || io_request_buffer_size(request) < sizeof(io_vfs_operation_t)) return;
    io_vfs_operation_t *operation = io_request_buffer(request);
    size_t available = io_request_buffer_size(request) - sizeof(*operation);
    fd_description_t *description = io_request_description(request);
    if (!io_stream_description_valid(description)) { result->result = -EBADF; return; }
    if (operation->reserved || operation->count > available) return;
    io_stream_t *stream = fd_description_context(description);
    switch (operation->opcode)
    {
        case IO_VFS_READ:
            result->result = stream->ops.read ? stream->ops.read(stream->context, operation->data, operation->count) : -EBADF;
            break;
        case IO_VFS_WRITE:
            result->result = stream->ops.write ? stream->ops.write(stream->context, operation->data, operation->count) : -EBADF;
            break;
        case IO_VFS_PREAD:
            result->result = stream->ops.pread && operation->offset >= 0 ?
                stream->ops.pread(stream->context, operation->data, operation->count, operation->offset) : -ESPIPE;
            break;
        case IO_VFS_SEEK:
            result->result = stream->ops.lseek ? stream->ops.lseek(stream->context, operation->offset, operation->whence) : -ESPIPE;
            return;
        case IO_VFS_STAT:
            result->result = stream->ops.fstat ? stream->ops.fstat(stream->context, &operation->stat) : -ENOSYS;
            return;
        default: return;
    }
    if (result->result > 0 && (uint64_t)result->result > operation->count) result->result = -EIO;
    if (result->result == -1) result->result = -EIO;
}

static ssize_t io_null_read(void *context, void *buffer, size_t count)
{
    (void)context; (void)buffer; (void)count;
    return 0;
}

static int io_character_stat(void *context, syscall_stat_t *out)
{
    (void)context;
    if (!out) return -EINVAL;
    *out = (syscall_stat_t){ .type = SYSCALL_NODE_TYPE_CHARACTER };
    return 0;
}

static ssize_t io_console_write(void *context, const void *buffer, size_t count)
{
    (void)context;
    if (!buffer && count) return -EINVAL;
    const char *data = buffer;
    for (size_t index = 0; index < count; ++index) console_putc(data[index]);
    serial_output_bytes(data, count);
    return (ssize_t)count;
}

static uint32_t io_null_poll(void *context) { (void)context; return SYSCALL_POLL_IN; }
static uint32_t io_console_poll(void *context) { (void)context; return SYSCALL_POLL_OUT; }

fd_description_t *io_null_input_create(fd_retirement_queue_t *retirement)
{
    const fd_ops_t ops = { .read = io_null_read, .fstat = io_character_stat, .poll = io_null_poll };
    return io_stream_create(&ops, NULL, NULL, retirement);
}

fd_description_t *io_console_import_owned(void *unused)
{
    (void)unused;
    const fd_ops_t ops = { .write = io_console_write, .fstat = io_character_stat, .poll = io_console_poll };
    return io_stream_create(&ops, NULL, NULL, process_fd_retirement_queue());
}
