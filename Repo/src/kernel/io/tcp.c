#include "io_tcp.h"
#include "net/tcp.h"
#include "heap.h"
#include "errno.h"
#include <stdint.h>

typedef struct
{
    net_tcp_socket_t *socket;
    bool reader_owned;
} io_tcp_file_t;

static int io_tcp_file_close(void *context)
{
    io_tcp_file_t *file = context;
    int result = 0;
    if (file)
    {
        if (file->socket) result = net_tcp_socket_put_owned(file->socket);
        free(file);
    }
    return result;
}

/* All data operations go through the multiplexed executor. Blocking fd_ops
 * callbacks would occupy a storage worker and are deliberately absent. */
static const fd_ops_t io_tcp_ops = { .close = io_tcp_file_close };

bool io_tcp_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_tcp_file_close;
}

bool io_tcp_execute(io_request_t *request, io_service_result_t *result,
                      fd_retirement_queue_t *retirement)
{
    if (!result) return true;
    result->result = -EINVAL;
    result->description_owned = NULL;
    if (!request || io_request_buffer_size(request) < sizeof(io_tcp_operation_t)) return true;
    io_tcp_operation_t *operation = io_request_buffer(request);
    size_t available = io_request_buffer_size(request) - sizeof(*operation);
    if (!operation || operation->reserved || operation->started > 1) return true;
    fd_description_t *description = io_request_description(request);
    if (operation->opcode == IO_TCP_OPEN)
    {
        if (!retirement || (description && !fd_table_reservation_valid(description)) || operation->started || operation->count ||
            operation->interface_index >= NET_MAX_INTERFACES) return true;
        net_interface_t *interface = net_if_at(operation->interface_index);
        if (!interface || !interface->present) { result->result = -ENODEV; return true; }
        io_tcp_file_t *file = calloc(1, sizeof(*file));
        if (!file) { result->result = -ENOMEM; return true; }
        description = fd_description_create_deferred(&io_tcp_ops, file, retirement);
        if (!description) { free(file); result->result = -ENOMEM; return true; }
        file->socket = net_tcp_socket_open_owned(interface);
        if (!file->socket)
        {
            fd_description_put(description);
            result->result = -ENOMEM;
        }
        else
        {
            result->result = 0;
            result->description_owned = description;
        }
        return true;
    }
    if (!io_tcp_description_valid(description))
    { result->result = -ENOTSOCK; return true; }
    io_tcp_file_t *file = fd_description_context(description);
    net_tcp_owned_status_t status;
    int error = net_tcp_socket_owned_snapshot(file->socket, &status);
    if (error) { result->result = error; return true; }
    switch (operation->opcode)
    {
        case IO_TCP_CONNECT:
            if (!operation->ipv4 || !operation->port || operation->port > 65535u || operation->count) return true;
            if (status.flags & NET_TCP_OWNED_ERROR) { result->result = -ECONNABORTED; return true; }
            if (status.flags & NET_TCP_OWNED_CONNECTED)
            { result->result = operation->started ? 0 : -EISCONN; return true; }
            if (!operation->started)
            {
                if (status.flags & NET_TCP_OWNED_CONNECTING) { result->result = -EALREADY; return true; }
                if (!net_tcp_socket_connect(file->socket, operation->ipv4, (uint16_t)operation->port))
                { result->result = -EHOSTUNREACH; return true; }
                operation->started = 1;
            }
            else if (!(status.flags & NET_TCP_OWNED_CONNECTING))
            { result->result = -ECONNABORTED; return true; }
            return false;
        case IO_TCP_READ:
        {
            if (operation->count > available) return true;
            if (!operation->count) { result->result = 0; return true; }
            bool expected = false;
            if (!__atomic_compare_exchange_n(&file->reader_owned, &expected, true, false,
                                              __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return false;
            /* Independent event services can share a description. Serialize
             * their reads without blocking either event worker. */
            error = net_tcp_socket_owned_snapshot(file->socket, &status);
            bool complete = true;
            if (error) result->result = error;
            else if (status.flags & NET_TCP_OWNED_READABLE)
            {
                size_t bytes = net_tcp_socket_read(file->socket, operation->data, (size_t)operation->count);
                if (bytes > operation->count) result->result = -EIO;
                else if (bytes) result->result = (int64_t)bytes;
                else complete = false;
            }
            else if (status.flags & NET_TCP_OWNED_ERROR) result->result = -ECONNRESET;
            else if (status.flags & NET_TCP_OWNED_EOF) result->result = 0;
            else if (!(status.flags & (NET_TCP_OWNED_CONNECTED | NET_TCP_OWNED_CONNECTING))) result->result = -ENOTCONN;
            else complete = false;
            __atomic_store_n(&file->reader_owned, false, __ATOMIC_RELEASE);
            return complete;
        }
        case IO_TCP_WRITE:
            if (operation->count > available) return true;
            if (!operation->count) { result->result = 0; return true; }
            if (status.flags & NET_TCP_OWNED_ERROR) { result->result = -ECONNRESET; return true; }
            if (status.flags & NET_TCP_OWNED_EOF) { result->result = -EPIPE; return true; }
            if (!(status.flags & NET_TCP_OWNED_CONNECTED)) { result->result = -ENOTCONN; return true; }
            if (!status.mss) { result->result = -EIO; return true; }
            size_t bytes = operation->count < status.mss ? (size_t)operation->count : status.mss;
            if (net_tcp_socket_send(file->socket, operation->data, bytes))
            { result->result = (int64_t)bytes; return true; }
            return false; /* Backpressure or a state transition: recheck next step. */
        case IO_TCP_AVAILABLE:
            if (operation->count) return true;
            result->result = status.available <= INT64_MAX ? (int64_t)status.available : -EOVERFLOW;
            return true;
        default: return true;
    }
}
