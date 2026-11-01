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
static uint32_t io_tcp_poll(void *context)
{
    io_tcp_file_t *file = context;
    net_tcp_owned_status_t status;
    if (net_tcp_socket_owned_snapshot(file->socket, &status)) return SYSCALL_POLL_ERR;
    uint32_t flags = 0;
    if (status.flags & NET_TCP_OWNED_READABLE) flags |= SYSCALL_POLL_IN;
    if (status.flags & NET_TCP_OWNED_WRITABLE) flags |= SYSCALL_POLL_OUT;
    if (status.flags & NET_TCP_OWNED_EOF) flags |= SYSCALL_POLL_IN | SYSCALL_POLL_HUP;
    if (status.flags & NET_TCP_OWNED_ERROR) flags |= SYSCALL_POLL_ERR | SYSCALL_POLL_HUP;
    return flags;
}
static int io_tcp_stat(void *context, syscall_stat_t *out)
{
    (void)context;
    if (!out) return -EINVAL;
    *out = (syscall_stat_t){ .type = SYSCALL_NODE_TYPE_SOCKET };
    return 0;
}
static const fd_ops_t io_tcp_ops = { .close = io_tcp_file_close, .fstat = io_tcp_stat, .poll = io_tcp_poll };

bool io_tcp_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_tcp_file_close;
}

typedef struct
{
    fd_description_t *owner;
    uint64_t error_generation;
} io_tcp_query_t;

static int io_tcp_query_finish(io_tcp_query_t *query, bool commit)
{
    uint64_t generation = __atomic_exchange_n(&query->error_generation, 0, __ATOMIC_ACQ_REL);
    if (!generation) return 0;
    io_tcp_file_t *file = fd_description_context(query->owner);
    return net_tcp_socket_error_finish_owned(file->socket, generation, commit);
}

static int io_tcp_query_close(void *context)
{
    io_tcp_query_t *query = context;
    int result = io_tcp_query_finish(query, false);
    fd_description_put(query->owner);
    free(query);
    return result;
}
static const fd_ops_t io_tcp_query_ops = { .close = io_tcp_query_close };

int io_tcp_query_create(fd_description_t *socket_owned, fd_retirement_queue_t *retirement,
                         fd_description_t **output)
{
    if (output) *output = NULL;
    if (!output || !retirement || !io_tcp_description_valid(socket_owned))
    { fd_description_put(socket_owned); return !output || !retirement ? -EINVAL : -ENOTSOCK; }
    io_tcp_query_t *query = calloc(1, sizeof(*query));
    if (!query) { fd_description_put(socket_owned); return -ENOMEM; }
    query->owner = socket_owned;
    fd_description_t *description = fd_description_create_deferred(&io_tcp_query_ops, query, retirement);
    if (!description) { fd_description_put(socket_owned); free(query); return -ENOMEM; }
    *output = description;
    return 0;
}

int io_tcp_query_commit(fd_description_t *description)
{
    if (!description || fd_description_ops(description)->close != io_tcp_query_close) return -EINVAL;
    return io_tcp_query_finish(fd_description_context(description), true);
}

static bool io_tcp_query_execute(io_request_t *request, io_service_result_t *result,
                                  io_tcp_query_t *query, io_tcp_file_t *file)
{
    io_tcp_operation_t *operation = io_request_buffer(request);
    size_t available = io_request_buffer_size(request) - sizeof(*operation);
    if (available != sizeof(io_tcp_query_reply_t) || operation->flags || operation->count || operation->started) return true;
    io_tcp_query_reply_t *reply = (void *)operation->data;
    net_tcp_owned_info_t info;
    result->result = net_tcp_socket_info_owned(file->socket, &info);
    if (result->result) return true;
    if (operation->opcode == IO_TCP_GETNAME)
    {
        if (operation->interface_index > 1) { result->result = -EINVAL; return true; }
        if (operation->interface_index && !(info.flags & NET_TCP_OWNED_CONNECTED))
        { result->result = -ENOTCONN; return true; }
        bool peer = operation->interface_index != 0;
        reply->address = (syscall_sockaddr_in_t){ .family = SYSCALL_AF_INET,
            .port_be = __builtin_bswap16(peer ? info.remote_port : info.local_port),
            .address_be = __builtin_bswap32(peer ? info.remote_ip : info.local_ip) };
        reply->length = sizeof(reply->address);
        return true;
    }
    if (operation->opcode == IO_TCP_SETOPT)
    {
        if (operation->ipv4 == SYSCALL_IPPROTO_TCP && operation->port == SYSCALL_TCP_NODELAY)
            result->result = reply->value ? 0 : -EOPNOTSUPP;
        else if (operation->ipv4 == SYSCALL_SOL_SOCKET &&
                 (operation->port == SYSCALL_SO_KEEPALIVE || operation->port == SYSCALL_SO_REUSEADDR))
            result->result = !reply->value ? 0 : -EOPNOTSUPP;
        else result->result = -ENOPROTOOPT;
        return true;
    }
    if (operation->opcode != IO_TCP_GETOPT) { result->result = -EINVAL; return true; }
    reply->length = sizeof(reply->value);
    if (operation->ipv4 == SYSCALL_SOL_SOCKET)
    {
        switch (operation->port)
        {
            case SYSCALL_SO_TYPE: reply->value = SYSCALL_SOCK_STREAM; break;
            case SYSCALL_SO_DOMAIN: reply->value = SYSCALL_AF_INET; break;
            case SYSCALL_SO_PROTOCOL: reply->value = SYSCALL_IPPROTO_TCP; break;
            case SYSCALL_SO_REUSEADDR: case SYSCALL_SO_KEEPALIVE: case SYSCALL_SO_ACCEPTCONN:
                reply->value = 0; break;
            case SYSCALL_SO_ERROR:
            {
                uint64_t generation = 0;
                result->result = net_tcp_socket_error_claim_owned(file->socket, &reply->value, &generation);
                if (result->result == -EAGAIN) return false;
                if (!result->result) __atomic_store_n(&query->error_generation, generation, __ATOMIC_RELEASE);
                return true;
            }
            case SYSCALL_SO_RCVBUF: case SYSCALL_SO_SNDBUF:
            {
                uint64_t size = operation->port == SYSCALL_SO_RCVBUF ? info.receive_buffer : info.send_buffer;
                if (size > INT32_MAX) result->result = -EOVERFLOW;
                else reply->value = (int32_t)size;
                break;
            }
            default: result->result = -ENOPROTOOPT; break;
        }
    }
    else if (operation->ipv4 == SYSCALL_IPPROTO_TCP)
    {
        if (operation->port == SYSCALL_TCP_NODELAY) reply->value = 1; /* No Nagle queue in this transport. */
        else if (operation->port == SYSCALL_TCP_MAXSEG) reply->value = (int32_t)info.mss;
        else result->result = -ENOPROTOOPT;
    }
    else result->result = -ENOPROTOOPT;
    return true;
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
    if (!operation || operation->reserved || operation->padding || operation->started > 1) return true;
    fd_description_t *description = io_request_description(request);
    if (operation->opcode == IO_TCP_OPEN)
    {
        if (!retirement || (description && !fd_table_reservation_valid(description)) || operation->started || operation->count ||
            operation->interface_index >= NET_MAX_INTERFACES ||
            (operation->flags & ~SYSCALL_OPEN_NONBLOCK)) return true;
        net_interface_t *interface = net_if_at(operation->interface_index);
        if (!interface || !interface->present) { result->result = -ENODEV; return true; }
        io_tcp_file_t *file = calloc(1, sizeof(*file));
        if (!file) { result->result = -ENOMEM; return true; }
        description = fd_description_create_deferred(&io_tcp_ops, file, retirement);
        if (!description) { free(file); result->result = -ENOMEM; return true; }
        (void)fd_description_initialize_status(description, FD_STATUS_READ | FD_STATUS_WRITE | operation->flags);
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
    if (description && fd_description_ops(description)->close == io_tcp_query_close)
    {
        io_tcp_query_t *query = fd_description_context(description);
        return io_tcp_query_execute(request, result, query, fd_description_context(query->owner));
    }
    if (!io_tcp_description_valid(description))
    { result->result = -ENOTSOCK; return true; }
    io_tcp_file_t *file = fd_description_context(description);
    uint32_t known_flags = SYSCALL_MSG_DONTWAIT;
    if (operation->opcode == IO_TCP_READ) known_flags |= SYSCALL_MSG_PEEK;
    else if (operation->opcode == IO_TCP_WRITE) known_flags |= SYSCALL_MSG_NOSIGNAL;
    else known_flags = 0;
    if (operation->flags & ~known_flags) { result->result = -EOPNOTSUPP; return true; }
    bool nonblocking = (fd_description_status_flags(description) & FD_STATUS_NONBLOCK) != 0 ||
                       (operation->flags & SYSCALL_MSG_DONTWAIT) != 0;
    net_tcp_owned_status_t status;
    int error = net_tcp_socket_owned_snapshot(file->socket, &status);
    if (error) { result->result = error; return true; }
    switch (operation->opcode)
    {
        case IO_TCP_CONNECT:
            if (!operation->ipv4 || !operation->port || operation->port > 65535u || operation->count) return true;
            if (status.flags & NET_TCP_OWNED_ERROR)
            { result->result = status.error_code ? -status.error_code : -ECONNABORTED; return true; }
            if (status.flags & NET_TCP_OWNED_CONNECTED)
            { result->result = operation->started ? 0 : -EISCONN; return true; }
            if (!operation->started)
            {
                if (status.flags & NET_TCP_OWNED_CONNECTING) { result->result = -EALREADY; return true; }
                if (!net_tcp_socket_connect(file->socket, operation->ipv4, (uint16_t)operation->port))
                {
                    error = net_tcp_socket_owned_snapshot(file->socket, &status);
                    result->result = !error && status.error_code ? -status.error_code : -EHOSTUNREACH;
                    return true;
                }
                operation->started = 1;
                if (nonblocking) { result->result = -EINPROGRESS; return true; }
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
                                              __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            { result->result = -EAGAIN; return nonblocking; }
            /* Independent event services can share a description. Serialize
             * their reads without blocking either event worker. */
            error = net_tcp_socket_owned_snapshot(file->socket, &status);
            bool complete = true;
            if (error) result->result = error;
            else if (status.flags & NET_TCP_OWNED_READABLE)
            {
                ssize_t bytes = operation->flags & SYSCALL_MSG_PEEK ?
                    net_tcp_socket_peek_owned(file->socket, operation->data, (size_t)operation->count) :
                    (ssize_t)net_tcp_socket_read(file->socket, operation->data, (size_t)operation->count);
                if (bytes < 0) result->result = bytes;
                else if ((size_t)bytes > operation->count) result->result = -EIO;
                else if (bytes) result->result = (int64_t)bytes;
                else complete = false;
            }
            else if (status.flags & NET_TCP_OWNED_ERROR) result->result = -ECONNRESET;
            else if (status.flags & NET_TCP_OWNED_EOF) result->result = 0;
            else if (!(status.flags & (NET_TCP_OWNED_CONNECTED | NET_TCP_OWNED_CONNECTING))) result->result = -ENOTCONN;
            else complete = false;
            __atomic_store_n(&file->reader_owned, false, __ATOMIC_RELEASE);
            if (!complete && nonblocking) { result->result = -EAGAIN; complete = true; }
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
            if (nonblocking) { result->result = -EAGAIN; return true; }
            return false; /* Backpressure or a state transition: recheck next step. */
        case IO_TCP_AVAILABLE:
            if (operation->count) return true;
            result->result = status.available <= INT64_MAX ? (int64_t)status.available : -EOVERFLOW;
            return true;
        default: return true;
    }
}
