#include "io_udp.h"
#include "heap.h"
#include "errno.h"
#include "timer.h"
#include "netinet/in.h"

typedef struct { net_udp_socket_t *socket; } io_udp_file_t;
static int io_udp_close(void *context)
{
    io_udp_file_t *file = context;
    int result = file ? net_udp_socket_put_owned(file->socket) : 0;
    free(file);
    return result;
}
static uint32_t io_udp_poll(void *context)
{
    io_udp_file_t *file = context;
    net_udp_socket_info_t info;
    if (net_udp_socket_info_owned(file->socket, &info)) return SYSCALL_POLL_ERR;
    return ((info.flags & NET_UDP_READABLE) ? SYSCALL_POLL_IN : 0) |
           ((info.flags & NET_UDP_WRITABLE) ? SYSCALL_POLL_OUT : 0);
}
static int io_udp_stat(void *context, syscall_stat_t *out)
{
    (void)context;
    if (!out) return -EINVAL;
    *out = (syscall_stat_t){ .type = SYSCALL_NODE_TYPE_SOCKET };
    return 0;
}
static const fd_ops_t io_udp_ops = { .close = io_udp_close, .poll = io_udp_poll, .fstat = io_udp_stat };
bool io_udp_description_valid(const fd_description_t *description)
{ return description && fd_description_ops(description)->close == io_udp_close; }
io_udp_state_t *io_udp_state(io_request_t *request)
{
    size_t size = io_request_buffer_size(request);
    return size < sizeof(io_tcp_operation_t) + sizeof(io_udp_state_t) ? NULL :
        (void *)((unsigned char *)io_request_buffer(request) + size - sizeof(io_udp_state_t));
}
bool io_udp_request_valid(io_request_t *request)
{
    if (!request || !io_udp_state(request)) return false;
    io_tcp_operation_t *work = io_request_buffer(request);
    return work->opcode == IO_UDP_OPEN || io_udp_description_valid(io_request_description(request));
}
static int io_udp_option(io_udp_file_t *file, io_tcp_operation_t *work, io_tcp_query_reply_t *reply,
                          net_udp_socket_info_t *info)
{
    bool set = work->opcode == IO_TCP_SETOPT;
    if (work->ipv4 == SYSCALL_SOL_SOCKET)
    {
        switch (work->port)
        {
            case SYSCALL_SO_RCVBUF:
                if (set) return net_udp_socket_option_owned(file->socket, NET_UDP_RECV_BUFFER, reply->value);
                reply->value = (int32_t)info->receive_capacity; return 0;
            case SYSCALL_SO_SNDBUF:
                if (set) return net_udp_socket_option_owned(file->socket, NET_UDP_SEND_BUFFER, reply->value);
                reply->value = (int32_t)info->send_capacity; return 0;
            case SYSCALL_SO_KEEPALIVE: case SYSCALL_SO_REUSEADDR:
                if (set) return reply->value ? -EOPNOTSUPP : 0;
                reply->value = 0; return 0;
            case SYSCALL_SO_TYPE: if (!set) { reply->value = 2; return 0; } break;
            case SYSCALL_SO_DOMAIN: if (!set) { reply->value = SYSCALL_AF_INET; return 0; } break;
            case SYSCALL_SO_PROTOCOL: if (!set) { reply->value = 17; return 0; } break;
            case SYSCALL_SO_ERROR: case SYSCALL_SO_ACCEPTCONN:
                if (!set) { reply->value = 0; return 0; } break;
        }
    }
    else if (work->ipv4 == IPPROTO_IP && (work->port == IP_TOS || work->port == IP_TTL))
    {
        if (set) return net_udp_socket_option_owned(file->socket,
            work->port == IP_TOS ? NET_UDP_TOS : NET_UDP_TTL, reply->value);
        reply->value = (int32_t)(work->port == IP_TOS ? info->tos : info->ttl); return 0;
    }
    return -ENOPROTOOPT;
}
bool io_udp_execute(io_request_t *request, io_service_result_t *result, fd_retirement_queue_t *retirement)
{
    result->result = -EINVAL; result->description_owned = NULL;
    io_udp_state_t *state = io_udp_state(request);
    if (!state) return true;
    io_tcp_operation_t *work = io_request_buffer(request);
    size_t available = io_request_buffer_size(request) - sizeof(*work) - sizeof(*state);
    fd_description_t *description = io_request_description(request);
    if (work->opcode == IO_UDP_OPEN)
    {
        if (!retirement || !fd_table_reservation_valid(description) || work->flags & ~SYSCALL_OPEN_NONBLOCK) return true;
        io_udp_file_t *file = calloc(1, sizeof(*file));
        if (!file) { result->result = -ENOMEM; return true; }
        file->socket = net_udp_socket_open_owned();
        if (!file->socket) { free(file); result->result = -ENOBUFS; return true; }
        description = fd_description_create_deferred(&io_udp_ops, file, retirement);
        if (!description) { (void)io_udp_close(file); result->result = -ENOMEM; return true; }
        (void)fd_description_initialize_status(description, FD_STATUS_READ | FD_STATUS_WRITE | work->flags);
        result->description_owned = description; result->result = 0; return true;
    }
    if (!io_udp_description_valid(description)) { result->result = -ENOTSOCK; return true; }
    io_udp_file_t *file = fd_description_context(description);
    int error = net_udp_socket_info_owned(file->socket, &state->info);
    if (error) { result->result = error; return true; }
    bool nonblock = (fd_description_status_flags(description) & FD_STATUS_NONBLOCK) || (work->flags & SYSCALL_MSG_DONTWAIT);
    switch (work->opcode)
    {
        case IO_UDP_BIND:
            if (work->port && work->port < 1024 && io_request_uid(request) != 0) result->result = -EACCES;
            else result->result = net_udp_socket_bind_owned(file->socket, work->ipv4, (uint16_t)work->port);
            return true;
        case IO_TCP_CONNECT:
            result->result = net_udp_socket_connect_owned(file->socket, work->ipv4, (uint16_t)work->port); return true;
        case IO_TCP_READ:
            if (work->count > available || work->flags & ~(SYSCALL_MSG_PEEK | SYSCALL_MSG_DONTWAIT | 0x20u)) return true;
            result->result = net_udp_socket_recv_owned(file->socket, work->data, (size_t)work->count,
                (work->flags & SYSCALL_MSG_PEEK) != 0, &state->packet);
            return result->result != -EAGAIN || nonblock;
        case IO_TCP_WRITE:
            if (work->count > available || work->count > NET_UDP_MAX_PAYLOAD ||
                work->flags & ~(SYSCALL_MSG_DONTWAIT | SYSCALL_MSG_NOSIGNAL) || work->padding > 256) return true;
            result->result = net_udp_socket_send_owned(file->socket, work->data, (size_t)work->count,
                work->ipv4, (uint16_t)work->port, work->padding ? (int)work->padding - 1 : -1,
                work->interface_index, &state->next_arp_ms);
            if (result->result != -EAGAIN || nonblock) return true;
            if (!state->deadline_ms) state->deadline_ms = timer_monotonic_millis() + 5000;
            if (timer_monotonic_millis() >= state->deadline_ms) { result->result = -ETIMEDOUT; return true; }
            return false;
        case IO_TCP_AVAILABLE: result->result = state->info.available; return true;
        case IO_TCP_GETNAME: case IO_TCP_GETOPT: case IO_TCP_SETOPT:
        {
            if (available < sizeof(io_tcp_query_reply_t)) return true;
            io_tcp_query_reply_t *reply = (void *)work->data;
            if (work->opcode == IO_TCP_GETNAME)
            {
                bool peer = work->interface_index != 0;
                if (peer && !(state->info.flags & NET_UDP_CONNECTED)) { result->result = -ENOTCONN; return true; }
                reply->address = (syscall_sockaddr_in_t){ .family = SYSCALL_AF_INET,
                    .address_be = __builtin_bswap32(peer ? state->info.remote_ip : state->info.local_ip),
                    .port_be = __builtin_bswap16(peer ? state->info.remote_port : state->info.local_port) };
                reply->length = sizeof(reply->address); result->result = 0;
            }
            else { reply->length = sizeof(reply->value); result->result = io_udp_option(file, work, reply, &state->info); }
            return true;
        }
        default: return true;
    }
}
