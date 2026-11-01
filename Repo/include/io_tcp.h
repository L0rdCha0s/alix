#ifndef IO_TCP_H
#define IO_TCP_H

#include "io_event_service.h"

typedef enum
{
    IO_TCP_OPEN,
    IO_TCP_CONNECT,
    IO_TCP_READ,
    IO_TCP_WRITE,
    IO_TCP_AVAILABLE,
    IO_TCP_GETOPT,
    IO_TCP_SETOPT,
    IO_TCP_GETNAME
} io_tcp_opcode_t;

/* Internal heap operation, not a userspace ABI. CONNECT uses a numeric IPv4
 * destination; DNS/storage waits do not belong on the event worker. 'started'
 * is worker-owned continuation state and must be zero on new requests. OPEN
 * flags select NONBLOCK before publication; READ/WRITE flags are per-call
 * message options. Padding and reserved fields must remain zero. */
typedef struct
{
    uint32_t opcode, interface_index, ipv4, port;
    uint32_t started, reserved;
    uint64_t count;
    uint32_t flags;
    uint32_t padding;
    unsigned char data[];
} io_tcp_operation_t;
typedef struct
{
    uint32_t length;
    int32_t value;
    syscall_sockaddr_in_t address;
} io_tcp_query_reply_t;

/* Consumes one owned socket-description reference on every return. Caller
 * protects construction and publishes the returned lease in a registered
 * request before dropping that guard. The lease cancels an abandoned SO_ERROR
 * claim on the persistent retirement worker. Commit only after valid copyout. */
int io_tcp_query_create(fd_description_t *socket_owned, fd_retirement_queue_t *retirement,
                         fd_description_t **output);
int io_tcp_query_commit(fd_description_t *query);

/* Nonblocking event step. Returns false only for pending connection/read/write
 * readiness; all retained state lives in the request/description. OPEN returns
 * a deferred description in retirement. All inputs use the owned socket mode,
 * never a legacy global FD number or borrowed creating process/thread. */
bool io_tcp_execute(io_request_t *request, io_service_result_t *result,
                      fd_retirement_queue_t *retirement);
/* Caller holds a description reference; immutable backend identity only. */
bool io_tcp_description_valid(const fd_description_t *description);

#endif
