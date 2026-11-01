#ifndef IO_TCP_H
#define IO_TCP_H

#include "io_event_service.h"

typedef enum
{
    IO_TCP_OPEN,
    IO_TCP_CONNECT,
    IO_TCP_READ,
    IO_TCP_WRITE,
    IO_TCP_AVAILABLE
} io_tcp_opcode_t;

/* Internal heap operation, not a userspace ABI. CONNECT uses a numeric IPv4
 * destination; DNS/storage waits do not belong on the event worker. 'started'
 * is worker-owned continuation state and must be zero on new requests. */
typedef struct
{
    uint32_t opcode, interface_index, ipv4, port;
    uint32_t started, reserved;
    uint64_t count;
    unsigned char data[];
} io_tcp_operation_t;

/* Nonblocking event step. Returns false only for pending connection/read/write
 * readiness; all retained state lives in the request/description. OPEN returns
 * a deferred description in retirement. All inputs use the owned socket mode,
 * never a legacy global FD number or borrowed creating process/thread. */
bool io_tcp_execute(io_request_t *request, io_service_result_t *result,
                      fd_retirement_queue_t *retirement);
/* Caller holds a description reference; immutable backend identity only. */
bool io_tcp_description_valid(const fd_description_t *description);

#endif
