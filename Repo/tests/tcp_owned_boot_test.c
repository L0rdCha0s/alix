#include "process_internal.h"
#include "net/tcp.h"
#include "net/dhcp.h"
#include "errno.h"

#define TCP_OWNED_WORKERS 8u
extern bool io_event_tcp_boot_test(void);
typedef struct tcp_owned_boot_state tcp_owned_boot_state_t;
typedef struct
{
    tcp_owned_boot_state_t *state;
    process_t *process;
    net_tcp_socket_t *socket;
    net_tcp_owned_status_t status;
    unsigned cpu, failure;
} tcp_owned_worker_t;
struct tcp_owned_boot_state
{
    tcp_owned_worker_t workers[TCP_OWNED_WORKERS];
    net_tcp_socket_t *socket, *other, *fresh;
    net_tcp_owned_status_t status;
    unsigned char *response;
    size_t response_bytes;
    uint32_t ready, start, abort, completed, mask;
    bool extra_owner;
    const char *failure;
};

static void tcp_owned_worker_entry(void *argument)
{
    tcp_owned_worker_t *worker = argument;
    tcp_owned_boot_state_t *state = worker->state;
    process_set_affinity(process_current(), worker->cpu);
    while (smp_current_cpu_index() != worker->cpu) process_yield();
    __atomic_add_fetch(&state->ready, 1u, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&state->start, __ATOMIC_ACQUIRE)) process_sleep_ms(1);
    if (!__atomic_load_n(&state->abort, __ATOMIC_ACQUIRE))
    {
        for (unsigned index = 0; index < 1024; ++index)
        {
            if (!net_tcp_socket_get_owned(worker->socket)) { worker->failure = 1; break; }
            if (net_tcp_socket_owned_snapshot(worker->socket, &worker->status) || worker->status.references < 2)
                worker->failure = 2;
            if (net_tcp_socket_put_owned(worker->socket)) worker->failure = 3;
            if (worker->failure) break;
        }
        __atomic_fetch_or(&state->mask, 1u << smp_current_cpu_index(), __ATOMIC_RELEASE);
    }
    if (net_tcp_socket_put_owned(worker->socket)) worker->failure = 4;
    worker->socket = NULL;
    __atomic_add_fetch(&state->completed, 1u, __ATOMIC_RELEASE);
}

bool tcp_owned_boot_test(void)
{
    tcp_owned_boot_state_t *state = calloc(1, sizeof(*state));
    if (!state) { serial_printf("TCP_OWNED_TEST: FAIL controller allocation"); return false; }
#define REQUIRE(test,label) do { if (!(test)) { state->failure = (label); goto failed; } } while (0)
    serial_printf("TCP_OWNED_TEST: start owned socket lifetime");
    state->socket = net_tcp_socket_open_owned(NULL);
    REQUIRE(state->socket && net_tcp_socket_fd(state->socket) == -1, "no global descriptor");
    REQUIRE(net_tcp_socket_get_owned(state->socket), "second owner");
    state->extra_owner = true;
    net_tcp_socket_release(state->socket); /* Legacy release cannot recycle it. */
    REQUIRE(!net_tcp_socket_owned_snapshot(state->socket, &state->status) && state->status.references == 2,
            "legacy reset excluded");
    net_tcp_socket_close(state->socket);
    REQUIRE(!net_tcp_socket_owned_snapshot(state->socket, &state->status) &&
            state->status.references == 2 && (state->status.flags & NET_TCP_OWNED_EOF), "close retains owner");
    state->other = net_tcp_socket_open_owned(NULL);
    REQUIRE(state->other && state->other != state->socket, "live slot cannot be reused");
    REQUIRE(!net_tcp_socket_put_owned(state->other), "other final release"); state->other = NULL;
    REQUIRE(!net_tcp_socket_put_owned(state->socket), "drop second owner");
    state->extra_owner = false;
    for (unsigned index = 0; index < TCP_OWNED_WORKERS; ++index)
    {
        tcp_owned_worker_t *worker = &state->workers[index];
        worker->state = state; worker->cpu = index;
        REQUIRE(net_tcp_socket_get_owned(state->socket), "register worker socket owner");
        worker->socket = state->socket;
        worker->process = process_create_kernel_service("tcp-owned-test", tcp_owned_worker_entry, worker, 0);
        if (!worker->process)
        {
            net_tcp_socket_put_owned(worker->socket); worker->socket = NULL;
            state->failure = "create protected worker"; goto failed;
        }
    }
    uint64_t deadline = timer_ticks() + (uint64_t)timer_frequency() * 10u;
    while (__atomic_load_n(&state->ready, __ATOMIC_ACQUIRE) != TCP_OWNED_WORKERS && timer_ticks() < deadline)
        process_sleep_ms(1);
    REQUIRE(__atomic_load_n(&state->ready, __ATOMIC_ACQUIRE) == TCP_OWNED_WORKERS, "all CPUs ready");
    __atomic_store_n(&state->start, 1u, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < TCP_OWNED_WORKERS; ++index)
    {
        tcp_owned_worker_t *worker = &state->workers[index];
        REQUIRE(process_join_kernel_service(worker->process, NULL) == 0, "join protected worker"); worker->process = NULL;
        REQUIRE(!worker->failure, "worker references");
    }
    REQUIRE(state->mask == 0xff && state->completed == TCP_OWNED_WORKERS, "eight CPU coverage");
    REQUIRE(!net_tcp_socket_owned_snapshot(state->socket, &state->status) && state->status.references == 1,
            "only controller owner remains");
    net_tcp_socket_t *old = state->socket;
    REQUIRE(!net_tcp_socket_put_owned(state->socket), "final controller release"); state->socket = NULL;
    REQUIRE(!net_tcp_socket_get_owned(old) && net_tcp_socket_put_owned(old) == -EBADF, "cannot resurrect retired slot");
    state->fresh = net_tcp_socket_open_owned(NULL);
    REQUIRE(state->fresh == old, "slot reusable after final owner");
    REQUIRE(!net_tcp_socket_put_owned(state->fresh), "fresh final release"); state->fresh = NULL;
    REQUIRE(!net_tcp_socket_get_owned((void *)1) && net_tcp_socket_put_owned((void *)1) == -EINVAL, "invalid owner rejected");
    /* Real transport through the owned constructor: keep the second owner
     * after dropping the original, then receive the complete HTTP body. */
    REQUIRE(TCP_OWNED_TEST_PORT > 0 && TCP_OWNED_TEST_PORT < 65536, "configured host test port");
    net_interface_t *iface = net_if_at(0);
    REQUIRE(iface && iface->present && iface->link_up, "native NIC ready");
    if (!__atomic_load_n(&iface->ipv4_addr, __ATOMIC_ACQUIRE) && !net_dhcp_in_progress())
        REQUIRE(net_dhcp_acquire(iface), "start native DHCP discovery");
    deadline = timer_ticks() + (uint64_t)timer_frequency() * 10u;
    while (!__atomic_load_n(&iface->ipv4_addr, __ATOMIC_ACQUIRE) && timer_ticks() < deadline)
        process_sleep_ms(1);
    REQUIRE(__atomic_load_n(&iface->ipv4_addr, __ATOMIC_ACQUIRE), "native DHCP address assigned");
    state->response = malloc(65536);
    REQUIRE(state->response, "heap HTTP response");
    state->socket = net_tcp_socket_open_owned(iface);
    REQUIRE(state->socket && net_tcp_socket_get_owned(state->socket), "HTTP second owner");
    state->extra_owner = true;
    REQUIRE(net_tcp_socket_connect(state->socket, UINT32_C(0x0a000202), TCP_OWNED_TEST_PORT), "owned TCP connect");
    REQUIRE(!net_tcp_socket_put_owned(state->socket), "HTTP original owner released");
    state->extra_owner = false;
    deadline = timer_ticks() + (uint64_t)timer_frequency() * 10u;
    for (;;)
    {
        REQUIRE(!net_tcp_socket_owned_snapshot(state->socket, &state->status), "owned connect snapshot");
        REQUIRE(!(state->status.flags & NET_TCP_OWNED_ERROR), "owned connect error");
        if (state->status.flags & NET_TCP_OWNED_WRITABLE) break;
        REQUIRE(timer_ticks() < deadline, "owned connect deadline");
        process_sleep_ms(1);
    }
    static const unsigned char request[] = "GET /owned HTTP/1.0\r\nHost: alix-test\r\nConnection: close\r\n\r\n";
    REQUIRE(net_tcp_socket_send(state->socket, request, sizeof(request) - 1u), "owned HTTP send");
    for (;;)
    {
        REQUIRE(!net_tcp_socket_owned_snapshot(state->socket, &state->status), "owned receive snapshot");
        REQUIRE(!(state->status.flags & NET_TCP_OWNED_ERROR), "owned receive error");
        if (state->status.flags & NET_TCP_OWNED_READABLE)
        {
            REQUIRE(state->response_bytes < 65535u, "bounded owned response");
            state->response_bytes += net_tcp_socket_read(state->socket, state->response + state->response_bytes,
                                                         65535u - state->response_bytes);
        }
        else if (state->status.flags & NET_TCP_OWNED_EOF) break;
        REQUIRE(timer_ticks() < deadline, "owned receive deadline");
        process_sleep_ms(1);
    }
    state->response[state->response_bytes] = 0;
    REQUIRE(state->response_bytes >= 12u && !memcmp(state->response, "HTTP/1.0 200", 12), "owned HTTP status");
    unsigned char *body = (unsigned char *)strstr((char *)state->response, "\r\n\r\n");
    REQUIRE(body, "owned HTTP headers"); body += 4;
    REQUIRE(state->response_bytes - (size_t)(body - state->response) == 16384u, "complete owned HTTP payload");
    for (unsigned index = 0; index < 16384u; ++index)
        REQUIRE(body[index] == (unsigned char)(index * 73u + 19u), "owned HTTP payload bytes");
    /* Let tcp_timerd observe a drained peer FIN before application close. It
     * must preserve CLOSE_WAIT so the local FIN is still sent. */
    process_sleep_ms(50);
    net_tcp_socket_close(state->socket);
    REQUIRE(!net_tcp_socket_put_owned(state->socket), "HTTP final owner released"); state->socket = NULL;
    process_sleep_ms(50);
    free(state->response);
    free(state);
    if (!io_event_tcp_boot_test()) return false;
    serial_printf("TCP_OWNED_TEST: PASS workers=8 mask=0xFF refs=8192 no_global_fd=1 reuse_after_final=1 HTTP=16384");
    return true;
failed:
    __atomic_store_n(&state->abort, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&state->start, 1u, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < TCP_OWNED_WORKERS; ++index)
        if (state->workers[index].process) (void)process_join_kernel_service(state->workers[index].process, NULL);
    if (state->other) net_tcp_socket_put_owned(state->other);
    if (state->fresh) net_tcp_socket_put_owned(state->fresh);
    if (state->extra_owner) net_tcp_socket_put_owned(state->socket);
    if (state->socket) net_tcp_socket_put_owned(state->socket);
    free(state->response);
    serial_printf("TCP_OWNED_TEST: FAIL %s", state->failure ? state->failure : "unknown");
    free(state);
    return false;
#undef REQUIRE
}
