#include "process_internal.h"
#include "net/udp.h"
#include "net/dhcp.h"
#include "net/dns.h"
#include "net/ntp.h"
#include "errno.h"

typedef struct udp_boot_state udp_boot_state_t;
typedef struct
{
    udp_boot_state_t *state;
    process_t *process;
    net_udp_socket_t *socket;
    net_udp_socket_info_t socket_info;
    net_udp_packet_info_t packet;
    unsigned char *sent, *received;
    uint64_t next_arp, deadline;
    unsigned cpu, failure, completed, reply_tos;
} udp_boot_worker_t;
struct udp_boot_state
{
    udp_boot_worker_t workers[8];
    net_dns_result_t dns;
    net_udp_socket_t *temporary;
    unsigned ready, start, abort, mask;
    uint32_t source_ip;
    const char *failure;
};
static size_t udp_test_length(unsigned index)
{
    static const size_t sizes[] = {0, 1, 17, 1472, 511};
    return sizes[index % 5];
}
static void udp_boot_worker(void *argument)
{
    udp_boot_worker_t *worker = argument;
    udp_boot_state_t *state = worker->state;
    process_set_affinity(process_current(), worker->cpu);
    while (smp_current_cpu_index() != worker->cpu) process_yield();
    __atomic_add_fetch(&state->ready, 1u, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&state->start, __ATOMIC_ACQUIRE)) process_sleep_ms(1);
#define REQUIRE(c, code) do { if (!(c)) { worker->failure = code; goto finished; } } while (0)
    if (__atomic_load_n(&state->abort, __ATOMIC_ACQUIRE)) goto finished;
    REQUIRE(net_udp_socket_send_owned(worker->socket, worker->sent, 1473, 0, 0, -1, 0, &worker->next_arp) == -EMSGSIZE, 1);
    for (unsigned n = 0; n < 32; ++n)
    {
        size_t length = udp_test_length(n);
        for (size_t i = 0; i < length; ++i) worker->sent[i] = (unsigned char)(worker->cpu * 31u + n + i);
        REQUIRE(net_udp_socket_get_owned(worker->socket), 2);
        worker->deadline = timer_ticks() + (uint64_t)timer_frequency() * 5;
        ssize_t count;
        do {
            count = net_udp_socket_send_owned(worker->socket, worker->sent, length, 0, 0, -1, 0, &worker->next_arp);
            if (count == -EAGAIN) process_sleep_ms(1);
            REQUIRE(timer_ticks() < worker->deadline, 3);
        } while (count == -EAGAIN);
        REQUIRE(count == (ssize_t)length && !net_udp_socket_put_owned(worker->socket), 4);
        worker->deadline = timer_ticks() + (uint64_t)timer_frequency() * 5;
        do {
            count = net_udp_socket_recv_owned(worker->socket, worker->received, 7, true, &worker->packet);
            if (count == -EAGAIN) process_sleep_ms(1);
            REQUIRE(timer_ticks() < worker->deadline, 5);
        } while (count == -EAGAIN);
        REQUIRE(count == (ssize_t)(length < 7 ? length : 7) && worker->packet.length == length &&
                worker->packet.source_ip == 0x0a000202 && worker->packet.source_port == UDP_OWNED_TEST_PORT &&
                worker->packet.destination_ip == state->source_ip && worker->packet.interface_index > 0, 6);
        if (!n) worker->reply_tos = worker->packet.tos;
        for (size_t i = 0; i < (size_t)count; ++i) REQUIRE(worker->received[i] == worker->sent[i], 7);
        REQUIRE(!net_udp_socket_info_owned(worker->socket, &worker->socket_info) &&
                (worker->socket_info.flags & NET_UDP_READABLE) && worker->socket_info.available == length, 8);
        size_t capacity = n & 1 ? 7 : NET_UDP_MAX_PAYLOAD;
        count = net_udp_socket_recv_owned(worker->socket, worker->received, capacity, false, &worker->packet);
        REQUIRE(count == (ssize_t)(length < capacity ? length : capacity) && worker->packet.length == length, 9);
        for (size_t i = 0; i < (size_t)count; ++i) REQUIRE(worker->received[i] == worker->sent[i], 10);
        REQUIRE(net_udp_socket_recv_owned(worker->socket, worker->received, capacity, false, &worker->packet) == -EAGAIN, 11);
        ++worker->completed;
    }
    __atomic_fetch_or(&state->mask, 1u << smp_current_cpu_index(), __ATOMIC_RELEASE);
finished:
    if (worker->failure) serial_printf("UDP_CORE_WORKER: cpu=%u code=%u completed=%u", worker->cpu, worker->failure, worker->completed);
#undef REQUIRE
}

bool udp_owned_boot_test(void)
{
    udp_boot_state_t *state = calloc(1, sizeof(*state));
    if (!state) return false;
#define REQUIRE(c, message) do { if (!(c)) { state->failure = message; goto finished; } } while (0)
    REQUIRE(UDP_OWNED_TEST_PORT > 0 && UDP_OWNED_TEST_PORT < 65536 && UDP_OWNED_DNS_PORT > 0, "host ports");
    net_interface_t *iface = net_if_at(0);
    REQUIRE(iface && iface->present && iface->link_up, "native NIC");
    if (!__atomic_load_n(&iface->ipv4_addr, __ATOMIC_ACQUIRE) && !net_dhcp_in_progress())
        REQUIRE(net_dhcp_acquire(iface), "start DHCP");
    uint64_t deadline = timer_ticks() + (uint64_t)timer_frequency() * 10;
    while (!__atomic_load_n(&iface->ipv4_addr, __ATOMIC_ACQUIRE) && timer_ticks() < deadline) process_sleep_ms(1);
    state->source_ip = __atomic_load_n(&iface->ipv4_addr, __ATOMIC_ACQUIRE);
    REQUIRE(state->source_ip != 0, "DHCP address");
    for (unsigned i = 0; i < 8; ++i)
    {
        udp_boot_worker_t *worker = &state->workers[i];
        worker->state = state; worker->cpu = i;
        worker->sent = malloc(NET_UDP_MAX_PAYLOAD + 1); worker->received = malloc(NET_UDP_MAX_PAYLOAD);
        worker->socket = net_udp_socket_open_owned();
        REQUIRE(worker->sent && worker->received && worker->socket, "worker allocation");
        REQUIRE(!net_udp_socket_bind_owned(worker->socket, 0, 0) &&
                !net_udp_socket_connect_owned(worker->socket, 0x0a000202, UDP_OWNED_TEST_PORT), "bind/connect");
        REQUIRE(!net_udp_socket_option_owned(worker->socket, NET_UDP_TOS, (int)(i & 3)) &&
                !net_udp_socket_option_owned(worker->socket, NET_UDP_TTL, (int)(48 + i)), "TOS/TTL");
        REQUIRE(net_udp_socket_get_owned(worker->socket) && !net_udp_socket_put_owned(worker->socket), "retained second owner");
        REQUIRE(!net_udp_socket_info_owned(worker->socket, &worker->socket_info) && worker->socket_info.references == 1, "owner count");
        serial_printf("UDP_CORE_ENDPOINT: cpu=%u port=%u tos=%u ttl=%u", i,
                      (unsigned)worker->socket_info.local_port, worker->socket_info.tos, worker->socket_info.ttl);
        worker->process = process_create_kernel_service("udp-core-test", udp_boot_worker, worker, 0);
        REQUIRE(worker->process, "protected worker");
    }
    deadline = timer_ticks() + (uint64_t)timer_frequency() * 10;
    while (__atomic_load_n(&state->ready, __ATOMIC_ACQUIRE) != 8 && timer_ticks() < deadline) process_sleep_ms(1);
    REQUIRE(state->ready == 8, "all CPUs ready");
    /* The actual resolver must allocate around the live application ports. */
    REQUIRE(net_dns_resolve_at("udp-alix.test", NET_DNS_TYPE_A, NULL, 0x0a000202, UDP_OWNED_DNS_PORT, &state->dns) &&
            state->dns.addr == 0x0a000202, "DNS coexistence");
    net_ntp_clear_pending();
    REQUIRE(!net_ntp_set_pending(1, 2, state->workers[0].socket_info.local_port, 0x0a000202), "NTP cannot steal application port");
    state->temporary = net_udp_socket_open_owned();
    REQUIRE(state->temporary && net_ntp_set_pending(1, 2, 35555, 0x0a000202), "NTP port reservation");
    REQUIRE(net_udp_socket_bind_owned(state->temporary, 0, 35555) == -EADDRINUSE, "application cannot steal NTP port");
    net_ntp_clear_pending();
    REQUIRE(!net_udp_socket_bind_owned(state->temporary, 0, 35555), "NTP release");
    REQUIRE(!net_udp_socket_put_owned(state->temporary), "temporary close"); state->temporary = NULL;
    __atomic_store_n(&state->start, 1u, __ATOMIC_RELEASE);
finished:
    if (state->failure) { __atomic_store_n(&state->abort, 1u, __ATOMIC_RELEASE); __atomic_store_n(&state->start, 1u, __ATOMIC_RELEASE); }
    for (unsigned i = 0; i < 8; ++i)
    {
        udp_boot_worker_t *worker = &state->workers[i];
        if (worker->process) { if (process_join_kernel_service(worker->process, NULL)) return false; worker->process = NULL; }
        if (!state->failure && (worker->failure || worker->completed != 32)) state->failure = "worker transport";
        if (!worker->failure && worker->completed == 32)
            serial_printf("UDP_CORE_RECEIVE_META: cpu=%u tos=%u", i, worker->reply_tos);
        if (worker->socket) { if (net_udp_socket_put_owned(worker->socket)) state->failure = "final close"; worker->socket = NULL; }
        free(worker->sent); free(worker->received);
    }
    net_ntp_clear_pending();
    if (state->temporary) (void)net_udp_socket_put_owned(state->temporary);
    bool success = !state->failure && state->mask == 255;
    if (success) serial_printf("UDP_CORE_TEST: PASS cpus=8 mask=0xFF datagrams=256 zero=1 max_mtu=1 peek=1 truncation=1 ownership=1 ecn=1 dns=1 ntp=1 cleanup=1");
    else serial_printf("UDP_CORE_TEST: FAIL %s mask=%u", state->failure ? state->failure : "CPU coverage", state->mask);
    free(state);
    return success;
#undef REQUIRE
}
