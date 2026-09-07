#!/usr/bin/env python3
"""Exercise actual TCP receive and deferred IGB IRQ code in host harnesses."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def definition(source, signature):
    start = source.find(signature)
    while start >= 0:
        opening = source.find("{", start + len(signature))
        semicolon = source.find(";", start + len(signature))
        if opening >= 0 and (semicolon < 0 or opening < semicolon):
            break
        start = source.find(signature, start + len(signature))
    if start < 0:
        raise AssertionError(f"missing definition: {signature}")
    depth = 0
    for end in range(opening, len(source)):
        depth += source[end] == "{"
        depth -= source[end] == "}"
        if not depth:
            return source[start:end + 1]
    raise AssertionError(f"unclosed definition: {signature}")


def run(name, program):
    with tempfile.TemporaryDirectory(prefix="alix-net-receive-") as directory:
        binary = Path(directory) / name
        subprocess.run([*shlex.split(os.environ.get("HOST_CC", "cc")),
                        "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                        "-x", "c", "-", "-o", str(binary)],
                       input=program, text=True, check=True)
        subprocess.run([str(binary)], check=True)


def test_tcp():
    source = (ROOT / "src/net/tcp.c").read_text()
    types = source[source.index("#define TCP_FLAG_FIN"):
                   source.index("static void tcp_log_send_block")]
    program = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef struct { uint32_t ipv4_addr; } net_interface_t;
typedef struct { int unused; } wait_queue_t;
typedef void thread_t;
typedef struct net_tcp_socket net_tcp_socket_t;
#define TCP_LOG(...) ((void)0)
#define TCP_TRACE_VERBOSE 0
""" + types + r"""
static net_tcp_socket_t sock;
static unsigned wakes, acks;
static uint64_t now = 5, g_connect_timeout_ticks = 1200;
static uint64_t timer_ticks(void) { return now; }
static uint32_t timer_frequency(void) { return 100; }
static uint64_t tcp_lock(void) { return 0; }
static void tcp_unlock(uint64_t f) { (void)f; }
static void wait_queue_wake_all(wait_queue_t *q) { (void)q; wakes++; }
static void tcp_log_hex32(uint32_t n) { (void)n; }
static net_tcp_socket_t *tcp_find_socket(net_interface_t *i, uint16_t l,
                                        uint32_t r, uint16_t p)
{ (void)i; (void)l; (void)r; (void)p; return &sock; }
static uint16_t tcp_allocate_port(void) { return 49152; }
static uint32_t tcp_initial_seq(void) { return 1000; }
static bool tcp_send_syn(net_tcp_socket_t *s) { (void)s; return true; }
static void tcp_handle_ack(net_tcp_socket_t *s, uint32_t a) { (void)s; (void)a; }
static bool tcp_send_segment(net_tcp_socket_t *s, uint32_t q, uint8_t f,
                              const uint8_t *p, size_t n, bool a, bool r)
{ (void)s; (void)q; (void)f; (void)p; (void)n; (void)a; (void)r; acks++; return true; }
static bool tcp_reassembly_store(net_tcp_socket_t *s, uint32_t q,
                                 const uint8_t *p, size_t n)
{ (void)s; (void)q; (void)p; (void)n; return true; }
static void tcp_reassembly_drain(net_tcp_socket_t *s) { (void)s; }
"""
    for signature in ["static inline void tcp_signal_read_event",
                      "static void tcp_send_ack", "static void tcp_schedule_ack",
                      "static void tcp_mark_error", "static bool tcp_rx_reserve_space",
                      "static uint16_t read_be16", "static uint32_t read_be32",
                      "static uint16_t tcp_checksum", "static void tcp_process_payload",
                      "void net_tcp_handle_frame"]:
        program += definition(source, signature) + "\n"
    program += r"""
static uint8_t receive_buffer[32768], packet[1600];
static net_interface_t iface = { 0x0a00020f };
static void be16(uint8_t *p, uint16_t n) { p[0] = n >> 8; p[1] = n; }
static void be32(uint8_t *p, uint32_t n)
{ p[0] = n >> 24; p[1] = n >> 16; p[2] = n >> 8; p[3] = n; }
static void reset(void)
{
    memset(&sock, 0, sizeof(sock));
    sock.state = TCP_STATE_ESTABLISHED;
    sock.iface = &iface;
    sock.remote_ip = 0x0a000202;
    sock.have_mac = true;
    sock.rx_buffer = receive_buffer;
    sock.rx_capacity = sizeof(receive_buffer);
    sock.mss = 1460;
    sock.recv_next = 1000;
    wakes = acks = 0;
}
static size_t frame(size_t payload, size_t options, uint8_t flags)
{
    size_t tcp_len = 20 + options + payload;
    memset(packet, 0, sizeof(packet));
    packet[12] = 8;
    uint8_t *ip = packet + 14, *tcp = ip + 20;
    ip[0] = 0x45; ip[9] = 6;
    be16(ip + 2, 20 + tcp_len);
    be32(ip + 12, sock.remote_ip); be32(ip + 16, iface.ipv4_addr);
    be16(tcp, 8000); be16(tcp + 2, 49152);
    be32(tcp + 4, sock.recv_next);
    tcp[12] = ((20 + options) / 4) << 4; tcp[13] = flags;
    be16(tcp + 14, 65535);
    for (size_t i = 0; i < payload; ++i)
        tcp[20 + options + i] = (uint8_t)(i * 17 + 3);
    be16(tcp + 16, tcp_checksum(&sock, tcp, tcp_len));
    return 34 + tcp_len;
}
int main(void)
{
    /* Odd/even payloads and every valid TCP option size retain integrity. */
    for (size_t options = 0; options <= 40; options += 4)
    for (size_t payload = 0; payload <= 1460; ++payload)
    {
        reset();
        size_t length = frame(payload, options, TCP_FLAG_ACK);
        net_tcp_handle_frame(&iface, packet, length);
        assert(sock.rx_size == payload);
        assert(wakes == (payload != 0));
        assert(sock.read_event_seq == (payload != 0));
        assert(memcmp(receive_buffer, packet + 54 + options, payload) == 0);
        reset();
        length = frame(payload, options, TCP_FLAG_ACK);
        packet[length - 1] ^= 1; /* Corrupt header/options or payload. */
        net_tcp_handle_frame(&iface, packet, length);
        assert(sock.rx_size == 0 && sock.recv_next == 1000 && wakes == 0);
    }
    reset();
    for (unsigned i = 0; i < 16; ++i)
    {
        size_t length = frame(1460, 0, TCP_FLAG_ACK);
        net_tcp_handle_frame(&iface, packet, length);
    }
    assert(wakes == 1 && sock.read_event_seq == 16);
    assert(acks == 8);
    /* A reader that empties the queue gets a fresh event and wake. */
    sock.rx_size = 0;
    uint64_t observed = sock.read_event_seq;
    size_t length = frame(1, 0, TCP_FLAG_ACK);
    net_tcp_handle_frame(&iface, packet, length);
    assert(wakes == 2 && sock.read_event_seq != observed);
    /* FIN and RST wake even with an already nonempty buffer. */
    length = frame(0, 0, TCP_FLAG_FIN | TCP_FLAG_ACK);
    net_tcp_handle_frame(&iface, packet, length);
    assert(wakes == 3 && sock.remote_closed && sock.read_event_seq == 18);
    reset();
    length = frame(1, 0, TCP_FLAG_ACK);
    net_tcp_handle_frame(&iface, packet, length);
    length = frame(0, 0, TCP_FLAG_RST);
    net_tcp_handle_frame(&iface, packet, length);
    assert(sock.error && wakes >= 2 && sock.read_event_seq == 2);
    /* Allocation/receive failure also cannot strand the blocked reader. */
    reset(); sock.rx_buffer = NULL; sock.rx_capacity = 0;
    length = frame(1, 0, TCP_FLAG_ACK);
    net_tcp_handle_frame(&iface, packet, length);
    assert(sock.error && wakes > 0 && sock.read_event_seq > 0);
    /* Real Slirp pattern: negotiated MSS 1460, actual segments 1440. */
    reset();
    for (unsigned i = 0; i < 16; ++i)
    {
        length = frame(1440, 0, TCP_FLAG_ACK);
        net_tcp_handle_frame(&iface, packet, length);
    }
    assert(acks == 8 && wakes == 1 && !sock.ack_pending);
    reset();
    length = frame(17, 0, TCP_FLAG_ACK);
    net_tcp_handle_frame(&iface, packet, length);
    assert(acks == 0 && sock.ack_pending && sock.ack_deadline_tick == now + 1);
    /* The exact due-ACK branch used by net_tcp_poll handles an odd tail. */
    now++;
    POLL_DUE_ACK
    assert(acks == 1 && !sock.ack_pending && !sock.ack_deadline_tick);
    reset();
    length = frame(17, 0, TCP_FLAG_ACK | TCP_FLAG_PSH);
    net_tcp_handle_frame(&iface, packet, length);
    assert(acks == 1 && !sock.ack_pending);
    return 0;
}
"""
    poll = definition(source, "void net_tcp_poll")
    due_ack = definition(poll, "if (socket->ack_pending && now >= socket->ack_deadline_tick)")
    program = program.replace("    POLL_DUE_ACK", "    net_tcp_socket_t *socket = &sock;\n    " + due_ack)
    run("tcp-receive", program)


def test_igb():
    source = (ROOT / "src/drivers/igb.c").read_text()
    program = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef unsigned spinlock_t;
#define IGB_REG_ICR 0xc0
#define IGB_REG_STATUS 8
#define serial_printf(...) ((void)0)
static bool g_igb_present = true, locked, g_rx_pending;
static void *g_regs = (void *)1;
static unsigned g_irq_log_budget, ready_packets, rx_calls, polled;
static uint32_t icr;
static spinlock_t g_tx_lock;
static uint64_t now, g_irq_count, g_irq_deferred_count, g_irq_rx_count;
static uint64_t g_poll_rx_count, g_deferred_poll_count, g_watchdog_poll_count;
static uint64_t g_watchdog_next_tick = 10, g_watchdog_interval_ticks = 10;
static uint64_t timer_ticks(void) { return now; }
static bool spinlock_preempt_disabled(void) { return locked; }
static uint32_t igb_read32(uint32_t r)
{ (void)r; uint32_t result = icr; icr = 0; return result; }
static uint64_t spinlock_lock_irqsave(spinlock_t *l) { (void)l; return 0; }
static void spinlock_unlock_irqrestore(spinlock_t *l, uint64_t f)
{ (void)l; (void)f; }
static void igb_reclaim_tx(void) { }
static uint32_t igb_handle_receive(void)
{
    assert(!locked);
    rx_calls++;
    unsigned count = ready_packets;
    ready_packets = 0;
    return count;
}
"""
    # Keep the debug-only STATUS read compiled but silence its local variable.
    program = program.replace("#define serial_printf(...) ((void)0)",
                              "#define serial_printf(...) ((void)status)")
    for signature in ["void igb_on_irq", "void igb_poll", "static void igb_timer_task"]:
        program += definition(source, signature) + "\n"
    program += r"""
int main(void)
{
    assert(timer_ticks() == 0 && g_watchdog_next_tick == 10 &&
           g_watchdog_interval_ticks == 10);
    ready_packets = 40; icr = 0x80; locked = true;
    igb_on_irq();
    assert(icr == 0 && g_irq_deferred_count == 1 && g_rx_pending);
    assert(rx_calls == 0); /* IRQ must not invert interrupted lock ordering. */
    locked = false; now = 1;
    igb_timer_task(NULL);
    assert(rx_calls == 1 && ready_packets == 0 && !g_rx_pending);
    assert(g_poll_rx_count == 40 && g_deferred_poll_count == 1);
    /* No hardware polling on intervening ticks when the interface is idle. */
    polled = rx_calls;
    for (now = 2; now < 11; ++now) igb_timer_task(NULL);
    assert(rx_calls == polled);
    now = 11; igb_timer_task(NULL);
    assert(rx_calls == polled + 1 && g_watchdog_poll_count == 1);
    /* A later safe hardware IRQ can consume pending work before that tick. */
    ready_packets = 2; icr = 0x80; locked = true; igb_on_irq();
    locked = false; icr = 0x80; igb_on_irq();
    assert(ready_packets == 0 && !g_rx_pending && g_irq_rx_count == 2);
    polled = rx_calls; now = 12; igb_timer_task(NULL);
    assert(rx_calls == polled);
    return 0;
}
"""
    run("igb-deferred", program)


def test_igb_ring():
    source = (ROOT / "src/drivers/igb.c").read_text()
    first = source.index("typedef struct\n{\n    union")
    last = source.index("igb_rx_desc_t;", first) + len("igb_rx_desc_t;")
    defines = "\n".join(re.findall(
        r"^#define IGB_(?:RX_DESC_COUNT|RX_REFILL_BATCH|RX_BUFFER_SIZE|REG_RDT0|RX_STATUS_DD|RX_STATUS_EOP)\s+.*$",
        source, re.MULTILINE))
    program = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef unsigned spinlock_t;
typedef unsigned net_interface_t;
""" + defines + "\n" + source[first:last] + r"""
static igb_rx_desc_t g_rx_desc[IGB_RX_DESC_COUNT];
static uint8_t g_rx_buffers[IGB_RX_DESC_COUNT][IGB_RX_BUFFER_SIZE];
static uint32_t g_rx_index;
static net_interface_t iface, *g_iface = &iface;
static spinlock_t g_rx_lock;
static uint64_t g_rx_batch_count, g_rx_batch_max, g_rx_tail_write_count;
static unsigned next_publish, published, dispatched, bad_interval;
static bool continuous, held;
static void complete(unsigned index)
{
    g_rx_desc[index].wb.upper.length = 64;
    g_rx_desc[index].wb.upper.status_error = IGB_RX_STATUS_DD |
        ((bad_interval && index % bad_interval == 0) ? 0 : IGB_RX_STATUS_EOP);
    memset(g_rx_buffers[index], index, 64);
    g_rx_buffers[index][12] = 8; g_rx_buffers[index][13] = 0;
}
static uint64_t spinlock_lock_irqsave(spinlock_t *l)
{ (void)l; assert(!held); held = true; return 0; }
static void spinlock_unlock_irqrestore(spinlock_t *l, uint64_t f)
{ (void)l; (void)f; assert(held); held = false; }
static void igb_log_rx_idle(uint32_t n) { (void)n; }
static void igb_log_rx_debug(uint32_t n, uint16_t l, uint16_t e, uint32_t s)
{ (void)n; (void)l; (void)e; (void)s; }
static void net_if_record_rx(net_interface_t *i, uint16_t l) { (void)i; (void)l; }
static void net_arp_handle_frame(net_interface_t *i, uint8_t *f, uint16_t l)
{ (void)i; (void)f; (void)l; assert(false); }
static void igb_dispatch_ipv4(net_interface_t *i, uint8_t *f, uint16_t l)
{
    (void)i;
    unsigned index = (unsigned)((f - &g_rx_buffers[0][0]) / IGB_RX_BUFFER_SIZE);
    assert(held && l == 64 && f[0] == (uint8_t)index && f[63] == (uint8_t)index);
    assert(g_rx_desc[index].wb.upper.status_error & IGB_RX_STATUS_DD);
    dispatched++;
}
static void igb_write32(uint32_t reg, uint32_t tail)
{
    assert(held && reg == IGB_REG_RDT0);
    unsigned count = (tail + IGB_RX_DESC_COUNT - next_publish) % IGB_RX_DESC_COUNT + 1;
    assert(count <= IGB_RX_REFILL_BATCH);
    for (unsigned i = 0; i < count; ++i)
    {
        unsigned index = (next_publish + i) % IGB_RX_DESC_COUNT;
        assert(g_rx_desc[index].read.header_addr == 0);
        assert(g_rx_desc[index].read.packet_addr == (uint64_t)(uintptr_t)g_rx_buffers[index]);
        if (continuous) complete(index); /* Hardware may reuse only published buffers. */
    }
    next_publish = (tail + 1) % IGB_RX_DESC_COUNT;
    published += count;
}
""" + definition(source, "static uint32_t igb_handle_receive") + r"""
static void reset(unsigned start, unsigned count, unsigned malformed)
{
    memset(g_rx_desc, 0, sizeof(g_rx_desc));
    g_rx_index = next_publish = start;
    published = dispatched = 0; bad_interval = malformed; continuous = held = false;
    g_rx_batch_count = g_rx_batch_max = g_rx_tail_write_count = 0;
    for (unsigned i = 0; i < count; ++i) complete((start + i) % IGB_RX_DESC_COUNT);
}
int main(void)
{
    const unsigned counts[] = { 0, 1, 31, 32, 33, 255, 256 };
    const unsigned starts[] = { 0, 17, 250 };
    for (unsigned s = 0; s < 3; ++s)
    for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c)
    for (unsigned malformed = 0; malformed < 3; ++malformed)
    {
        unsigned count = counts[c], start = starts[s];
        reset(start, count, malformed);
        assert(igb_handle_receive() == count);
        assert(!held && published == count);
        assert(g_rx_index == (start + count) % IGB_RX_DESC_COUNT);
        assert(g_rx_tail_write_count == (count + IGB_RX_REFILL_BATCH - 1) / IGB_RX_REFILL_BATCH);
        unsigned expected = 0;
        for (unsigned i = 0; i < count; ++i)
            expected += !malformed || ((start + i) % IGB_RX_DESC_COUNT) % malformed != 0;
        assert(dispatched == expected);
        assert(igb_handle_receive() == 0 && published == count);
    }
    reset(250, IGB_RX_DESC_COUNT, 0); continuous = true;
    assert(igb_handle_receive() == IGB_RX_DESC_COUNT);
    assert(published == IGB_RX_DESC_COUNT && dispatched == IGB_RX_DESC_COUNT);
    assert(g_rx_index == 250); /* Continuous arrivals still respect the IRQ budget. */
    assert(igb_handle_receive() == IGB_RX_DESC_COUNT);
    assert(published == 2 * IGB_RX_DESC_COUNT);
    return 0;
}
"""
    run("igb-ring", program)


if __name__ == "__main__":
    test_tcp()
    test_igb()
    test_igb_ring()
    print("network receive behavior tests passed")
