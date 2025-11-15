#include "rtl8139.h"
#include "pci.h"
#include "serial.h"
#include "io.h"
#include "libc.h"
#include "net/interface.h"
#include "net/dhcp.h"
#include "net/arp.h"
#include "net/icmp.h"
#include "net/dns.h"
#include "net/ntp.h"
#include "net/tcp.h"
#include "interrupts.h"
#include "timer.h"
#include "spinlock.h"
#include "process.h"

#ifndef RTL8139_TRACE_ENABLE
#define RTL8139_TRACE_ENABLE 0
#endif

#define RTL_VENDOR_ID 0x10EC
#define RTL_DEVICE_ID 0x8139

#define RTL_REG_IDR0     0x00
#define RTL_REG_MAR0     0x08
#define RTL_REG_TSD0     0x10
#define RTL_REG_TSAD0    0x20
#define RTL_REG_RBSTART  0x30
#define RTL_REG_CAPR     0x38
#define RTL_REG_CBR      0x3A
#define RTL_REG_IMR      0x3C
#define RTL_REG_ISR      0x3E
#define RTL_REG_TCR      0x40
#define RTL_REG_RCR      0x44
#define RTL_REG_CR       0x37
#define RTL_REG_CONFIG1  0x52
#define RTL_REG_MSR      0x58

#define RTL_ISR_ROK 0x0001
#define RTL_ISR_RER 0x0002
#define RTL_ISR_TOK 0x0004
#define RTL_ISR_TER 0x0008

#define RTL_CR_RESET    0x10
#define RTL_CR_RE       0x08
#define RTL_CR_TE       0x04
#define RTL_CR_RX_EMPTY 0x01

#define RTL_RCR_AAP   (1U << 0)
#define RTL_RCR_APM   (1U << 1)
#define RTL_RCR_AM    (1U << 2)
#define RTL_RCR_AB    (1U << 3)
#define RTL_RCR_WRAP  (1U << 7)
#define RTL_RCR_MXDMA_SHIFT 8
#define RTL_RCR_MXDMA_UNLIMITED (7U << RTL_RCR_MXDMA_SHIFT)
#define RTL_RCR_RBLEN_8K   (0U << 11)
#define RTL_RCR_RBLEN_16K  (1U << 11)
#define RTL_RCR_RBLEN_32K  (2U << 11)
#define RTL_RCR_RBLEN_64K  (3U << 11)

// Remove AAP (promisc) and AM (all multicast)
#define RTL_RCR_DEFAULT ( \
    RTL_RCR_APM | RTL_RCR_AB | \
    RTL_RCR_WRAP | RTL_RCR_MXDMA_UNLIMITED | RTL_RCR_RBLEN_64K)


/* RX ring in the 8139 is 64 KiB plus a 16-byte header when RBLEN is set
   accordingly. We keep an additional safety tail for convenient linear reads across the wrap,
   but all hardware offsets must wrap at exactly 64 KiB. */
#define RTL_RX_RING_SIZE   (64 * 1024)
#define RTL_RX_BUFFER_SIZE (RTL_RX_RING_SIZE + 16 + 1500)

static bool g_rtl_present = false;
static pci_device_t g_device;
static uint16_t g_io_base = 0;
static uint8_t g_mac[6];
static uint32_t g_rx_offset = 0;
static net_interface_t *g_iface = NULL;
static spinlock_t g_tx_lock;

static inline uint64_t rtl8139_save_flags(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags) :: "memory");
    return flags;
}

static inline void rtl8139_restore_flags(uint64_t flags)
{
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "memory", "cc");
}

static inline void rtl8139_cli(void)
{
    __asm__ volatile ("cli" ::: "memory");
}

static inline void rtl8139_sti(void)
{
    __asm__ volatile ("sti" ::: "memory");
}

static inline uint64_t rtl8139_acquire_tx(void)
{
    uint64_t flags = rtl8139_save_flags();
    rtl8139_cli();
    spinlock_lock(&g_tx_lock);
    return flags;
}

static inline void rtl8139_release_tx(uint64_t flags)
{
    spinlock_unlock(&g_tx_lock);
    rtl8139_restore_flags(flags);
}

#define RTL_TX_SLOT_COUNT 4
static __attribute__((aligned(16))) uint8_t g_tx_buffer[RTL_TX_SLOT_COUNT][2048];
static uint32_t g_tx_phys[RTL_TX_SLOT_COUNT];
/* Per Realtek docs the RX buffer must be at least 256-byte aligned.
   Insufficient alignment can cause DMA writes to land at unexpected
   addresses and corrupt nearby kernel data/rodata. */
static __attribute__((aligned(256))) uint8_t g_rx_buffer[RTL_RX_BUFFER_SIZE];
static int g_log_rx_count = 0;
#define RTL_RX_FRAME_MAX  12288
static int g_state_dump_budget = 12;
static int g_tx_dump_budget = 32;
static int g_hw_tx_cursor = 0; // which TSD/TSAD pair the NIC expects next
static int g_tx_tail_cursor = 0; // oldest descriptor that might still be owned by NIC
static int g_tx_inflight = 0;    // number of descriptors handed to NIC

#define RTL_RX_BOUNCE_COUNT 4
static uint8_t g_rx_bounce[RTL_RX_BOUNCE_COUNT][RTL_RX_FRAME_MAX];
static volatile bool g_rx_bounce_in_use[RTL_RX_BOUNCE_COUNT];

#define RTL_TX_QUEUE_MAX 16
#define RTL_TX_FRAME_MAX 1600
static int g_arp_dump_budget = 16;
static uint8_t g_tx_queue_data[RTL_TX_QUEUE_MAX][RTL_TX_FRAME_MAX];
static size_t g_tx_queue_len[RTL_TX_QUEUE_MAX];
static int g_tx_queue_head = 0;
static int g_tx_queue_tail = 0;
static int g_tx_queue_count = 0;

typedef struct
{
    bool valid;
    uint64_t issue_tick;
    uint32_t seq;
    uint32_t ack;
    uint8_t flags;
    uint16_t length;
} rtl8139_tx_meta_t;

static rtl8139_tx_meta_t g_tx_meta[RTL_TX_SLOT_COUNT];
static const uint64_t RTL_TX_STALL_TICKS = 50;
static void rtl8139_log(const char *msg);
static void rtl8139_log_hex8(uint8_t value);
static void rtl8139_log_hex16(uint16_t value);
static void rtl8139_log_hex32(uint32_t value);
static void rtl8139_log_mac_address(void);
static void rtl8139_dispatch_ipv4(net_interface_t *iface, uint8_t *frame, uint16_t frame_len);
static void rtl8139_handle_receive(void);
static void rtl8139_dump_state(const char *context);
static uint16_t rtl8139_buffer_read16(uint32_t offset);
static uint8_t rtl8139_buffer_read8(uint32_t offset);
static void rtl8139_copy_packet(uint32_t offset, uint8_t *dest, uint16_t len);
static bool rtl8139_tx_send(net_interface_t *iface, const uint8_t *data, size_t len);
static void rtl8139_dump_frame(int slot, size_t len, const uint8_t *data);
static bool rtl8139_tx_slot_ready(int slot);
static void rtl8139_reclaim_tx(void);
static void rtl8139_hw_send_slot(int slot, const uint8_t *data, size_t len);
static bool rtl8139_tx_queue_push(const uint8_t *data, size_t len);
static void rtl8139_tx_flush_queue(void);
static void rtl8139_log_stack_source(const thread_t *owner, const void *ptr, size_t len);
static void rtl8139_log_dma_target(const char *context,
                                   int slot,
                                   const uint8_t *buffer,
                                   size_t len);
static void rtl8139_dump_bytes(const char *prefix, const uint8_t *data, size_t len);
static void rtl8139_timer_task(void *context);
static void rtl8139_log_tx_state(const char *context);
static void rtl8139_log_tsd_status(uint32_t tsd);
static void rtl8139_tx_meta_capture(int slot, const uint8_t *frame, size_t len);
static void rtl8139_tx_meta_clear(int slot);
static void rtl8139_tx_check_stuck(const char *context);
static void rtl8139_tx_force_release(const char *context);
static uint8_t *rtl8139_rx_bounce_acquire(void);
static void rtl8139_rx_bounce_release(uint8_t *buffer);

void rtl8139_init(void)
{
    g_rtl_present = false;
    g_io_base = 0;
    g_rx_offset = 0;
    g_log_rx_count = 0;
    spinlock_init(&g_tx_lock);

    if (!pci_find_device(RTL_VENDOR_ID, RTL_DEVICE_ID, &g_device))
    {
        rtl8139_log("device not found");
        return;
    }

    uint32_t bar0 = pci_config_read32(g_device, 0x10);
    if ((bar0 & 0x01U) == 0)
    {
        rtl8139_log("expected IO BAR, found memory BAR");
        return;
    }

    g_io_base = (uint16_t)(bar0 & ~0x3U);
    if (g_io_base == 0)
    {
        rtl8139_log("IO base is zero");
        return;
    }

    pci_set_command_bits(g_device, 0x0005, 0); /* enable IO space + bus mastering */

    outb(g_io_base + RTL_REG_CONFIG1, 0x00);

    outb(g_io_base + RTL_REG_CR, RTL_CR_RESET);
    for (int i = 0; i < 100000; ++i)
    {
        if ((inb(g_io_base + RTL_REG_CR) & RTL_CR_RESET) == 0)
        {
            break;
        }
    }

    outw(g_io_base + RTL_REG_IMR, 0x0000);
    outw(g_io_base + RTL_REG_ISR, 0xFFFF);

    outl(g_io_base + RTL_REG_RBSTART, (uint32_t)(uintptr_t)g_rx_buffer);
    g_rx_offset = 0;
    /* CAPR is driver-owned; CBR is HW-owned (read-only). Initialize CAPR. */
    outw(g_io_base + RTL_REG_CAPR, 0);

    outl(g_io_base + RTL_REG_RCR, RTL_RCR_DEFAULT);
    /* Recommended TCR value: IFG=3 (96ns), max DMA burst, default thresholds. */
    outl(g_io_base + RTL_REG_TCR, 0x03000700);

    outw(g_io_base + RTL_REG_IMR, RTL_ISR_ROK | RTL_ISR_RER | RTL_ISR_TOK | RTL_ISR_TER);
    outb(g_io_base + RTL_REG_CR, (uint8_t)(RTL_CR_RE | RTL_CR_TE));

    for (int i = 0; i < 6; ++i)
    {
        g_mac[i] = inb(g_io_base + RTL_REG_IDR0 + i);
    }

    g_rtl_present = true;
    interrupts_enable_irq(11);

    g_hw_tx_cursor = 0;  // after reset, the NIC starts at pair 0
    g_tx_tail_cursor = 0;
    g_tx_inflight = 0;
    g_tx_queue_head = 0;
    g_tx_queue_tail = 0;
    g_tx_queue_count = 0;
    memset(g_tx_meta, 0, sizeof(g_tx_meta));
    for (int i = 0; i < RTL_TX_SLOT_COUNT; ++i) {
        g_tx_phys[i] = (uint32_t)(uintptr_t)g_tx_buffer[i];
        outl(g_io_base + RTL_REG_TSAD0 + i*4, g_tx_phys[i]); // program once
        outl(g_io_base + RTL_REG_TSD0 + i*4, 0x00002000U);   // mark slot available
    }

    g_iface = net_if_register("rtl0", g_mac);
    if (g_iface)
    {
        net_if_set_link_up(g_iface, true);
        net_if_set_tx_handler(g_iface, rtl8139_tx_send);
    }

    uint32_t timer_freq = timer_frequency();
    if (timer_freq == 0)
    {
        timer_freq = 100;
    }
    uint32_t interval = timer_freq / 200U;
    if (interval == 0)
    {
        interval = 1;
    }
    if (!timer_register_periodic(rtl8139_timer_task, NULL, interval))
    {
        rtl8139_log("failed to register timer task");
    }

    serial_write_string("rtl8139: found at bus ");
    rtl8139_log_hex8(g_device.bus);
    serial_write_string(" device ");
    rtl8139_log_hex8(g_device.device);
    serial_write_string(" function ");
    rtl8139_log_hex8(g_device.function);
    serial_write_string(" io=0x");
    rtl8139_log_hex16(g_io_base);
    serial_write_string("\r\n");
    rtl8139_log_mac_address();
    rtl8139_dump_state("after init");
}

void rtl8139_on_irq(void)
{
    if (!g_rtl_present)
    {
        return;
    }

    uint16_t status = inw(g_io_base + RTL_REG_ISR);
    if (status == 0)
    {
        return;
    }

#if RTL8139_TRACE_ENABLE
    serial_write_string("rtl8139: irq status=0x");
    rtl8139_log_hex16(status);
    serial_write_string("\r\n");
#endif

    outw(g_io_base + RTL_REG_ISR, status);

    if (status & RTL_ISR_RER)
    {
        rtl8139_log("rx error");
    }
    if (status & RTL_ISR_TER)
    {
        rtl8139_log("tx error");
    }
#if RTL8139_TRACE_ENABLE
    if (status & RTL_ISR_TOK)
    {
        rtl8139_log("tx ok");
    }
#endif
    if (status & RTL_ISR_ROK)
    {
        rtl8139_handle_receive();
    }

#if RTL8139_TRACE_ENABLE
    if (status & (RTL_ISR_RER | RTL_ISR_TER | RTL_ISR_TOK | RTL_ISR_ROK))
    {
        rtl8139_dump_state("irq");
    }
#endif

    if (status & (RTL_ISR_TOK | RTL_ISR_TER))
    {
        uint64_t irq_flags = rtl8139_acquire_tx();
        rtl8139_reclaim_tx();
        rtl8139_tx_flush_queue();
        rtl8139_release_tx(irq_flags);
    }

    net_tcp_poll();
}

void rtl8139_poll(void)
{
    if (!g_rtl_present)
    {
        return;
    }
    rtl8139_handle_receive();
    uint64_t irq_flags = rtl8139_acquire_tx();
    rtl8139_reclaim_tx();
    rtl8139_tx_flush_queue();
    rtl8139_release_tx(irq_flags);
    net_tcp_poll();
}

static void rtl8139_timer_task(void *context)
{
    (void)context;
    rtl8139_poll();
}

bool rtl8139_is_present(void)
{
    return g_rtl_present;
}

bool rtl8139_get_mac(uint8_t mac_out[6])
{
    if (!g_rtl_present || !mac_out)
    {
        return false;
    }
    memmove(mac_out, g_mac, 6);
    return true;
}

static void rtl8139_handle_receive(void)
{
#if RTL8139_TRACE_ENABLE
    rtl8139_dump_state("rx poll");
#endif

    int safety = 4096;

    while ((inb(g_io_base + RTL_REG_CR) & RTL_CR_RX_EMPTY) == 0 && safety-- > 0)
    {
        uint32_t offset = g_rx_offset;
        uint8_t *frame = NULL;

        uint16_t rsr   = rtl8139_buffer_read16(offset + 0);
        uint16_t rxlen = rtl8139_buffer_read16(offset + 2);   // includes CRC
        rxlen &= 0x1FFFU; // length occupies 13 bits; high bits are reserved/status
        bool ok = (rsr & 0x0001U) && rxlen >= 8 && rxlen <= (RTL_RX_RING_SIZE - 16);

        if (!ok) {
            if (g_iface)
            {
                net_if_record_rx_error(g_iface);
            }
            rtl8139_dump_state("rx invalid");
            goto release_frame;
        }

        uint16_t frame_len = (uint16_t)(rxlen - 4);  // strip CRC
        if (frame_len > RTL_RX_FRAME_MAX) {
            if (g_iface)
            {
                net_if_record_rx_error(g_iface);
            }
            goto release_frame;
        }

        frame = rtl8139_rx_bounce_acquire();
        if (!frame)
        {
            if (g_iface)
            {
                net_if_record_rx_error(g_iface);
            }
            serial_write_string("rtl8139: rx bounce exhausted\r\n");
            goto release_frame;
        }

        rtl8139_copy_packet(offset, frame, frame_len);

        if (frame_len >= 14) {
            uint16_t eth_type = (uint16_t)((frame[12] << 8) | frame[13]);
#if RTL8139_TRACE_ENABLE
            const uint32_t l2_off = 14;
#endif
            bool vlan = false;

            // If VLAN tagged, strip one 802.1Q header (4 bytes) and rebase EtherType
            if (eth_type == 0x8100 && frame_len >= 18)
            {
                vlan = true;
                uint16_t inner = (uint16_t)((frame[16] << 8) | frame[17]);

                // shift bytes [18..end) down to [14..)
                size_t tail = (size_t)frame_len - 18;
                memmove(&frame[14], &frame[18], tail);
                frame_len = (uint16_t)(frame_len - 4);
                eth_type = inner;
                // l2_off remains 14 (we presented an untagged frame to upper layers)
            }

            if (g_iface)
            {
                net_if_record_rx(g_iface, frame_len);
            }

            // Only process IPv4 and ARP
            if (!(eth_type == 0x0800 || eth_type == 0x0806)) {
                goto advance_ring;
            }

#if RTL8139_TRACE_ENABLE
            bool log_frame = true;
            bool have_proto = false;
            bool have_ports = false;
            uint8_t proto = 0;
            uint16_t sport = 0;
            uint16_t dport = 0;

            if (eth_type == 0x0800 && frame_len >= l2_off + 20) {
                uint8_t ihl = (uint8_t)(frame[l2_off] & 0x0F);
                size_t ip_hlen = (size_t)ihl * 4;
                if (frame_len >= l2_off + ip_hlen) {
                    proto = frame[l2_off + 9];
                    have_proto = true;
                    if ((proto == 6 /*TCP*/ || proto == 17 /*UDP*/) &&
                        frame_len >= l2_off + ip_hlen + 4)
                    {
                        sport = (uint16_t)((frame[l2_off + ip_hlen + 0] << 8) |
                                           frame[l2_off + ip_hlen + 1]);
                        dport = (uint16_t)((frame[l2_off + ip_hlen + 2] << 8) |
                                           frame[l2_off + ip_hlen + 3]);
                        have_ports = true;
                        if (proto == 17 &&
                            (sport == 0x0043 || sport == 0x0044 ||
                             dport == 0x0043 || dport == 0x0044))
                        {
                            log_frame = false; /* suppress noisy DHCP chatter */
                        }
                    }
                }
            }

            if (log_frame) {
                serial_write_string("rtl8139: rx frame eth_type=0x");
                rtl8139_log_hex16(eth_type);
                serial_write_string(" len=0x");
                rtl8139_log_hex16(frame_len);
                if (vlan) serial_write_string(" (vlan-stripped)");
                serial_write_string("\r\n");

                if (have_proto) {
                    serial_write_string("rtl8139: ip proto=0x");
                    rtl8139_log_hex16(proto);
                    if (have_ports) {
                        serial_write_string(" src_port=0x");
                        rtl8139_log_hex16(sport);
                        serial_write_string(" dst_port=0x");
                        rtl8139_log_hex16(dport);
                    }
                    serial_write_string("\r\n");
                }
            }
#endif
#if !RTL8139_TRACE_ENABLE
            (void)vlan;
#endif

            if (g_iface)
            {
                if (eth_type == 0x0806)
                {
                    net_arp_handle_frame(g_iface, frame, frame_len);
                }
                else if (eth_type == 0x0800)
                {
                    rtl8139_dispatch_ipv4(g_iface, frame, frame_len);
                }
            }
        }

release_frame:
        if (frame)
        {
            rtl8139_rx_bounce_release(frame);
            frame = NULL;
        }

    advance_ring:
        {
            uint32_t advance = (uint32_t)((rxlen + 4 + 3) & ~3U);
            g_rx_offset = (g_rx_offset + advance) & (RTL_RX_RING_SIZE - 1);
            outw(g_io_base + RTL_REG_CAPR, (uint16_t)((g_rx_offset - 16) & 0xFFFF));
        }
    }
}



static uint16_t rtl8139_buffer_read16(uint32_t offset)
{
    uint32_t index0 = offset % RTL_RX_RING_SIZE;
    uint32_t index1 = (index0 + 1) % RTL_RX_RING_SIZE;
    return (uint16_t)(g_rx_buffer[index0] | ((uint16_t)g_rx_buffer[index1] << 8));
}

static uint8_t rtl8139_buffer_read8(uint32_t offset)
{
    return g_rx_buffer[offset % RTL_RX_RING_SIZE];
}

static void rtl8139_copy_packet(uint32_t offset, uint8_t *dest, uint16_t len)
{
    uint32_t start = (offset + 4) & (RTL_RX_RING_SIZE - 1); // skip status/length
    uint32_t head  = RTL_RX_RING_SIZE - start;
    uint32_t n0    = (len <= head) ? len : head;

    memcpy(dest,                &g_rx_buffer[start], n0);
    if (len > n0) memcpy(dest + n0, &g_rx_buffer[0], len - n0);
}

static void rtl8139_dispatch_ipv4(net_interface_t *iface, uint8_t *frame, uint16_t frame_len)
{
    if (!iface || !frame || frame_len < 34)
    {
        return;
    }

    const uint8_t *ip = frame + 14;
    uint8_t version = (uint8_t)(ip[0] >> 4);
    uint8_t ihl = (uint8_t)(ip[0] & 0x0F);
    if (version != 4 || ihl < 5)
    {
        return;
    }
    size_t ip_hlen = (size_t)ihl * 4;
    if ((size_t)frame_len < 14 + ip_hlen)
    {
        return;
    }

    uint16_t total_len = (uint16_t)((ip[2] << 8) | ip[3]);
    if (total_len < ip_hlen)
    {
        return;
    }
    size_t ip_available = (size_t)frame_len - 14;
    if (total_len > ip_available)
    {
        total_len = (uint16_t)ip_available;
    }

    uint8_t protocol = ip[9];
    switch (protocol)
    {
        case 1: /* ICMP */
            net_icmp_handle_frame(iface, frame, frame_len);
            break;
        case 6: /* TCP */
            net_tcp_handle_frame(iface, frame, frame_len);
            break;
        case 17: /* UDP */
        {
            if (total_len < ip_hlen + 8)
            {
                break;
            }
            const uint8_t *udp = ip + ip_hlen;
            uint16_t src_port = (uint16_t)((udp[0] << 8) | udp[1]);
            uint16_t dst_port = (uint16_t)((udp[2] << 8) | udp[3]);
            if (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68)
            {
                net_dhcp_handle_frame(iface, frame, frame_len);
            }
            else if (src_port == 53 || dst_port == 53)
            {
                net_dns_handle_frame(iface, frame, frame_len);
            }
            else if (src_port == 123 || dst_port == 123)
            {
                net_ntp_handle_frame(iface, frame, frame_len);
            }
            break;
        }
        default:
            break;
    }
}



static bool rtl8139_tx_send(net_interface_t *iface, const uint8_t *data, size_t len)
{
    (void)iface;
    if (!g_rtl_present || !data || len == 0)
    {
        return false;
    }

    if (len > sizeof(g_tx_buffer[0]))
    {
        rtl8139_log("tx frame too large");
        return false;
    }

    const uint8_t *payload = data;
    uint8_t *stack_clone = NULL;
    thread_t *stack_owner = NULL;
    if (len > 0)
    {
        stack_owner = process_find_stack_owner(data, len);
    }
    if (stack_owner)
    {
        rtl8139_log_stack_source(stack_owner, data, len);
        stack_clone = (uint8_t *)malloc(len);
        if (!stack_clone)
        {
            return false;
        }
        memcpy(stack_clone, data, len);
        payload = stack_clone;
    }

    bool ok = false;
    uint64_t irq_flags = rtl8139_acquire_tx();
    rtl8139_reclaim_tx();
    if (g_tx_inflight < RTL_TX_SLOT_COUNT && rtl8139_tx_slot_ready(g_hw_tx_cursor))
    {
        rtl8139_hw_send_slot(g_hw_tx_cursor, payload, len);
        rtl8139_tx_flush_queue();
        ok = true;
        goto out;
    }

    if (rtl8139_tx_queue_push(payload, len))
    {
        rtl8139_tx_flush_queue();
        ok = true;
        goto out;
    }

    rtl8139_log("tx ring saturated");
    rtl8139_log_tx_state("ring_saturated");
    rtl8139_tx_check_stuck("ring_saturated");
    rtl8139_tx_force_release("ring_saturated");
    rtl8139_reclaim_tx();
    if (rtl8139_tx_queue_push(payload, len))
    {
        rtl8139_tx_flush_queue();
        ok = true;
    }

out:
    rtl8139_release_tx(irq_flags);
    if (stack_clone)
    {
        free(stack_clone);
    }
    return ok;
}


static void rtl8139_log(const char *msg)
{
    serial_write_string("rtl8139: ");
    serial_write_string(msg);
    serial_write_string("\r\n");
}

static void rtl8139_log_thread_owner(const thread_t *owner)
{
    if (!owner)
    {
        serial_write_string("<none>");
        return;
    }
    const char *name = process_thread_name_const(owner);
    serial_write_string(name && name[0] ? name : "<unnamed>");
    serial_write_string(" pid=0x");
    process_t *proc = process_thread_owner(owner);
    serial_write_hex64(proc ? process_get_pid(proc) : 0);
}

static void rtl8139_log_stack_source(const thread_t *owner, const void *ptr, size_t len)
{
    serial_write_string("rtl8139: stack tx buffer ptr=0x");
    serial_write_hex64((uintptr_t)ptr);
    serial_write_string(" len=0x");
    serial_write_hex64(len);
    serial_write_string(" owner=");
    rtl8139_log_thread_owner(owner);
    serial_write_string("\r\n");
}

static void rtl8139_log_dma_target(const char *context,
                                   int slot,
                                   const uint8_t *buffer,
                                   size_t len)
{
    serial_write_string("rtl8139: dma context=");
    serial_write_string(context ? context : "<none>");
    serial_write_string(" slot=0x");
    serial_write_hex64((uint64_t)slot);
    serial_write_string(" virt=0x");
    serial_write_hex64((uintptr_t)buffer);
    serial_write_string(" phys=0x");
    serial_write_hex64((uint64_t)g_tx_phys[slot]);
    serial_write_string(" len=0x");
    serial_write_hex64(len);
    serial_write_string(" owner=");
    thread_t *owner = process_find_stack_owner(buffer, len);
    rtl8139_log_thread_owner(owner);
    serial_write_string("\r\n");
}

static void rtl8139_log_hex8(uint8_t value)
{
    static const char hex[] = "0123456789ABCDEF";
    char buf[3];
    buf[0] = hex[(value >> 4) & 0xF];
    buf[1] = hex[value & 0xF];
    buf[2] = '\0';
    serial_write_string(buf);
}

static void rtl8139_log_hex16(uint16_t value)
{
    rtl8139_log_hex8((uint8_t)((value >> 8) & 0xFF));
    rtl8139_log_hex8((uint8_t)(value & 0xFF));
}

static void rtl8139_log_hex32(uint32_t value)
{
    rtl8139_log_hex16((uint16_t)((value >> 16) & 0xFFFF));
    rtl8139_log_hex16((uint16_t)(value & 0xFFFF));
}

static void rtl8139_log_mac_address(void)
{
    serial_write_string("rtl8139: mac ");
    for (int i = 0; i < 6; ++i)
    {
        rtl8139_log_hex8(g_mac[i]);
        if (i != 5)
        {
            serial_write_char(':');
        }
    }
    serial_write_string("\r\n");
}

static void rtl8139_dump_state(const char *context)
{
#if !RTL8139_TRACE_ENABLE
    (void)context;
    return;
#else
    if (!g_rtl_present || g_state_dump_budget <= 0)
    {
        return;
    }

    uint8_t cr = inb(g_io_base + RTL_REG_CR);
    uint32_t rcr = inl(g_io_base + RTL_REG_RCR);
    uint16_t capr = inw(g_io_base + RTL_REG_CAPR);
    uint16_t cbr = inw(g_io_base + RTL_REG_CBR);
    uint16_t isr = inw(g_io_base + RTL_REG_ISR);
    uint16_t imr = inw(g_io_base + RTL_REG_IMR);
    uint8_t msr = inb(g_io_base + RTL_REG_MSR);
    uint32_t tcr = inl(g_io_base + RTL_REG_TCR);
    uint32_t tsad0 = inl(g_io_base + RTL_REG_TSAD0);

    serial_write_string("rtl8139: regs[");
    serial_write_string(context);
    serial_write_string("] CR=0x");
    rtl8139_log_hex8(cr);
    serial_write_string(" RCR=0x");
    rtl8139_log_hex32(rcr);
    serial_write_string(" CAPR=0x");
    rtl8139_log_hex16(capr);
    serial_write_string(" CBR=0x");
    rtl8139_log_hex16(cbr);
    serial_write_string(" ISR=0x");
    rtl8139_log_hex16(isr);
    serial_write_string(" IMR=0x");
    rtl8139_log_hex16(imr);
    serial_write_string(" MSR=0x");
    rtl8139_log_hex8(msr);
    serial_write_string(" TCR=0x");
    rtl8139_log_hex32(tcr);
    serial_write_string(" TSAD0=0x");
    rtl8139_log_hex32(tsad0);
    serial_write_string("\r\n");

    g_state_dump_budget--;
#endif
}

static void rtl8139_log_tx_state(const char *context)
{
    if (!g_rtl_present || g_tx_dump_budget <= 0)
    {
        return;
    }

    serial_write_string("rtl8139: tx state[");
    if (context)
    {
        serial_write_string(context);
    }
    serial_write_string("] inflight=0x");
    rtl8139_log_hex16((uint16_t)g_tx_inflight);
    serial_write_string(" queue=0x");
    rtl8139_log_hex16((uint16_t)g_tx_queue_count);
    serial_write_string(" head=0x");
    rtl8139_log_hex16((uint16_t)g_tx_queue_head);
    serial_write_string(" tail=0x");
    rtl8139_log_hex16((uint16_t)g_tx_queue_tail);
    serial_write_string(" hw_cur=0x");
    rtl8139_log_hex16((uint16_t)g_hw_tx_cursor);
    serial_write_string(" tail_cur=0x");
    rtl8139_log_hex16((uint16_t)g_tx_tail_cursor);
    serial_write_string("\r\n");

    for (int i = 0; i < RTL_TX_SLOT_COUNT; ++i)
    {
        uint32_t tsd = inl(g_io_base + RTL_REG_TSD0 + i * 4);
        serial_write_string("rtl8139:   slot=");
        rtl8139_log_hex8((uint8_t)i);
        serial_write_string(" tsd=0x");
        rtl8139_log_hex32(tsd);
        serial_write_string("\r\n");
    }

    g_tx_dump_budget--;
}

static uint32_t rtl8139_read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void rtl8139_tx_meta_clear(int slot)
{
    if (slot < 0 || slot >= RTL_TX_SLOT_COUNT)
    {
        return;
    }
    g_tx_meta[slot].valid = false;
    g_tx_meta[slot].issue_tick = 0;
    g_tx_meta[slot].seq = 0;
    g_tx_meta[slot].ack = 0;
    g_tx_meta[slot].flags = 0;
    g_tx_meta[slot].length = 0;
}

static void rtl8139_tx_meta_capture(int slot, const uint8_t *frame, size_t len)
{
    if (slot < 0 || slot >= RTL_TX_SLOT_COUNT || !frame)
    {
        return;
    }

    rtl8139_tx_meta_t *meta = &g_tx_meta[slot];
    meta->valid = false;
    meta->issue_tick = timer_ticks();
    meta->length = (uint16_t)((len < 60) ? 60 : len);
    meta->seq = 0;
    meta->ack = 0;
    meta->flags = 0;

    if (len < 54)
    {
        return;
    }

    uint16_t eth_type = (uint16_t)((frame[12] << 8) | frame[13]);
    if (eth_type != 0x0800)
    {
        return;
    }

    const uint8_t *ip = frame + 14;
    uint8_t version = (uint8_t)(ip[0] >> 4);
    uint8_t ihl = (uint8_t)(ip[0] & 0x0F);
    size_t ip_hlen = (size_t)ihl * 4U;
    if (version != 4 || ihl < 5)
    {
        return;
    }
    if (len < 14 + ip_hlen + 20)
    {
        return;
    }
    if (ip[9] != 6) /* TCP */
    {
        return;
    }

    const uint8_t *tcp = ip + ip_hlen;
    meta->seq = rtl8139_read_be32(tcp + 4);
    meta->ack = rtl8139_read_be32(tcp + 8);
    meta->flags = tcp[13];
    meta->valid = true;
}

static void rtl8139_tx_log_meta(const char *context, int slot, const rtl8139_tx_meta_t *meta, uint32_t tsd, uint64_t delta)
{
#if !RTL8139_TRACE_ENABLE
    (void)context;
    (void)slot;
    (void)meta;
    (void)tsd;
    (void)delta;
    return;
#else
    if (!meta || !meta->valid || g_tx_dump_budget <= 0)
    {
        return;
    }

    serial_write_string("rtl8139: tx meta[");
    if (context)
    {
        serial_write_string(context);
    }
    serial_write_string("] slot=0x");
    rtl8139_log_hex8((uint8_t)slot);
    serial_write_string(" seq=0x");
    rtl8139_log_hex32(meta->seq);
    serial_write_string(" ack=0x");
    rtl8139_log_hex32(meta->ack);
    serial_write_string(" flags=0x");
    rtl8139_log_hex16(meta->flags);
    serial_write_string(" len=0x");
    rtl8139_log_hex16(meta->length);
    serial_write_string(" dticks=0x");
    rtl8139_log_hex32((uint32_t)delta);
    serial_write_string(" tsd=0x");
    rtl8139_log_hex32(tsd);
    serial_write_string(" ");
    rtl8139_log_tsd_status(tsd);
    serial_write_string("]\r\n");

    g_tx_dump_budget--;
#endif
}

static void rtl8139_tx_check_stuck(const char *context)
{
    if (!g_rtl_present)
    {
        return;
    }
    uint64_t now = timer_ticks();
    for (int slot = 0; slot < RTL_TX_SLOT_COUNT; ++slot)
    {
        rtl8139_tx_meta_t *meta = &g_tx_meta[slot];
        if (!meta->valid)
        {
            continue;
        }
        uint64_t delta = now - meta->issue_tick;
        if (delta < RTL_TX_STALL_TICKS)
        {
            continue;
        }
        uint32_t tsd = inl(g_io_base + RTL_REG_TSD0 + slot * 4);
        if ((tsd & 0x2000U) != 0)
        {
            /* descriptor already host-owned; will be reclaimed shortly */
            continue;
        }
        rtl8139_tx_log_meta(context ? context : "stuck", slot, meta, tsd, delta);
    }
}

static void rtl8139_tx_force_release(const char *context)
{
    if (!g_rtl_present)
    {
        return;
    }

    bool any = false;
    uint64_t now = timer_ticks();
    for (int slot = 0; slot < RTL_TX_SLOT_COUNT; ++slot)
    {
        rtl8139_tx_meta_t *meta = &g_tx_meta[slot];
        if (!meta->valid)
        {
            continue;
        }
        uint64_t delta = now - meta->issue_tick;
        if (delta < (RTL_TX_STALL_TICKS * 2))
        {
            continue;
        }
        uint32_t tsd = inl(g_io_base + RTL_REG_TSD0 + slot * 4);
        if ((tsd & 0x2000U) != 0)
        {
            continue;
        }
        if (g_tx_dump_budget > 0)
        {
            serial_write_string("rtl8139: tx force release[");
            if (context)
            {
                serial_write_string(context);
            }
            serial_write_string("] slot=0x");
            rtl8139_log_hex8((uint8_t)slot);
            serial_write_string(" dticks=0x");
            rtl8139_log_hex32((uint32_t)delta);
            serial_write_string(" tsd=0x");
            rtl8139_log_hex32(tsd);
            serial_write_string(" ");
            rtl8139_log_tsd_status(tsd);
            serial_write_string("\r\n");
            g_tx_dump_budget--;
        }
        outl(g_io_base + RTL_REG_TSD0 + slot * 4, 0x00002000U);
        rtl8139_tx_meta_clear(slot);
        any = true;
    }

    if (any)
    {
        rtl8139_reclaim_tx();
    }
}

static void rtl8139_dump_bytes(const char *prefix, const uint8_t *data, size_t len)
{
#if !RTL8139_TRACE_ENABLE
    (void)prefix;
    (void)data;
    (void)len;
    return;
#else
    if (!data || len == 0)
    {
        return;
    }

    size_t limit = (len < 64) ? len : 64;
    serial_write_string(prefix);
    serial_write_string(" len=0x");
    rtl8139_log_hex16((uint16_t)len);
    serial_write_string("\r\n");

    size_t idx = 0;
    while (idx < limit)
    {
        serial_write_string("rtl8139:   ");
        for (size_t j = 0; j < 16 && idx < limit; ++j, ++idx)
        {
            rtl8139_log_hex8(data[idx]);
            if (j != 15 && idx < limit)
            {
                serial_write_char(' ');
            }
        }
        serial_write_string("\r\n");
    }
#endif
}

static void rtl8139_dump_frame(int slot, size_t len, const uint8_t *data)
{
#if !RTL8139_TRACE_ENABLE
    (void)slot;
    (void)len;
    (void)data;
    return;
#else
    serial_write_string("rtl8139: frame[slot=");
    rtl8139_log_hex8((uint8_t)slot);
    serial_write_string("] len=0x");
    rtl8139_log_hex16((uint16_t)len);
    serial_write_string(" data=");
    size_t preview = (len < 64) ? len : 64;
    for (size_t i = 0; i < preview; ++i)
    {
        rtl8139_log_hex8(data[i]);
        if ((i & 0x0F) == 0x0F || i + 1 == preview)
        {
            serial_write_string("\r\n");
            if (i + 1 < preview)
            {
                serial_write_string("rtl8139: ");
            }
        }
        else
        {
            serial_write_char(' ');
        }
    }
#endif
}

static void rtl8139_log_tsd_status(uint32_t tsd) {
    serial_write_string("[");
    if (tsd & 0x40000000U) serial_write_string("TABT ");    // abort
    if (tsd & 0x00004000U) serial_write_string("TUN ");     // underrun
    if (tsd & 0x00008000U) serial_write_string("TOK ");     // tx ok
    if (tsd & 0x00002000U) serial_write_string("OWN=host "); // free
    serial_write_string("]");
}

static uint8_t *rtl8139_rx_bounce_acquire(void)
{
    for (int i = 0; i < RTL_RX_BOUNCE_COUNT; ++i)
    {
        if (__sync_bool_compare_and_swap(&g_rx_bounce_in_use[i], false, true))
        {
            return g_rx_bounce[i];
        }
    }
    return NULL;
}

static void rtl8139_rx_bounce_release(uint8_t *buffer)
{
    if (!buffer)
    {
        return;
    }
    for (int i = 0; i < RTL_RX_BOUNCE_COUNT; ++i)
    {
        if (g_rx_bounce[i] == buffer)
        {
            __sync_bool_compare_and_swap(&g_rx_bounce_in_use[i], true, false);
            return;
        }
    }
}

static void rtl8139_dump_state(const char *context);

static bool rtl8139_tx_slot_ready(int slot)
{
    uint32_t tsd = inl(g_io_base + RTL_REG_TSD0 + slot * 4);
    return (tsd & 0x2000U) != 0;
}

static void rtl8139_reclaim_tx(void)
{
    while (g_tx_inflight > 0)
    {
        int slot = g_tx_tail_cursor;
        uint32_t tsd = inl(g_io_base + RTL_REG_TSD0 + slot * 4);
        if ((tsd & 0x2000U) == 0)
        {
            break;
        }
        if (g_tx_meta[slot].valid)
        {
            uint64_t now = timer_ticks();
            rtl8139_tx_log_meta("complete", slot, &g_tx_meta[slot], tsd, now - g_tx_meta[slot].issue_tick);
        }
        rtl8139_tx_meta_clear(slot);
        g_tx_tail_cursor = (g_tx_tail_cursor + 1) % RTL_TX_SLOT_COUNT;
        g_tx_inflight--;
    }
}

static void rtl8139_hw_send_slot(int slot, const uint8_t *data, size_t len)
{
    size_t frame_len = (len < 60) ? 60 : len;
    memcpy(g_tx_buffer[slot], data, len);
    if (frame_len > len)
    {
        memset(g_tx_buffer[slot] + len, 0, frame_len - len);
    }

    rtl8139_dump_frame(slot, frame_len, g_tx_buffer[slot]);
    rtl8139_tx_meta_capture(slot, g_tx_buffer[slot], frame_len);
    rtl8139_log_dma_target("hw_send", slot, g_tx_buffer[slot], frame_len);

    outl(g_io_base + RTL_REG_TSD0 + slot * 4, (uint32_t)frame_len & 0x1FFFU);
    rtl8139_dump_state("after tx");

    g_hw_tx_cursor = (g_hw_tx_cursor + 1) % RTL_TX_SLOT_COUNT;
    g_tx_inflight++;
}

static bool rtl8139_tx_queue_push(const uint8_t *data, size_t len)
{
    if (g_tx_queue_count >= RTL_TX_QUEUE_MAX || len > RTL_TX_FRAME_MAX)
    {
        rtl8139_log("tx queue push failed");
        rtl8139_log_tx_state("queue_push_fail");
        rtl8139_tx_check_stuck("queue_push_fail");
        rtl8139_tx_force_release("queue_push_fail");
        rtl8139_reclaim_tx();
        if (g_tx_queue_count >= RTL_TX_QUEUE_MAX || len > RTL_TX_FRAME_MAX)
        {
            return false;
        }
    }
    memcpy(g_tx_queue_data[g_tx_queue_tail], data, len);
    g_tx_queue_len[g_tx_queue_tail] = len;
    g_tx_queue_tail = (g_tx_queue_tail + 1) % RTL_TX_QUEUE_MAX;
    g_tx_queue_count++;
    return true;
}

static void rtl8139_tx_flush_queue(void)
{
    bool progressed = false;
    while (g_tx_queue_count > 0)
    {
        if (g_tx_inflight >= RTL_TX_SLOT_COUNT)
        {
            break;
        }
        int slot = g_hw_tx_cursor;
        if (!rtl8139_tx_slot_ready(slot))
        {
            break;
        }
        const uint8_t *buffer = g_tx_queue_data[g_tx_queue_head];
        size_t len = g_tx_queue_len[g_tx_queue_head];
        g_tx_queue_head = (g_tx_queue_head + 1) % RTL_TX_QUEUE_MAX;
        g_tx_queue_count--;
        rtl8139_hw_send_slot(slot, buffer, len);
        progressed = true;
    }
    if (!progressed && g_tx_queue_count > 0)
    {
        rtl8139_log_tx_state("flush_blocked");
        rtl8139_tx_check_stuck("flush_blocked");
        rtl8139_tx_force_release("flush_blocked");
    }
}
