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
#include "net/tcp.h"
#include "interrupts.h"

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
#define RTL_RCR_RBLEN_8K (0U << 11)

// Remove AAP (promisc) and AM (all multicast)
#define RTL_RCR_DEFAULT ( \
    RTL_RCR_APM | RTL_RCR_AB | \
    RTL_RCR_WRAP | RTL_RCR_MXDMA_UNLIMITED | RTL_RCR_RBLEN_8K)


/* RX ring in the 8139 is 8 KiB plus a 16-byte header. We keep an
   additional safety tail for convenient linear reads across the wrap,
   but all hardware offsets must wrap at exactly 8 KiB. */
#define RTL_RX_RING_SIZE   (8192)
#define RTL_RX_BUFFER_SIZE (RTL_RX_RING_SIZE + 16 + 1500)

static bool g_rtl_present = false;
static pci_device_t g_device;
static uint16_t g_io_base = 0;
static uint8_t g_mac[6];
static uint32_t g_rx_offset = 0;
static net_interface_t *g_iface = NULL;

#define RTL_TX_SLOT_COUNT 4
static __attribute__((aligned(16))) uint8_t g_tx_buffer[RTL_TX_SLOT_COUNT][2048];
static uint32_t g_tx_phys[RTL_TX_SLOT_COUNT];
/* Per Realtek docs the RX buffer must be at least 256-byte aligned.
   Insufficient alignment can cause DMA writes to land at unexpected
   addresses and corrupt nearby kernel data/rodata. */
static __attribute__((aligned(256))) uint8_t g_rx_buffer[RTL_RX_BUFFER_SIZE];
static int g_log_rx_count = 0;
static uint8_t g_rx_frame[2048];
static int g_state_dump_budget = 12;
static int g_tx_dump_budget = 32;
static int g_hw_tx_cursor = 0; // which TSD/TSAD pair the NIC expects next
static int g_tx_tail_cursor = 0; // oldest descriptor that might still be owned by NIC
static int g_tx_inflight = 0;    // number of descriptors handed to NIC

#define RTL_TX_QUEUE_MAX 16
#define RTL_TX_FRAME_MAX 1600
static int g_arp_dump_budget = 16;
static uint8_t g_tx_queue_data[RTL_TX_QUEUE_MAX][RTL_TX_FRAME_MAX];
static size_t g_tx_queue_len[RTL_TX_QUEUE_MAX];
static int g_tx_queue_head = 0;
static int g_tx_queue_tail = 0;
static int g_tx_queue_count = 0;
static void rtl8139_log(const char *msg);
static void rtl8139_log_hex8(uint8_t value);
static void rtl8139_log_hex16(uint16_t value);
static void rtl8139_log_hex32(uint32_t value);
static void rtl8139_log_mac_address(void);
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
static void rtl8139_dump_bytes(const char *prefix, const uint8_t *data, size_t len);

void rtl8139_init(void)
{
    g_rtl_present = false;
    g_io_base = 0;
    g_rx_offset = 0;
    g_log_rx_count = 0;

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

    serial_write_string("rtl8139: irq status=0x");
    rtl8139_log_hex16(status);
    serial_write_string("\r\n");

    outw(g_io_base + RTL_REG_ISR, status);

    if (status & RTL_ISR_RER)
    {
        rtl8139_log("rx error");
    }
    if (status & RTL_ISR_TER)
    {
        rtl8139_log("tx error");
    }
    if (status & RTL_ISR_TOK)
    {
        rtl8139_log("tx ok");
    }
    if (status & RTL_ISR_ROK)
    {
        rtl8139_handle_receive();
    }

    if (status & (RTL_ISR_RER | RTL_ISR_TER | RTL_ISR_TOK | RTL_ISR_ROK))
    {
        rtl8139_dump_state("irq");
    }

    if (status & (RTL_ISR_TOK | RTL_ISR_TER))
    {
        rtl8139_reclaim_tx();
        rtl8139_tx_flush_queue();
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
    rtl8139_reclaim_tx();
    rtl8139_tx_flush_queue();
    net_tcp_poll();
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
    rtl8139_dump_state("rx poll");

    // Safety cap so we never spin forever if RX_EMPTY flickers
    int safety = 4096;

    while ((inb(g_io_base + RTL_REG_CR) & RTL_CR_RX_EMPTY) == 0 && safety-- > 0)
    {
        uint32_t offset = g_rx_offset;

        // Descriptor header in ring: [status:16][length:16][payload...][CRC(4)]
        uint16_t rsr   = rtl8139_buffer_read16(offset + 0);
        uint16_t rxlen = rtl8139_buffer_read16(offset + 2);   // includes CRC
        bool ok = (rsr & 0x0001U) && rxlen >= 8 && rxlen <= (RTL_RX_RING_SIZE - 16);

        if (!ok) {
            rtl8139_dump_state("rx invalid");
            goto advance_ring;
        }

        uint16_t frame_len = (uint16_t)(rxlen - 4);  // strip CRC
        if (frame_len > 9216) {                      // jumbo/garbage guard
            goto advance_ring;
        }

        // Peek first up to 18 bytes to decide whether we care (VLAN-aware)
        uint8_t hdr[18];
        {
            uint32_t start = (offset + 4) & (RTL_RX_RING_SIZE - 1);
            uint32_t first = (frame_len < sizeof(hdr)) ? frame_len : (uint32_t)sizeof(hdr);
            uint32_t head  = RTL_RX_RING_SIZE - start;
            uint32_t n0    = (first <= head) ? first : head;
            memcpy(hdr,                &g_rx_buffer[start], n0);
            if (first > n0) memcpy(hdr + n0, &g_rx_buffer[0], first - n0);
        }

        if (frame_len >= 14) {
            uint16_t eth_type = (uint16_t)((hdr[12] << 8) | hdr[13]);
            uint32_t l2_off = 14;

            // If VLAN tagged (0x8100), drop for now (stack not parsing 802.1Q yet).
            // (If you want to support it later, parse inner EtherType at bytes 16/17
            //  and keep l2_off = 18, but then your upper stack must understand VLAN.)
            if (eth_type == 0x8100) {
                goto advance_ring;
            }

            // Optional early filtering: only accept IPv4 and ARP currently.
            if (!(eth_type == 0x0800 || eth_type == 0x0806)) {
                goto advance_ring;
            }

            // Copy only frames we’ll actually process
            if (frame_len > sizeof(g_rx_frame)) {
                serial_write_string("rtl8139: frame too large for buffer\r\n");
                goto advance_ring;
            }

            // Linearize the frame into g_rx_frame
            rtl8139_copy_packet(offset, g_rx_frame, frame_len);

            // Light logging + IP/TCP/UDP port logging guarded by proto
            serial_write_string("rtl8139: rx frame eth_type=0x");
            rtl8139_log_hex16(eth_type);
            serial_write_string(" len=0x");
            rtl8139_log_hex16(frame_len);
            serial_write_string("\r\n");

            if (eth_type == 0x0806 && g_arp_dump_budget > 0)
            {
                rtl8139_dump_bytes("rtl8139: arp frame snapshot", g_rx_frame, frame_len);
                g_arp_dump_budget--;
            }

            if (eth_type == 0x0800 && frame_len >= l2_off + 20) {
                uint8_t ihl = (uint8_t)(g_rx_frame[l2_off] & 0x0F);
                size_t ip_hlen = (size_t)ihl * 4;
                if (frame_len >= l2_off + ip_hlen) {
                    uint8_t proto = g_rx_frame[l2_off + 9];
                    serial_write_string("rtl8139: ip proto=0x");
                    rtl8139_log_hex16(proto);

                    if ((proto == 6 /*TCP*/ || proto == 17 /*UDP*/) &&
                        frame_len >= l2_off + ip_hlen + 4)
                    {
                        uint16_t sport = (uint16_t)((g_rx_frame[l2_off + ip_hlen + 0] << 8) |
                                                    g_rx_frame[l2_off + ip_hlen + 1]);
                        uint16_t dport = (uint16_t)((g_rx_frame[l2_off + ip_hlen + 2] << 8) |
                                                    g_rx_frame[l2_off + ip_hlen + 3]);
                        serial_write_string(" src_port=0x");
                        rtl8139_log_hex16(sport);
                        serial_write_string(" dst_port=0x");
                        rtl8139_log_hex16(dport);
                    }
                    serial_write_string("\r\n");
                }
            }

            // Hand off to upper layers (full Ethernet frame)
            if (g_iface) {
                net_arp_handle_frame(g_iface,  g_rx_frame, frame_len);
                net_dhcp_handle_frame(g_iface, g_rx_frame, frame_len);
                net_icmp_handle_frame(g_iface, g_rx_frame, frame_len);
                net_dns_handle_frame(g_iface, g_rx_frame, frame_len);
                net_tcp_handle_frame(g_iface, g_rx_frame, frame_len);
            }
        }

        advance_ring:
        {
            // Advance ring: descriptor(4) + data + CRC(4), then DWORD align
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



static bool rtl8139_tx_send(net_interface_t *iface, const uint8_t *data, size_t len)
{
    (void)iface;
    if (!g_rtl_present || !data || len == 0) return false;

    if (len > sizeof(g_tx_buffer[0]))
    {
        rtl8139_log("tx frame too large");
        return false;
    }

    rtl8139_reclaim_tx();
    if (g_tx_inflight < RTL_TX_SLOT_COUNT && rtl8139_tx_slot_ready(g_hw_tx_cursor))
    {
        rtl8139_hw_send_slot(g_hw_tx_cursor, data, len);
        rtl8139_tx_flush_queue();
        return true;
    }

    if (rtl8139_tx_queue_push(data, len))
    {
        rtl8139_tx_flush_queue();
        return true;
    }

    rtl8139_log("tx ring saturated");
    return false;
}


static void rtl8139_log(const char *msg)
{
    serial_write_string("rtl8139: ");
    serial_write_string(msg);
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
}

static void rtl8139_dump_bytes(const char *prefix, const uint8_t *data, size_t len)
{
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
}

static void rtl8139_dump_frame(int slot, size_t len, const uint8_t *data)
{
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
}

static void __attribute__((unused)) rtl8139_log_tsd_status(uint32_t tsd) {
    serial_write_string("[");
    if (tsd & 0x40000000U) serial_write_string("TABT ");    // abort
    if (tsd & 0x00004000U) serial_write_string("TUN ");     // underrun
    if (tsd & 0x00008000U) serial_write_string("TOK ");     // tx ok
    if (tsd & 0x00002000U) serial_write_string("OWN=host "); // free
    serial_write_string("]");
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

    outl(g_io_base + RTL_REG_TSD0 + slot * 4, (uint32_t)frame_len & 0x1FFFU);
    rtl8139_dump_state("after tx");

    g_hw_tx_cursor = (g_hw_tx_cursor + 1) % RTL_TX_SLOT_COUNT;
    g_tx_inflight++;
}

static bool rtl8139_tx_queue_push(const uint8_t *data, size_t len)
{
    if (g_tx_queue_count >= RTL_TX_QUEUE_MAX || len > RTL_TX_FRAME_MAX)
    {
        return false;
    }
    memcpy(g_tx_queue_data[g_tx_queue_tail], data, len);
    g_tx_queue_len[g_tx_queue_tail] = len;
    g_tx_queue_tail = (g_tx_queue_tail + 1) % RTL_TX_QUEUE_MAX;
    g_tx_queue_count++;
    return true;
}

static void rtl8139_tx_flush_queue(void)
{
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
    }
}
