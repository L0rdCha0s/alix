#include "rtl8139.h"
#include "pci.h"
#include "serial.h"
#include "io.h"
#include "libc.h"
#include "net/interface.h"
#include "net/dhcp.h"
#include "net/arp.h"
#include "net/icmp.h"
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

#define RTL_RCR_DEFAULT (RTL_RCR_AAP | RTL_RCR_APM | RTL_RCR_AB | RTL_RCR_AM | \
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
static int g_tx_index = 0;
/* Per Realtek docs the RX buffer must be at least 256-byte aligned.
   Insufficient alignment can cause DMA writes to land at unexpected
   addresses and corrupt nearby kernel data/rodata. */
static __attribute__((aligned(256))) uint8_t g_rx_buffer[RTL_RX_BUFFER_SIZE];
static int g_log_rx_count = 0;
static uint8_t g_rx_frame[2048];
static int g_state_dump_budget = 12;
static int g_tx_dump_budget = 4;

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
static void rtl8139_log_tsd_status(uint32_t tsd);

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

    for (int i = 0; i < RTL_TX_SLOT_COUNT; ++i) {
        g_tx_phys[i] = (uint32_t)(uintptr_t)g_tx_buffer[i];   // ensure this is PHYS (see note below)
        outl(g_io_base + RTL_REG_TSAD0 + i*4, g_tx_phys[i]);
        // outl(g_io_base + RTL_REG_TSD0 + i*4, 0x0000);  // REMOVE this
        // Optionally: mark host owns (not required, but safe)
        // outl(g_io_base + RTL_REG_TSD0 + i*4, 0x2000);
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
}

void rtl8139_poll(void)
{
    if (!g_rtl_present)
    {
        return;
    }
    rtl8139_handle_receive();
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
    /* Some environments occasionally report RX_EMPTY=0 with no valid
       descriptors available, which could spin forever. Put a hard
       safety cap on how many iterations we perform in one poll to
       prevent the kernel from stalling before the shell starts. */
    int safety = 4096;
    while ((inb(g_io_base + RTL_REG_CR) & RTL_CR_RX_EMPTY) == 0 && safety-- > 0)
    {
        uint32_t offset = g_rx_offset;
        uint16_t packet_status = rtl8139_buffer_read16(offset);
        uint16_t length = rtl8139_buffer_read16(offset + 2);
        if ((packet_status & 0x01U) == 0 || length == 0)
        {
            //rtl8139_log("dropping invalid packet");
            rtl8139_dump_state("rx invalid");
        }
        else if (g_log_rx_count < 8)
        {
            ++g_log_rx_count;
            serial_write_string("rtl8139: rx len=0x");
            rtl8139_log_hex16(length);
            serial_write_string(" data=");
            uint16_t preview = (length < 6) ? length : 6;
            for (uint16_t i = 0; i < preview; ++i)
            {
                uint8_t byte = rtl8139_buffer_read8(offset + 4 + i);
                rtl8139_log_hex8(byte);
                if (i + 1 != preview)
                {
                    serial_write_char(' ');
                }
            }
            serial_write_string("\r\n");
        }

        if (g_iface && length >= 4)
        {
            uint16_t frame_len = (uint16_t)(length - 4);
            if (frame_len > 0 && frame_len <= sizeof(g_rx_frame))
            {
                rtl8139_copy_packet(offset, g_rx_frame, frame_len);

                if (frame_len >= 14)
                {
                    uint16_t eth_type = (uint16_t)((g_rx_frame[12] << 8) | g_rx_frame[13]);
                    serial_write_string("rtl8139: rx frame eth_type=0x");
                    rtl8139_log_hex16(eth_type);
                    serial_write_string(" len=0x");
                    rtl8139_log_hex16(frame_len);
                    serial_write_string("\r\n");

                    if (eth_type == 0x0800 && frame_len >= 38)
                    {
                        uint8_t ihl = (uint8_t)(g_rx_frame[14] & 0x0F);
                        size_t ip_header_len = (size_t)ihl * 4;
                        if (14 + ip_header_len + 8 <= frame_len)
                        {
                            uint8_t proto = g_rx_frame[23];
                            uint16_t src_port = (uint16_t)((g_rx_frame[14 + ip_header_len] << 8) | g_rx_frame[15 + ip_header_len]);
                            uint16_t dst_port = (uint16_t)((g_rx_frame[16 + ip_header_len] << 8) | g_rx_frame[17 + ip_header_len]);
                            serial_write_string("rtl8139: ip proto=0x");
                            rtl8139_log_hex16(proto);
                            serial_write_string(" src_port=0x");
                            rtl8139_log_hex16(src_port);
                            serial_write_string(" dst_port=0x");
                            rtl8139_log_hex16(dst_port);
                            serial_write_string("\r\n");
                        }
                    }
                }
                net_arp_handle_frame(g_iface, g_rx_frame, frame_len);
                net_dhcp_handle_frame(g_iface, g_rx_frame, frame_len);
                net_icmp_handle_frame(g_iface, g_rx_frame, frame_len);
            }
            else
            {
                serial_write_string("rtl8139: frame too large for buffer\r\n");
            }
        }

        /* Hardware ring wraps at 8 KiB. Advance and wrap accordingly. */
        uint32_t advance = (uint32_t)((length + 4 + 3) & ~3U);
        uint32_t next = g_rx_offset + advance;
        while (next >= RTL_RX_RING_SIZE)
        {
            next -= RTL_RX_RING_SIZE;
        }
        g_rx_offset = next;

        outw(g_io_base + RTL_REG_CAPR, (uint16_t)((g_rx_offset - 16) & 0xFFFF));
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
    uint32_t start = (offset + 4) % RTL_RX_RING_SIZE;
    for (uint16_t i = 0; i < len; ++i)
    {
        dest[i] = g_rx_buffer[(start + i) % RTL_RX_RING_SIZE];
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
        serial_write_string("rtl8139: tx packet too large\r\n");
        return false;
    }

    size_t frame_len = len;
    if (frame_len < 60)
    {
        frame_len = 60;
    }

    int slot = -1;
    for (int attempt = 0; attempt < RTL_TX_SLOT_COUNT; ++attempt) {
        int cand = (g_tx_index + attempt) % RTL_TX_SLOT_COUNT;
        uint32_t tsd = inl(g_io_base + RTL_REG_TSD0 + cand*4);

        if (tsd & 0x2000U) {              // Host owns => free
            slot = cand;
            break;
        }
        if (tsd & 0x40000000U) {          // Aborted: reclaim it
            outl(g_io_base + RTL_REG_TSD0 + cand*4, 0x2000U);
            slot = cand;
            break;
        }
    }
    if (slot < 0) { /* all busy */ return false; }

    uint16_t tsad_reg = RTL_REG_TSAD0 + slot * 4;
    uint16_t tsd_reg = RTL_REG_TSD0 + slot * 4;

    memcpy(g_tx_buffer[slot], data, len);
    if (frame_len > len)
    {
        memset(g_tx_buffer[slot] + len, 0, frame_len - len);
    }

    if (g_tx_dump_budget > 0)
    {
        rtl8139_dump_frame(slot, frame_len, g_tx_buffer[slot]);
        g_tx_dump_budget--;
    }

    outl(g_io_base + RTL_REG_TSAD0 + slot*4, g_tx_phys[slot]);
    outl(g_io_base + RTL_REG_TSD0  + slot*4, (uint32_t)frame_len & 0x1FFFU);

    rtl8139_dump_state("after tx");

    uint32_t tsd_after;
    for (int i = 0; i < 100000; ++i) {
        tsd_after = inl(g_io_base + RTL_REG_TSD0 + slot*4);
        if (tsd_after & 0x2000U) break;   // done when HostOwns==1
    }

    serial_write_string("rtl8139: tsd after=0x");
    rtl8139_log_hex32(tsd_after);
    serial_write_string(" ");
    rtl8139_log_tsd_status(tsd_after);
    serial_write_string("\r\n");

    g_tx_index = (slot + 1) % RTL_TX_SLOT_COUNT;
    return true;
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

static void rtl8139_log_tsd_status(uint32_t tsd) {
    serial_write_string("[");
    if (tsd & 0x40000000U) serial_write_string("TABT ");    // abort
    if (tsd & 0x00004000U) serial_write_string("TUN ");     // underrun
    if (tsd & 0x00008000U) serial_write_string("TOK ");     // tx ok
    if (tsd & 0x00002000U) serial_write_string("OWN=host "); // free
    serial_write_string("]");
}

static void rtl8139_dump_state(const char *context);
