#include "rtl8139.h"
#include "pci.h"
#include "serial.h"
#include "io.h"
#include "libc.h"

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

#define RTL_ISR_ROK 0x0001
#define RTL_ISR_RER 0x0002
#define RTL_ISR_TOK 0x0004
#define RTL_ISR_TER 0x0008

#define RTL_CR_RESET    0x10
#define RTL_CR_RE       0x08
#define RTL_CR_TE       0x04
#define RTL_CR_RX_EMPTY 0x01

#define RTL_RCR_DEFAULT (0x0000000F | (1U << 7))

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
/* Per Realtek docs the RX buffer must be at least 256-byte aligned.
   Insufficient alignment can cause DMA writes to land at unexpected
   addresses and corrupt nearby kernel data/rodata. */
static __attribute__((aligned(256))) uint8_t g_rx_buffer[RTL_RX_BUFFER_SIZE];
static int g_log_rx_count = 0;

static void rtl8139_log(const char *msg);
static void rtl8139_log_hex8(uint8_t value);
static void rtl8139_log_hex16(uint16_t value);
static void rtl8139_log_mac_address(void);
static void rtl8139_handle_receive(void);
static uint16_t rtl8139_buffer_read16(uint32_t offset);
static uint8_t rtl8139_buffer_read8(uint32_t offset);

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
    outw(g_io_base + RTL_REG_CAPR, 0);
    outw(g_io_base + RTL_REG_CBR, 0);

    outl(g_io_base + RTL_REG_RCR, RTL_RCR_DEFAULT);
    outl(g_io_base + RTL_REG_TCR, 0x00000600);

    outw(g_io_base + RTL_REG_IMR, RTL_ISR_ROK | RTL_ISR_RER | RTL_ISR_TOK | RTL_ISR_TER);
    outb(g_io_base + RTL_REG_CR, (uint8_t)(RTL_CR_RE | RTL_CR_TE));

    for (int i = 0; i < 6; ++i)
    {
        g_mac[i] = inb(g_io_base + RTL_REG_IDR0 + i);
    }

    g_rtl_present = true;

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
            rtl8139_log("dropping invalid packet");
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
