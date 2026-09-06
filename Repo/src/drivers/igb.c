#include "igb.h"
#include "pci.h"
#include "serial.h"
#include "ioremap.h"
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
#include "lapic.h"

static void igb_irq_handler(uint8_t irq, interrupt_frame_t *frame, void *context)
{
    (void)irq;
    (void)frame;
    (void)context;
    igb_on_irq();
}

#define IGB_VENDOR_ID 0x8086
#define IGB_DEVICE_ID_82576 0x10C9
#define IGB_DEVICE_ID_I350  0x1521
#define IGB_DEVICE_ID_82574 0x10D3 /* accept e1000e-compatible parts if presented */

#define IGB_REG_CTRL        0x00000
#define IGB_REG_STATUS      0x00008
#define IGB_REG_MDIC        0x00020
#define IGB_REG_CTRL_EXT    0x00018
/*
 * Use the 82576 legacy aliases here.  They are valid on the hardware and are
 * the register addresses implemented by QEMU's igb model.  The main register
 * block is ICR=0x1500, ICS=0x1504, IMS=0x1508, IMC=0x150C; the old constants
 * accidentally treated ICS as IMS and IMS as IMC.
 */
#define IGB_REG_ICR         0x000C0
#define IGB_REG_ICS         0x000C8
#define IGB_REG_IMS         0x000D0
#define IGB_REG_IMC         0x000D8
#define IGB_REG_IAM         0x000E0
#define IGB_REG_RCTL        0x00100
#define IGB_REG_TCTL        0x00400
#define IGB_REG_TIPG        0x00410
#define IGB_REG_RAL0        0x05400
#define IGB_REG_RAH0        0x05404
#define IGB_REG_MTA         0x05200
#define IGB_REG_RDBAL0      0x02800
#define IGB_REG_RDBAH0      0x02804
#define IGB_REG_RDLEN0      0x02808
#define IGB_REG_SRRCTL0     0x0280C
#define IGB_REG_RDH0        0x02810
#define IGB_REG_RDT0        0x02818
#define IGB_REG_RXDCTL0     0x02828
#define IGB_REG_RDRXCTL     0x02F00
#define IGB_REG_RXCSUM      0x05000
#define IGB_REG_RLPML       0x05004
#define IGB_REG_RXPBSIZE0   0x02404
#define IGB_REG_RXCTRL      0x03000
#define IGB_REG_MRQC        0x05818
#define IGB_REG_VMOLR0      0x05AD0
#define IGB_REG_VFRE        0x00C8C
#define IGB_REG_RDBAL0_ALT  0x0C000
#define IGB_REG_RDBAH0_ALT  0x0C004
#define IGB_REG_RDLEN0_ALT  0x0C008
#define IGB_REG_SRRCTL0_ALT 0x0C00C
#define IGB_REG_RDH0_ALT    0x0C010
#define IGB_REG_RDT0_ALT    0x0C018
#define IGB_REG_RXDCTL0_ALT 0x0C028
#define IGB_REG_TDBAL0_ALT  0x0E000
#define IGB_REG_TDBAH0_ALT  0x0E004
#define IGB_REG_TDLEN0_ALT  0x0E008
#define IGB_REG_TDH0_ALT    0x0E010
#define IGB_REG_TDT0_ALT    0x0E018
#define IGB_REG_TXDCTL0_ALT 0x0E028
#define IGB_REG_TDBAL0      0x03800
#define IGB_REG_TDBAH0      0x03804
#define IGB_REG_TDLEN0      0x03808
#define IGB_REG_TDH0        0x03810
#define IGB_REG_TDT0        0x03818
#define IGB_REG_TXDCTL0     0x03828

#define IGB_MMIO_BYTES 0x20000ULL

#define IGB_CTRL_RST   (1U << 26)
#define IGB_CTRL_SLU   (1U << 6)
#define IGB_CTRL_ASDE  (1U << 5)

#define IGB_MDIC_DATA_MASK   0x0000FFFFU
#define IGB_MDIC_REG_SHIFT   16
#define IGB_MDIC_REG_MASK    (0x1FU << IGB_MDIC_REG_SHIFT)
#define IGB_MDIC_PHY_SHIFT   21
#define IGB_MDIC_PHY_MASK    (0x1FU << IGB_MDIC_PHY_SHIFT)
#define IGB_MDIC_OP_WRITE    0x04000000U
#define IGB_MDIC_OP_READ     0x08000000U
#define IGB_MDIC_READY       0x10000000U
#define IGB_MDIC_INT_EN      0x20000000U
#define IGB_MDIC_ERROR       0x40000000U

#define IGB_RCTL_EN     (1U << 1)
#define IGB_RCTL_SBP    (1U << 2)
#define IGB_RCTL_UPE    (1U << 3)
#define IGB_RCTL_MPE    (1U << 4)
#define IGB_RCTL_BAM    (1U << 15)
#define IGB_RCTL_SECRC  (1U << 26)
#define IGB_RCTL_BSIZE_2048 0

#define IGB_RDRXCTL_CRCSTRIP (1U << 1)
#define IGB_RDRXCTL_DMAIDONE (1U << 3)
#define IGB_RXCTRL_RXEN     (1U << 1)

#define IGB_TCTL_EN     (1U << 1)
#define IGB_TCTL_PSP    (1U << 3)
#define IGB_TCTL_CT_SHIFT   4
#define IGB_TCTL_COLD_SHIFT 12

#define IGB_SRRCTL_BSIZEPKT_SHIFT 10
#define IGB_SRRCTL_BSIZEPKT_MASK  0x0000007F
#define IGB_SRRCTL_DESCTYPE_ADV_ONEBUF 0x02000000

#define IGB_RXDCTL_QUEUE_ENABLE   (1U << 25)
#define IGB_TXDCTL_QUEUE_ENABLE   (1U << 25)

#define IGB_TX_CMD_EOP   (1U << 0)
#define IGB_TX_CMD_IFCS  (1U << 1)
#define IGB_TX_CMD_RS    (1U << 3)
#define IGB_TX_STATUS_DD (1U << 0)

#define IGB_RX_STATUS_DD  (1U << 0)
#define IGB_RX_STATUS_EOP (1U << 1)

#define IGB_RAH_AV (1U << 31)

#define IGB_VMOLR_AUPE   (1U << 24)
#define IGB_VMOLR_BAM    (1U << 27)
#define IGB_VMOLR_MPME   (1U << 28)
#define IGB_VMOLR_RLPML_MASK 0x00003FFFU

#define IGB_IMS_TXDW   (1U << 0)
#define IGB_IMS_RXDMT0 (1U << 4)
#define IGB_IMS_RXO    (1U << 6)
#define IGB_IMS_RXDW   (1U << 7)

#define IGB_PHY_ADDR            1U
#define IGB_MII_BMCR            0x00U
#define IGB_BMCR_SPEED1000      0x0040U
#define IGB_BMCR_FULL_DUPLEX    0x0100U
#define IGB_BMCR_AN_RESTART     0x0200U
#define IGB_BMCR_AN_ENABLE      0x1000U

#define IGB_RX_DESC_COUNT 256
#define IGB_TX_DESC_COUNT 64
#define IGB_RX_BUFFER_SIZE 2048
#define IGB_TX_BUFFER_SIZE 2048

#ifndef IGB_DEBUG_LOG
#define IGB_DEBUG_LOG 1
#endif

typedef struct
{
    union
    {
        struct
        {
            uint64_t packet_addr;
            uint64_t header_addr;
        } read;
        struct
        {
            struct
            {
                uint16_t pkt_info;
                uint16_t hdr_info;
                union
                {
                    uint32_t rss;
                    struct
                    {
                        uint16_t ip_id;
                        uint16_t csum;
                    } csum_ip;
                } hi_dword;
            } lower;
            struct
            {
                uint32_t status_error;
                uint16_t length;
                uint16_t vlan;
            } upper;
        } wb;
    };
} __attribute__((packed, aligned(16))) igb_rx_desc_t;

typedef struct
{
    uint64_t addr;
    uint16_t length;
    uint8_t cso;
    uint8_t cmd;
    uint8_t status;
    uint8_t css;
    uint16_t special;
} __attribute__((packed)) igb_tx_desc_t;

static bool g_igb_present = false;
static pci_device_t g_device;
static volatile uint8_t *g_regs = NULL;
static uint8_t g_mac[6];
static net_interface_t *g_iface = NULL;
static spinlock_t g_tx_lock;
static spinlock_t g_rx_lock;

static __attribute__((aligned(4096))) igb_rx_desc_t g_rx_desc[IGB_RX_DESC_COUNT];
static __attribute__((aligned(4096))) igb_tx_desc_t g_tx_desc[IGB_TX_DESC_COUNT];
static __attribute__((aligned(16))) uint8_t g_rx_buffers[IGB_RX_DESC_COUNT][IGB_RX_BUFFER_SIZE];
static __attribute__((aligned(16))) uint8_t g_tx_buffers[IGB_TX_DESC_COUNT][IGB_TX_BUFFER_SIZE];
static uint32_t g_rx_index = 0;
static uint32_t g_tx_head = 0;
static uint32_t g_tx_clean = 0;
static int g_rx_log_budget = 24;
static int g_rx_idle_log_budget = 8;
static int g_irq_log_budget = 16;

static void igb_log(const char *msg);
static inline uint32_t igb_read32(uint32_t offset);
static inline void igb_write32(uint32_t offset, uint32_t value);
static void igb_reset(void);
static bool igb_setup_rx(void);
static bool igb_setup_tx(void);
static void igb_handle_receive(void);
static void igb_reclaim_tx(void);
static bool igb_tx_send(net_interface_t *iface, const uint8_t *data, size_t len);
static void igb_dispatch_ipv4(net_interface_t *iface, uint8_t *frame, uint16_t frame_len);
static void igb_timer_task(void *context);
static bool igb_mdic_read(uint32_t reg, uint32_t *out);
static bool igb_mdic_write(uint32_t reg, uint32_t data);
static void igb_phy_restart_autoneg(void);
static uint8_t igb_select_msi_apic(void);
static void igb_log_rx_debug(uint32_t idx, uint16_t len, uint16_t eth_type, uint32_t status);
static void igb_log_rx_idle(uint32_t idx);

static const uint16_t g_device_ids[] = {
    IGB_DEVICE_ID_82576,
    IGB_DEVICE_ID_I350,
    IGB_DEVICE_ID_82574
};

void igb_init(void)
{
    g_igb_present = false;
    g_regs = NULL;
    g_iface = NULL;
    g_rx_index = 0;
    g_tx_head = 0;
    g_tx_clean = 0;
    spinlock_init(&g_tx_lock);
    spinlock_init(&g_rx_lock);

    bool found = false;
    for (size_t i = 0; i < (sizeof(g_device_ids) / sizeof(g_device_ids[0])); ++i)
    {
        if (pci_find_device(IGB_VENDOR_ID, g_device_ids[i], &g_device))
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        igb_log("device not found");
        return;
    }

    uint32_t bar0_low = pci_config_read32(g_device, 0x10);
    if ((bar0_low & 0x1u) != 0)
    {
        igb_log("expected MMIO BAR");
        return;
    }
    uint64_t bar0 = (uint64_t)(bar0_low & ~0xFUL);
    if ((bar0_low & 0x6u) == 0x4u)
    {
        uint32_t bar0_high = pci_config_read32(g_device, 0x14);
        bar0 |= ((uint64_t)bar0_high << 32);
    }
    if (bar0 == 0)
    {
        igb_log("MMIO base is zero");
        return;
    }
    g_regs = (volatile uint8_t *)ioremap((paddr_t)bar0, (size_t)IGB_MMIO_BYTES);
    if (!g_regs)
    {
        igb_log("ioremap failed for MMIO");
        return;
    }

    pci_set_command_bits(g_device, 0x0006, 0); /* enable memory + bus master */

    igb_reset();
    igb_phy_restart_autoneg();

    uint32_t rah = igb_read32(IGB_REG_RAH0);
    uint32_t ral = igb_read32(IGB_REG_RAL0);
    g_mac[0] = (uint8_t)(ral & 0xFF);
    g_mac[1] = (uint8_t)((ral >> 8) & 0xFF);
    g_mac[2] = (uint8_t)((ral >> 16) & 0xFF);
    g_mac[3] = (uint8_t)((ral >> 24) & 0xFF);
    g_mac[4] = (uint8_t)(rah & 0xFF);
    g_mac[5] = (uint8_t)((rah >> 8) & 0xFF);
    uint32_t ral_new = (uint32_t)g_mac[0] |
                       ((uint32_t)g_mac[1] << 8) |
                       ((uint32_t)g_mac[2] << 16) |
                       ((uint32_t)g_mac[3] << 24);
    uint32_t rah_new = (uint32_t)g_mac[4] |
                       ((uint32_t)g_mac[5] << 8) |
                       IGB_RAH_AV;
    igb_write32(IGB_REG_RAL0, ral_new);
    igb_write32(IGB_REG_RAH0, rah_new);

    if (!igb_setup_rx() || !igb_setup_tx())
    {
        igb_log("ring init failed");
        return;
    }

    /* Ensure RX packet buffer is enabled with a reasonable size (128 KiB). */
    igb_write32(IGB_REG_RXPBSIZE0, 128U * 1024U);
    igb_write32(IGB_REG_MRQC, 1); /* enable RSS/queue steering, single queue */
    igb_write32(IGB_REG_VFRE, 0xFFFFU); /* allow delivery to PF/VF pool 0 */

    for (int i = 0; i < 128; ++i)
    {
        igb_write32(IGB_REG_MTA + (uint32_t)(i * 4), 0);
    }
    igb_write32(IGB_REG_RXCSUM, 0);
    igb_write32(IGB_REG_RDRXCTL, IGB_RDRXCTL_CRCSTRIP | IGB_RDRXCTL_DMAIDONE);
    igb_write32(IGB_REG_RXCTRL, IGB_RXCTRL_RXEN);

    uint32_t rctl = IGB_RCTL_EN | IGB_RCTL_BAM | IGB_RCTL_SECRC | IGB_RCTL_MPE | IGB_RCTL_UPE | IGB_RCTL_SBP | IGB_RCTL_BSIZE_2048;
    igb_write32(IGB_REG_RCTL, rctl);
    igb_write32(IGB_REG_RLPML, IGB_VMOLR_RLPML_MASK);
    uint32_t vmolr = IGB_VMOLR_AUPE | IGB_VMOLR_BAM | IGB_VMOLR_MPME | IGB_VMOLR_RLPML_MASK;
    igb_write32(IGB_REG_VMOLR0, vmolr);
    igb_write32(IGB_REG_RDH0, 0);
    igb_write32(IGB_REG_RDT0, IGB_RX_DESC_COUNT - 1);

    uint32_t tctl = IGB_TCTL_EN | IGB_TCTL_PSP | (0x10U << IGB_TCTL_CT_SHIFT) | (0x40U << IGB_TCTL_COLD_SHIFT);
    igb_write32(IGB_REG_TCTL, tctl);
    igb_write32(IGB_REG_TIPG, 0x0060200AU);

    /* Some emulations gate RX on STATUS.LU; try to force link-up in case PHY/AN bits lag. */
    uint32_t status = igb_read32(IGB_REG_STATUS);
    igb_write32(IGB_REG_STATUS, status | 0x00000002U);

    uint32_t ctrl = igb_read32(IGB_REG_CTRL);
    uint32_t rxctrl = igb_read32(IGB_REG_RXCTRL);
    uint32_t srrctl = igb_read32(IGB_REG_SRRCTL0);
    uint32_t rxdctl = igb_read32(IGB_REG_RXDCTL0);
    uint32_t rdrxctl = igb_read32(IGB_REG_RDRXCTL);
    uint32_t rxpbsize = igb_read32(IGB_REG_RXPBSIZE0);
    uint32_t mrqc = igb_read32(IGB_REG_MRQC);
    uint32_t vfre = igb_read32(IGB_REG_VFRE);
    serial_printf("igb: init CTRL=0x%08X STATUS=0x%08X RCTL=0x%08X RXCTRL=0x%08X SRRCTL=0x%08X RXDCTL=0x%08X RDRXCTL=0x%08X RXPBSIZE=0x%08X MRQC=0x%08X VFRE=0x%08X\r\n",
                  (unsigned)ctrl,
                  (unsigned)status,
                  (unsigned)rctl,
                  (unsigned)rxctrl,
                  (unsigned)srrctl,
                  (unsigned)rxdctl,
                  (unsigned)rdrxctl,
                  (unsigned)rxpbsize,
                  (unsigned)mrqc,
                  (unsigned)vfre);

    g_igb_present = true;
    if (!interrupts_register_irq_handler(11, igb_irq_handler, NULL))
    {
        igb_log("failed to register IRQ handler");
    }
    interrupts_enable_irq(11);

    g_iface = net_if_register("igb0", g_mac);
    if (g_iface)
    {
        net_if_set_link_up(g_iface, true);
        net_if_set_tx_handler(g_iface, igb_tx_send);
    }

    uint8_t vector = (uint8_t)(32 + 11);
    uint8_t apic = igb_select_msi_apic();
    if (pci_enable_msi(g_device, vector, apic))
    {
        serial_printf("[igb] MSI enabled vec=0x%02X apic=%u\r\n",
                      (unsigned)vector,
                      (unsigned)apic);
    }

    /*
     * Clear stale causes only after the handler and MSI/INTx route exist, then
     * enable receive causes.  TXDW is deliberately omitted: TCP ACK traffic
     * would otherwise generate a completion interrupt for every ACK frame.
     */
    (void)igb_read32(IGB_REG_ICR);
    igb_write32(IGB_REG_IAM, 0);
    uint32_t imr = IGB_IMS_RXDW | IGB_IMS_RXO | IGB_IMS_RXDMT0;
    igb_write32(IGB_REG_IMS, imr);
    uint32_t enabled_imr = igb_read32(IGB_REG_IMS);
    serial_printf("[igb] interrupt mask requested=0x%08X enabled=0x%08X mode=%s\r\n",
                  (unsigned)imr,
                  (unsigned)enabled_imr,
                  (pci_config_read16(g_device, 0x04) & 0x0400U) ? "msi" : "intx");

    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 100;
    }
    /* A slow watchdog recovers a genuinely missed interrupt; normal RX is IRQ-driven. */
    uint32_t interval = freq / 10U;
    if (interval == 0)
    {
        interval = 1;
    }
    (void)timer_register_periodic(igb_timer_task, NULL, interval);

    serial_printf("igb: found at bus %02X device %02X function %02X mmio=0x%llX\r\n",
                  (unsigned)g_device.bus,
                  (unsigned)g_device.device,
                  (unsigned)g_device.function,
                  (unsigned long long)bar0);
    uint16_t vid = pci_config_read16(g_device, 0x00);
    uint16_t did = pci_config_read16(g_device, 0x02);
    serial_printf("igb: pci vid=0x%04X did=0x%04X\r\n",
                  (unsigned)vid,
                  (unsigned)did);
    serial_printf("igb: mac %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                  (unsigned)g_mac[0],
                  (unsigned)g_mac[1],
                  (unsigned)g_mac[2],
                  (unsigned)g_mac[3],
                  (unsigned)g_mac[4],
                  (unsigned)g_mac[5]);
}

void igb_on_irq(void)
{
    if (!g_igb_present || !g_regs)
    {
        return;
    }
    uint32_t icr = igb_read32(IGB_REG_ICR);
    if (icr == 0)
    {
        return;
    }
    /* Reading ICR acknowledges the interrupt.  If it interrupted a generic
     * lock owner, leave descriptor work to the watchdog on a safe tick;
     * receive dispatch can wake threads and enter the scheduler. */
    if (spinlock_preempt_disabled())
    {
        return;
    }
    if (g_irq_log_budget > 0)
    {
        --g_irq_log_budget;
        uint32_t status = igb_read32(IGB_REG_STATUS);
        serial_printf("igb: irq icr=0x%08X status=0x%08X\r\n",
                      (unsigned)icr,
                      (unsigned)status);
    }

    igb_handle_receive();
    uint64_t flags = spinlock_lock_irqsave(&g_tx_lock);
    igb_reclaim_tx();
    spinlock_unlock_irqrestore(&g_tx_lock, flags);
    /* TCP maintenance runs in tcp_timerd to avoid IRQ-context polling. */
}

void igb_poll(void)
{
    if (!g_igb_present)
    {
        return;
    }
    igb_handle_receive();
    uint64_t flags = spinlock_lock_irqsave(&g_tx_lock);
    igb_reclaim_tx();
    spinlock_unlock_irqrestore(&g_tx_lock, flags);
}

bool igb_is_present(void)
{
    return g_igb_present;
}

bool igb_get_mac(uint8_t mac_out[6])
{
    if (!g_igb_present || !mac_out)
    {
        return false;
    }
    memcpy(mac_out, g_mac, 6);
    return true;
}

static inline uint32_t igb_read32(uint32_t offset)
{
    return *((volatile uint32_t *)(g_regs + offset));
}

static inline void igb_write32(uint32_t offset, uint32_t value)
{
    *((volatile uint32_t *)(g_regs + offset)) = value;
}

static bool igb_mdic_op(uint32_t reg, uint32_t data, uint32_t op, uint32_t *out)
{
    uint32_t cmd = (data & IGB_MDIC_DATA_MASK) |
                   ((reg << IGB_MDIC_REG_SHIFT) & IGB_MDIC_REG_MASK) |
                   ((IGB_PHY_ADDR << IGB_MDIC_PHY_SHIFT) & IGB_MDIC_PHY_MASK) |
                   op;
    igb_write32(IGB_REG_MDIC, cmd);
    for (int i = 0; i < 1000; ++i)
    {
        uint32_t v = igb_read32(IGB_REG_MDIC);
        if ((v & IGB_MDIC_READY) != 0)
        {
            if ((v & IGB_MDIC_ERROR) != 0)
            {
                return false;
            }
            if (out)
            {
                *out = v & IGB_MDIC_DATA_MASK;
            }
            return true;
        }
    }
    return false;
}

static bool igb_mdic_read(uint32_t reg, uint32_t *out)
{
    return igb_mdic_op(reg, 0, IGB_MDIC_OP_READ, out);
}

static bool igb_mdic_write(uint32_t reg, uint32_t data)
{
    return igb_mdic_op(reg, data, IGB_MDIC_OP_WRITE, NULL);
}

static void igb_phy_restart_autoneg(void)
{
    uint32_t bmcr = IGB_BMCR_SPEED1000 | IGB_BMCR_FULL_DUPLEX | IGB_BMCR_AN_ENABLE | IGB_BMCR_AN_RESTART;
    uint32_t current = 0;
    if (igb_mdic_read(IGB_MII_BMCR, &current))
    {
        bmcr |= (current & ~(IGB_BMCR_AN_RESTART | IGB_BMCR_AN_ENABLE));
    }
    (void)igb_mdic_write(IGB_MII_BMCR, bmcr);
}

static void igb_reset(void)
{
    igb_write32(IGB_REG_IMC, 0xFFFFFFFFU);
    igb_write32(IGB_REG_CTRL, IGB_CTRL_RST);
    for (int i = 0; i < 100000; ++i)
    {
        uint32_t ctrl = igb_read32(IGB_REG_CTRL);
        if ((ctrl & IGB_CTRL_RST) == 0)
        {
            break;
        }
    }
    igb_write32(IGB_REG_CTRL, IGB_CTRL_SLU | IGB_CTRL_ASDE);
}

static bool igb_setup_rx(void)
{
    memset(g_rx_desc, 0, sizeof(g_rx_desc));
    for (uint32_t i = 0; i < IGB_RX_DESC_COUNT; ++i)
    {
        g_rx_desc[i].read.packet_addr = (uint64_t)(uintptr_t)g_rx_buffers[i];
        g_rx_desc[i].read.header_addr = 0;
    }

    igb_write32(IGB_REG_RDBAL0, (uint32_t)(uintptr_t)g_rx_desc);
    igb_write32(IGB_REG_RDBAH0, 0);
    igb_write32(IGB_REG_RDLEN0, IGB_RX_DESC_COUNT * sizeof(igb_rx_desc_t));
    igb_write32(IGB_REG_RDBAL0_ALT, (uint32_t)(uintptr_t)g_rx_desc);
    igb_write32(IGB_REG_RDBAH0_ALT, 0);
    igb_write32(IGB_REG_RDLEN0_ALT, IGB_RX_DESC_COUNT * sizeof(igb_rx_desc_t));

    uint32_t srrctl = ((IGB_RX_BUFFER_SIZE >> IGB_SRRCTL_BSIZEPKT_SHIFT) & IGB_SRRCTL_BSIZEPKT_MASK) |
                      IGB_SRRCTL_DESCTYPE_ADV_ONEBUF;
    igb_write32(IGB_REG_SRRCTL0, srrctl);
    igb_write32(IGB_REG_SRRCTL0_ALT, srrctl);

    uint32_t rxdctl = IGB_RXDCTL_QUEUE_ENABLE | (8U) | (4U << 8) | (1U << 16) | (1U << 24);
    igb_write32(IGB_REG_RXDCTL0, rxdctl);
    igb_write32(IGB_REG_RXDCTL0_ALT, rxdctl);
    for (int i = 0; i < 10000; ++i)
    {
        if (igb_read32(IGB_REG_RXDCTL0) & IGB_RXDCTL_QUEUE_ENABLE)
        {
            break;
        }
    }

    igb_write32(IGB_REG_RDH0, 0);
    igb_write32(IGB_REG_RDT0, IGB_RX_DESC_COUNT - 1);
    igb_write32(IGB_REG_RDH0_ALT, 0);
    igb_write32(IGB_REG_RDT0_ALT, IGB_RX_DESC_COUNT - 1);
    g_rx_index = 0;
    return true;
}

static bool igb_setup_tx(void)
{
    memset(g_tx_desc, 0, sizeof(g_tx_desc));
    for (uint32_t i = 0; i < IGB_TX_DESC_COUNT; ++i)
    {
        g_tx_desc[i].addr = (uint64_t)(uintptr_t)g_tx_buffers[i];
        g_tx_desc[i].status = IGB_TX_STATUS_DD;
    }

    igb_write32(IGB_REG_TDBAL0, (uint32_t)(uintptr_t)g_tx_desc);
    igb_write32(IGB_REG_TDBAH0, 0);
    igb_write32(IGB_REG_TDLEN0, IGB_TX_DESC_COUNT * sizeof(igb_tx_desc_t));
    igb_write32(IGB_REG_TDBAL0_ALT, (uint32_t)(uintptr_t)g_tx_desc);
    igb_write32(IGB_REG_TDBAH0_ALT, 0);
    igb_write32(IGB_REG_TDLEN0_ALT, IGB_TX_DESC_COUNT * sizeof(igb_tx_desc_t));

    uint32_t txdctl = IGB_TXDCTL_QUEUE_ENABLE | (8U) | (4U << 8) | (1U << 16) | (1U << 24);
    igb_write32(IGB_REG_TXDCTL0, txdctl);
    igb_write32(IGB_REG_TXDCTL0_ALT, txdctl);
    for (int i = 0; i < 10000; ++i)
    {
        if (igb_read32(IGB_REG_TXDCTL0) & IGB_TXDCTL_QUEUE_ENABLE)
        {
            break;
        }
    }

    igb_write32(IGB_REG_TDH0, 0);
    igb_write32(IGB_REG_TDT0, 0);
    igb_write32(IGB_REG_TDH0_ALT, 0);
    igb_write32(IGB_REG_TDT0_ALT, 0);
    g_tx_head = 0;
    g_tx_clean = 0;
    return true;
}

static void igb_handle_receive(void)
{
    uint64_t flags = spinlock_lock_irqsave(&g_rx_lock);
    for (int safety = IGB_RX_DESC_COUNT; safety > 0; --safety)
    {
        igb_rx_desc_t *desc = &g_rx_desc[g_rx_index];
        uint32_t status = (uint32_t)desc->wb.upper.status_error;
        if ((status & IGB_RX_STATUS_DD) == 0)
        {
            igb_log_rx_idle(g_rx_index);
            break;
        }
        if ((status & IGB_RX_STATUS_EOP) == 0)
        {
            /* Should not happen with one-buffer descriptors. */
            desc->read.header_addr = 0;
            desc->read.packet_addr = (uint64_t)(uintptr_t)g_rx_buffers[g_rx_index];
            igb_write32(IGB_REG_RDT0, g_rx_index);
            g_rx_index = (g_rx_index + 1) % IGB_RX_DESC_COUNT;
            continue;
        }

        uint16_t frame_len = desc->wb.upper.length;
        uint16_t eth_type = 0;
        uint8_t *frame = g_rx_buffers[g_rx_index];
        if (frame_len >= 14)
        {
            eth_type = (uint16_t)((frame[12] << 8) | frame[13]);
        }
        igb_log_rx_debug(g_rx_index, frame_len, eth_type, status);

        if (g_iface)
        {
            net_if_record_rx(g_iface, frame_len);
        }

        if (frame_len >= 14)
        {
            if (eth_type == 0x0806)
            {
                if (g_iface)
                {
                    net_arp_handle_frame(g_iface, frame, frame_len);
                }
            }
            else if (eth_type == 0x0800)
            {
                if (g_iface)
                {
                    igb_dispatch_ipv4(g_iface, frame, frame_len);
                }
            }
        }

        desc->read.header_addr = 0;
        desc->read.packet_addr = (uint64_t)(uintptr_t)g_rx_buffers[g_rx_index];
        uint32_t cur = g_rx_index;
        g_rx_index = (g_rx_index + 1U) % IGB_RX_DESC_COUNT;
        igb_write32(IGB_REG_RDT0, cur);
    }
    spinlock_unlock_irqrestore(&g_rx_lock, flags);
}

static void igb_reclaim_tx(void)
{
    while (g_tx_clean != g_tx_head)
    {
        igb_tx_desc_t *desc = &g_tx_desc[g_tx_clean];
        if ((desc->status & IGB_TX_STATUS_DD) == 0)
        {
            break;
        }
        g_tx_clean = (g_tx_clean + 1) % IGB_TX_DESC_COUNT;
    }
}

static bool igb_tx_send(net_interface_t *iface, const uint8_t *data, size_t len)
{
    (void)iface;
    if (!g_igb_present || !data || len == 0)
    {
        return false;
    }
    if (len > IGB_TX_BUFFER_SIZE)
    {
        igb_log("tx frame too large");
        return false;
    }

    const uint8_t *payload = data;
    uint8_t *stack_clone = NULL;
    thread_t *stack_owner = process_find_stack_owner(data, len);
    if (stack_owner)
    {
        stack_clone = (uint8_t *)malloc(len);
        if (!stack_clone)
        {
            return false;
        }
        memcpy(stack_clone, data, len);
        payload = stack_clone;
    }

    bool ok = false;
    uint64_t flags = spinlock_lock_irqsave(&g_tx_lock);

    igb_reclaim_tx();

    uint32_t next_head = (g_tx_head + 1U) % IGB_TX_DESC_COUNT;
    if (next_head == g_tx_clean)
    {
        if (g_iface)
        {
            net_if_record_tx_error(g_iface);
        }
        goto out;
    }

    igb_tx_desc_t *desc = &g_tx_desc[g_tx_head];
    desc->status = 0;
    desc->length = (uint16_t)len;
    desc->cso = 0;
    desc->cmd = (uint8_t)(IGB_TX_CMD_EOP | IGB_TX_CMD_IFCS | IGB_TX_CMD_RS);
    memcpy(g_tx_buffers[g_tx_head], payload, len);
    desc->addr = (uint64_t)(uintptr_t)g_tx_buffers[g_tx_head];

    g_tx_head = next_head;
    igb_write32(IGB_REG_TDT0, g_tx_head);
    ok = true;

out:
    spinlock_unlock_irqrestore(&g_tx_lock, flags);
    if (stack_clone)
    {
        free(stack_clone);
    }
    return ok;
}

static void igb_dispatch_ipv4(net_interface_t *iface, uint8_t *frame, uint16_t frame_len)
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
        case 1:
            net_icmp_handle_frame(iface, frame, frame_len);
            break;
        case 6:
            net_tcp_handle_frame(iface, frame, frame_len);
            break;
        case 17:
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

static void igb_timer_task(void *context)
{
    (void)context;
    /* Polling is only a watchdog/deferred-IRQ fallback, never the fast path. */
    igb_poll();
}

static void igb_log_rx_debug(uint32_t idx, uint16_t len, uint16_t eth_type, uint32_t status)
{
    if (!IGB_DEBUG_LOG)
    {
        return;
    }
    if (g_rx_log_budget <= 0)
    {
        return;
    }
    --g_rx_log_budget;
    uint32_t rdh = igb_read32(IGB_REG_RDH0);
    uint32_t rdt = igb_read32(IGB_REG_RDT0);
    serial_printf("igb: rx idx=%u len=%u eth=0x%04X status=0x%08X rdh=%u rdt=%u\r\n",
                  (unsigned)idx,
                  (unsigned)len,
                  (unsigned)eth_type,
                  (unsigned)status,
                  (unsigned)rdh,
                  (unsigned)rdt);
}

static void igb_log_rx_idle(uint32_t idx)
{
    if (!IGB_DEBUG_LOG)
    {
        return;
    }
    if (g_rx_idle_log_budget <= 0)
    {
        return;
    }
    --g_rx_idle_log_budget;
    uint32_t rdh = igb_read32(IGB_REG_RDH0);
    uint32_t rdt = igb_read32(IGB_REG_RDT0);
    uint32_t ctrl = igb_read32(IGB_REG_CTRL);
    uint32_t status = igb_read32(IGB_REG_STATUS);
    uint32_t rctl = igb_read32(IGB_REG_RCTL);
    uint32_t srrctl = igb_read32(IGB_REG_SRRCTL0);
    uint32_t rxdctl = igb_read32(IGB_REG_RXDCTL0);
    uint32_t rdrxctl = igb_read32(IGB_REG_RDRXCTL);
    uint32_t rxpbsize = igb_read32(IGB_REG_RXPBSIZE0);
    uint32_t rdbal = igb_read32(IGB_REG_RDBAL0);
    uint32_t rdbah = igb_read32(IGB_REG_RDBAH0);
    uint32_t rxctrl = igb_read32(IGB_REG_RXCTRL);
    uint32_t mrqc = igb_read32(IGB_REG_MRQC);
    uint32_t vfre = igb_read32(IGB_REG_VFRE);
    uint32_t rdh_alt = igb_read32(IGB_REG_RDH0_ALT);
    uint32_t rdt_alt = igb_read32(IGB_REG_RDT0_ALT);
    uint32_t rdbal_alt = igb_read32(IGB_REG_RDBAL0_ALT);
    uint32_t rdbah_alt = igb_read32(IGB_REG_RDBAH0_ALT);
    uint32_t rxdctl_alt = igb_read32(IGB_REG_RXDCTL0_ALT);
    uint32_t desc_status = g_rx_desc[idx].wb.upper.status_error;
    uint16_t desc_len = g_rx_desc[idx].wb.upper.length;
    uint64_t desc_buf = g_rx_desc[idx].read.packet_addr;
    uint64_t desc_hdr = g_rx_desc[idx].read.header_addr;
    serial_printf("igb: rx idle idx=%u rdh=%u rdt=%u rdh2=%u rdt2=%u CTRL=0x%08X STATUS=0x%08X RCTL=0x%08X RXCTRL=0x%08X MRQC=0x%08X VFRE=0x%08X SRRCTL=0x%08X RXDCTL=0x%08X RXDCTL2=0x%08X RDRXCTL=0x%08X RXPBSIZE=0x%08X RDBAL=0x%08X RDBAH=0x%08X RDBAL2=0x%08X RDBAH2=0x%08X desc_status=0x%08X len=0x%04X buf=0x%llX hdr=0x%llX\r\n",
                  (unsigned)idx,
                  (unsigned)rdh,
                  (unsigned)rdt,
                  (unsigned)rdh_alt,
                  (unsigned)rdt_alt,
                  (unsigned)ctrl,
                  (unsigned)status,
                  (unsigned)rctl,
                  (unsigned)rxctrl,
                  (unsigned)mrqc,
                  (unsigned)vfre,
                  (unsigned)srrctl,
                  (unsigned)rxdctl,
                  (unsigned)rxdctl_alt,
                  (unsigned)rdrxctl,
                  (unsigned)rxpbsize,
                  (unsigned)rdbal,
                  (unsigned)rdbah,
                  (unsigned)rdbal_alt,
                  (unsigned)rdbah_alt,
                  (unsigned)desc_status,
                  (unsigned)desc_len,
                  (unsigned long long)desc_buf,
                  (unsigned long long)desc_hdr);
}

static uint8_t igb_select_msi_apic(void)
{
    return (uint8_t)lapic_get_id();
}

static void igb_log(const char *msg)
{
    serial_printf("igb: %s\r\n", msg ? msg : "<null>");
}
