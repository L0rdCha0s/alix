#include "ahci.h"
#include "block.h"
#include "heap.h"
#include "libc.h"
#include "pci.h"
#include "serial.h"
#include "types.h"
#include "interrupts.h"
#include "process.h"

#define AHCI_MAX_PORTS            32
#define AHCI_MAX_COMMANDS         32
#define AHCI_SECTOR_SIZE          512
#define AHCI_MAX_PRDT_ENTRIES     8
#define AHCI_PRDT_MAX_BYTES       (4 * 1024 * 1024)
#define AHCI_MAX_TRANSFER_SECTORS 0xFFFFU
#define AHCI_CMD_FIS_LENGTH_DW    5
#define AHCI_CMD_TIMEOUT          1000000U
#define AHCI_COMRESET_DELAY       1000U

#define HBA_GHC_HR   (1U << 0)
#define HBA_GHC_IE   (1U << 1)
#define HBA_GHC_AE   (1U << 31)

#define HBA_PORT_DEV_PRESENT 0x3
#define HBA_PORT_IPM_ACTIVE  0x1

#define HBA_PORT_SIG_SATA 0x00000101

#define HBA_PxCMD_ST    (1U << 0)
#define HBA_PxCMD_SUD   (1U << 1)
#define HBA_PxCMD_POD   (1U << 2)
#define HBA_PxCMD_FRE   (1U << 4)
#define HBA_PxCMD_FR    (1U << 14)
#define HBA_PxCMD_CR    (1U << 15)

#define HBA_PxIS_DHRS   (1U << 0)
#define HBA_PxIS_PSS    (1U << 1)
#define HBA_PxIS_DSS    (1U << 2)
#define HBA_PxIS_SDBS   (1U << 3)
#define HBA_PxIS_TFES   (1U << 30)

#define HBA_PxSCTL_DET_MASK 0xF
#define HBA_PxSCTL_DET_INIT 0x1

#define HBA_BOHC_BOS    (1U << 0)
#define HBA_BOHC_OOS    (1U << 1)

#define FIS_TYPE_REG_H2D 0x27
#define ATA_CMD_READ_DMA_EXT  0x25
#define ATA_CMD_WRITE_DMA_EXT 0x35

#define ATA_CMD_IDENTIFY 0xEC

#define ATA_DEV_BUSY 0x80
#define ATA_DEV_DRQ  0x08

typedef volatile struct
{
    uint32_t clb;
    uint32_t clbu;
    uint32_t fb;
    uint32_t fbu;
    uint32_t is;
    uint32_t ie;
    uint32_t cmd;
    uint32_t rsv0;
    uint32_t tfd;
    uint32_t sig;
    uint32_t ssts;
    uint32_t sctl;
    uint32_t serr;
    uint32_t sact;
    uint32_t ci;
    uint32_t sntf;
    uint32_t fbs;
    uint32_t rsv1[11];
    uint32_t vendor[4];
} hba_port_t;

typedef volatile struct
{
    uint32_t cap;
    uint32_t ghc;
    uint32_t is;
    uint32_t pi;
    uint32_t vs;
    uint32_t ccc_ctl;
    uint32_t ccc_ports;
    uint32_t em_loc;
    uint32_t em_ctl;
    uint32_t cap2;
    uint32_t bohc;
    uint8_t  rsv[0xA0 - 0x2C];
    uint8_t  vendor[0x100 - 0xA0];
    hba_port_t ports[32];
} hba_mem_t;

typedef struct
{
    uint32_t dba;
    uint32_t dbau;
    uint32_t rsv0;
    uint32_t dbc:22;
    uint32_t rsv1:9;
    uint32_t i:1;
} hba_prdt_entry_t;

typedef struct
{
    uint8_t cfis[64];
    uint8_t acmd[16];
    uint8_t rsv[48];
    hba_prdt_entry_t prdt_entry[AHCI_MAX_PRDT_ENTRIES];
} hba_cmd_tbl_t;

typedef struct
{
    uint16_t cfl:5;
    uint16_t atapi:1;
    uint16_t write:1;
    uint16_t prefetchable:1;
    uint16_t reset:1;
    uint16_t bist:1;
    uint16_t clear_busy:1;
    uint16_t rsv0:1;
    uint16_t pmp:4;
    uint16_t prdtl;
    uint32_t prdbc;
    uint32_t ctba;
    uint32_t ctbau;
    uint32_t rsv1[4];
} hba_cmd_header_t;

typedef struct
{
    hba_port_t *port;
    hba_cmd_header_t *cmd_headers;
    hba_cmd_tbl_t *cmd_tables[AHCI_MAX_COMMANDS];
    uint8_t *fis;
    uint8_t port_no;
    block_device_t *block;
    volatile bool waiting;
    volatile bool wait_success;
    uint32_t wait_slot_mask;
} ahci_port_ctx_t;

static volatile hba_mem_t *g_hba = NULL;
static ahci_port_ctx_t *g_ahci_ports[AHCI_MAX_PORTS] = { 0 };
static uint8_t g_ahci_irq_line = 10;
static bool g_ahci_irq_ready = false;
static bool g_ahci_use_interrupts = false;

static void ahci_log(const char *msg)
{
    serial_write_string("[ahci] ");
    serial_write_string(msg ? msg : "(null)");
    serial_write_string("\r\n");
}

static void ahci_log_hex(const char *msg, uint64_t value)
{
    serial_write_string("[ahci] ");
    if (msg)
    {
        serial_write_string(msg);
    }
    serial_write_string("0x");
    serial_write_hex64(value);
    serial_write_string("\r\n");
}

static void ahci_log_port(uint32_t port_no, const char *msg)
{
    serial_write_string("[ahci] port ");
    serial_write_hex64(port_no);
    serial_write_string(": ");
    serial_write_string(msg ? msg : "(null)");
    serial_write_string("\r\n");
}

static void ahci_log_port_hex(uint32_t port_no, const char *msg, uint64_t value)
{
    serial_write_string("[ahci] port ");
    serial_write_hex64(port_no);
    serial_write_string(": ");
    if (msg)
    {
        serial_write_string(msg);
    }
    serial_write_string("0x");
    serial_write_hex64(value);
    serial_write_string("\r\n");
}

static void ahci_request_os_ownership(void)
{
    if (!g_hba)
    {
        return;
    }
    if (!(g_hba->cap2 & 1U))
    {
        return;
    }
    g_hba->bohc |= HBA_BOHC_OOS;
    for (uint32_t i = 0; i < AHCI_CMD_TIMEOUT; ++i)
    {
        if ((g_hba->bohc & HBA_BOHC_BOS) == 0)
        {
            ahci_log("claimed ownership from BIOS");
            return;
        }
    }
    ahci_log("BIOS ownership release timed out");
}

static bool ahci_reset_controller(void)
{
    if (!g_hba)
    {
        return false;
    }
    g_hba->ghc |= HBA_GHC_HR;
    for (uint32_t i = 0; i < AHCI_CMD_TIMEOUT; ++i)
    {
        if ((g_hba->ghc & HBA_GHC_HR) == 0)
        {
            g_hba->ghc |= HBA_GHC_AE;
            g_hba->ghc &= ~HBA_GHC_IE;
            g_hba->is = (uint32_t)~0U;
            ahci_log("controller reset complete");
            return true;
        }
    }
    ahci_log("controller reset timeout");
    return false;
}

static bool ahci_issue_cmd(ahci_port_ctx_t *ctx,
                           uint8_t command,
                           uint64_t lba,
                           uint32_t count,
                           void *buffer,
                           bool write);
static bool ahci_identify_port(ahci_port_ctx_t *ctx, uint16_t *identify);
static void ahci_handle_port_irq(uint32_t port_no);

static void *alloc_aligned(size_t size, size_t align)
{
    size_t total = size + align + sizeof(uintptr_t);
    uint8_t *raw = (uint8_t *)malloc(total);
    if (!raw)
    {
        return NULL;
    }
    uintptr_t addr = (uintptr_t)(raw + sizeof(uintptr_t));
    uintptr_t aligned = (addr + (align - 1)) & ~(uintptr_t)(align - 1);
    ((uintptr_t *)aligned)[-1] = (uintptr_t)raw;
    memset((void *)aligned, 0, size);
    return (void *)aligned;
}

static void free_aligned(void *ptr)
{
    if (!ptr)
    {
        return;
    }
    uintptr_t raw = ((uintptr_t *)ptr)[-1];
    free((void *)raw);
}

static void ahci_spin_delay(uint32_t loops)
{
    for (volatile uint32_t i = 0; i < loops; ++i)
    {
        __asm__ volatile ("" ::: "memory");
    }
}
static void ahci_port_stop(hba_port_t *port)
{
    port->cmd &= ~(HBA_PxCMD_ST | HBA_PxCMD_FRE);
    while (port->cmd & (HBA_PxCMD_FR | HBA_PxCMD_CR))
    {
    }
}

static void ahci_port_start(hba_port_t *port)
{
    while (port->cmd & HBA_PxCMD_CR)
    {
    }
    port->cmd |= (HBA_PxCMD_SUD | HBA_PxCMD_POD);
    port->cmd |= HBA_PxCMD_FRE;
    port->cmd |= HBA_PxCMD_ST;
}

static bool ahci_port_status_device(uint32_t ssts)
{
    uint8_t det = (uint8_t)(ssts & 0x0F);
    uint8_t ipm = (uint8_t)((ssts >> 8) & 0x0F);
    return det == HBA_PORT_DEV_PRESENT && ipm == HBA_PORT_IPM_ACTIVE;
}

static bool ahci_port_wait_device(hba_port_t *port)
{
    for (uint32_t i = 0; i < AHCI_CMD_TIMEOUT; ++i)
    {
        uint32_t ssts = port->ssts;
        if (ahci_port_status_device(ssts))
        {
            return true;
        }
    }
    return false;
}

static void ahci_port_comreset(hba_port_t *port)
{
    if (!port)
    {
        return;
    }
    ahci_port_stop(port);
    uint32_t sctl = port->sctl;
    port->sctl = (sctl & ~HBA_PxSCTL_DET_MASK) | HBA_PxSCTL_DET_INIT;
    ahci_spin_delay(AHCI_COMRESET_DELAY);
    port->sctl = sctl & ~HBA_PxSCTL_DET_MASK;
    ahci_spin_delay(AHCI_COMRESET_DELAY);
}

static bool ahci_port_device_present(hba_port_t *port, uint32_t port_no)
{
    if (!port)
    {
        return false;
    }
    uint32_t initial_ssts = port->ssts;
    ahci_log_port_hex(port_no, "ssts before spin-up: ", initial_ssts);
    if (initial_ssts == 0)
    {
        ahci_log_port(port_no, "ssts zero, skipping");
        return false;
    }
    port->cmd |= (HBA_PxCMD_SUD | HBA_PxCMD_POD);
    if (ahci_port_wait_device(port))
    {
        ahci_log_port_hex(port_no, "link ready ssts=", port->ssts);
        return true;
    }
    ahci_port_comreset(port);
    port->cmd |= (HBA_PxCMD_SUD | HBA_PxCMD_POD);
    bool ready = ahci_port_wait_device(port);
    if (ready)
    {
        ahci_log_port_hex(port_no, "link ready after COMRESET ssts=", port->ssts);
    }
    else
    {
        ahci_log_port_hex(port_no, "link failed to come ready ssts=", port->ssts);
    }
    return ready;
}

static int ahci_port_find_slot(hba_port_t *port)
{
    uint32_t slots = port->sact | port->ci;
    for (int i = 0; i < AHCI_MAX_COMMANDS; ++i)
    {
        if (!(slots & (1U << i)))
        {
            return i;
        }
    }
    return -1;
}

static void ahci_port_release(ahci_port_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }
    if (ctx->cmd_headers)
    {
        free_aligned((void *)ctx->cmd_headers);
        ctx->cmd_headers = NULL;
    }
    if (ctx->fis)
    {
        free_aligned(ctx->fis);
        ctx->fis = NULL;
    }
    for (int i = 0; i < AHCI_MAX_COMMANDS; ++i)
    {
        if (ctx->cmd_tables[i])
        {
            free_aligned(ctx->cmd_tables[i]);
            ctx->cmd_tables[i] = NULL;
        }
    }
    g_ahci_ports[ctx->port_no] = NULL;
    free(ctx);
}

static void ahci_handle_port_irq(uint32_t port_no)
{
    if (port_no >= AHCI_MAX_PORTS)
    {
        return;
    }
    ahci_port_ctx_t *ctx = g_ahci_ports[port_no];
    if (!ctx || !ctx->port)
    {
        return;
    }
    hba_port_t *port = ctx->port;
    uint32_t status = port->is;
    if (!status)
    {
        return;
    }
    port->is = status;
#if 1
    ahci_log_port_hex(port_no, "irq PxIS=", status);
#endif
    if (status & HBA_PxIS_TFES)
    {
        ctx->wait_success = false;
        ctx->waiting = false;
        port->serr = (uint32_t)~0U;
        return;
    }
    if (ctx->waiting && !(port->ci & ctx->wait_slot_mask))
    {
        ctx->wait_success = true;
        ctx->waiting = false;
    }
}

static bool ahci_port_configure(ahci_port_ctx_t *ctx)
{
    hba_port_t *port = ctx->port;
    ahci_port_stop(port);

    ctx->cmd_headers = (hba_cmd_header_t *)alloc_aligned(sizeof(hba_cmd_header_t) * AHCI_MAX_COMMANDS, 1024);
    ctx->fis = (uint8_t *)alloc_aligned(256, 256);
    if (!ctx->cmd_headers || !ctx->fis)
    {
        return false;
    }
    memset((void *)ctx->cmd_headers, 0, sizeof(hba_cmd_header_t) * AHCI_MAX_COMMANDS);
    memset(ctx->fis, 0, 256);

    port->clb = (uint32_t)(uintptr_t)ctx->cmd_headers;
    port->clbu = (uint32_t)((uintptr_t)ctx->cmd_headers >> 32);
    port->fb = (uint32_t)(uintptr_t)ctx->fis;
    port->fbu = (uint32_t)((uintptr_t)ctx->fis >> 32);

    for (int i = 0; i < AHCI_MAX_COMMANDS; ++i)
    {
        ctx->cmd_tables[i] = (hba_cmd_tbl_t *)alloc_aligned(sizeof(hba_cmd_tbl_t), 256);
        if (!ctx->cmd_tables[i])
        {
            return false;
        }
        memset(ctx->cmd_tables[i], 0, sizeof(hba_cmd_tbl_t));
        uintptr_t ctba = (uintptr_t)ctx->cmd_tables[i];
        ctx->cmd_headers[i].ctba = (uint32_t)ctba;
        ctx->cmd_headers[i].ctbau = (uint32_t)(ctba >> 32);
    }

    port->is = (uint32_t)~0U;
    port->serr = (uint32_t)~0U;
    port->ie = HBA_PxIS_DHRS | HBA_PxIS_PSS | HBA_PxIS_DSS | HBA_PxIS_SDBS | HBA_PxIS_TFES;
    port->sact = 0;
    port->ci = 0;
    port->cmd |= (HBA_PxCMD_SUD | HBA_PxCMD_POD);

    ahci_port_start(port);
    return true;
}

static bool ahci_wait_ready(hba_port_t *port)
{
    for (uint32_t i = 0; i < 1000000; ++i)
    {
        uint32_t tfd = port->tfd;
        if (!(tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)))
        {
            return true;
        }
    }
    return false;
}

static bool ahci_issue_cmd(ahci_port_ctx_t *ctx,
                           uint8_t command,
                           uint64_t lba,
                           uint32_t count,
                           void *buffer,
                           bool write)
{
    hba_port_t *port = ctx->port;
    if (!buffer)
    {
        return false;
    }
    if (count > AHCI_MAX_TRANSFER_SECTORS)
    {
        return false;
    }
    if (!ahci_wait_ready(port))
    {
        return false;
    }

    int slot = ahci_port_find_slot(port);
    if (slot < 0)
    {
        return false;
    }

    hba_cmd_header_t *hdr = &ctx->cmd_headers[slot];
    hdr->cfl = AHCI_CMD_FIS_LENGTH_DW;
    hdr->atapi = 0;
    hdr->write = write ? 1 : 0;
    hdr->prdbc = 0;

    hba_cmd_tbl_t *tbl = ctx->cmd_tables[slot];
    memset(tbl, 0, sizeof(hba_cmd_tbl_t));

    uintptr_t buf_addr = (uintptr_t)buffer;
    uint64_t total_bytes = count ? ((uint64_t)count * AHCI_SECTOR_SIZE) : AHCI_SECTOR_SIZE;
    uint32_t prdt_index = 0;
    while (total_bytes && prdt_index < AHCI_MAX_PRDT_ENTRIES)
    {
        uint32_t chunk = (total_bytes > AHCI_PRDT_MAX_BYTES) ? AHCI_PRDT_MAX_BYTES : (uint32_t)total_bytes;
        hba_prdt_entry_t *entry = &tbl->prdt_entry[prdt_index];
        entry->dba = (uint32_t)buf_addr;
        entry->dbau = (uint32_t)(buf_addr >> 32);
        entry->dbc = chunk - 1;
        entry->i = (total_bytes <= chunk) ? 1 : 0;
        buf_addr += chunk;
        total_bytes -= chunk;
        ++prdt_index;
    }
    if (total_bytes)
    {
        return false;
    }
    hdr->prdtl = (uint16_t)prdt_index;

    uint8_t *cfis = tbl->cfis;
    memset(cfis, 0, sizeof(tbl->cfis));
    cfis[0] = FIS_TYPE_REG_H2D;
    cfis[1] = (1U << 7);
    cfis[2] = command;
    cfis[3] = 0;
    cfis[4] = (uint8_t)(lba & 0xFF);
    cfis[5] = (uint8_t)((lba >> 8) & 0xFF);
    cfis[6] = (uint8_t)((lba >> 16) & 0xFF);
    cfis[7] = (1U << 6);
    cfis[8] = (uint8_t)((lba >> 24) & 0xFF);
    cfis[9] = (uint8_t)((lba >> 32) & 0xFF);
    cfis[10] = (uint8_t)((lba >> 40) & 0xFF);
    cfis[12] = (uint8_t)(count & 0xFF);
    cfis[13] = (uint8_t)((count >> 8) & 0xFF);

    port->is = (uint32_t)~0U;
    ctx->wait_slot_mask = (uint32_t)(1U << slot);
    ctx->wait_success = false;
    bool use_irq = g_ahci_use_interrupts;
    ctx->waiting = use_irq;
    port->ci |= ctx->wait_slot_mask;
    if (use_irq)
    {
        ahci_log_port_hex(ctx->port_no, "waiting on slot mask ", ctx->wait_slot_mask);
    }

    if (use_irq)
    {
        uint32_t timeout = AHCI_CMD_TIMEOUT;
        while (ctx->waiting && timeout--)
        {
            process_yield();
        }
        if (ctx->waiting)
        {
            ctx->waiting = false;
            ahci_log_port(ctx->port_no, "irq wait timed out");
            use_irq = false;
        }
        if (ctx->wait_success)
        {
            return true;
        }
        ahci_log_port(ctx->port_no, "irq wait failed, retrying with polling");
    }

    while (port->ci & ctx->wait_slot_mask)
    {
        if (port->is & HBA_PxIS_TFES)
        {
            port->is = HBA_PxIS_TFES;
            return false;
        }
    }
    if (port->is & HBA_PxIS_TFES)
    {
        port->is = HBA_PxIS_TFES;
        return false;
    }
    return true;
}

static bool ahci_block_read(block_device_t *device, uint64_t lba, uint32_t count, void *buffer)
{
    ahci_port_ctx_t *ctx = (ahci_port_ctx_t *)device->driver_data;
    uint8_t *dst = (uint8_t *)buffer;
    if (!count)
    {
        return true;
    }
    while (count > 0)
    {
        uint32_t chunk = (count > AHCI_MAX_TRANSFER_SECTORS) ? AHCI_MAX_TRANSFER_SECTORS : count;
        if (!ahci_issue_cmd(ctx, ATA_CMD_READ_DMA_EXT, lba, chunk, dst, false))
        {
            return false;
        }
        lba += chunk;
        dst += chunk * device->sector_size;
        count -= chunk;
    }
    return true;
}

static bool ahci_block_write(block_device_t *device, uint64_t lba, uint32_t count, const void *buffer)
{
    ahci_port_ctx_t *ctx = (ahci_port_ctx_t *)device->driver_data;
    const uint8_t *src = (const uint8_t *)buffer;
    if (!count)
    {
        return true;
    }
    while (count > 0)
    {
        uint32_t chunk = (count > AHCI_MAX_TRANSFER_SECTORS) ? AHCI_MAX_TRANSFER_SECTORS : count;
        if (!ahci_issue_cmd(ctx, ATA_CMD_WRITE_DMA_EXT, lba, chunk, (void *)src, true))
        {
            return false;
        }
        lba += chunk;
        src += chunk * device->sector_size;
        count -= chunk;
    }
    return true;
}

static void ahci_init_port(volatile hba_mem_t *hba, uint32_t port_no)
{
    hba_port_t *port = &hba->ports[port_no];
    if (!ahci_port_device_present(port, port_no))
    {
        ahci_log_port(port_no, "no device detected");
        return;
    }
    uint32_t ssts = port->ssts;
    if (!ahci_port_status_device(ssts))
    {
        ahci_log_port(port_no, "device status check failed");
        return;
    }
    ahci_port_ctx_t *ctx = (ahci_port_ctx_t *)calloc(1, sizeof(ahci_port_ctx_t));
    if (!ctx)
    {
        serial_write_string("[ahci] failed to allocate port context\r\n");
        return;
    }
    ctx->port = (hba_port_t *)port;
    ctx->port_no = (uint8_t)port_no;
    ctx->waiting = false;
    ctx->wait_success = false;
    ctx->wait_slot_mask = 0;
    g_ahci_ports[port_no] = ctx;

    if (!ahci_port_configure(ctx))
    {
        ahci_log_port(port_no, "port configure failed");
        ahci_port_release(ctx);
        return;
    }

    uint32_t signature = port->sig;
    for (uint32_t i = 0; i < AHCI_CMD_TIMEOUT && (!signature || signature == 0xFFFFFFFF); ++i)
    {
        signature = port->sig;
    }
    if (signature != HBA_PORT_SIG_SATA)
    {
        ahci_log_port_hex(port_no, "unsupported signature ", signature);
        ahci_port_release(ctx);
        return;
    }

    uint16_t *identify = (uint16_t *)malloc(AHCI_SECTOR_SIZE);
    if (!identify)
    {
        ahci_port_release(ctx);
        return;
    }
    bool ok = ahci_identify_port(ctx, identify);
    if (!ok)
    {
        ahci_log_port(port_no, "IDENTIFY failed");
        free(identify);
        ahci_port_release(ctx);
        return;
    }

    uint64_t sectors = ((uint64_t)identify[103] << 48) |
                       ((uint64_t)identify[102] << 32) |
                       ((uint64_t)identify[101] << 16) |
                       identify[100];
    if (sectors == 0)
    {
        sectors = ((uint32_t)identify[61] << 16) | identify[60];
    }
    free(identify);
    if (!sectors)
    {
        sectors = 0x800000;
    }

    char name[16];
    memset(name, 0, sizeof(name));
    const char prefix[] = "ahci";
    size_t pos = 0;
    while (prefix[pos] && pos + 1 < sizeof(name))
    {
        name[pos] = prefix[pos];
        pos++;
    }
    uint32_t tmp = port_no;
    char digits[6];
    size_t dpos = 0;
    if (tmp == 0)
    {
        digits[dpos++] = '0';
    }
    else
    {
        while (tmp > 0 && dpos < sizeof(digits))
        {
            digits[dpos++] = (char)('0' + (tmp % 10));
            tmp /= 10;
        }
    }
    while (dpos > 0 && pos + 1 < sizeof(name))
    {
        name[pos++] = digits[--dpos];
    }
    name[pos] = '\0';
    block_device_t *blk = block_register(name, AHCI_SECTOR_SIZE, sectors, ahci_block_read, ahci_block_write, ctx);
    if (blk)
    {
        ctx->block = blk;
        ahci_log_port(port_no, "registered block device");
        ahci_log_port_hex(port_no, "sectors=", sectors);
        return;
    }

    ahci_log_port(port_no, "failed to register block device");
    ahci_port_release(ctx);
}

static bool pci_find_ahci(pci_device_t *out)
{
    for (uint16_t bus = 0; bus < 256; ++bus)
    {
        for (uint8_t dev = 0; dev < 32; ++dev)
        {
            for (uint8_t func = 0; func < 8; ++func)
            {
                pci_device_t candidate = { .bus = (uint8_t)bus, .device = dev, .function = func };
                uint16_t vendor = pci_config_read16(candidate, 0x00);
                if (vendor == 0xFFFF)
                {
                    if (func == 0)
                    {
                        break;
                    }
                    continue;
                }
                uint32_t class_prog = pci_config_read32(candidate, 0x08);
                uint8_t class_code = (uint8_t)(class_prog >> 24);
                uint8_t subclass = (uint8_t)(class_prog >> 16);
                uint8_t prog_if = (uint8_t)(class_prog >> 8);
                if (class_code == 0x01 && subclass == 0x06 && prog_if == 0x01)
                {
                    if (out)
                    {
                        *out = candidate;
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

void ahci_init(void)
{
    pci_device_t dev;
    if (!pci_find_ahci(&dev))
    {
        serial_write_string("[ahci] controller not found\r\n");
        return;
    }

    pci_set_command_bits(dev, 0x7, 0);
    uint64_t bdf = ((uint64_t)dev.bus << 16) | ((uint64_t)dev.device << 8) | dev.function;
    ahci_log_hex("controller PCI bdf=", bdf);
    uint32_t bar5 = pci_config_read32(dev, 0x24) & ~0xF;
    ahci_log_hex("controller BAR5=", bar5);
    if (!bar5)
    {
        serial_write_string("[ahci] BAR5 invalid\r\n");
        return;
    }
    g_hba = (volatile hba_mem_t *)(uintptr_t)bar5;
    if (!g_hba)
    {
        serial_write_string("[ahci] BAR5 invalid\r\n");
        return;
    }

    ahci_request_os_ownership();
    if (!ahci_reset_controller())
    {
        return;
    }

    uint8_t irq_line = pci_config_read8(dev, 0x3C);
    if (irq_line == 0 || irq_line == 0xFF)
    {
        irq_line = 11;
        pci_config_write8(dev, 0x3C, irq_line);
    }
    g_ahci_irq_line = irq_line;

    uint32_t pi = g_hba->pi;
    ahci_log_hex("port implemented mask=", pi);
    for (uint32_t i = 0; i < AHCI_MAX_PORTS; ++i)
    {
        if (pi & (1U << i))
        {
            ahci_init_port(g_hba, i);
        }
    }
}
static bool ahci_identify_port(ahci_port_ctx_t *ctx, uint16_t *identify)
{
    return ahci_issue_cmd(ctx, ATA_CMD_IDENTIFY, 0, 0, identify, false);
}

void ahci_on_irq(void)
{
    if (!g_hba)
    {
        return;
    }
    uint32_t pending = g_hba->is;
    if (!pending)
    {
        return;
    }
    ahci_log_hex("irq PxIS mask=", pending);
    g_hba->is = pending;
    for (uint32_t port_no = 0; port_no < AHCI_MAX_PORTS; ++port_no)
    {
        if (pending & (1U << port_no))
        {
            ahci_handle_port_irq(port_no);
        }
    }
}

void ahci_interrupts_activate(void)
{
    if (!g_hba || g_ahci_irq_ready)
    {
        return;
    }
    ahci_log_hex("enabling IRQ line=", g_ahci_irq_line);
    interrupts_enable_irq(g_ahci_irq_line);
    g_hba->ghc |= HBA_GHC_IE;
    g_ahci_irq_ready = true;
    g_ahci_use_interrupts = true;
}
