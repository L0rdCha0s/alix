#include "ahci.h"
#include "block.h"
#include "heap.h"
#include "libc.h"
#include "pci.h"
#include "serial.h"
#include "types.h"

#define HBA_PORT_DEV_PRESENT 0x3
#define HBA_PORT_IPM_ACTIVE  0x1

#define HBA_PORT_SIG_SATA 0x00000101

#define HBA_PxCMD_ST    (1U << 0)
#define HBA_PxCMD_FRE   (1U << 4)
#define HBA_PxCMD_FR    (1U << 14)
#define HBA_PxCMD_CR    (1U << 15)

#define HBA_PxIS_TFES   (1U << 30)

#define FIS_TYPE_REG_H2D 0x27
#define ATA_CMD_READ_DMA_EXT  0x25
#define ATA_CMD_WRITE_DMA_EXT 0x35

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
    hba_prdt_entry_t prdt_entry[1];
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
    hba_cmd_tbl_t *cmd_tables[32];
    uint8_t *fis;
    uint8_t port_no;
    block_device_t *block;
} ahci_port_ctx_t;

static volatile hba_mem_t *g_hba = NULL;

static bool ahci_issue_cmd(ahci_port_ctx_t *ctx,
                           uint8_t command,
                           uint64_t lba,
                           uint32_t count,
                           void *buffer,
                           bool write);
static bool ahci_identify_port(ahci_port_ctx_t *ctx, uint16_t *identify);

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
    port->cmd |= HBA_PxCMD_FRE;
    port->cmd |= HBA_PxCMD_ST;
}

static int ahci_port_find_slot(hba_port_t *port)
{
    uint32_t slots = port->sact | port->ci;
    for (int i = 0; i < 32; ++i)
    {
        if (!(slots & (1U << i)))
        {
            return i;
        }
    }
    return -1;
}

static bool ahci_port_configure(ahci_port_ctx_t *ctx)
{
    hba_port_t *port = ctx->port;
    ahci_port_stop(port);

    ctx->cmd_headers = (hba_cmd_header_t *)alloc_aligned(1024, 1024);
    ctx->fis = (uint8_t *)alloc_aligned(256, 256);
    if (!ctx->cmd_headers || !ctx->fis)
    {
        return false;
    }
    memset((void *)ctx->cmd_headers, 0, 1024);
    memset(ctx->fis, 0, 256);

    port->clb = (uint32_t)(uintptr_t)ctx->cmd_headers;
    port->clbu = (uint32_t)((uintptr_t)ctx->cmd_headers >> 32);
    port->fb = (uint32_t)(uintptr_t)ctx->fis;
    port->fbu = (uint32_t)((uintptr_t)ctx->fis >> 32);

    for (int i = 0; i < 32; ++i)
    {
        ctx->cmd_tables[i] = (hba_cmd_tbl_t *)alloc_aligned(sizeof(hba_cmd_tbl_t), 256);
        if (!ctx->cmd_tables[i])
        {
            return false;
        }
        memset(ctx->cmd_tables[i], 0, sizeof(hba_cmd_tbl_t));
        ctx->cmd_headers[i].prdtl = 1;
        uintptr_t ctba = (uintptr_t)ctx->cmd_tables[i];
        ctx->cmd_headers[i].ctba = (uint32_t)ctba;
        ctx->cmd_headers[i].ctbau = (uint32_t)(ctba >> 32);
    }

    ahci_port_start(port);
    return true;
}

static bool ahci_wait_ready(hba_port_t *port)
{
    for (uint32_t i = 0; i < 1000000; ++i)
    {
        uint32_t tfd = port->tfd;
        if (!(tfd & (0x80 | 0x08)))
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
    hdr->cfl = 5;
    hdr->write = write ? 1 : 0;
    hdr->prdtl = 1;
    hdr->prdbc = 0;

    hba_cmd_tbl_t *tbl = ctx->cmd_tables[slot];
    memset(tbl, 0, sizeof(hba_cmd_tbl_t));

    uintptr_t buf_addr = (uintptr_t)buffer;
    tbl->prdt_entry[0].dba = (uint32_t)buf_addr;
    tbl->prdt_entry[0].dbau = (uint32_t)(buf_addr >> 32);
    uint32_t bytes = count ? count * 512 : 512;
    tbl->prdt_entry[0].dbc = bytes - 1;
    tbl->prdt_entry[0].i = 1;

    uint8_t *cfis = tbl->cfis;
    memset(cfis, 0, 64);
    cfis[0] = FIS_TYPE_REG_H2D;
    cfis[1] = (1U << 7);
    cfis[2] = command;
    cfis[3] = 0;
    cfis[4] = (uint8_t)(lba & 0xFF);
    cfis[5] = (uint8_t)((lba >> 8) & 0xFF);
    cfis[6] = (uint8_t)((lba >> 16) & 0xFF);
    cfis[7] = 0;
    cfis[8] = (uint8_t)((lba >> 24) & 0xFF);
    cfis[9] = (uint8_t)((lba >> 32) & 0xFF);
    cfis[10] = (uint8_t)((lba >> 40) & 0xFF);
    cfis[12] = (uint8_t)(count & 0xFF);
    cfis[13] = (uint8_t)((count >> 8) & 0xFF);

    port->is = (uint32_t)-1;
    port->ci |= (1U << slot);

    while (port->ci & (1U << slot))
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
    while (count > 0)
    {
        uint32_t chunk = (count > 32) ? 32 : count;
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
    while (count > 0)
    {
        uint32_t chunk = (count > 32) ? 32 : count;
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
    uint32_t ssts = port->ssts;
    uint8_t ipm = (uint8_t)((ssts >> 8) & 0x0F);
    uint8_t det = (uint8_t)(ssts & 0x0F);
    if (det != HBA_PORT_DEV_PRESENT || ipm != HBA_PORT_IPM_ACTIVE)
    {
        return;
    }
    if (port->sig != HBA_PORT_SIG_SATA)
    {
        return;
    }

    ahci_port_ctx_t *ctx = (ahci_port_ctx_t *)calloc(1, sizeof(ahci_port_ctx_t));
    if (!ctx)
    {
        return;
    }
    ctx->port = (hba_port_t *)port;
    ctx->port_no = (uint8_t)port_no;

    if (!ahci_port_configure(ctx))
    {
        return;
    }

    uint16_t *identify = (uint16_t *)malloc(512);
    if (!identify)
    {
        return;
    }
    bool ok = ahci_identify_port(ctx, identify);
    uint64_t sectors = 0;
    if (ok)
    {
        sectors = ((uint64_t)identify[103] << 48) |
                  ((uint64_t)identify[102] << 32) |
                  ((uint64_t)identify[101] << 16) |
                  identify[100];
        if (sectors == 0)
        {
            sectors = ((uint32_t)identify[61] << 16) | identify[60];
        }
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
    block_device_t *blk = block_register(name, 512, sectors, ahci_block_read, ahci_block_write, ctx);
    ctx->block = blk;
    if (blk)
    {
        serial_write_string("[ahci] registered ");
        serial_write_string(name);
        serial_write_string("\r\n");
    }
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
    uint32_t bar5 = pci_config_read32(dev, 0x24) & ~0xF;
    g_hba = (volatile hba_mem_t *)(uintptr_t)bar5;
    if (!g_hba)
    {
        serial_write_string("[ahci] BAR5 invalid\r\n");
        return;
    }

    uint32_t pi = g_hba->pi;
    for (uint32_t i = 0; i < 32; ++i)
    {
        if (pi & (1U << i))
        {
            ahci_init_port(g_hba, i);
        }
    }
}
static bool ahci_identify_port(ahci_port_ctx_t *ctx, uint16_t *identify)
{
    return ahci_issue_cmd(ctx, 0xEC, 0, 0, identify, false);
}
