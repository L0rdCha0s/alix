#include "block.h"
#include "io.h"
#include "libc.h"
#include "serial.h"

#define ATA_PRIMARY_IO       0x1F0
#define ATA_PRIMARY_CTRL     0x3F6
#define ATA_SECONDARY_IO     0x170
#define ATA_SECONDARY_CTRL   0x376

#define ATA_REG_DATA         0x00
#define ATA_REG_ERROR        0x01
#define ATA_REG_FEATURES     0x01
#define ATA_REG_SECCOUNT0    0x02
#define ATA_REG_LBA0         0x03
#define ATA_REG_LBA1         0x04
#define ATA_REG_LBA2         0x05
#define ATA_REG_HDDEVSEL     0x06
#define ATA_REG_COMMAND      0x07
#define ATA_REG_STATUS       0x07

#define ATA_REG_ALTSTATUS    0x02

#define ATA_CMD_IDENTIFY     0xEC
#define ATA_CMD_READ_PIO     0x20
#define ATA_CMD_WRITE_PIO    0x30
#define ATA_CMD_CACHE_FLUSH  0xE7

#define ATA_STATUS_ERR       0x01
#define ATA_STATUS_DRQ       0x08
#define ATA_STATUS_DF        0x20
#define ATA_STATUS_BSY       0x80

typedef struct
{
    uint16_t io_base;
    uint16_t ctrl_base;
} ata_channel_t;

typedef struct
{
    ata_channel_t *channel;
    uint8_t drive;
} ata_device_ctx_t;

static ata_channel_t g_ata_channels[] = {
    { ATA_PRIMARY_IO,   ATA_PRIMARY_CTRL },
    { ATA_SECONDARY_IO, ATA_SECONDARY_CTRL },
};

static void ata_delay(ata_channel_t *channel)
{
    (void)inb(channel->ctrl_base + ATA_REG_ALTSTATUS);
    (void)inb(channel->ctrl_base + ATA_REG_ALTSTATUS);
    (void)inb(channel->ctrl_base + ATA_REG_ALTSTATUS);
    (void)inb(channel->ctrl_base + ATA_REG_ALTSTATUS);
}

static bool ata_wait_not_busy(ata_channel_t *channel)
{
    for (uint32_t i = 0; i < 1000000; ++i)
    {
        uint8_t status = inb(channel->io_base + ATA_REG_STATUS);
        if (!(status & ATA_STATUS_BSY))
        {
            if (status & (ATA_STATUS_ERR | ATA_STATUS_DF))
            {
                return false;
            }
            return true;
        }
    }
    return false;
}

static bool ata_wait_drq(ata_channel_t *channel)
{
    for (uint32_t i = 0; i < 1000000; ++i)
    {
        uint8_t status = inb(channel->io_base + ATA_REG_STATUS);
        if (status & (ATA_STATUS_ERR | ATA_STATUS_DF))
        {
            return false;
        }
        if (!(status & ATA_STATUS_BSY) && (status & ATA_STATUS_DRQ))
        {
            return true;
        }
    }
    return false;
}

static bool ata_select_drive(ata_device_ctx_t *ctx, uint64_t lba)
{
    if (!ctx || !ctx->channel)
    {
        return false;
    }
    ata_channel_t *channel = ctx->channel;
    if (!ata_wait_not_busy(channel))
    {
        return false;
    }
    uint8_t head = (uint8_t)(0xE0 | ((ctx->drive & 0x1) << 4) | ((lba >> 24) & 0x0F));
    outb(channel->io_base + ATA_REG_HDDEVSEL, head);
    ata_delay(channel);
    return true;
}

static bool ata_identify(ata_channel_t *channel, uint8_t drive, uint16_t *identify)
{
    if (!channel || !identify)
    {
        return false;
    }

    uint16_t io = channel->io_base;

    outb(io + ATA_REG_HDDEVSEL, (uint8_t)(0xA0 | (drive << 4)));
    ata_delay(channel);

    outb(io + ATA_REG_SECCOUNT0, 0);
    outb(io + ATA_REG_LBA0, 0);
    outb(io + ATA_REG_LBA1, 0);
    outb(io + ATA_REG_LBA2, 0);

    outb(io + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
    ata_delay(channel);

    uint8_t status = inb(io + ATA_REG_STATUS);
    if (status == 0)
    {
        return false; /* no device */
    }

    uint8_t lba1 = inb(io + ATA_REG_LBA1);
    uint8_t lba2 = inb(io + ATA_REG_LBA2);
    if (lba1 == 0x14 && lba2 == 0xEB)
    {
        return false; /* ATAPI device */
    }

    if (!ata_wait_drq(channel))
    {
        return false;
    }

    for (int i = 0; i < 256; ++i)
    {
        identify[i] = inw(io + ATA_REG_DATA);
    }
    return true;
}

static bool ata_flush_cache(ata_device_ctx_t *ctx)
{
    if (!ctx || !ctx->channel)
    {
        return false;
    }
    ata_channel_t *channel = ctx->channel;
    if (!ata_select_drive(ctx, 0))
    {
        return false;
    }
    outb(channel->io_base + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
    return ata_wait_not_busy(channel);
}

static bool ata_pio_read_sector(ata_device_ctx_t *ctx, uint64_t lba, void *buffer)
{
    if (!ctx || !buffer || !ctx->channel)
    {
        return false;
    }
    if (lba >= (1ULL << 28))
    {
        return false;
    }

    ata_channel_t *channel = ctx->channel;
    uint16_t io = channel->io_base;

    if (!ata_select_drive(ctx, lba))
    {
        return false;
    }

    outb(io + ATA_REG_SECCOUNT0, 1);
    outb(io + ATA_REG_LBA0, (uint8_t)(lba & 0xFF));
    outb(io + ATA_REG_LBA1, (uint8_t)((lba >> 8) & 0xFF));
    outb(io + ATA_REG_LBA2, (uint8_t)((lba >> 16) & 0xFF));

    outb(io + ATA_REG_COMMAND, ATA_CMD_READ_PIO);

    if (!ata_wait_drq(channel))
    {
        return false;
    }

    uint16_t *dst = (uint16_t *)buffer;
    for (int i = 0; i < 256; ++i)
    {
        dst[i] = inw(io + ATA_REG_DATA);
    }

    ata_delay(channel);
    return true;
}

static bool ata_pio_write_sector(ata_device_ctx_t *ctx, uint64_t lba, const void *buffer)
{
    if (!ctx || !buffer || !ctx->channel)
    {
        return false;
    }
    if (lba >= (1ULL << 28))
    {
        return false;
    }

    ata_channel_t *channel = ctx->channel;
    uint16_t io = channel->io_base;

    if (!ata_select_drive(ctx, lba))
    {
        return false;
    }

    outb(io + ATA_REG_SECCOUNT0, 1);
    outb(io + ATA_REG_LBA0, (uint8_t)(lba & 0xFF));
    outb(io + ATA_REG_LBA1, (uint8_t)((lba >> 8) & 0xFF));
    outb(io + ATA_REG_LBA2, (uint8_t)((lba >> 16) & 0xFF));

    outb(io + ATA_REG_COMMAND, ATA_CMD_WRITE_PIO);

    if (!ata_wait_drq(channel))
    {
        return false;
    }

    const uint16_t *src = (const uint16_t *)buffer;
    for (int i = 0; i < 256; ++i)
    {
        outw(io + ATA_REG_DATA, src[i]);
    }

    if (!ata_wait_not_busy(channel))
    {
        return false;
    }

    return true;
}

static bool ata_block_read(block_device_t *device, uint64_t lba, uint32_t count, void *buffer)
{
    ata_device_ctx_t *ctx = (ata_device_ctx_t *)device->driver_data;
    if (!ctx || !buffer)
    {
        return false;
    }

    uint8_t *dst = (uint8_t *)buffer;
    uint32_t sector_size = device->sector_size;

    for (uint32_t i = 0; i < count; ++i)
    {
        if (!ata_pio_read_sector(ctx, lba + i, dst + (size_t)i * sector_size))
        {
            return false;
        }
    }
    return true;
}

static bool ata_block_write(block_device_t *device, uint64_t lba, uint32_t count, const void *buffer)
{
    ata_device_ctx_t *ctx = (ata_device_ctx_t *)device->driver_data;
    if (!ctx || !buffer)
    {
        return false;
    }

    const uint8_t *src = (const uint8_t *)buffer;
    uint32_t sector_size = device->sector_size;

    for (uint32_t i = 0; i < count; ++i)
    {
        if (!ata_pio_write_sector(ctx, lba + i, src + (size_t)i * sector_size))
        {
            return false;
        }
    }

    return ata_flush_cache(ctx);
}

static void ata_log_device(const char *name, uint64_t sectors)
{
    serial_write_string("ATA device ");
    serial_write_string(name);
    serial_write_string(" sectors=");
    serial_write_hex64(sectors);
    serial_write_string("\r\n");
}

static void ata_register_from_identify(ata_channel_t *channel, uint8_t drive, uint16_t *identify, uint32_t index)
{
    uint32_t sectors28 = ((uint32_t)identify[61] << 16) | identify[60];
    uint64_t sectors = sectors28;
    if (sectors == 0)
    {
        sectors = ((uint64_t)identify[103] << 48) |
                  ((uint64_t)identify[102] << 32) |
                  ((uint64_t)identify[101] << 16) |
                  (uint64_t)identify[100];
    }
    if (sectors == 0)
    {
        return;
    }

    char name[16];
    memset(name, 0, sizeof(name));
    const char prefix[] = "disk";
    size_t pos = 0;
    while (prefix[pos] && pos + 1 < sizeof(name))
    {
        name[pos] = prefix[pos];
        pos++;
    }
    uint32_t tmp = index;
    char digits[12];
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

    ata_device_ctx_t *ctx = (ata_device_ctx_t *)malloc(sizeof(ata_device_ctx_t));
    if (!ctx)
    {
        return;
    }
    ctx->channel = channel;
    ctx->drive = drive;

    block_device_t *device = block_register(name, 512, sectors, ata_block_read, ata_block_write, ctx);
    if (!device)
    {
        free(ctx);
        return;
    }

    ata_log_device(name, sectors);
}

void ata_init(void)
{
    static uint32_t device_index = 0;
    for (size_t c = 0; c < sizeof(g_ata_channels) / sizeof(g_ata_channels[0]); ++c)
    {
        ata_channel_t *channel = &g_ata_channels[c];
        for (uint8_t drive = 0; drive < 2; ++drive)
        {
            uint16_t identify[256];
            if (ata_identify(channel, drive, identify))
            {
                ata_register_from_identify(channel, drive, identify, device_index++);
            }
        }
    }
}
