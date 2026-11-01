/* USB Mass Storage, SCSI transparent subclass, Bulk-Only Transport (USB-IF
 * usbmassbulk_10). Disks are registered, never formatted or mounted here.
 * One LUN is exposed per block device; UAS is deliberately not claimed. */
#include "usb_storage.h"
#include "usb.h"
#include "block.h"
#include "devfs.h"
#include "libc.h"
#include "serial.h"
#include "process.h"
#include "timer.h"

typedef struct
{
    uint32_t signature, tag, length;
    uint8_t flags, lun, cdb_length, cdb[16];
} __attribute__((packed)) bot_cbw_t;
typedef struct { uint32_t signature, tag, residue; uint8_t status; } __attribute__((packed)) bot_csw_t;
_Static_assert(sizeof(bot_cbw_t) == 31, "BOT CBW wire layout");
_Static_assert(sizeof(bot_csw_t) == 13, "BOT CSW wire layout");
typedef struct
{
    usb_device_t *usb;
    uint8_t lun;
    uint32_t tag;
    bool read_only;
    bot_cbw_t cbw;
    bot_csw_t csw;
    uint8_t scratch[64];
} usb_disk_t;

static unsigned g_disk_count;

static uint32_t be32(const uint8_t *bytes)
{ return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3]; }
static void put_be32(uint8_t *bytes, uint32_t value)
{ bytes[0] = value >> 24; bytes[1] = value >> 16; bytes[2] = value >> 8; bytes[3] = value; }

static void disk_acquire(usb_disk_t *disk)
{
    for (;;)
    {
        spinlock_preempt_disable();
        if (!__atomic_exchange_n(&disk->usb->storage_busy, 1, __ATOMIC_ACQUIRE)) return;
        spinlock_preempt_enable();
        process_yield();
    }
}
static void disk_release(usb_disk_t *disk)
{
    __atomic_store_n(&disk->usb->storage_busy, 0, __ATOMIC_RELEASE);
    spinlock_preempt_enable();
}

static bool clear_halt(usb_disk_t *disk, bool input)
{
    usb_endpoint_t *ep = input ? &disk->usb->bulk_in : &disk->usb->bulk_out;
    usb_setup_packet_t setup = { .bmRequestType = 2, .bRequest = USB_REQ_CLEAR_FEATURE,
        .wIndex = ep->endpoint | (input ? 0x80 : 0) };
    bool ok = usb_control_transfer(disk->usb, &setup, NULL, 0);
    ep->data_toggle = 0;
    return ok;
}

static void bot_reset(usb_disk_t *disk)
{
    usb_setup_packet_t setup = { .bmRequestType = 0x21, .bRequest = 0xff,
        .wIndex = disk->usb->interface_number };
    usb_control_transfer(disk->usb, &setup, NULL, 0);
    clear_halt(disk, true);
    clear_halt(disk, false);
}

/* 0=success, 1=SCSI command failed (CSW consumed), -1=transport error.
 * A failed write is never replayed: its completion may be ambiguous. */
static int bot_command(usb_disk_t *disk, const uint8_t *cdb, unsigned cdb_length,
                       void *data, uint32_t length, bool input)
{
    if (!cdb_length || cdb_length > 16) return -1;
    bot_cbw_t *cbw = &disk->cbw;
    memset(cbw, 0, sizeof(*cbw));
    cbw->signature = 0x43425355;
    cbw->tag = ++disk->tag;
    cbw->length = length;
    cbw->flags = input ? 0x80 : 0;
    cbw->lun = disk->lun;
    cbw->cdb_length = cdb_length;
    memcpy(cbw->cdb, cdb, cdb_length);
    uint32_t got = 0, data_got = 0;
    if (!usb_bulk_transfer(disk->usb, &disk->usb->bulk_out, false, cbw, sizeof(*cbw), &got) || got != sizeof(*cbw))
        goto transport_error;
    if (length)
    {
        if (!usb_bulk_transfer(disk->usb, input ? &disk->usb->bulk_in : &disk->usb->bulk_out,
                               input, data, length, &data_got))
        {
            /* BOT permits a data endpoint stall before a valid failure CSW. */
            if (!clear_halt(disk, input)) goto transport_error;
        }
    }
    bot_csw_t *csw = &disk->csw;
    memset(csw, 0, sizeof(*csw));
    if (!usb_bulk_transfer(disk->usb, &disk->usb->bulk_in, true, csw, sizeof(*csw), &got))
    {
        if (!clear_halt(disk, true) ||
            !usb_bulk_transfer(disk->usb, &disk->usb->bulk_in, true, csw, sizeof(*csw), &got)) goto transport_error;
    }
    if (got != sizeof(*csw) || csw->signature != 0x53425355 || csw->tag != cbw->tag ||
        csw->residue > length || csw->status > 1) goto transport_error;
    if (csw->status == 1) return 1;
    if (data_got != length || csw->residue != 0) goto transport_error;
    return 0;
transport_error:
    bot_reset(disk);
    return -1;
}

static int sense_key(usb_disk_t *disk)
{
    uint8_t cdb[6] = { 3, 0, 0, 0, 18, 0 };
    memset(disk->scratch, 0, sizeof(disk->scratch));
    if (bot_command(disk, cdb, sizeof(cdb), disk->scratch, 18, true) != 0) return -1;
    int key = disk->scratch[2] & 15;
    if (key == 7) disk->read_only = true;
    return key;
}

static bool disk_io(block_device_t *block, uint64_t lba, uint32_t count, void *buffer, bool input)
{
    usb_disk_t *disk = block->driver_data;
    if (!count || lba >= block->sector_count || count > block->sector_count - lba ||
        (!input && disk->read_only)) return false;
    disk_acquire(disk);
    bool ok = true;
    while (count)
    {
        uint32_t sectors = 16384 / block->sector_size;
        if (sectors > count) sectors = count;
        uint8_t cdb[16] = {0};
        unsigned cdb_length;
        if (lba <= UINT32_MAX && sectors - 1 <= UINT32_MAX - lba)
        {
            cdb_length = 10;
            cdb[0] = input ? 0x28 : 0x2a;
            put_be32(cdb + 2, lba);
            cdb[7] = sectors >> 8;
            cdb[8] = sectors;
        }
        else
        {
            cdb_length = 16;
            cdb[0] = input ? 0x88 : 0x8a;
            put_be32(cdb + 2, lba >> 32);
            put_be32(cdb + 6, lba);
            put_be32(cdb + 10, sectors);
        }
        int result = bot_command(disk, cdb, cdb_length, buffer, sectors * block->sector_size, input);
        if (result) { if (result == 1) sense_key(disk); ok = false; break; }
        buffer = (uint8_t *)buffer + sectors * block->sector_size;
        lba += sectors;
        count -= sectors;
    }
    disk_release(disk);
    return ok;
}
static bool disk_read(block_device_t *block, uint64_t lba, uint32_t count, void *buffer)
{ return disk_io(block, lba, count, buffer, true); }
static bool disk_write(block_device_t *block, uint64_t lba, uint32_t count, const void *buffer)
{ return disk_io(block, lba, count, (void *)buffer, false); }
static bool disk_flush(block_device_t *block)
{
    usb_disk_t *disk = block->driver_data;
    uint8_t cdb[10] = { 0x35 };
    disk_acquire(disk);
    bool ok = bot_command(disk, cdb, sizeof(cdb), NULL, 0, false) == 0;
    disk_release(disk);
    return ok;
}

static void probe_lun(usb_device_t *usb, unsigned lun)
{
    usb_disk_t *disk = calloc(1, sizeof(*disk));
    if (!disk) return;
    disk->usb = usb;
    disk->lun = lun;
    disk_acquire(disk);
    uint8_t inquiry[6] = { 0x12, 0, 0, 0, 36, 0 };
    if (bot_command(disk, inquiry, sizeof(inquiry), disk->scratch, 36, true) ||
        (disk->scratch[0] & 31) != 0) goto failed;
    uint8_t ready[6] = { 0 };
    bool available = false;
    for (unsigned attempt = 0; attempt < 8; ++attempt)
    {
        int result = bot_command(disk, ready, sizeof(ready), NULL, 0, false);
        if (result == 0) { available = true; break; }
        if (result < 0) break;
        int key = sense_key(disk);
        if (key != 2 && key != 6) break; /* becoming ready / unit attention */
    }
    if (!available) goto failed;
    uint8_t capacity[16] = { 0x25 };
    if (bot_command(disk, capacity, 10, disk->scratch, 8, true)) goto failed;
    uint64_t last = be32(disk->scratch);
    uint32_t sector_size = be32(disk->scratch + 4);
    if (last == UINT32_MAX)
    {
        memset(capacity, 0, sizeof(capacity));
        capacity[0] = 0x9e; capacity[1] = 0x10; capacity[13] = 32;
        if (bot_command(disk, capacity, 16, disk->scratch, 32, true)) goto failed;
        last = ((uint64_t)be32(disk->scratch) << 32) | be32(disk->scratch + 4);
        sector_size = be32(disk->scratch + 8);
    }
    if (last == UINT64_MAX || sector_size < 512 || sector_size > 4096 || (sector_size & (sector_size - 1))) goto failed;
    char name[16] = "usb";
    unsigned number = g_disk_count, digits = 1;
    for (unsigned value = number; value >= 10; value /= 10) ++digits;
    for (unsigned i = 0; i < digits; ++i)
    { name[3 + digits - 1 - i] = '0' + number % 10; number /= 10; }
    block_device_t *block = block_register(name, sector_size, last + 1, disk_read, disk_write, disk_flush, disk);
    disk_release(disk);
    if (!block) { free(disk); return; }
    ++g_disk_count;
    serial_printf("[usb-storage] registered %s lun=%u sectors=%llu sector_size=%u (no automatic mount/format)",
                   name, lun, (unsigned long long)(last + 1), sector_size);
    return;
failed:
    disk_release(disk);
    serial_printf("[usb-storage] probe failed address=%u lun=%u", usb->address, lun);
    free(disk);
}

void usb_storage_init(void)
{
    for (size_t i = 0; i < usb_bus_device_count(); ++i)
    {
        usb_device_t *usb = usb_bus_device_at(i);
        if (!usb || usb->type != USB_DEV_STORAGE || !usb->bulk_in.endpoint || !usb->bulk_out.endpoint) continue;
        /* GET_MAX_LUN may STALL on a single-LUN device; zero is then required. */
        uint8_t *max_lun = calloc(1, 1);
        if (!max_lun) continue;
        usb_setup_packet_t setup = { .bmRequestType = 0xa1, .bRequest = 0xfe,
            .wIndex = usb->interface_number, .wLength = 1 };
        if (!usb_control_transfer(usb, &setup, max_lun, 1)) *max_lun = 0;
        unsigned last = *max_lun <= 15 ? *max_lun : 0;
        free(max_lun);
        for (unsigned lun = 0; lun <= last; ++lun) probe_lun(usb, lun);
    }
    devfs_register_block_devices();
}
