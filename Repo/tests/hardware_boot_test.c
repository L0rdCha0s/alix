#include "block.h"
#include "libc.h"
#include "serial.h"
#include "usb.h"

/* Linked only by the hardware acceptance runner. Write exclusively to a disk
 * carrying our explicit fixture signature, and only inside its scratch range. */
bool hardware_usb_boot_test(void)
{
    block_device_t *disk = block_find("usb0");
    uint8_t *data = malloc(512 * 33);
    uint8_t *readback = malloc(512 * 33);
    bool ok = disk && data && readback && disk->sector_size == 512 && disk->sector_count == 65536;
    if (ok) ok = block_read(disk, 0, 1, data) && memcmp(data, "ALIX_USB_FIXTURE", 16) == 0;
    if (ok)
    {
        for (unsigned i = 0; i < 512 * 33; ++i) data[i] = (uint8_t)(i * 17u + 93u);
        ok = block_write(disk, 40, 33, data) && block_flush(disk) &&
             block_read(disk, 40, 33, readback) && memcmp(data, readback, 512 * 33) == 0;
        /* Wrap the bulk endpoint rings repeatedly and exercise event-cycle wrap. */
        for (unsigned i = 0; ok && i < 180; ++i)
            ok = block_read(disk, 40, 1, readback) && memcmp(data, readback, 512) == 0;
        ok = ok && !block_read(disk, UINT64_MAX, 2, readback) &&
             !block_write(disk, disk->sector_count - 1, 2, data);
    }
    for (size_t i = 0; ok && i < usb_bus_device_count(); ++i)
    {
        usb_device_t *dev = usb_bus_device_at(i);
        if (!dev || !dev->xhci || dev->type != USB_DEV_HID_KEYBOARD) continue;
        usb_setup_packet_t invalid = { .bmRequestType = 0x80, .bRequest = 0x7f };
        usb_setup_packet_t valid = { .bmRequestType = 0x80, .bRequest = USB_REQ_GET_DESCRIPTOR,
            .wValue = USB_DESC_DEVICE << 8, .wLength = 8 };
        ok = !usb_control_transfer(dev, &invalid, NULL, 0);
        for (unsigned attempt = 0; ok && attempt < 180; ++attempt)
            ok = usb_control_transfer(dev, &valid, readback, 8) && readback[1] == USB_DESC_DEVICE;
        /* An overlong descriptor request must never report stale DMA bytes as
         * valid data. Verify recovery after a short control data stage. */
        valid.wLength = 64;
        ok = ok && !usb_control_transfer(dev, &valid, readback, 64);
        valid.wLength = 8;
        ok = ok && usb_control_transfer(dev, &valid, readback, 8);
    }
    serial_printf("HARDWARE_USB_TEST: %s read=1 write=1 flush=1 ring_wrap=1 bounds=1 ep0_stall_recovery=1", ok ? "PASS" : "FAIL");
    free(data);
    free(readback);
    return ok;
}
