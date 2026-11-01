#include "usb.h"
#include "libc.h"

/* Select one supported, alternate-zero interface. Bounds are checked before
 * every descriptor access; never mix endpoints belonging to different interfaces. */
bool usb_parse_configuration(usb_device_t *dev, const uint8_t *config, size_t length)
{
    if (!dev || !config || length < 9 || config[0] < 9 || config[1] != USB_DESC_CONFIGURATION)
        return false;
    size_t total = config[2] | ((size_t)config[3] << 8);
    if (total < 9 || total > length) return false;
    dev->type = USB_DEV_UNKNOWN;
    memset(&dev->intr_ep, 0, sizeof(dev->intr_ep));
    memset(&dev->bulk_in, 0, sizeof(dev->bulk_in));
    memset(&dev->bulk_out, 0, sizeof(dev->bulk_out));
    bool selected = false;
    usb_endpoint_t *last = NULL;
    for (size_t offset = 0; offset < total;)
    {
        if (total - offset < 2) return false;
        const uint8_t *d = config + offset;
        size_t size = d[0];
        if (size < 2 || size > total - offset) return false;
        if (d[1] == USB_DESC_INTERFACE)
        {
            if (size < 9) return false;
            selected = false;
            last = NULL;
            usb_device_type_t type = USB_DEV_UNKNOWN;
            if (d[3] == 0 && d[5] == USB_CLASS_HID && d[6] == 1)
            {
                if (d[7] == 1) type = USB_DEV_HID_KEYBOARD;
                if (d[7] == 2) type = USB_DEV_HID_MOUSE;
            }
            if (d[3] == 0 && d[5] == USB_CLASS_STORAGE && d[6] == 6 && d[7] == 0x50)
                type = USB_DEV_STORAGE;
            if (d[3] == 0 && d[5] == USB_CLASS_HUB) dev->is_hub = true;
            if (type != USB_DEV_UNKNOWN && dev->type == USB_DEV_UNKNOWN)
            {
                selected = true;
                dev->type = type;
                dev->interface_number = d[2];
            }
        }
        else if (d[1] == USB_DESC_ENDPOINT)
        {
            last = NULL;
            if (size < 7) return false;
            uint8_t number = d[2] & 15;
            uint8_t kind = d[3] & 3;
            if (selected && number)
            {
                if (dev->type == USB_DEV_STORAGE && kind == 2)
                    last = (d[2] & 0x80) ? &dev->bulk_in : &dev->bulk_out;
                else if (kind == 3 && (d[2] & 0x80)) last = &dev->intr_ep;
                if (last && last->endpoint) return false;
                if (last)
                {
                    last->endpoint = number;
                    last->max_packet = (d[4] | ((uint16_t)d[5] << 8)) & 0x7ff;
                    last->interval = d[6];
                    last->interval_ms = d[6] ? d[6] : 1;
                    if (!last->max_packet || last->max_packet > 1024) return false;
                }
            }
        }
        else if (d[1] == 0x30 && last)
        {
            if (size < 6 || d[2] > 15) return false;
            last->max_burst = d[2];
        }
        offset += size;
    }
    dev->configuration_value = config[5];
    return dev->configuration_value != 0;
}
