#ifndef USB_H
#define USB_H

#include "types.h"
#include "spinlock.h"

#define USB_REQ_GET_STATUS        0x00
#define USB_REQ_CLEAR_FEATURE     0x01
#define USB_REQ_SET_FEATURE       0x03
#define USB_REQ_SET_ADDRESS       0x05
#define USB_REQ_GET_DESCRIPTOR    0x06
#define USB_REQ_SET_DESCRIPTOR    0x07
#define USB_REQ_GET_CONFIGURATION 0x08
#define USB_REQ_SET_CONFIGURATION 0x09
#define USB_REQ_GET_INTERFACE     0x0A
#define USB_REQ_SET_INTERFACE     0x0B
#define USB_REQ_SYNCH_FRAME       0x0C

#define USB_DESC_DEVICE        0x01
#define USB_DESC_CONFIGURATION 0x02
#define USB_DESC_STRING        0x03
#define USB_DESC_INTERFACE     0x04
#define USB_DESC_ENDPOINT      0x05
#define USB_DESC_DEVICE_QUAL   0x06
#define USB_DESC_HID           0x21
#define USB_DESC_HID_REPORT    0x22

#define USB_CLASS_HID          0x03

#define UHCI_MAX_CONTROLLERS   4

typedef enum
{
    USB_SPEED_LOW,
    USB_SPEED_FULL
} usb_speed_t;

typedef enum
{
    USB_DEV_UNKNOWN = 0,
    USB_DEV_HID_KEYBOARD,
    USB_DEV_HID_MOUSE
} usb_device_type_t;

typedef struct
{
    uint8_t  endpoint;
    uint16_t max_packet;
    uint8_t  interval_ms;
    uint8_t  data_toggle;
} usb_endpoint_t;

typedef struct usb_device
{
    void *host; /* opaque controller pointer (UHCI) */
    uint8_t address;
    uint8_t port;
    uint8_t configuration_value;
    uint8_t interface_number;
    uint16_t vendor_id;
    uint16_t product_id;
    usb_speed_t speed;
    uint8_t max_packet0;
    usb_device_type_t type;
    usb_endpoint_t intr_ep;
} usb_device_t;

typedef struct
{
    uint8_t bmRequestType;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
} __attribute__((packed)) usb_setup_packet_t;

bool usb_bus_init(void);
size_t usb_bus_device_count(void);
usb_device_t *usb_bus_device_at(size_t index);

bool usb_control_transfer(usb_device_t *dev,
                          const usb_setup_packet_t *setup,
                          void *buffer,
                          uint16_t length);

bool usb_interrupt_in(usb_device_t *dev,
                      usb_endpoint_t *ep,
                      void *buffer,
                      uint16_t length,
                      uint16_t *transferred);

#endif /* USB_H */
