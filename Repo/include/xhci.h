#ifndef XHCI_H
#define XHCI_H
#include "usb.h"
bool xhci_init(void);
size_t xhci_device_count(void);
usb_device_t *xhci_device_at(size_t index);
bool xhci_control_transfer(usb_device_t *, const usb_setup_packet_t *, void *, uint16_t);
bool xhci_transfer(usb_device_t *, usb_endpoint_t *, bool input, bool interrupt,
                   void *, uint32_t, uint32_t *);
#endif
