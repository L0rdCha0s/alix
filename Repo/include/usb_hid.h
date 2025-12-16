#ifndef USB_HID_H
#define USB_HID_H

#include "usb.h"

void usb_hid_init(void);
bool usb_hid_have_keyboard(void);
bool usb_hid_have_mouse(void);

#endif /* USB_HID_H */
