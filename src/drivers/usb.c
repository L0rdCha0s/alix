#include "usb.h"
#include "pci.h"
#include "io.h"
#include "serial.h"
#include "libc.h"
#include "timer.h"
#include "process.h"

#define UHCI_MAX_PORTS 2

#define UHCI_USBCMD      0x00
#define UHCI_USBSTS      0x02
#define UHCI_USBINTR     0x04
#define UHCI_FRNUM       0x06
#define UHCI_FRBASEADD   0x08
#define UHCI_SOFMOD      0x0C
#define UHCI_PORTSC1     0x10
#define UHCI_PORTSC2     0x12
#define UHCI_LEGSUP      0xC0

#define UHCI_CMD_RS      (1u << 0)
#define UHCI_CMD_HCRESET (1u << 1)
#define UHCI_CMD_CF      (1u << 6)
#define UHCI_CMD_MAXP    (1u << 7)

#define UHCI_STS_USBINT   (1u << 0)
#define UHCI_STS_ERROR    (1u << 1)
#define UHCI_STS_RD       (1u << 2)
#define UHCI_STS_HSE      (1u << 3)
#define UHCI_STS_HCPE     (1u << 4)
#define UHCI_STS_HCHALTED (1u << 5)

#define UHCI_PORT_CCS    (1u << 0)
#define UHCI_PORT_CSC    (1u << 1)
#define UHCI_PORT_PE     (1u << 2)
#define UHCI_PORT_PEC    (1u << 3)
#define UHCI_PORT_RD     (1u << 6)
#define UHCI_PORT_SUSP   (1u << 7)
#define UHCI_PORT_LSDA   (1u << 8)
#define UHCI_PORT_PR     (1u << 9)

#define UHCI_LINK_TERMINATE 0x00000001u
#define UHCI_LINK_QH        0x00000002u

#define UHCI_PID_OUT   0xE1
#define UHCI_PID_IN    0x69
#define UHCI_PID_SETUP 0x2D

#define UHCI_TD_CTRL_SPD       (1u << 29)
#define UHCI_TD_CTRL_ERRCNT(n) (((uint32_t)(n) & 3u) << 27)
#define UHCI_TD_CTRL_LS        (1u << 26)
#define UHCI_TD_CTRL_ISO       (1u << 25)
#define UHCI_TD_CTRL_IOC       (1u << 24)
#define UHCI_TD_CTRL_ACTIVE    (1u << 23)
#define UHCI_TD_CTRL_STALLED   (1u << 22)
#define UHCI_TD_CTRL_DBUF_ERR  (1u << 21)
#define UHCI_TD_CTRL_BABBLE    (1u << 20)
#define UHCI_TD_CTRL_NAK       (1u << 19)
#define UHCI_TD_CTRL_CRCTIMEO  (1u << 18)
#define UHCI_TD_CTRL_BITSTUFF  (1u << 17)
#define UHCI_TD_CTRL_ACTLEN_MASK 0x000007FFu

typedef struct
{
    uint32_t link;
    uint32_t control;
    uint32_t token;
    uint32_t buffer;
} __attribute__((packed, aligned(16))) uhci_td_t;

typedef struct
{
    uint32_t head_link;
    uint32_t element_link;
    uint32_t reserved0;
    uint32_t reserved1;
} __attribute__((packed, aligned(16))) uhci_qh_t;

typedef struct
{
    pci_device_t pci;
    uint16_t iobase;
    uint32_t *frame_list;
    uhci_qh_t *async_qh;
    spinlock_t lock;
    usb_device_t devices[UHCI_MAX_PORTS];
    size_t device_count;
} uhci_controller_t;

static uhci_controller_t g_uhci[UHCI_MAX_CONTROLLERS] = { 0 };
static size_t g_uhci_count = 0;
static bool ehci_route_ports_to_uhci(void);

static inline uint64_t usb_now_ms(void)
{
    uint32_t freq = timer_frequency();
    if (freq > 0)
    {
        uint64_t ticks = timer_ticks();
        return (ticks * 1000ULL) / (uint64_t)freq;
    }
    /* Fallback: approximate using a monotonically increasing counter. */
    static volatile uint64_t fallback_ms = 0;
    return fallback_ms++;
}

static void usb_delay_ms(uint32_t ms)
{
    /* Early boot and SMP bring-up: avoid relying on PIT ticks across CPUs. */
    if (ms == 0)
    {
        return;
    }

    uint32_t freq = timer_frequency();
    if (freq > 0)
    {
        uint64_t ticks = ((uint64_t)ms * (uint64_t)freq + 999ULL) / 1000ULL;
        if (ticks == 0)
        {
            ticks = 1;
        }
        uint64_t target = timer_ticks() + ticks;
        uint64_t guard = ticks * 50000ULL; /* prevent spin forever if timer stalls */
        if (guard < 50000ULL)
        {
            guard = 50000ULL;
        }
        while (timer_ticks() < target)
        {
            if (guard == 0)
            {
                serial_printf("[usb] delay guard hit ms=%u target=%llu now=%llu\r\n",
                              (unsigned)ms,
                              (unsigned long long)target,
                              (unsigned long long)timer_ticks());
                break;
            }
            guard--;
            __asm__ volatile ("pause");
        }
        return;
    }

    static int delay_log_budget = 12;
    if (delay_log_budget > 0 && ms >= 10)
    {
        delay_log_budget--;
        serial_printf("[usb] delay busywait ms=%u\r\n", (unsigned)ms);
    }

    /* Fallback busy loop when timer ticks are not yet available. */
    const uint32_t inner = 2000;
    for (uint32_t i = 0; i < ms; ++i)
    {
        for (volatile uint32_t j = 0; j < inner; ++j)
        {
            __asm__ volatile ("pause");
        }
    }
}

static uint32_t virt_to_phys(void *ptr)
{
    return (uint32_t)(uintptr_t)ptr;
}

static void usb_log(const char *msg)
{
    if (msg)
    {
        serial_printf("%s\r\n", msg);
    }
}

static bool pci_find_class(uint8_t class_code,
                           uint8_t subclass,
                           uint8_t prog_if,
                           pci_device_t *out_dev)
{
    uint64_t start_ms = usb_now_ms();
    /* Limit to the first 32 buses to avoid slow/quirky bridges during early boot. */
    for (uint16_t bus = 0; bus < 32; ++bus)
    {
        if (bus < 4 || (bus & 0x1Fu) == 0)
        {
            serial_printf("[usb][pci_scan] bus=%u elapsed_ms=%llu\r\n",
                          (unsigned)bus,
                          (unsigned long long)(usb_now_ms() - start_ms));
        }
        for (uint8_t dev = 0; dev < 32; ++dev)
        {
            for (uint8_t fn = 0; fn < 8; ++fn)
            {
                pci_device_t candidate = { .bus = (uint8_t)bus, .device = dev, .function = fn };
                uint16_t vendor = pci_config_read16(candidate, 0x00);
                if (vendor == 0xFFFF)
                {
                    if (fn == 0)
                    {
                        break;
                    }
                    continue;
                }
                uint8_t cc = pci_config_read8(candidate, 0x0B);
                uint8_t sc = pci_config_read8(candidate, 0x0A);
                uint8_t pi = pci_config_read8(candidate, 0x09);
                if (cc == class_code && sc == subclass && pi == prog_if)
                {
                    if (out_dev)
                    {
                        *out_dev = candidate;
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

static bool uhci_reset_controller(uhci_controller_t *hc)
{
    if (!hc)
    {
        return false;
    }

    usb_log("[usb] uhci reset start (skipping HCRESET)");
    /* Avoid potential hang during HCRESET on some platforms; just clear command/status. */
    outw(hc->iobase + UHCI_USBCMD, 0);
    outw(hc->iobase + UHCI_USBSTS, 0xFFFF);
    outw(hc->iobase + UHCI_USBINTR, 0);
    uint16_t cmd_final = inw(hc->iobase + UHCI_USBCMD);
    uint16_t sts = inw(hc->iobase + UHCI_USBSTS);
    serial_printf("[usb] uhci reset done cmd_final=0x%04X sts=0x%04X\r\n",
                  (unsigned)cmd_final,
                  (unsigned)sts);
    return true;
}

static void uhci_stop(uhci_controller_t *hc)
{
    if (!hc)
    {
        return;
    }
    uint16_t cmd = inw(hc->iobase + UHCI_USBCMD);
    cmd &= ~UHCI_CMD_RS;
    outw(hc->iobase + UHCI_USBCMD, cmd);
}

static bool uhci_start(uhci_controller_t *hc)
{
    if (!hc)
    {
        return false;
    }
    usb_log("[usb] uhci start");
    outw(hc->iobase + UHCI_FRNUM, 0);
    outl(hc->iobase + UHCI_FRBASEADD, virt_to_phys(hc->frame_list));
    outb(hc->iobase + UHCI_SOFMOD, 0x40);

    uint16_t cmd = inw(hc->iobase + UHCI_USBCMD);
    cmd |= (UHCI_CMD_RS | UHCI_CMD_CF | UHCI_CMD_MAXP);
    outw(hc->iobase + UHCI_USBCMD, cmd);
    return true;
}

static uhci_td_t *uhci_alloc_td_chain(size_t count)
{
    size_t bytes = sizeof(uhci_td_t) * count;
    uhci_td_t *tds = (uhci_td_t *)malloc(bytes);
    if (!tds)
    {
        return NULL;
    }
    memset(tds, 0, bytes);
    return tds;
}

static inline uint32_t uhci_build_token(uint8_t pid,
                                        uint8_t addr,
                                        uint8_t endpoint,
                                        uint8_t data_toggle,
                                        uint16_t len)
{
    uint16_t max_len_field = (len == 0) ? 0x7FFu : (uint16_t)(len - 1u);
    return (uint32_t)pid |
           ((uint32_t)addr << 8) |
           ((uint32_t)endpoint << 15) |
           ((uint32_t)(data_toggle ? 1u : 0u) << 19) |
           ((uint32_t)max_len_field << 21);
}

static bool uhci_wait_for_td(uhci_td_t *last, uint32_t timeout_ms)
{
    if (!last)
    {
        return false;
    }
    uint64_t deadline = usb_now_ms() + timeout_ms;
    uint32_t spin_guard = timeout_ms ? (timeout_ms * 5000u) : 100000u;
    while (spin_guard-- > 0)
    {
        uint32_t ctrl = last->control;
        if ((ctrl & UHCI_TD_CTRL_ACTIVE) == 0)
        {
            if (ctrl & (UHCI_TD_CTRL_STALLED |
                        UHCI_TD_CTRL_DBUF_ERR |
                        UHCI_TD_CTRL_BABBLE |
                        UHCI_TD_CTRL_CRCTIMEO |
                        UHCI_TD_CTRL_BITSTUFF))
            {
                usb_log("[usb] td error status");
                return false;
            }
            return true;
        }
        if (usb_now_ms() >= deadline)
        {
            usb_log("[usb] td wait deadline");
            break;
        }
        __asm__ volatile ("pause");
    }
    return false;
}

static bool uhci_submit_chain(uhci_controller_t *hc,
                              uhci_td_t *tds,
                              size_t td_count,
                              bool short_ok,
                              bool is_interrupt)
{
    if (!hc || !tds || td_count == 0)
    {
        return false;
    }

    spinlock_lock(&hc->lock);
    hc->async_qh->element_link = virt_to_phys(tds);
    hc->async_qh->head_link = UHCI_LINK_TERMINATE;

    uhci_td_t *last = &tds[td_count - 1];
    uint32_t wait_ms = is_interrupt ? 20 : 200;
    bool ok = uhci_wait_for_td(last, wait_ms);
    bool soft_no_data = false;
    if (!ok && is_interrupt)
    {
        /* Interrupt endpoints can legitimately NAK with no data; treat as empty. */
        last->control &= ~UHCI_TD_CTRL_ACTIVE;
        last->control |= UHCI_TD_CTRL_SPD;
        ok = true;
        soft_no_data = true;
    }
    /* Unlink the chain before releasing the lock so the controller does not
       keep walking freed TDs on subsequent frames. */
    hc->async_qh->element_link = UHCI_LINK_TERMINATE;
    hc->async_qh->head_link = UHCI_LINK_TERMINATE;
    spinlock_unlock(&hc->lock);
    if (!ok)
    {
        uint32_t token = tds[0].token;
        uint8_t pid = (uint8_t)(token & 0xFFu);
        uint8_t addr = (uint8_t)((token >> 8) & 0x7Fu);
        uint8_t ep = (uint8_t)((token >> 15) & 0x1Fu);
        serial_printf("[usb] td chain timeout pid=0x%02X addr=%u ep=%u ctrl=0x%08X last_ctrl=0x%08X\r\n",
                      (unsigned)pid,
                      (unsigned)addr,
                      (unsigned)ep,
                      (unsigned)tds[0].control,
                      (unsigned)last->control);
        return false;
    }

    if (!short_ok && (last->control & UHCI_TD_CTRL_SPD))
    {
        return false;
    }

    return !soft_no_data || short_ok;
}

static bool uhci_control_xfer(uhci_controller_t *hc,
                              usb_device_t *dev,
                              const usb_setup_packet_t *setup,
                              void *buffer,
                              uint16_t length)
{
    if (!hc || !setup)
    {
        return false;
    }

    uint8_t addr = dev ? dev->address : 0;
    uint8_t max_packet = dev ? dev->max_packet0 : 8;
    size_t data_tds = (length + max_packet - 1u) / max_packet;
    size_t total_tds = 2 + (data_tds > 0 ? data_tds : 0);
    uhci_td_t *tds = uhci_alloc_td_chain(total_tds);
    if (!tds)
    {
        return false;
    }

    uint32_t common = UHCI_TD_CTRL_ERRCNT(3) | UHCI_TD_CTRL_ACTIVE;
    if (dev && dev->speed == USB_SPEED_LOW)
    {
        common |= UHCI_TD_CTRL_LS;
    }

    uint8_t *setup_bytes = (uint8_t *)setup;
    tds[0].control = common;
    tds[0].token = uhci_build_token(UHCI_PID_SETUP, addr, 0, 0, sizeof(usb_setup_packet_t));
    tds[0].buffer = virt_to_phys(setup_bytes);
    tds[0].link = (total_tds > 1) ? (virt_to_phys(&tds[1])) : UHCI_LINK_TERMINATE;

    uint8_t toggle = 1;
    uint32_t td_index = 1;
    uint16_t remaining = length;
    uint8_t *cursor = (uint8_t *)buffer;

    for (size_t i = 0; i < data_tds; ++i)
    {
        uint16_t chunk = remaining;
        if (chunk > max_packet)
        {
            chunk = max_packet;
        }

        uhci_td_t *td = &tds[td_index];
        td->control = common;
        td->token = uhci_build_token((setup->bmRequestType & 0x80) ? UHCI_PID_IN : UHCI_PID_OUT,
                                     addr,
                                     0,
                                     toggle,
                                     chunk);
        td->buffer = virt_to_phys(cursor);
        td->link = virt_to_phys(&tds[td_index + 1]);

        cursor += chunk;
        remaining = (uint16_t)(remaining - chunk);
        toggle ^= 1u;
        td_index++;
    }

    uhci_td_t *status_td = &tds[total_tds - 1];
    status_td->control = common | UHCI_TD_CTRL_IOC;
    status_td->token = uhci_build_token((setup->bmRequestType & 0x80) ? UHCI_PID_OUT : UHCI_PID_IN,
                                        addr,
                                        0,
                                        1,
                                        0);
    status_td->buffer = 0;
    status_td->link = UHCI_LINK_TERMINATE;

    usb_log("[usb] control xfer submit");
    bool ok = uhci_submit_chain(hc, tds, total_tds, true, false);
    free(tds);
    usb_log(ok ? "[usb] control xfer ok" : "[usb] control xfer fail");
    return ok;
}

static bool uhci_interrupt_in_xfer(uhci_controller_t *hc,
                                   usb_device_t *dev,
                                   usb_endpoint_t *ep,
                                   void *buffer,
                                   uint16_t length,
                                   uint16_t *transferred)
{
    if (!hc || !dev || !ep || !buffer || length == 0)
    {
        return false;
    }

    uhci_td_t *td = uhci_alloc_td_chain(1);
    if (!td)
    {
        return false;
    }

    uint32_t ctrl = UHCI_TD_CTRL_ERRCNT(3) | UHCI_TD_CTRL_ACTIVE | UHCI_TD_CTRL_SPD;
    if (dev->speed == USB_SPEED_LOW)
    {
        ctrl |= UHCI_TD_CTRL_LS;
    }
    td->control = ctrl;
    td->token = uhci_build_token(UHCI_PID_IN, dev->address, ep->endpoint, ep->data_toggle, length);
    td->buffer = virt_to_phys(buffer);
    td->link = UHCI_LINK_TERMINATE;

    bool ok = uhci_submit_chain(hc, td, 1, true, true);
    if (ok && transferred)
    {
        uint32_t act_len = td->control & UHCI_TD_CTRL_ACTLEN_MASK;
        if (act_len == UHCI_TD_CTRL_ACTLEN_MASK)
        {
            *transferred = 0;
        }
        else
        {
            *transferred = (uint16_t)(act_len + 1u);
        }
    }
    ep->data_toggle ^= 1u;
    free(td);
    return ok;
}

static bool usb_parse_config(usb_device_t *dev, uint8_t *config, uint16_t total_len)
{
    if (!dev || !config || total_len < 9)
    {
        return false;
    }

    uint16_t idx = 0;
    uint8_t current_interface = 0xFF;
    while (idx + 2 < total_len)
    {
        uint8_t len = config[idx];
        uint8_t dtype = config[idx + 1];
        if (len == 0)
        {
            break;
        }
        if (idx + len > total_len)
        {
            break;
        }

        if (dtype == USB_DESC_INTERFACE && len >= 9)
        {
            uint8_t iface_class = config[idx + 5];
            uint8_t iface_proto = config[idx + 7];
            current_interface = config[idx + 2];
            dev->interface_number = current_interface;
            if (iface_class == USB_CLASS_HID)
            {
                if (iface_proto == 1)
                {
                    dev->type = USB_DEV_HID_KEYBOARD;
                }
                else if (iface_proto == 2)
                {
                    dev->type = USB_DEV_HID_MOUSE;
                }
            }
        }
        else if (dtype == USB_DESC_ENDPOINT && len >= 7 && current_interface != 0xFF)
        {
            uint8_t ep_addr = config[idx + 2];
            uint8_t attributes = config[idx + 3];
            uint16_t mps = (uint16_t)config[idx + 4] | ((uint16_t)config[idx + 5] << 8);
            uint8_t interval = config[idx + 6];
            if ((attributes & 0x3) == 0x3 && (ep_addr & 0x80))
            {
                dev->intr_ep.endpoint = (uint8_t)(ep_addr & 0x0F);
                dev->intr_ep.max_packet = mps ? mps : 8;
                dev->intr_ep.interval_ms = interval ? interval : 10;
            }
        }

        idx = (uint16_t)(idx + len);
    }
    return true;
}

static bool usb_enumerate_port(uhci_controller_t *hc, uint16_t port_reg, uint8_t port_index)
{
    serial_printf("[usb] port%u check\r\n", (unsigned)port_index);
    uint16_t status = inw(hc->iobase + port_reg);
    serial_printf("[usb] port%u status initial=0x%04X\r\n",
                  (unsigned)port_index,
                  (unsigned)status);

    /* Ports can be left suspended by firmware; bring them back before checking. */
    if (status & UHCI_PORT_SUSP)
    {
        serial_printf("[usb] port%u resume start status=0x%04X\r\n",
                      (unsigned)port_index,
                      (unsigned)status);
        outw(hc->iobase + port_reg, status | UHCI_PORT_RD | UHCI_PORT_CSC | UHCI_PORT_PEC);
        usb_delay_ms(20);
        status = inw(hc->iobase + port_reg);
        outw(hc->iobase + port_reg,
             (uint16_t)((status & ~(UHCI_PORT_RD | UHCI_PORT_SUSP)) | UHCI_PORT_CSC | UHCI_PORT_PEC));
        usb_delay_ms(2);
        status = inw(hc->iobase + port_reg);
        serial_printf("[usb] port%u resume done status=0x%04X\r\n",
                      (unsigned)port_index,
                      (unsigned)status);
    }

    if ((status & UHCI_PORT_CCS) == 0)
    {
        serial_printf("[usb] port%u no device status=0x%04X\r\n",
                      (unsigned)port_index,
                      (unsigned)status);
        return false;
    }

    outw(hc->iobase + port_reg, status | UHCI_PORT_PR);
    serial_printf("[usb] port%u reset asserted\r\n", (unsigned)port_index);
    usb_delay_ms(50);
    outw(hc->iobase + port_reg, status & ~UHCI_PORT_PR);
    serial_printf("[usb] port%u reset released\r\n", (unsigned)port_index);
    usb_delay_ms(10);

    status = inw(hc->iobase + port_reg);
    if ((status & UHCI_PORT_CCS) == 0)
    {
        serial_printf("[usb] port%u lost connect after reset status=0x%04X\r\n",
                      (unsigned)port_index,
                      (unsigned)status);
        return false;
    }
    serial_printf("[usb] port%u status after reset=0x%04X\r\n",
                  (unsigned)port_index,
                  (unsigned)status);

    outw(hc->iobase + port_reg, status | UHCI_PORT_PE | UHCI_PORT_CSC | UHCI_PORT_PEC);
    usb_delay_ms(2);

    if (hc->device_count >= UHCI_MAX_PORTS)
    {
        serial_printf("[usb] port%u device limit reached\r\n", (unsigned)port_index);
        return false;
    }

    usb_device_t *dev = &hc->devices[hc->device_count];
    memset(dev, 0, sizeof(*dev));
    dev->host = hc;
    dev->port = port_index;
    dev->speed = (status & UHCI_PORT_LSDA) ? USB_SPEED_LOW : USB_SPEED_FULL;
    serial_printf("[usb] port%u connected speed=%s\r\n",
                  (unsigned)port_index,
                  dev->speed == USB_SPEED_LOW ? "low" : "full");
    dev->max_packet0 = 8;

    uint8_t device_desc_buf[18];
    usb_setup_packet_t get_dev = {
        .bmRequestType = 0x80,
        .bRequest = USB_REQ_GET_DESCRIPTOR,
        .wValue = (USB_DESC_DEVICE << 8),
        .wIndex = 0,
        .wLength = 8
    };

    if (!uhci_control_xfer(hc, NULL, &get_dev, device_desc_buf, 8))
    {
        usb_log("[usb] failed to get dev desc (first stage)");
        return false;
    }
    serial_printf("[usb] port%u stage1 maxpkt0=%u\r\n",
                  (unsigned)port_index,
                  (unsigned)device_desc_buf[7]);

    dev->max_packet0 = device_desc_buf[7];
    if (dev->max_packet0 == 0)
    {
        dev->max_packet0 = 8;
    }

    get_dev.wLength = sizeof(device_desc_buf);

    dev->address = (uint8_t)(hc->device_count + 1);
    usb_setup_packet_t set_addr = {
        .bmRequestType = 0x00,
        .bRequest = USB_REQ_SET_ADDRESS,
        .wValue = dev->address,
        .wIndex = 0,
        .wLength = 0
    };
    if (!uhci_control_xfer(hc, NULL, &set_addr, NULL, 0))
    {
        usb_log("[usb] failed to set address");
        return false;
    }
    serial_printf("[usb] port%u address=%u\r\n", (unsigned)port_index, (unsigned)dev->address);
    usb_delay_ms(4);

    if (!uhci_control_xfer(hc, dev, &get_dev, device_desc_buf, sizeof(device_desc_buf)))
    {
        usb_log("[usb] failed to read device descriptor");
        return false;
    }
    serial_printf("[usb] port%u dev vid=0x%04X pid=0x%04X pkt0=%u\r\n",
                  (unsigned)port_index,
                  (unsigned)dev->vendor_id,
                  (unsigned)dev->product_id,
                  (unsigned)dev->max_packet0);

    dev->vendor_id = (uint16_t)device_desc_buf[8] | ((uint16_t)device_desc_buf[9] << 8);
    dev->product_id = (uint16_t)device_desc_buf[10] | ((uint16_t)device_desc_buf[11] << 8);
    dev->max_packet0 = device_desc_buf[7];

    uint8_t config_head[9];
    usb_setup_packet_t get_cfg_head = {
        .bmRequestType = 0x80,
        .bRequest = USB_REQ_GET_DESCRIPTOR,
        .wValue = (USB_DESC_CONFIGURATION << 8),
        .wIndex = 0,
        .wLength = sizeof(config_head)
    };
    if (!uhci_control_xfer(hc, dev, &get_cfg_head, config_head, sizeof(config_head)))
    {
        usb_log("[usb] failed to read config head");
        return false;
    }

    uint16_t total_len = (uint16_t)config_head[2] | ((uint16_t)config_head[3] << 8);
    if (total_len < sizeof(config_head))
    {
        total_len = sizeof(config_head);
    }
    if (total_len > 512)
    {
        total_len = 512;
    }

    uint8_t *config_buf = (uint8_t *)malloc(total_len);
    if (!config_buf)
    {
        serial_printf("[usb] port%u config malloc failed len=%u\r\n",
                      (unsigned)port_index,
                      (unsigned)total_len);
        return false;
    }
    get_cfg_head.wLength = total_len;
    if (!uhci_control_xfer(hc, dev, &get_cfg_head, config_buf, total_len))
    {
        free(config_buf);
        usb_log("[usb] failed to read full config");
        return false;
    }

    usb_parse_config(dev, config_buf, total_len);
    dev->configuration_value = config_buf[5];
    free(config_buf);
    serial_printf("[usb] port%u config parsed type=%u intr_ep=%u mps=%u intv=%u\r\n",
                  (unsigned)port_index,
                  (unsigned)dev->type,
                  (unsigned)dev->intr_ep.endpoint,
                  (unsigned)dev->intr_ep.max_packet,
                  (unsigned)dev->intr_ep.interval_ms);

    usb_setup_packet_t set_cfg = {
        .bmRequestType = 0x00,
        .bRequest = USB_REQ_SET_CONFIGURATION,
        .wValue = dev->configuration_value,
        .wIndex = 0,
        .wLength = 0
    };
    if (!uhci_control_xfer(hc, dev, &set_cfg, NULL, 0))
    {
        usb_log("[usb] failed to set configuration");
        return false;
    }
    serial_printf("[usb] port%u configured cfg=%u\r\n",
                  (unsigned)port_index,
                  (unsigned)dev->configuration_value);

    dev->intr_ep.data_toggle = 0;

    hc->device_count++;
    serial_printf("[usb] port%u enumerate complete count=%u\r\n",
                  (unsigned)port_index,
                  (unsigned)hc->device_count);
    return true;
}

static bool usb_probe_uhci(uhci_controller_t *hc, pci_device_t dev)
{
    if (!hc)
    {
        return false;
    }
    memset(hc, 0, sizeof(*hc));
    hc->pci = dev;
    usb_log("[usb] probe uhci begin");

    uint32_t bar4 = pci_config_read32(hc->pci, 0x20);
    hc->iobase = (uint16_t)(bar4 & 0xFFF0u);
    serial_printf("[usb] UHCI found bus=%u dev=%u fn=%u\r\n",
                  (unsigned)hc->pci.bus,
                  (unsigned)hc->pci.device,
                  (unsigned)hc->pci.function);
    serial_printf("[usb] UHCI iobase=0x%04X bar4=0x%08X\r\n",
                  (unsigned)hc->iobase,
                  (unsigned)bar4);
    pci_set_command_bits(hc->pci, 0x0005u, 0);
    pci_config_write16(hc->pci, UHCI_LEGSUP, 0x8F00u);

    hc->frame_list = (uint32_t *)malloc(4096 + 4096);
    if (!hc->frame_list)
    {
        usb_log("[usb] frame_list alloc failed");
        return false;
    }
    uintptr_t frame_phys = (uintptr_t)hc->frame_list;
    if (frame_phys & 0xFFFu)
    {
        frame_phys = (frame_phys + 0xFFFu) & ~0xFFFu;
        hc->frame_list = (uint32_t *)frame_phys;
    }
    memset(hc->frame_list, 0, 4096);

    hc->async_qh = (uhci_qh_t *)malloc(sizeof(uhci_qh_t));
    if (!hc->async_qh)
    {
        usb_log("[usb] async_qh alloc failed");
        return false;
    }
    memset(hc->async_qh, 0, sizeof(*hc->async_qh));
    hc->async_qh->head_link = UHCI_LINK_TERMINATE;
    hc->async_qh->element_link = UHCI_LINK_TERMINATE;

    uint32_t qh_phys = virt_to_phys(hc->async_qh) | UHCI_LINK_QH;
    for (size_t i = 0; i < 1024; ++i)
    {
        hc->frame_list[i] = qh_phys;
    }

    spinlock_lock(&hc->lock);
    spinlock_unlock(&hc->lock);

    usb_log("[usb] probe uhci done");
    return true;
}

bool usb_bus_init(void)
{
    usb_log("[usb] bus_init begin");
    usb_log("[usb] attempting ehci port routing");
    ehci_route_ports_to_uhci();
    usb_log("[usb] ehci port routing done");
    g_uhci_count = 0;
    /* Limit scan to first 32 buses to avoid long config walks under TCG. */
    for (uint16_t bus = 0; bus < 32 && g_uhci_count < UHCI_MAX_CONTROLLERS; ++bus)
    {
        if (bus < 4 || (bus & 0x7u) == 0)
        {
            serial_printf("[usb][uhci_scan] bus=%u count=%u\r\n",
                          (unsigned)bus,
                          (unsigned)g_uhci_count);
        }
        for (uint8_t dev = 0; dev < 32 && g_uhci_count < UHCI_MAX_CONTROLLERS; ++dev)
        {
            for (uint8_t fn = 0; fn < 8 && g_uhci_count < UHCI_MAX_CONTROLLERS; ++fn)
            {
                pci_device_t candidate = { .bus = (uint8_t)bus, .device = dev, .function = fn };
                uint16_t vendor = pci_config_read16(candidate, 0x00);
                if (vendor == 0xFFFF)
                {
                    if (fn == 0)
                    {
                        break;
                    }
                    continue;
                }
                uint8_t cc = pci_config_read8(candidate, 0x0B);
                uint8_t sc = pci_config_read8(candidate, 0x0A);
                uint8_t pi = pci_config_read8(candidate, 0x09);
                if (cc == 0x0C && sc == 0x03 && pi == 0x00)
                {
                    if (usb_probe_uhci(&g_uhci[g_uhci_count], candidate))
                    {
                        g_uhci_count++;
                    }
                }
            }
        }
        if (g_uhci_count > 0)
        {
            break;
        }
    }
    serial_printf("[usb] uhci probe scan complete count=%u\r\n", (unsigned)g_uhci_count);
    if (g_uhci_count == 0)
    {
        usb_log("[usb] bus_init probe failed");
        return false;
    }
    serial_printf("[usb] uhci controllers=%u\r\n", (unsigned)g_uhci_count);

    for (size_t i = 0; i < g_uhci_count; ++i)
    {
        uhci_controller_t *hc = &g_uhci[i];
        uhci_stop(hc);
    }
    usb_log("[usb] uhci stopped");
    for (size_t i = 0; i < g_uhci_count; ++i)
    {
        uhci_controller_t *hc = &g_uhci[i];
        if (!uhci_reset_controller(hc))
        {
            usb_log("[usb] reset failed");
            continue;
        }
        usb_log("[usb] reset ok");
        if (!uhci_start(hc))
        {
            usb_log("[usb] start failed");
            continue;
        }
        usb_log("[usb] start ok");
        usb_enumerate_port(hc, UHCI_PORTSC1, 0);
        usb_enumerate_port(hc, UHCI_PORTSC2, 1);
    }
    size_t total = 0;
    for (size_t i = 0; i < g_uhci_count; ++i)
    {
        total += g_uhci[i].device_count;
    }
    for (size_t i = 0; i < g_uhci_count; ++i)
    {
        for (size_t j = 0; j < g_uhci[i].device_count; ++j)
        {
            usb_device_t *dev = &g_uhci[i].devices[j];
            serial_printf("[usb] devsummary ctrl=%u idx=%u addr=%u port=%u type=%u ep=%u mps=%u intv=%u pkt0=%u iface=%u cfg=%u\r\n",
                          (unsigned)i,
                          (unsigned)j,
                          (unsigned)dev->address,
                          (unsigned)dev->port,
                          (unsigned)dev->type,
                          (unsigned)dev->intr_ep.endpoint,
                          (unsigned)dev->intr_ep.max_packet,
                          (unsigned)dev->intr_ep.interval_ms,
                          (unsigned)dev->max_packet0,
                          (unsigned)dev->interface_number,
                          (unsigned)dev->configuration_value);
        }
    }
    serial_printf("[usb] bus_init complete devices=%u\r\n", (unsigned)total);
    return true;
}

/* EHCI on Q35 owns the physical ports by default. Hand them to UHCI companions. */
static bool ehci_route_ports_to_uhci(void)
{
    serial_printf("%s", "[usb] ehci route entry\r\n");
    pci_device_t ehci;
    if (!pci_find_class(0x0C, 0x03, 0x20, &ehci))
    {
        usb_log("[usb] no EHCI controller found for port routing");
        return true; /* Not fatal; maybe pure UHCI. */
    }

    serial_printf("[usb] ehci route start bus=%u dev=%u fn=%u\r\n",
                  (unsigned)ehci.bus,
                  (unsigned)ehci.device,
                  (unsigned)ehci.function);

    /* Make sure MEM/IO/BusMaster are enabled before touching BAR space. */
    pci_set_command_bits(ehci, 0x0007u, 0);
    uint16_t cmd_reg = pci_config_read16(ehci, 0x04);

    uint32_t bar = pci_config_read32(ehci, 0x10);
    if (bar & 0x1u)
    {
        usb_log("[usb] EHCI BAR0 is IO, unexpected");
        return false;
    }
    uintptr_t base = (uintptr_t)(bar & ~0xFu);
    if (base == 0)
    {
        usb_log("[usb] EHCI BAR0 is zero");
        return false;
    }

    volatile uint32_t *regs = (volatile uint32_t *)base;
    uint32_t hcsparams = regs[1]; /* HCSPARAMS at offset 0x04 */
    uint8_t ports = (uint8_t)(hcsparams & 0x0F);
    serial_printf("[usb] ehci route ports count=%u base=0x%08llX cmd=0x%04X bar=0x%08X\r\n",
                  (unsigned)ports,
                  (unsigned long long)base,
                  (unsigned)cmd_reg,
                  (unsigned)bar);

    /* Stop EHCI (clear RS) to avoid races while switching ownership. */
    uint32_t cmd = regs[0];
    regs[0] = (cmd & ~0x1u);
    serial_printf("[usb] ehci cmd before=0x%08X after_stop=0x%08X\r\n",
                  (unsigned)cmd,
                  (unsigned)(cmd & ~0x1u));

    for (uint8_t i = 0; i < ports; ++i)
    {
        volatile uint32_t *portsc = regs + (0x40u / 4u) + i;
        uint32_t v = *portsc;
        uint32_t new_v = v | (1u << 13); /* PORT_OWNER -> companion */
        new_v |= (1u << 12);             /* ensure port power */
        *portsc = new_v;
        serial_printf("[usb] ehci port%u route owner old=0x%08X new=0x%08X\r\n",
                      (unsigned)i,
                      (unsigned)v,
                      (unsigned)new_v);
    }
    usb_log("[usb] ehci route complete");
    return true;
}

size_t usb_bus_device_count(void)
{
    size_t total = 0;
    for (size_t i = 0; i < g_uhci_count; ++i)
    {
        total += g_uhci[i].device_count;
    }
    return total;
}

usb_device_t *usb_bus_device_at(size_t index)
{
    size_t cursor = 0;
    for (size_t i = 0; i < g_uhci_count; ++i)
    {
        if (index < cursor + g_uhci[i].device_count)
        {
            usb_device_t *dev = &g_uhci[i].devices[index - cursor];
            serial_printf("[usb] bus_device_at idx=%u -> ctrl=%u slot=%u addr=%u port=%u type=%u ep=%u mps=%u intv=%u pkt0=%u cfg=%u\r\n",
                          (unsigned)index,
                          (unsigned)i,
                          (unsigned)(index - cursor),
                          (unsigned)dev->address,
                          (unsigned)dev->port,
                          (unsigned)dev->type,
                          (unsigned)dev->intr_ep.endpoint,
                          (unsigned)dev->intr_ep.max_packet,
                          (unsigned)dev->intr_ep.interval_ms,
                          (unsigned)dev->max_packet0,
                          (unsigned)dev->configuration_value);
            return dev;
        }
        cursor += g_uhci[i].device_count;
    }
    return NULL;
}

bool usb_control_transfer(usb_device_t *dev,
                          const usb_setup_packet_t *setup,
                          void *buffer,
                          uint16_t length)
{
    uhci_controller_t *hc = NULL;
    if (dev && dev->host)
    {
        hc = (uhci_controller_t *)dev->host;
    }
    else if (g_uhci_count > 0)
    {
        hc = &g_uhci[0];
    }
    return hc ? uhci_control_xfer(hc, dev, setup, buffer, length) : false;
}

bool usb_interrupt_in(usb_device_t *dev,
                      usb_endpoint_t *ep,
                      void *buffer,
                      uint16_t length,
                      uint16_t *transferred)
{
    if (!dev || !dev->host)
    {
        return false;
    }
    uhci_controller_t *hc = (uhci_controller_t *)dev->host;
    return uhci_interrupt_in_xfer(hc, dev, ep, buffer, length, transferred);
}
