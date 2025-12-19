#include "usb.h"
#include "pci.h"
#include "io.h"
#include "serial.h"
#include "ioremap.h"
#include "libc.h"
#include "timer.h"
#include "process.h"
#include "interrupts.h"

static bool g_usb_irq_registered[INTERRUPTS_IRQ_COUNT];

static void usb_irq_handler(uint8_t irq, interrupt_frame_t *frame, void *context)
{
    (void)irq;
    (void)frame;
    (void)context;
    usb_on_irq();
}

#define UHCI_MAX_PORTS 2
#define UHCI_MAX_DEVICES 16
#define UHCI_TD_POOL_SIZE 2048

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

#define USB_PORT_STAT_CONNECTION   0x0001u
#define USB_PORT_STAT_ENABLE       0x0002u
#define USB_PORT_STAT_RESET        0x0010u
#define USB_PORT_STAT_POWER        0x0100u
#define USB_PORT_STAT_LOW_SPEED    0x0200u
#define USB_PORT_STAT_HIGH_SPEED   0x0400u

#define USB_PORT_FEAT_CONNECTION     0
#define USB_PORT_FEAT_ENABLE         1
#define USB_PORT_FEAT_RESET          4
#define USB_PORT_FEAT_POWER          8
#define USB_PORT_FEAT_C_CONNECTION   16
#define USB_PORT_FEAT_C_ENABLE       17
#define USB_PORT_FEAT_C_SUSPEND      18
#define USB_PORT_FEAT_C_OVER_CURRENT 19
#define USB_PORT_FEAT_C_RESET        20

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
    bool transfer_active;
    uint8_t irq_line;
    bool irq_enabled;
    usb_device_t devices[UHCI_MAX_DEVICES];
    size_t device_count;
} uhci_controller_t;

static __attribute__((aligned(16))) uhci_td_t g_td_pool[UHCI_TD_POOL_SIZE];
static uint16_t g_td_pool_next = 0;
static uint16_t g_td_pool_free[UHCI_TD_POOL_SIZE];
static uint16_t g_td_pool_free_count = 0;
static spinlock_t g_td_pool_lock;

static uhci_controller_t g_uhci[UHCI_MAX_CONTROLLERS] = { 0 };
static size_t g_uhci_count = 0;
static bool ehci_route_ports_to_uhci(void);

static inline bool td_in_pool(uhci_td_t *td)
{
    return td && td >= g_td_pool && td < (g_td_pool + UHCI_TD_POOL_SIZE);
}

static uhci_td_t *td_pool_alloc(size_t count)
{
    uhci_td_t *tds = NULL;
    spinlock_lock(&g_td_pool_lock);
    if (count == 1 && g_td_pool_free_count > 0)
    {
        uint16_t idx = g_td_pool_free[--g_td_pool_free_count];
        tds = &g_td_pool[idx];
    }
    else if (g_td_pool_next + count <= UHCI_TD_POOL_SIZE)
    {
        tds = &g_td_pool[g_td_pool_next];
        g_td_pool_next = (uint16_t)(g_td_pool_next + count);
    }
    spinlock_unlock(&g_td_pool_lock);
    if (tds)
    {
        memset(tds, 0, sizeof(uhci_td_t) * count);
    }
    return tds;
}

static void td_pool_free(uhci_td_t *td)
{
    if (!td_in_pool(td))
    {
        return;
    }
    uint16_t idx = (uint16_t)(td - g_td_pool);
    spinlock_lock(&g_td_pool_lock);
    if (g_td_pool_free_count < UHCI_TD_POOL_SIZE)
    {
        g_td_pool_free[g_td_pool_free_count++] = idx;
    }
    spinlock_unlock(&g_td_pool_lock);
}

static void td_pool_free_chain(uhci_td_t *tds, size_t count)
{
    if (!tds || count == 0)
    {
        return;
    }
    for (size_t i = 0; i < count; ++i)
    {
        td_pool_free(&tds[i]);
    }
}

static void uhci_unlink_chain(uhci_td_t *tds, size_t td_count)
{
    if (!tds || td_count == 0)
    {
        return;
    }
    for (size_t i = 0; i < td_count; ++i)
    {
        tds[i].link = UHCI_LINK_TERMINATE;
        tds[i].control &= ~UHCI_TD_CTRL_ACTIVE;
    }
}

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
    if (ms == 0)
    {
        return;
    }

    /*
     * We run the PIT at 100Hz (10ms granularity), so any delay smaller than a
     * tick must round up to at least one tick. Sleeping is preferred once the
     * scheduler is ready; it avoids CPU-speed-dependent busy waits that can
     * cause flaky USB timing under QEMU TCG.
     */
    if (process_scheduler_ready())
    {
        process_sleep_ms(ms);
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
    return td_pool_alloc(count);
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

typedef enum
{
    UHCI_WAIT_OK,
    UHCI_WAIT_TIMEOUT,
    UHCI_WAIT_ERROR
} uhci_wait_result_t;

static uhci_wait_result_t uhci_wait_for_td(uhci_controller_t *hc,
                                           uhci_td_t *last,
                                           uint32_t timeout_ms,
                                           bool yield_on_frame)
{
    if (!hc)
    {
        return UHCI_WAIT_ERROR;
    }
    if (!last)
    {
        return UHCI_WAIT_ERROR;
    }

    /* UHCI FRNUM increments every 1ms frame (11-bit counter). */
    uint32_t timeout_frames = timeout_ms ? timeout_ms : 1u;
    if (timeout_frames > 0x7FFu)
    {
        timeout_frames = 0x7FFu;
    }
    uint16_t start_frame = (uint16_t)(inw(hc->iobase + UHCI_FRNUM) & 0x07FFu);
    uint64_t fallback_deadline_ms = usb_now_ms() + (uint64_t)timeout_frames + 50ULL;

    uint16_t last_frame = start_frame;
    uint32_t same_frame_spins = 0;
    static int deadline_log_budget = 8;

    while (1)
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
                return UHCI_WAIT_ERROR;
            }
            return UHCI_WAIT_OK;
        }

        uint16_t frame = (uint16_t)(inw(hc->iobase + UHCI_FRNUM) & 0x07FFu);
        uint16_t elapsed = (uint16_t)((frame - start_frame) & 0x07FFu);
        if ((uint32_t)elapsed >= timeout_frames || usb_now_ms() >= fallback_deadline_ms)
        {
            if (deadline_log_budget > 0)
            {
                deadline_log_budget--;
                usb_log("[usb] td wait deadline");
            }
            return UHCI_WAIT_TIMEOUT;
        }

        if (frame == last_frame)
        {
            /* Avoid burning an entire CPU if FRNUM is slow/paused under TCG. */
            if (++same_frame_spins >= 20000)
            {
                same_frame_spins = 0;
                process_yield();
            }
        }
        else
        {
            last_frame = frame;
            same_frame_spins = 0;
            if (yield_on_frame)
            {
                process_yield();
            }
        }
        __asm__ volatile ("pause");
    }
    return UHCI_WAIT_TIMEOUT;
}

static void uhci_acquire_transfer(uhci_controller_t *hc)
{
    while (1)
    {
        spinlock_lock(&hc->lock);
        if (!hc->transfer_active)
        {
            hc->transfer_active = true;
            spinlock_unlock(&hc->lock);
            return;
        }
        spinlock_unlock(&hc->lock);
        process_yield();
    }
}

static void uhci_release_transfer(uhci_controller_t *hc)
{
    spinlock_lock(&hc->lock);
    hc->async_qh->element_link = UHCI_LINK_TERMINATE;
    hc->async_qh->head_link = UHCI_LINK_TERMINATE;
    hc->transfer_active = false;
    spinlock_unlock(&hc->lock);
}

static bool uhci_submit_chain(uhci_controller_t *hc,
                              uhci_td_t *tds,
                              size_t td_count,
                              bool short_ok,
                              bool is_interrupt,
                              uint32_t wait_ms)
{
    if (!hc || !tds || td_count == 0)
    {
        return false;
    }

    uhci_acquire_transfer(hc);
    spinlock_lock(&hc->lock);
    hc->async_qh->element_link = virt_to_phys(tds);
    hc->async_qh->head_link = UHCI_LINK_TERMINATE;
    spinlock_unlock(&hc->lock);

    uhci_td_t *last = &tds[td_count - 1];
    if (wait_ms == 0)
    {
        wait_ms = is_interrupt ? 10 : 200;
    }
    uhci_wait_result_t wait = uhci_wait_for_td(hc, last, wait_ms, is_interrupt);
    bool ok = (wait == UHCI_WAIT_OK);
    bool soft_no_data = false;
    if (wait == UHCI_WAIT_TIMEOUT && is_interrupt)
    {
        /* Interrupt endpoints can legitimately NAK with no data; treat as empty. */
        last->control &= ~UHCI_TD_CTRL_ACTIVE;
        last->control |= UHCI_TD_CTRL_SPD;
        /* Mark actual length as "no data" so callers see transferred=0. */
        last->control = (last->control & ~UHCI_TD_CTRL_ACTLEN_MASK) | UHCI_TD_CTRL_ACTLEN_MASK;
        soft_no_data = true;
        ok = true;
    }
    /* Unlink the chain before releasing the lock so the controller does not
       keep walking freed TDs on subsequent frames. */
    uhci_release_transfer(hc);
    if (!ok)
    {
        const char *reason = (wait == UHCI_WAIT_ERROR) ? "error" : "timeout";
        uint32_t token = tds[0].token;
        uint8_t pid = (uint8_t)(token & 0xFFu);
        uint8_t addr = (uint8_t)((token >> 8) & 0x7Fu);
        uint8_t ep = (uint8_t)((token >> 15) & 0x1Fu);
        serial_printf("[usb] td chain %s pid=0x%02X addr=%u ep=%u ctrl=0x%08X last_ctrl=0x%08X\r\n",
                      reason,
                      (unsigned)pid,
                      (unsigned)addr,
                      (unsigned)ep,
                      (unsigned)tds[0].control,
                      (unsigned)last->control);
        /* Stop the controller from continually re-walking this chain. */
        uhci_unlink_chain(tds, td_count);
        outw(hc->iobase + UHCI_USBSTS, 0xFFFF);
        /* If the controller halted, try to restart it so later transfers keep working. */
        uint16_t sts = inw(hc->iobase + UHCI_USBSTS);
        if (sts & UHCI_STS_HCHALTED)
        {
            uhci_start(hc);
        }
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
    bool ok = uhci_submit_chain(hc, tds, total_tds, true, false, 200);
    usb_log(ok ? "[usb] control xfer ok" : "[usb] control xfer fail");
    td_pool_free_chain(tds, total_tds);
    return ok;
}

static bool uhci_interrupt_in_xfer_td(uhci_controller_t *hc,
                                      usb_device_t *dev,
                                      usb_endpoint_t *ep,
                                      void *buffer,
                                      uint16_t length,
                                      uint16_t *transferred,
                                      uhci_td_t *td,
                                      bool free_td)
{
    (void)free_td; /* caller owns td lifetime now */
    if (!hc || !dev || !ep || !buffer || length == 0 || !td)
    {
        return false;
    }

    memset(td, 0, sizeof(*td));
    uint32_t ctrl = UHCI_TD_CTRL_ERRCNT(3) | UHCI_TD_CTRL_ACTIVE | UHCI_TD_CTRL_SPD;
    if (dev->speed == USB_SPEED_LOW)
    {
        ctrl |= UHCI_TD_CTRL_LS;
    }
    td->control = ctrl;
    td->token = uhci_build_token(UHCI_PID_IN, dev->address, ep->endpoint, ep->data_toggle, length);
    td->buffer = virt_to_phys(buffer);
    td->link = UHCI_LINK_TERMINATE;

    uint32_t wait_ms = ep ? ep->interval_ms : 0;
    if (wait_ms < 2)
    {
        wait_ms = 2;
    }
    if (wait_ms > 20)
    {
        wait_ms = 20;
    }
    bool ok = uhci_submit_chain(hc, td, 1, true, true, wait_ms);
    uint16_t actual = 0;
    if (ok && transferred)
    {
        uint32_t act_len = td->control & UHCI_TD_CTRL_ACTLEN_MASK;
        if (act_len == UHCI_TD_CTRL_ACTLEN_MASK)
        {
            actual = 0;
        }
        else
        {
            actual = (uint16_t)(act_len + 1u);
        }
        *transferred = actual;
    }
    if (ok && actual > 0)
    {
        ep->data_toggle ^= 1u;
    }
    return ok;
}

static bool uhci_interrupt_in_xfer(uhci_controller_t *hc,
                                   usb_device_t *dev,
                                   usb_endpoint_t *ep,
                                   void *buffer,
                                   uint16_t length,
                                   uint16_t *transferred)
{
    uhci_td_t *td = uhci_alloc_td_chain(1);
    if (!td)
    {
        return false;
    }
    bool ok = uhci_interrupt_in_xfer_td(hc, dev, ep, buffer, length, transferred, td, true);
    td_pool_free(td);
    return ok;
}

static usb_device_t *usb_alloc_device_slot(uhci_controller_t *hc)
{
    if (!hc)
    {
        return NULL;
    }
    if (hc->device_count >= UHCI_MAX_DEVICES)
    {
        serial_printf("[usb] device limit reached (%u)\r\n", (unsigned)UHCI_MAX_DEVICES);
        return NULL;
    }
    usb_device_t *dev = &hc->devices[hc->device_count];
    memset(dev, 0, sizeof(*dev));
    dev->host = hc;
    dev->max_packet0 = 8;
    return dev;
}

static bool usb_hub_get_descriptor(usb_device_t *hub, uint8_t *buf, uint16_t len)
{
    if (!hub || !buf || len == 0)
    {
        return false;
    }
    usb_setup_packet_t setup = {
        .bmRequestType = 0xA0,
        .bRequest = USB_REQ_GET_DESCRIPTOR,
        .wValue = (USB_DESC_HUB << 8),
        .wIndex = 0,
        .wLength = len
    };
    return usb_control_transfer(hub, &setup, buf, len);
}

static bool usb_hub_set_port_feature(usb_device_t *hub, uint8_t port, uint16_t feature)
{
    if (!hub || port == 0)
    {
        return false;
    }
    usb_setup_packet_t setup = {
        .bmRequestType = 0x23,
        .bRequest = USB_REQ_SET_FEATURE,
        .wValue = feature,
        .wIndex = port,
        .wLength = 0
    };
    return usb_control_transfer(hub, &setup, NULL, 0);
}

static bool usb_hub_clear_port_feature(usb_device_t *hub, uint8_t port, uint16_t feature)
{
    if (!hub || port == 0)
    {
        return false;
    }
    usb_setup_packet_t setup = {
        .bmRequestType = 0x23,
        .bRequest = USB_REQ_CLEAR_FEATURE,
        .wValue = feature,
        .wIndex = port,
        .wLength = 0
    };
    return usb_control_transfer(hub, &setup, NULL, 0);
}

static bool usb_hub_get_port_status(usb_device_t *hub,
                                    uint8_t port,
                                    uint16_t *status,
                                    uint16_t *change)
{
    if (!hub || port == 0)
    {
        return false;
    }
    uint16_t buf[2] = { 0, 0 };
    usb_setup_packet_t setup = {
        .bmRequestType = 0xA3,
        .bRequest = USB_REQ_GET_STATUS,
        .wValue = 0,
        .wIndex = port,
        .wLength = sizeof(buf)
    };
    if (!usb_control_transfer(hub, &setup, buf, sizeof(buf)))
    {
        return false;
    }
    if (status)
    {
        *status = buf[0];
    }
    if (change)
    {
        *change = buf[1];
    }
    return true;
}

static bool usb_parse_config(usb_device_t *dev, uint8_t *config, uint16_t total_len)
{
    if (!dev || !config || total_len < 9)
    {
        return false;
    }

    uint16_t idx = 0;
    uint8_t current_interface = 0xFF;
    uint8_t selected_interface = 0xFF;
    usb_device_type_t selected_type = USB_DEV_UNKNOWN;
    usb_endpoint_t selected_ep = { 0 };
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
            if (iface_class == USB_CLASS_HID)
            {
                usb_device_type_t iface_type = USB_DEV_UNKNOWN;
                if (iface_proto == 1)
                {
                    iface_type = USB_DEV_HID_KEYBOARD;
                }
                else if (iface_proto == 2)
                {
                    iface_type = USB_DEV_HID_MOUSE;
                }
                if (iface_type != USB_DEV_UNKNOWN)
                {
                    bool prefer = (selected_type == USB_DEV_UNKNOWN) ||
                                  (selected_type == USB_DEV_HID_MOUSE &&
                                   iface_type == USB_DEV_HID_KEYBOARD);
                    if (prefer)
                    {
                        selected_type = iface_type;
                        selected_interface = current_interface;
                        memset(&selected_ep, 0, sizeof(selected_ep));
                    }
                }
            }
        }
        else if (dtype == USB_DESC_ENDPOINT && len >= 7 && current_interface != 0xFF)
        {
            uint8_t ep_addr = config[idx + 2];
            uint8_t attributes = config[idx + 3];
            uint16_t mps = (uint16_t)config[idx + 4] | ((uint16_t)config[idx + 5] << 8);
            uint8_t interval = config[idx + 6];
            if (current_interface == selected_interface &&
                (attributes & 0x3) == 0x3 &&
                (ep_addr & 0x80) &&
                selected_ep.endpoint == 0)
            {
                selected_ep.endpoint = (uint8_t)(ep_addr & 0x0F);
                selected_ep.max_packet = mps ? mps : 8;
                selected_ep.interval_ms = interval ? interval : 10;
            }
        }

        idx = (uint16_t)(idx + len);
    }

    dev->type = selected_type;
    dev->interface_number = (selected_interface == 0xFF) ? 0 : selected_interface;
    if (selected_ep.endpoint != 0)
    {
        dev->intr_ep = selected_ep;
    }
    return true;
}

static void usb_enumerate_hub_ports(uhci_controller_t *hc, usb_device_t *hub);

static bool usb_enumerate_device(uhci_controller_t *hc,
                                 usb_device_t *dev,
                                 uint8_t port_index)
{
    if (!hc || !dev)
    {
        return false;
    }

    uint8_t device_desc_buf[18];
    usb_setup_packet_t get_dev = {
        .bmRequestType = 0x80,
        .bRequest = USB_REQ_GET_DESCRIPTOR,
        .wValue = (USB_DESC_DEVICE << 8),
        .wIndex = 0,
        .wLength = 8
    };

    if (!uhci_control_xfer(hc, dev, &get_dev, device_desc_buf, 8))
    {
        usb_log("[usb] failed to get dev desc (first stage)");
        return false;
    }
    serial_printf("[usb] port%u stage1 maxpkt0=%u\r\n",
                  (unsigned)port_index,
                  (unsigned)device_desc_buf[7]);

    dev->max_packet0 = device_desc_buf[7] ? device_desc_buf[7] : 8;

    uint8_t new_addr = (uint8_t)(hc->device_count + 1);
    usb_setup_packet_t set_addr = {
        .bmRequestType = 0x00,
        .bRequest = USB_REQ_SET_ADDRESS,
        .wValue = new_addr,
        .wIndex = 0,
        .wLength = 0
    };
    if (!uhci_control_xfer(hc, dev, &set_addr, NULL, 0))
    {
        usb_log("[usb] failed to set address");
        return false;
    }
    serial_printf("[usb] port%u address=%u\r\n", (unsigned)port_index, (unsigned)new_addr);
    usb_delay_ms(4);
    dev->address = new_addr;

    get_dev.wLength = sizeof(device_desc_buf);
    if (!uhci_control_xfer(hc, dev, &get_dev, device_desc_buf, sizeof(device_desc_buf)))
    {
        usb_log("[usb] failed to read device descriptor");
        return false;
    }
    dev->vendor_id = (uint16_t)device_desc_buf[8] | ((uint16_t)device_desc_buf[9] << 8);
    dev->product_id = (uint16_t)device_desc_buf[10] | ((uint16_t)device_desc_buf[11] << 8);
    dev->max_packet0 = device_desc_buf[7] ? device_desc_buf[7] : dev->max_packet0;
    dev->device_class = device_desc_buf[4];
    dev->device_subclass = device_desc_buf[5];
    dev->device_protocol = device_desc_buf[6];
    dev->is_hub = (dev->device_class == USB_CLASS_HUB);
    dev->hub_port_count = 0;
    serial_printf("[usb] port%u dev vid=0x%04X pid=0x%04X cls=0x%02X sub=0x%02X proto=0x%02X pkt0=%u\r\n",
                  (unsigned)port_index,
                  (unsigned)dev->vendor_id,
                  (unsigned)dev->product_id,
                  (unsigned)dev->device_class,
                  (unsigned)dev->device_subclass,
                  (unsigned)dev->device_protocol,
                  (unsigned)dev->max_packet0);

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

    if (dev->is_hub)
    {
        usb_enumerate_hub_ports(hc, dev);
    }
    return true;
}

static void usb_enumerate_hub_ports(uhci_controller_t *hc, usb_device_t *hub)
{
    if (!hc || !hub)
    {
        return;
    }
    uint8_t hub_desc[8];
    if (!usb_hub_get_descriptor(hub, hub_desc, sizeof(hub_desc)))
    {
        serial_printf("[usb] hub addr=%u descriptor read failed\r\n",
                      (unsigned)hub->address);
        return;
    }

    uint8_t ports = hub_desc[2];
    hub->hub_port_count = ports;
    serial_printf("[usb] hub addr=%u ports=%u\r\n",
                  (unsigned)hub->address,
                  (unsigned)ports);
    if (ports == 0)
    {
        return;
    }

    for (uint8_t p = 1; p <= ports; ++p)
    {
        usb_hub_set_port_feature(hub, p, USB_PORT_FEAT_POWER);
    }
    usb_delay_ms(20);

    for (uint8_t p = 1; p <= ports; ++p)
    {
        uint16_t ps = 0, pc = 0;
        if (!usb_hub_get_port_status(hub, p, &ps, &pc))
        {
            continue;
        }
        if (!(ps & USB_PORT_STAT_CONNECTION))
        {
            continue;
        }

        usb_hub_clear_port_feature(hub, p, USB_PORT_FEAT_C_CONNECTION);
        usb_hub_clear_port_feature(hub, p, USB_PORT_FEAT_C_ENABLE);
        usb_hub_clear_port_feature(hub, p, USB_PORT_FEAT_C_RESET);

        if (!usb_hub_set_port_feature(hub, p, USB_PORT_FEAT_RESET))
        {
            serial_printf("[usb] hub addr=%u port%u reset failed\r\n",
                          (unsigned)hub->address,
                          (unsigned)p);
            continue;
        }
        usb_delay_ms(50);
        usb_hub_clear_port_feature(hub, p, USB_PORT_FEAT_C_RESET);

        int wait_enable = 10;
        while (wait_enable-- > 0)
        {
            if (!usb_hub_get_port_status(hub, p, &ps, &pc))
            {
                break;
            }
            if (ps & USB_PORT_STAT_ENABLE)
            {
                break;
            }
            usb_delay_ms(10);
        }
        if (!(ps & USB_PORT_STAT_ENABLE))
        {
            serial_printf("[usb] hub addr=%u port%u not enabled status=0x%04X\r\n",
                          (unsigned)hub->address,
                          (unsigned)p,
                          (unsigned)ps);
            continue;
        }

        bool low_speed = (ps & USB_PORT_STAT_LOW_SPEED) != 0;
        usb_device_t *child = usb_alloc_device_slot(hc);
        if (!child)
        {
            return;
        }
        child->port = p;
        child->speed = low_speed ? USB_SPEED_LOW : USB_SPEED_FULL;
        child->address = 0;
        if (!usb_enumerate_device(hc, child, p))
        {
            memset(child, 0, sizeof(*child));
        }
    }
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

    usb_device_t *dev = usb_alloc_device_slot(hc);
    if (!dev)
    {
        return false;
    }
    dev->port = port_index;
    dev->speed = (status & UHCI_PORT_LSDA) ? USB_SPEED_LOW : USB_SPEED_FULL;
    serial_printf("[usb] port%u connected speed=%s\r\n",
                  (unsigned)port_index,
                  dev->speed == USB_SPEED_LOW ? "low" : "full");
    dev->address = 0;
    return usb_enumerate_device(hc, dev, port_index);
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
    hc->irq_line = pci_config_read8(hc->pci, 0x3Cu);

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
    g_td_pool_next = 0;
    g_td_pool_free_count = 0;
    memset(g_usb_irq_registered, 0, sizeof(g_usb_irq_registered));
    spinlock_init(&g_td_pool_lock);
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
        if (hc->irq_line < INTERRUPTS_IRQ_COUNT && !hc->irq_enabled)
        {
            bool registered = g_usb_irq_registered[hc->irq_line];
            if (!registered)
            {
                registered = interrupts_register_irq_handler(hc->irq_line, usb_irq_handler, NULL);
                if (registered)
                {
                    g_usb_irq_registered[hc->irq_line] = true;
                }
            }
            if (registered)
            {
                interrupts_enable_irq(hc->irq_line);
                hc->irq_enabled = true;
                serial_printf("[usb] enabled irq line %u for uhci %u\r\n",
                              (unsigned)hc->irq_line,
                              (unsigned)i);
            }
            else
            {
                serial_printf("[usb] failed to register IRQ handler line %u for uhci %u\r\n",
                              (unsigned)hc->irq_line,
                              (unsigned)i);
            }
        }
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

    uint32_t bar_low = pci_config_read32(ehci, 0x10);
    if (bar_low & 0x1u)
    {
        usb_log("[usb] EHCI BAR0 is IO, unexpected");
        return false;
    }
    uint64_t base = (uint64_t)(bar_low & ~0xFULL);
    if ((bar_low & 0x6u) == 0x4u)
    {
        uint32_t bar_high = pci_config_read32(ehci, 0x14);
        base |= ((uint64_t)bar_high << 32);
    }
    if (base == 0)
    {
        usb_log("[usb] EHCI BAR0 is zero");
        return false;
    }

    volatile uint32_t *regs = (volatile uint32_t *)ioremap((paddr_t)base, 0x1000);
    if (!regs)
    {
        usb_log("[usb] EHCI ioremap failed");
        return false;
    }
    uint32_t hcsparams = regs[1]; /* HCSPARAMS at offset 0x04 */
    uint8_t ports = (uint8_t)(hcsparams & 0x0F);
    serial_printf("[usb] ehci route ports count=%u base=0x%016llX cmd=0x%04X bar=0x%08X\r\n",
                  (unsigned)ports,
                  (unsigned long long)base,
                  (unsigned)cmd_reg,
                  (unsigned)bar_low);

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

bool usb_interrupt_in_prealloc(usb_device_t *dev,
                               usb_endpoint_t *ep,
                               void *buffer,
                               uint16_t length,
                               uint16_t *transferred,
                               void *td_mem)
{
    if (!dev || !dev->host || !td_mem)
    {
        return false;
    }
    uhci_controller_t *hc = (uhci_controller_t *)dev->host;
    return uhci_interrupt_in_xfer_td(hc,
                                     dev,
                                     ep,
                                     buffer,
                                     length,
                                     transferred,
                                     (uhci_td_t *)td_mem,
                                     false);
}

void usb_on_irq(void)
{
    static int log_budget = 8;
    for (size_t i = 0; i < g_uhci_count; ++i)
    {
        uhci_controller_t *hc = &g_uhci[i];
        uint16_t status = inw(hc->iobase + UHCI_USBSTS);
        if (status != 0)
        {
            outw(hc->iobase + UHCI_USBSTS, status);
            if (log_budget > 0)
            {
                log_budget--;
                serial_printf("[usb] irq status=0x%04X hc=%u\r\n",
                              (unsigned)status,
                              (unsigned)i);
            }
        }
    }
}
