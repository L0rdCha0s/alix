#include "usb_hid.h"
#include "keyboard.h"
#include "mouse.h"
#include "serial.h"
#include "libc.h"
#include "process.h"

typedef struct
{
    uint8_t scancode;
    bool extended;
} hid_map_t;

static usb_device_t *g_kbd = NULL;
static usb_device_t *g_mouse = NULL;
static usb_endpoint_t g_kbd_ep = { 0 };
static usb_endpoint_t g_mouse_ep = { 0 };
static uint8_t g_prev_keys[6] = { 0 };
static uint8_t g_prev_modifiers = 0;
static bool g_usb_hid_started = false;

static void hid_release_all_keys(void);

static hid_map_t hid_usage_to_set1(uint8_t usage)
{
    switch (usage)
    {
        case 0x04: return (hid_map_t){ 0x1E, false }; /* A */
        case 0x05: return (hid_map_t){ 0x30, false }; /* B */
        case 0x06: return (hid_map_t){ 0x2E, false }; /* C */
        case 0x07: return (hid_map_t){ 0x20, false }; /* D */
        case 0x08: return (hid_map_t){ 0x12, false }; /* E */
        case 0x09: return (hid_map_t){ 0x21, false }; /* F */
        case 0x0A: return (hid_map_t){ 0x22, false }; /* G */
        case 0x0B: return (hid_map_t){ 0x23, false }; /* H */
        case 0x0C: return (hid_map_t){ 0x17, false }; /* I */
        case 0x0D: return (hid_map_t){ 0x24, false }; /* J */
        case 0x0E: return (hid_map_t){ 0x25, false }; /* K */
        case 0x0F: return (hid_map_t){ 0x26, false }; /* L */
        case 0x10: return (hid_map_t){ 0x32, false }; /* M */
        case 0x11: return (hid_map_t){ 0x31, false }; /* N */
        case 0x12: return (hid_map_t){ 0x18, false }; /* O */
        case 0x13: return (hid_map_t){ 0x19, false }; /* P */
        case 0x14: return (hid_map_t){ 0x10, false }; /* Q */
        case 0x15: return (hid_map_t){ 0x13, false }; /* R */
        case 0x16: return (hid_map_t){ 0x1F, false }; /* S */
        case 0x17: return (hid_map_t){ 0x14, false }; /* T */
        case 0x18: return (hid_map_t){ 0x16, false }; /* U */
        case 0x19: return (hid_map_t){ 0x2F, false }; /* V */
        case 0x1A: return (hid_map_t){ 0x11, false }; /* W */
        case 0x1B: return (hid_map_t){ 0x2D, false }; /* X */
        case 0x1C: return (hid_map_t){ 0x15, false }; /* Y */
        case 0x1D: return (hid_map_t){ 0x2C, false }; /* Z */
        case 0x1E: return (hid_map_t){ 0x02, false }; /* 1 */
        case 0x1F: return (hid_map_t){ 0x03, false }; /* 2 */
        case 0x20: return (hid_map_t){ 0x04, false }; /* 3 */
        case 0x21: return (hid_map_t){ 0x05, false }; /* 4 */
        case 0x22: return (hid_map_t){ 0x06, false }; /* 5 */
        case 0x23: return (hid_map_t){ 0x07, false }; /* 6 */
        case 0x24: return (hid_map_t){ 0x08, false }; /* 7 */
        case 0x25: return (hid_map_t){ 0x09, false }; /* 8 */
        case 0x26: return (hid_map_t){ 0x0A, false }; /* 9 */
        case 0x27: return (hid_map_t){ 0x0B, false }; /* 0 */
        case 0x28: return (hid_map_t){ 0x1C, false }; /* Enter */
        case 0x29: return (hid_map_t){ 0x01, false }; /* Esc */
        case 0x2A: return (hid_map_t){ 0x0E, false }; /* Backspace */
        case 0x2B: return (hid_map_t){ 0x0F, false }; /* Tab */
        case 0x2C: return (hid_map_t){ 0x39, false }; /* Space */
        case 0x2D: return (hid_map_t){ 0x0C, false }; /* - */
        case 0x2E: return (hid_map_t){ 0x0D, false }; /* = */
        case 0x2F: return (hid_map_t){ 0x1A, false }; /* [ */
        case 0x30: return (hid_map_t){ 0x1B, false }; /* ] */
        case 0x31: return (hid_map_t){ 0x2B, false }; /* \\ */
        case 0x33: return (hid_map_t){ 0x27, false }; /* ; */
        case 0x34: return (hid_map_t){ 0x28, false }; /* ' */
        case 0x35: return (hid_map_t){ 0x29, false }; /* ` */
        case 0x36: return (hid_map_t){ 0x33, false }; /* , */
        case 0x37: return (hid_map_t){ 0x34, false }; /* . */
        case 0x38: return (hid_map_t){ 0x35, false }; /* / */
        case 0x39: return (hid_map_t){ 0x3A, false }; /* Caps */
        case 0x3A: return (hid_map_t){ 0x3B, false }; /* F1 */
        case 0x3B: return (hid_map_t){ 0x3C, false }; /* F2 */
        case 0x3C: return (hid_map_t){ 0x3D, false }; /* F3 */
        case 0x3D: return (hid_map_t){ 0x3E, false }; /* F4 */
        case 0x3E: return (hid_map_t){ 0x3F, false }; /* F5 */
        case 0x3F: return (hid_map_t){ 0x40, false }; /* F6 */
        case 0x40: return (hid_map_t){ 0x41, false }; /* F7 */
        case 0x41: return (hid_map_t){ 0x42, false }; /* F8 */
        case 0x42: return (hid_map_t){ 0x43, false }; /* F9 */
        case 0x43: return (hid_map_t){ 0x44, false }; /* F10 */
        case 0x44: return (hid_map_t){ 0x57, false }; /* F11 */
        case 0x45: return (hid_map_t){ 0x58, false }; /* F12 */
        case 0x46: return (hid_map_t){ 0x46, false }; /* Print Screen / Scroll Lock */
        case 0x47: return (hid_map_t){ 0x46, false }; /* Scroll Lock */
        case 0x49: return (hid_map_t){ 0x52, true }; /* Insert */
        case 0x4A: return (hid_map_t){ 0x47, true }; /* Home */
        case 0x4B: return (hid_map_t){ 0x49, true }; /* Page Up */
        case 0x4C: return (hid_map_t){ 0x53, true }; /* Delete */
        case 0x4D: return (hid_map_t){ 0x4F, true }; /* End */
        case 0x4E: return (hid_map_t){ 0x51, true }; /* Page Down */
        case 0x4F: return (hid_map_t){ 0x4D, true }; /* Right */
        case 0x50: return (hid_map_t){ 0x4B, true }; /* Left */
        case 0x51: return (hid_map_t){ 0x50, true }; /* Down */
        case 0x52: return (hid_map_t){ 0x48, true }; /* Up */
        case 0x54: return (hid_map_t){ 0x5B, true }; /* Right GUI */
        case 0xE0: return (hid_map_t){ 0x5B, true }; /* Left GUI */
        default: break;
    }
    return (hid_map_t){ 0, false };
}

static void push_scancode(uint8_t scancode, bool extended, bool release)
{
    if (scancode == 0)
    {
        return;
    }
    if (extended)
    {
        keyboard_buffer_push(0xE0);
    }
    keyboard_buffer_push(release ? (uint8_t)(scancode | 0x80u) : scancode);
}

static bool usage_in_list(const uint8_t *list, size_t len, uint8_t usage)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (list[i] == usage)
        {
            return true;
        }
    }
    return false;
}

static void handle_modifiers(uint8_t mods, bool release_only)
{
    const struct
    {
        uint8_t mask;
        uint8_t scancode;
        bool extended;
    } modmap[] = {
        { 0x01, 0x1D, false }, /* LCtrl */
        { 0x02, 0x2A, false }, /* LShift */
        { 0x04, 0x38, false }, /* LAlt */
        { 0x08, 0x5B, true },  /* LGUI */
        { 0x10, 0x1D, true },  /* RCtrl */
        { 0x20, 0x36, false }, /* RShift */
        { 0x40, 0x38, true },  /* RAlt */
        { 0x80, 0x5C, true },  /* RGUI */
    };

    for (size_t i = 0; i < sizeof(modmap) / sizeof(modmap[0]); ++i)
    {
        bool was_set = (g_prev_modifiers & modmap[i].mask) != 0;
        bool now_set = (mods & modmap[i].mask) != 0;
        if (was_set && !now_set)
        {
            push_scancode(modmap[i].scancode, modmap[i].extended, true);
        }
        else if (!release_only && !was_set && now_set)
        {
            push_scancode(modmap[i].scancode, modmap[i].extended, false);
        }
    }
    g_prev_modifiers = mods;
}

static void process_keyboard_report(const uint8_t *report, size_t len)
{
    if (!report)
    {
        return;
    }
    if (len < 8)
    {
        hid_release_all_keys();
        return;
    }
    if (len > 8)
    {
        len = 8;
    }

    uint8_t modifiers = report[0];
    const uint8_t *keys = &report[2];

    for (size_t i = 0; i < 6; ++i)
    {
        if (keys[i] >= 0x01 && keys[i] <= 0x03)
        {
            hid_release_all_keys();
            return;
        }
    }

    handle_modifiers(modifiers, false);

    for (size_t i = 0; i < 6; ++i)
    {
        uint8_t prev = g_prev_keys[i];
        if (prev && !usage_in_list(keys, 6, prev))
        {
            hid_map_t map = hid_usage_to_set1(prev);
            push_scancode(map.scancode, map.extended, true);
            g_prev_keys[i] = 0;
        }
    }

    for (size_t i = 0; i < 6; ++i)
    {
        uint8_t usage = keys[i];
        if (usage == 0 || usage < 0x04)
        {
            continue;
        }
        if (usage_in_list(g_prev_keys, 6, usage))
        {
            continue;
        }

        hid_map_t map = hid_usage_to_set1(usage);
        push_scancode(map.scancode, map.extended, false);
        for (size_t j = 0; j < 6; ++j)
        {
            if (g_prev_keys[j] == 0)
            {
                g_prev_keys[j] = usage;
                break;
            }
        }
    }
}

static void hid_release_all_keys(void)
{
    handle_modifiers(0, true);
    for (size_t i = 0; i < 6; ++i)
    {
        uint8_t usage = g_prev_keys[i];
        if (usage == 0)
        {
            continue;
        }
        hid_map_t map = hid_usage_to_set1(usage);
        push_scancode(map.scancode, map.extended, true);
        g_prev_keys[i] = 0;
    }
}

static void hid_reset_endpoint_toggle(usb_endpoint_t *ep)
{
    if (ep)
    {
        ep->data_toggle = 0;
    }
}

static void hid_clear_endpoint_halt(usb_device_t *dev, usb_endpoint_t *ep)
{
    if (!dev || !ep || ep->endpoint == 0)
    {
        return;
    }
    usb_setup_packet_t setup = {
        .bmRequestType = 0x02,
        .bRequest = USB_REQ_CLEAR_FEATURE,
        .wValue = 0,
        .wIndex = (uint16_t)(0x80u | ep->endpoint),
        .wLength = 0
    };
    usb_control_transfer(dev, &setup, NULL, 0);
}

static uint8_t hid_idle_units_from_interval(uint8_t interval_ms)
{
    if (interval_ms == 0)
    {
        interval_ms = 10;
    }
    uint16_t units = (uint16_t)((interval_ms + 3u) / 4u);
    if (units == 0)
    {
        units = 1;
    }
    if (units > 0xFFu)
    {
        units = 0xFFu;
    }
    return (uint8_t)units;
}

static void keyboard_thread(void *arg)
{
    (void)arg;
    uint16_t buf_len = (g_kbd_ep.max_packet > 0) ? g_kbd_ep.max_packet : 8;
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    size_t td_bytes = 64 + 15; /* UHCI TD is 16-byte aligned, 32 bytes in size. */
    uint8_t *td_raw = (uint8_t *)malloc(td_bytes);
    void *td = td_raw ? (void *)((uintptr_t)(td_raw + 15) & ~(uintptr_t)0xFULL) : NULL;
    if (!buf || !td)
    {
        serial_printf("%s", "[usb] keyboard thread no buffer/td\r\n");
        if (buf)
        {
            free(buf);
        }
        if (td_raw)
        {
            free(td_raw);
        }
        process_exit(-1);
    }

    while (1)
    {
        uint16_t got = 0;
        if (g_kbd && g_kbd_ep.max_packet > 0)
        {
            bool ok = usb_interrupt_in_prealloc(g_kbd, &g_kbd_ep, buf, buf_len, &got, td);
            if (ok && got > 0)
            {
                process_keyboard_report(buf, got);
            }
            else if (!ok)
            {
                hid_release_all_keys();
                hid_reset_endpoint_toggle(&g_kbd_ep);
                hid_clear_endpoint_halt(g_kbd, &g_kbd_ep);
            }
        }
        /* USB interrupt transfer already waits per endpoint interval; avoid extra 10ms sleep. */
        process_yield();
    }
}

static void process_mouse_report(const uint8_t *buf, size_t len)
{
    if (!buf || len < 3)
    {
        return;
    }
    int dx = (int8_t)buf[1];
    int dy = (int8_t)buf[2];
    bool left = (buf[0] & 0x01u) != 0;
    static int log_budget = 8;
    if (log_budget > 0)
    {
        serial_printf("[usb] mouse report len=%u dx=%d dy=%d left=%u\r\n",
                      (unsigned)len,
                      dx,
                      dy,
                      left ? 1u : 0u);
        log_budget--;
    }
    mouse_inject_event(dx, dy, left);
}

static void mouse_thread(void *arg)
{
    (void)arg;
    uint16_t buf_len = (g_mouse_ep.max_packet > 0) ? g_mouse_ep.max_packet : 8;
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    size_t td_bytes = 64 + 15;
    uint8_t *td_raw = (uint8_t *)malloc(td_bytes);
    void *td = td_raw ? (void *)((uintptr_t)(td_raw + 15) & ~(uintptr_t)0xFULL) : NULL;
    if (!buf || !td)
    {
        serial_printf("%s", "[usb] mouse thread no buffer/td\r\n");
        if (buf)
        {
            free(buf);
        }
        if (td_raw)
        {
            free(td_raw);
        }
        process_exit(-1);
    }

    while (1)
    {
        uint16_t got = 0;
        if (g_mouse && g_mouse_ep.max_packet > 0)
        {
            bool ok = usb_interrupt_in_prealloc(g_mouse, &g_mouse_ep, buf, buf_len, &got, td);
            if (ok && got > 0)
            {
                process_mouse_report(buf, got);
            }
            else if (!ok)
            {
                hid_reset_endpoint_toggle(&g_mouse_ep);
                hid_clear_endpoint_halt(g_mouse, &g_mouse_ep);
            }
        }
        /* Drain events immediately so UI stays responsive even during heavy CPU load. */
        mouse_dispatch_events();
        uint16_t sleep_ms = g_mouse_ep.interval_ms;
        if (sleep_ms == 0 || sleep_ms > 8)
        {
            sleep_ms = 1;
        }
        process_sleep_ms(sleep_ms);
    }
}

static void configure_hid_device(usb_device_t *dev)
{
    if (!dev || dev->intr_ep.max_packet == 0 || dev->intr_ep.endpoint == 0)
    {
        return;
    }
    uint8_t idle_units = 0;
    if (dev->type == USB_DEV_HID_KEYBOARD)
    {
        idle_units = hid_idle_units_from_interval(dev->intr_ep.interval_ms);
    }
    usb_setup_packet_t set_idle = {
        .bmRequestType = 0x21,
        .bRequest = 0x0A,
        .wValue = (uint16_t)((uint16_t)idle_units << 8),
        .wIndex = dev->interface_number,
        .wLength = 0
    };
    usb_control_transfer(dev, &set_idle, NULL, 0);

    usb_setup_packet_t set_proto = {
        .bmRequestType = 0x21,
        .bRequest = 0x0B,
        .wValue = 0,
        .wIndex = dev->interface_number,
        .wLength = 0
    };
    usb_control_transfer(dev, &set_proto, NULL, 0);
}

void usb_hid_init(void)
{
    if (g_usb_hid_started)
    {
        return;
    }
    g_usb_hid_started = true;
    serial_printf("%s", "[usb] hid init begin\r\n");

    if (!usb_bus_init())
    {
        serial_printf("%s", "[usb] bus init failed\r\n");
        return;
    }

    size_t count = usb_bus_device_count();
    serial_printf("[usb] hid devices=%u\r\n", (unsigned)count);
    for (size_t i = 0; i < count; ++i)
    {
        usb_device_t *dev = usb_bus_device_at(i);
        if (!dev)
        {
            continue;
        }
        usb_device_t snapshot = *dev;
        serial_printf("[usb] hid dev%u ptr=0x%016llX type=%u addr=%u intr_ep=%u mps=%u intv=%u pkt0=%u\r\n",
                      (unsigned)i,
                      (unsigned long long)(uintptr_t)dev,
                      (unsigned)snapshot.type,
                      (unsigned)snapshot.address,
                      (unsigned)snapshot.intr_ep.endpoint,
                      (unsigned)snapshot.intr_ep.max_packet,
                      (unsigned)snapshot.intr_ep.interval_ms,
                      (unsigned)snapshot.max_packet0);
        /* Skip devices without a usable interrupt endpoint to avoid TD timeouts. */
        if (snapshot.intr_ep.max_packet == 0 || snapshot.intr_ep.endpoint == 0)
        {
            serial_printf("[usb] hid dev%u skipped: bad intr ep=%u mps=%u\r\n",
                          (unsigned)i,
                          (unsigned)snapshot.intr_ep.endpoint,
                          (unsigned)snapshot.intr_ep.max_packet);
            continue;
        }

        if (snapshot.type != USB_DEV_HID_KEYBOARD && snapshot.type != USB_DEV_HID_MOUSE)
        {
            serial_printf("[usb] hid dev%u skipped: unsupported type=%u\r\n",
                          (unsigned)i,
                          (unsigned)snapshot.type);
            continue;
        }
        configure_hid_device(dev);

        if (dev->type == USB_DEV_HID_KEYBOARD && !g_kbd)
        {
            g_kbd = dev;
            g_kbd_ep = dev->intr_ep;
            keyboard_disable_ps2();
            serial_printf("%s", "[usb] keyboard bound\r\n");
        }
        else if (dev->type == USB_DEV_HID_MOUSE && !g_mouse)
        {
            g_mouse = dev;
            g_mouse_ep = dev->intr_ep;
            mouse_disable_ps2();
            serial_printf("%s", "[usb] mouse bound\r\n");
        }
    }

    if (g_kbd)
    {
        process_t *kbd_thread = process_create_kernel("usb_kbd", keyboard_thread, NULL, 0, -1);
        if (!kbd_thread)
        {
            serial_printf("%s", "[usb] failed to start keyboard thread\r\n");
        }
        else
        {
            uint32_t ui_cpu = process_get_ui_cpu();
            process_set_priority(kbd_thread, THREAD_PRIORITY_UI);
            if (ui_cpu != PROCESS_CPU_ANY)
            {
                process_set_affinity(kbd_thread, ui_cpu);
            }
            process_user_layout_t layout = { 0 };
            process_query_user_layout(kbd_thread, &layout);
            serial_printf("[usb] keyboard thread started proc=0x%016llX pid=0x%016llX cr3=0x%016llX as_cr3=0x%016llX\r\n",
                          (unsigned long long)(uintptr_t)kbd_thread,
                          (unsigned long long)process_get_pid(kbd_thread),
                          (unsigned long long)layout.cr3,
                          (unsigned long long)layout.cr3);
        }
    }
    if (g_mouse)
    {
        process_t *m_thread = process_create_kernel("usb_mouse", mouse_thread, NULL, 0, -1);
        if (!m_thread)
        {
            serial_printf("%s", "[usb] failed to start mouse thread\r\n");
        }
        else
        {
            uint32_t ui_cpu = process_get_ui_cpu();
            process_set_priority(m_thread, THREAD_PRIORITY_UI);
            if (ui_cpu != PROCESS_CPU_ANY)
            {
                process_set_affinity(m_thread, ui_cpu);
            }
            process_user_layout_t layout = { 0 };
            process_query_user_layout(m_thread, &layout);
            serial_printf("[usb] mouse thread started proc=0x%016llX pid=0x%016llX cr3=0x%016llX as_cr3=0x%016llX\r\n",
                          (unsigned long long)(uintptr_t)m_thread,
                          (unsigned long long)process_get_pid(m_thread),
                          (unsigned long long)layout.cr3,
                          (unsigned long long)layout.cr3);
        }
    }
}

bool usb_hid_have_keyboard(void)
{
    return g_kbd != NULL;
}

bool usb_hid_have_mouse(void)
{
    return g_mouse != NULL;
}
