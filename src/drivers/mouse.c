#include "mouse.h"
#include "io.h"
#include "serial.h"
#include "interrupts.h"
#include "keyboard.h"
#include "spinlock.h"

#define KBD_STATUS 0x64
#define KBD_COMMAND 0x64
#define KBD_DATA 0x60

static mouse_listener_t g_listener = 0;
static uint8_t packet[3];
static uint8_t packet_index = 0;
static int mouse_irq_log_count = 0;
static int mouse_irq_byte_log = 0;
static int mouse_poll_log = 0;
static int mouse_packet_log = 0;
static spinlock_t g_mouse_lock = { 0 };

typedef struct
{
    int dx;
    int dy;
    bool left;
} mouse_event_t;

#define MOUSE_QUEUE_CAP 128
static mouse_event_t g_mouse_queue[MOUSE_QUEUE_CAP];
static uint32_t g_mouse_queue_head = 0;
static uint32_t g_mouse_queue_tail = 0;
static spinlock_t g_mouse_queue_lock = { 0 };
static bool g_mouse_queue_overflow_logged = false;

static inline uint64_t mouse_irq_save(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    __asm__ volatile ("cli" ::: "memory");
    return flags;
}

static inline void mouse_irq_restore(uint64_t flags)
{
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc");
}

static void mouse_log(const char *msg)
{
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
}

static bool mouse_listener_valid(mouse_listener_t listener)
{
    if (!listener)
    {
        return true;
    }
    extern uint8_t __kernel_text_start[];
    extern uint8_t __kernel_text_end[];
    uintptr_t addr = (uintptr_t)listener;
    return addr >= (uintptr_t)__kernel_text_start &&
           addr < (uintptr_t)__kernel_text_end;
}

static void mouse_log_packet(int dx, int dy, bool left, uint8_t status)
{
    char buf[64];
    int idx = 0;
    buf[idx++] = 'P'; buf[idx++] = ':'; buf[idx++] = ' ';
    buf[idx++] = 's'; buf[idx++] = '='; buf[idx++] = '0'; buf[idx++] = 'x';
    const char *hex = "0123456789ABCDEF";
    buf[idx++] = hex[(status >> 4) & 0xF];
    buf[idx++] = hex[status & 0xF];
    buf[idx++] = ' ';
    buf[idx++] = 'd'; buf[idx++] = 'x'; buf[idx++] = '=';
    if (dx < 0) { buf[idx++] = '-'; dx = -dx; }
    else { buf[idx++] = '+'; }
    buf[idx++] = hex[(dx >> 4) & 0xF];
    buf[idx++] = hex[dx & 0xF];
    buf[idx++] = ' ';
    buf[idx++] = 'd'; buf[idx++] = 'y'; buf[idx++] = '=';
    if (dy < 0) { buf[idx++] = '-'; dy = -dy; }
    else { buf[idx++] = '+'; }
    buf[idx++] = hex[(dy >> 4) & 0xF];
    buf[idx++] = hex[dy & 0xF];
    buf[idx++] = ' ';
    buf[idx++] = 'L'; buf[idx++] = left ? '1' : '0';
    buf[idx++] = '\0';
    serial_printf("%s", buf);
}

static void mouse_queue_reset(void)
{
    uint64_t flags = mouse_irq_save();
    spinlock_lock(&g_mouse_queue_lock);
    g_mouse_queue_head = 0;
    g_mouse_queue_tail = 0;
    g_mouse_queue_overflow_logged = false;
    spinlock_unlock(&g_mouse_queue_lock);
    mouse_irq_restore(flags);
}

static void mouse_queue_push(int dx, int dy, bool left)
{
    uint64_t flags = mouse_irq_save();
    spinlock_lock(&g_mouse_queue_lock);

    uint32_t next_head = (g_mouse_queue_head + 1u) % MOUSE_QUEUE_CAP;
    if (next_head == g_mouse_queue_tail)
    {
        /* Drop oldest to keep newest input responsive. */
        g_mouse_queue_tail = (g_mouse_queue_tail + 1u) % MOUSE_QUEUE_CAP;
        if (!g_mouse_queue_overflow_logged)
        {
            mouse_log("mouse queue overflow (dropping oldest)");
            g_mouse_queue_overflow_logged = true;
        }
    }

    g_mouse_queue[g_mouse_queue_head].dx = dx;
    g_mouse_queue[g_mouse_queue_head].dy = dy;
    g_mouse_queue[g_mouse_queue_head].left = left;
    g_mouse_queue_head = next_head;

    spinlock_unlock(&g_mouse_queue_lock);
    mouse_irq_restore(flags);
}

static bool mouse_queue_pop(mouse_event_t *out)
{
    if (!out)
    {
        return false;
    }

    uint64_t flags = mouse_irq_save();
    spinlock_lock(&g_mouse_queue_lock);

    if (g_mouse_queue_head == g_mouse_queue_tail)
    {
        spinlock_unlock(&g_mouse_queue_lock);
        mouse_irq_restore(flags);
        return false;
    }

    *out = g_mouse_queue[g_mouse_queue_tail];
    g_mouse_queue_tail = (g_mouse_queue_tail + 1u) % MOUSE_QUEUE_CAP;
    if (g_mouse_queue_head == g_mouse_queue_tail)
    {
        g_mouse_queue_overflow_logged = false;
    }

    spinlock_unlock(&g_mouse_queue_lock);
    mouse_irq_restore(flags);
    return true;
}

void mouse_dispatch_events(void)
{
    /* Fast drop if nothing is interested. */
    if (!g_listener)
    {
        mouse_queue_reset();
        return;
    }

    mouse_event_t ev;
    while (mouse_queue_pop(&ev))
    {
        g_listener(ev.dx, ev.dy, ev.left);
    }
}

static void mouse_wait(uint8_t type)
{
    /* type: 0 = data, 1 = signal */
    uint32_t timeout = 100000;
    if (type == 0)
    {
        while (timeout-- && ((inb(KBD_STATUS) & 0x01) == 0))
        {
        }
    }
    else
    {
        while (timeout-- && ((inb(KBD_STATUS) & 0x02) != 0))
        {
        }
    }
}

static void mouse_write(uint8_t value)
{
    mouse_wait(1);
    outb(KBD_COMMAND, 0xD4);
    mouse_wait(1);
    outb(KBD_DATA, value);
    mouse_wait(0);
    (void)inb(KBD_DATA); /* ACK */
}

void mouse_register_listener(mouse_listener_t listener)
{
    if (listener && !mouse_listener_valid(listener))
    {
        serial_printf("%s", "mouse listener rejected ptr=0x");
        serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)listener));
        serial_printf("%s", "\r\n");
        return;
    }
    g_listener = listener;
}

void mouse_init(void)
{
    mouse_log("mouse_init: enabling aux port");
    mouse_wait(1);
    outb(KBD_COMMAND, 0xA8); /* enable aux */

    mouse_wait(1);
    outb(KBD_COMMAND, 0x20);
    mouse_wait(0);
    uint8_t status = inb(KBD_DATA);
    status |= 0x03;            /* enable both port IRQs */
    status &= ~(1 << 4);       /* ensure first port clock enabled */
    status &= ~(1 << 5);       /* ensure second port clock enabled */
    mouse_wait(1);
    outb(KBD_COMMAND, 0x60);
    mouse_wait(1);
    outb(KBD_DATA, status);

    mouse_write(0xF6); /* defaults */
    mouse_write(0xF4); /* enable streaming */

    packet_index = 0;
    mouse_irq_log_count = 0;
    mouse_log("mouse_init: streaming enabled");
    mouse_queue_reset();
    interrupts_enable_irq(12);
}

void mouse_reset_debug_counter(void)
{
    mouse_irq_log_count = 0;
    mouse_irq_byte_log = 0;
    mouse_poll_log = 0;
    mouse_log("mouse debug counter reset");
}

static void mouse_process_byte(uint8_t byte)
{
    int out_dx = 0;
    int out_dy = 0;
    bool out_left = false;
    bool emit = false;
    uint64_t irq_state = mouse_irq_save();
    spinlock_lock(&g_mouse_lock);

    if (byte == 0xFA || byte == 0xAA)
    {
        packet_index = 0;
        goto unlock;
    }
    if ((packet_index == 0) && ((byte & 0x08) == 0))
    {
        goto unlock; /* sync */
    }

    packet[packet_index++] = byte;
    if (packet_index < 3)
    {
        goto unlock;
    }

    packet_index = 0;

    out_dx = (int8_t)packet[1];
    out_dy = (int8_t)packet[2];
    if (packet[0] & 0xC0)
    {
        goto unlock;
    }
    out_left = (packet[0] & 0x01) != 0;
    emit = true;

unlock:
    spinlock_unlock(&g_mouse_lock);
    mouse_irq_restore(irq_state);

    if (!emit)
    {
        return;
    }

    if (mouse_packet_log < 16)
    {
        serial_printf("%s", "mouse packet dx=");
        serial_printf("%016llX", (unsigned long long)((uint64_t)(int64_t)out_dx));
        serial_printf("%s", " dy=");
        serial_printf("%016llX", (unsigned long long)((uint64_t)(int64_t)out_dy));
        serial_printf("%s", out_left ? " left=1\r\n" : " left=0\r\n");
        mouse_packet_log++;
    }

    mouse_queue_push(out_dx, -out_dy, out_left);
}

void mouse_on_irq(uint8_t byte)
{
    if (mouse_irq_log_count < 64)
    {
        //mouse_log("mouse IRQ data incoming");
        mouse_irq_log_count++;
    }
    if (mouse_irq_byte_log < 32)
    {
        serial_printf("%s", "mouse irq byte=0x");
        static const char hex[] = "0123456789ABCDEF";
        serial_printf("%c", hex[(byte >> 4) & 0xF]);
        serial_printf("%c", hex[byte & 0xF]);
        serial_printf("%s", "\r\n");
        mouse_irq_byte_log++;
    }
    mouse_process_byte(byte);
}

void mouse_poll(void)
{
    /* Drain ONLY PS/2 aux (mouse) bytes so they don't clog the buffer.
       Leave keyboard bytes untouched for keyboard_try_read(). */
    while (1)
    {
        uint64_t irq_state = mouse_irq_save();
        uint8_t status = inb(KBD_STATUS);
        if ((status & 0x01) == 0)
        {
            mouse_irq_restore(irq_state);
            break; /* no data pending */
        }
        if ((status & 0x20) == 0)
        {
            mouse_irq_restore(irq_state);
            break; /* keyboard data: leave for keyboard driver */
        }
        uint8_t data = inb(KBD_DATA);
        mouse_process_byte(data);
        mouse_irq_restore(irq_state);
    }
}
