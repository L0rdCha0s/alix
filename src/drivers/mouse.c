#include "mouse.h"
#include "io.h"
#include "serial.h"
#include "interrupts.h"
#include "keyboard.h"

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

static void mouse_log(const char *msg)
{
    serial_write_string(msg);
    serial_write_string("\r\n");
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
    serial_write_string(buf);
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
    if (byte == 0xFA || byte == 0xAA)
    {
        packet_index = 0;
        return;
    }
    if ((packet_index == 0) && ((byte & 0x08) == 0))
    {
        return; /* sync */
    }

    packet[packet_index++] = byte;
    if (packet_index < 3)
    {
        return;
    }

    packet_index = 0;

    int dx = (int8_t)packet[1];
    int dy = (int8_t)packet[2];
    bool left = (packet[0] & 0x01) != 0;
    //mouse_log_packet(dx, dy, left, packet[0]);
    if (mouse_packet_log < 16)
    {
        serial_write_string("mouse packet dx=");
        serial_write_hex64((uint64_t)(int64_t)dx);
        serial_write_string(" dy=");
        serial_write_hex64((uint64_t)(int64_t)dy);
        serial_write_string(left ? " left=1\r\n" : " left=0\r\n");
        mouse_packet_log++;
    }

    if (g_listener)
    {
        g_listener(dx, -dy, left);
    }
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
        serial_write_string("mouse irq byte=0x");
        static const char hex[] = "0123456789ABCDEF";
        serial_write_char(hex[(byte >> 4) & 0xF]);
        serial_write_char(hex[byte & 0xF]);
        serial_write_string("\r\n");
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
        uint8_t status = inb(KBD_STATUS);
        if ((status & 0x01) == 0)
        {
            break; /* no data pending */
        }
        uint8_t data = inb(KBD_DATA);
        if ((status & 0x20) == 0)
        {
            if (mouse_poll_log < 8)
            {
                serial_write_string("mouse_poll draining keyboard status=0x");
                static const char hex[] = "0123456789ABCDEF";
                serial_write_char(hex[(status >> 4) & 0xF]);
                serial_write_char(hex[status & 0xF]);
                serial_write_string(" data=0x");
                serial_write_char(hex[(data >> 4) & 0xF]);
                serial_write_char(hex[data & 0xF]);
                serial_write_string("\r\n");
                mouse_poll_log++;
            }
            keyboard_buffer_push(data);
            continue;
        }
        mouse_process_byte(data);
    }
}
