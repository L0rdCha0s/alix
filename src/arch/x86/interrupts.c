#include "idt.h"
#include "io.h"
#include "timer.h"
#include "mouse.h"
#include "types.h"
#include "rtl8139.h"
#include "serial.h"

#define PIC1_COMMAND 0x20
#define PIC1_DATA    0x21
#define PIC2_COMMAND 0xA0
#define PIC2_DATA    0xA1
#define PIC_EOI      0x20

static uint8_t pic1_mask = 0xFF;
static uint8_t pic2_mask = 0xFF;
static int irq12_log_count = 0;

struct interrupt_frame
{
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

static void pic_remap(void)
{
    outb(PIC1_COMMAND, 0x11);
    outb(PIC2_COMMAND, 0x11);
    outb(PIC1_DATA, 0x20);
    outb(PIC2_DATA, 0x28);
    outb(PIC1_DATA, 0x04);
    outb(PIC2_DATA, 0x02);
    outb(PIC1_DATA, 0x01);
    outb(PIC2_DATA, 0x01);
}

static void pic_set_masks(void)
{
    /* Bring-up: mask all IRQ lines initially so STI returns cleanly. */
    pic1_mask = 0xFF;
    pic2_mask = 0xFF;
    outb(PIC1_DATA, pic1_mask);
    outb(PIC2_DATA, pic2_mask);
}

static void pic_send_eoi(uint8_t irq)
{
    if (irq >= 8)
    {
        outb(PIC2_COMMAND, PIC_EOI);
    }
    outb(PIC1_COMMAND, PIC_EOI);
}

__attribute__((interrupt)) static void irq0_handler(struct interrupt_frame *frame)
{
    (void)frame;
    timer_on_tick();
    pic_send_eoi(0);
}

__attribute__((interrupt)) static void irq11_handler(struct interrupt_frame *frame)
{
    (void)frame;
    rtl8139_on_irq();
    pic_send_eoi(11);
}

__attribute__((interrupt)) static void irq12_handler(struct interrupt_frame *frame)
{
    (void)frame;
    uint8_t status = inb(0x64);
    if (irq12_log_count < 16)
    {
        serial_write_string("irq12 status=0x");
        static const char hex[] = "0123456789ABCDEF";
        serial_write_char(hex[(status >> 4) & 0xF]);
        serial_write_char(hex[status & 0xF]);
        serial_write_string("\r\n");
    }
    if ((status & 0x20) == 0)
    {
        pic_send_eoi(12);
        irq12_log_count++;
        return;
    }
    uint8_t data = inb(0x60);
    if (irq12_log_count < 16)
    {
        serial_write_string("irq12 data=0x");
        static const char hex[] = "0123456789ABCDEF";
        serial_write_char(hex[(data >> 4) & 0xF]);
        serial_write_char(hex[data & 0xF]);
        serial_write_string("\r\n");
    }
    mouse_on_irq(data);
    pic_send_eoi(12);
    irq12_log_count++;
}

void interrupts_init(void)
{
    idt_init();
    idt_set_gate(32, (void *)irq0_handler);
    idt_set_gate(43, (void *)irq11_handler);
    idt_set_gate(44, (void *)irq12_handler);
    idt_load();
    pic_remap();
    pic_set_masks();
}

void interrupts_enable_irq(uint8_t irq)
{
    static int log_count = 0;
    if (irq < 8)
    {
        pic1_mask &= (uint8_t)~(1u << irq);
        outb(PIC1_DATA, pic1_mask);
    }
    else
    {
        uint8_t line = (uint8_t)(irq - 8);
        pic2_mask &= (uint8_t)~(1u << line);
        outb(PIC2_DATA, pic2_mask);
        /* ensure cascade line is enabled */
        pic1_mask &= (uint8_t)~(1u << 2);
        outb(PIC1_DATA, pic1_mask);
    }
    if (log_count < 8)
    {
        serial_write_string("PIC masks: PIC1=0x");
        static const char hex[] = "0123456789ABCDEF";
        serial_write_char(hex[(pic1_mask >> 4) & 0xF]);
        serial_write_char(hex[pic1_mask & 0xF]);
        serial_write_string(" PIC2=0x");
        serial_write_char(hex[(pic2_mask >> 4) & 0xF]);
        serial_write_char(hex[pic2_mask & 0xF]);
        serial_write_string(" irq=");
        serial_write_char(hex[(irq >> 4) & 0xF]);
        serial_write_char(hex[irq & 0xF]);
        serial_write_string("\r\n");
        log_count++;
    }
}

void interrupts_enable(void)
{
    __asm__ volatile ("sti");
}
