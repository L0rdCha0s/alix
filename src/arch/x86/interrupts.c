#include "idt.h"
#include "io.h"
#include "timer.h"
#include "mouse.h"
#include "types.h"
#include "rtl8139.h"

#define PIC1_COMMAND 0x20
#define PIC1_DATA    0x21
#define PIC2_COMMAND 0xA0
#define PIC2_DATA    0xA1
#define PIC_EOI      0x20

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
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);
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
    uint8_t data = inb(0x60);
    mouse_on_irq(data);
    pic_send_eoi(12);
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

void interrupts_enable(void)
{
    __asm__ volatile ("sti");
}
