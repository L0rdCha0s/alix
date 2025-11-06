#include "idt.h"
#include "io.h"
#include "timer.h"
#include "mouse.h"
#include "keyboard.h"
#include "types.h"
#include "interrupts.h"
#include "rtl8139.h"
#include "serial.h"
#include "process.h"
#include "console.h"

#define PIC1_COMMAND 0x20
#define PIC1_DATA    0x21
#define PIC2_COMMAND 0xA0
#define PIC2_DATA    0xA1
#define PIC_EOI      0x20

static uint8_t pic1_mask = 0xFF;
static uint8_t pic2_mask = 0xFF;
static int irq12_log_count = 0;

static void halt_forever(void) __attribute__((noreturn));
static void fault_report(const char *reason,
                         const interrupt_frame_t *frame,
                         uint64_t error_code,
                         bool has_error,
                         bool include_cr2,
                         uint64_t cr2_value);

static inline uint64_t read_cr2(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr2, %0" : "=r"(value));
    return value;
}

static void halt_forever(void)
{
    for (;;)
    {
        __asm__ volatile ("cli; hlt");
    }
}

static void fault_report(const char *reason,
                         const interrupt_frame_t *frame,
                         uint64_t error_code,
                         bool has_error,
                         bool include_cr2,
                         uint64_t cr2_value)
{
    console_write("CPU exception encountered, see serial log.\n");
    serial_write_string("\r\n=== CPU EXCEPTION ===\r\n");
    serial_write_string("reason: ");
    serial_write_string(reason);
    serial_write_string("\r\n");
    if (frame)
    {
        serial_write_string("  RIP=");
        serial_write_hex64(frame->rip);
        serial_write_string(" RSP=");
        serial_write_hex64(frame->rsp);
        serial_write_string(" RFLAGS=");
        serial_write_hex64(frame->rflags);
        serial_write_string(" CS=");
        serial_write_hex64(frame->cs);
        serial_write_string(" SS=");
        serial_write_hex64(frame->ss);
        serial_write_string("\r\n");
    }
    if (has_error)
    {
        serial_write_string("  ERR=");
        serial_write_hex64(error_code);
        serial_write_string("\r\n");
    }
    if (include_cr2)
    {
        serial_write_string("  CR2=");
        serial_write_hex64(cr2_value);
        serial_write_string("\r\n");
    }
    uint64_t pid = process_current_pid();
    serial_write_string("  current_pid=0x");
    serial_write_hex64(pid);
    serial_write_string("\r\n");
    serial_write_string("======================\r\n");
}

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

__attribute__((interrupt)) static void irq1_handler(interrupt_frame_t *frame)
{
    (void)frame;
    uint8_t status = inb(0x64);
    if ((status & 0x01) != 0)
    {
        uint8_t scancode = inb(0x60);
        keyboard_buffer_push(scancode);
    
    }
    pic_send_eoi(1);
}

__attribute__((interrupt)) static void irq0_handler(interrupt_frame_t *frame)
{
    timer_on_tick();
    process_on_timer_tick(frame);
    pic_send_eoi(0);
}

__attribute__((interrupt)) static void irq11_handler(interrupt_frame_t *frame)
{
    (void)frame;
    rtl8139_on_irq();
    pic_send_eoi(11);
}

__attribute__((interrupt)) static void irq12_handler(interrupt_frame_t *frame)
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

__attribute__((interrupt)) static void divide_error_handler(interrupt_frame_t *frame)
{
    (void)frame;
    fault_report("divide_error", frame, 0, false, false, 0);
    halt_forever();
}

__attribute__((interrupt)) static void invalid_opcode_handler(interrupt_frame_t *frame)
{
    fault_report("invalid_opcode", frame, 0, false, false, 0);
    halt_forever();
}

__attribute__((interrupt)) static void general_protection_handler(interrupt_frame_t *frame, uint64_t error_code)
{
    fault_report("general_protection", frame, error_code, true, false, 0);
    halt_forever();
}

__attribute__((interrupt)) static void page_fault_handler(interrupt_frame_t *frame, uint64_t error_code)
{
    uint64_t fault_address = read_cr2();
    fault_report("page_fault", frame, error_code, true, true, fault_address);
    halt_forever();
}

void interrupts_init(void)
{
    idt_init();
    idt_set_gate(0, (void *)divide_error_handler);
    idt_set_gate(6, (void *)invalid_opcode_handler);
    idt_set_gate(13, (void *)general_protection_handler);
    idt_set_gate(14, (void *)page_fault_handler);
    idt_set_gate(32, (void *)irq0_handler);
    idt_set_gate(33, (void *)irq1_handler);
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
