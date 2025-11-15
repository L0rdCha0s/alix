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
#include "syscall.h"
#include "smp.h"
#include "paging.h"
#include "lapic.h"
#include "ahci.h"
#include "arch/x86/smp_boot.h"
#include "arch/x86/cpu.h"

extern void syscall_entry(void);

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
static void fault_dump_bytes(uint64_t rip);
static void dump_exception_stacktrace(const interrupt_frame_t *frame);

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

static bool is_canonical_address(uintptr_t addr)
{
    uint64_t upper = addr >> 48;
    uint64_t sign = (addr >> 47) & 1ULL;
    if (sign == 0)
    {
        return upper == 0;
    }
    return upper == 0xFFFFULL;
}

static void log_kernel_stack_bounds(const char *label, const interrupt_frame_t *frame)
{
    thread_t *thread = thread_current();
    if (!thread)
    {
        return;
    }
    uintptr_t base = 0;
    uintptr_t top = 0;
    if (!process_thread_stack_bounds(thread, &base, &top))
    {
        return;
    }
    uint32_t cpu = smp_current_cpu_index();
    uint64_t rsp0 = arch_cpu_get_kernel_stack(cpu);

    serial_printf("%s", "[stack] label=");
    serial_printf("%s", label ? label : "<none>");
    serial_printf("%s", " cpu=0x");
    serial_printf("%016llX", (unsigned long long)(cpu));
    serial_printf("%s", " base=0x");
    serial_printf("%016llX", (unsigned long long)(base));
    serial_printf("%s", " top=0x");
    serial_printf("%016llX", (unsigned long long)(top));
    serial_printf("%s", " rsp0=0x");
    serial_printf("%016llX", (unsigned long long)(rsp0));
    if (frame)
    {
        serial_printf("%s", " rsp=0x");
        serial_printf("%016llX", (unsigned long long)(frame->rsp));
    }
    serial_printf("%s", "\r\n");
}

static void dump_kernel_stack(uintptr_t rsp, size_t max_entries)
{
    serial_printf("%s", "  kernel stack trace:\r\n");
    if (rsp == 0)
    {
        serial_printf("%s", "    <rsp unavailable>\r\n");
        return;
    }

    for (size_t i = 0; i < max_entries; ++i)
    {
        uintptr_t addr = rsp - (i * sizeof(uintptr_t));
        if (!is_canonical_address(addr) ||
            !is_canonical_address(addr + sizeof(uintptr_t) - 1))
        {
            break;
        }
        uintptr_t value = *((const uintptr_t *)addr);
        serial_printf("%s", "    [");
        serial_printf("%016llX", (unsigned long long)(addr));
        serial_printf("%s", "] = 0x");
        serial_printf("%016llX", (unsigned long long)(value));
        if (i == 0)
        {
            serial_printf("%s", " <-- rsp");
        }
        serial_printf("%s", "\r\n");
    }
}

static void dump_exception_stacktrace(const interrupt_frame_t *frame)
{
    if (!frame)
    {
        return;
    }

    bool user_mode = (frame->cs & 0x3u) == 0x3u;
    if (user_mode)
    {
        process_t *proc = process_current();
        if (proc)
        {
            process_dump_user_stack(proc, frame->rsp, 24, 8);
        }
        else
        {
            serial_printf("%s", "  user stack: no current process\r\n");
        }
    }
    else
    {
        dump_kernel_stack(frame->rsp, 24);
        process_debug_scan_current_kernel_stack("exception", frame->rsp, true);
    }
}

static void fault_report(const char *reason,
                         const interrupt_frame_t *frame,
                         uint64_t error_code,
                         bool has_error,
                         bool include_cr2,
                         uint64_t cr2_value)
{
    /* Emit a minimal banner synchronously in case we halt before the queue drains. */
    serial_early_write_string("\r\nCPU exception encountered.\r\n");
    if (reason)
    {
        serial_early_write_string("reason: ");
        serial_early_write_string(reason);
        serial_early_write_string("\r\n");
    }
    console_write("CPU exception encountered, see serial log.\n");
    serial_printf("%s", "\r\n=== CPU EXCEPTION ===\r\n");
    serial_printf("%s", "reason: ");
    serial_printf("%s", reason);
    serial_printf("%s", "\r\n");
    uint32_t cpu_idx = smp_current_cpu_index();
    serial_printf("%s", "  cpu_index=0x");
    serial_printf("%016llX", (unsigned long long)(cpu_idx));
    serial_printf("%s", "\r\n");
    if (frame)
    {
        serial_printf("%s", "  RIP=");
        serial_printf("%016llX", (unsigned long long)(frame->rip));
        serial_printf("%s", " RSP=");
        serial_printf("%016llX", (unsigned long long)(frame->rsp));
        serial_printf("%s", " RFLAGS=");
        serial_printf("%016llX", (unsigned long long)(frame->rflags));
        serial_printf("%s", " CS=");
        serial_printf("%016llX", (unsigned long long)(frame->cs));
        serial_printf("%s", " SS=");
        serial_printf("%016llX", (unsigned long long)(frame->ss));
        serial_printf("%s", "\r\n");
    }
    if (has_error)
    {
        serial_printf("%s", "  ERR=");
        serial_printf("%016llX", (unsigned long long)(error_code));
        serial_printf("%s", "\r\n");
    }
    if (include_cr2)
    {
        serial_printf("%s", "  CR2=");
        serial_printf("%016llX", (unsigned long long)(cr2_value));
        serial_printf("%s", "\r\n");
    }
    uint64_t pid = process_current_pid();
    serial_printf("%s", "  current_pid=0x");
    serial_printf("%016llX", (unsigned long long)(pid));
    serial_printf("%s", "\r\n");
    process_dump_current_thread();
    if (frame)
    {
        fault_dump_bytes(frame->rip);
    }
    serial_printf("%s", "======================\r\n");
}

static void fault_dump_bytes(uint64_t rip)
{
    const uintptr_t IDENTITY_DUMP_LIMIT = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    if (!is_canonical_address((uintptr_t)rip) || rip >= IDENTITY_DUMP_LIMIT)
    {
        return;
    }
    serial_printf("%s", "  instr bytes:");
    for (size_t i = 0; i < 16; ++i)
    {
        uintptr_t addr = (uintptr_t)(rip + i);
        uint8_t byte = *((volatile uint8_t *)addr);
        serial_printf("%s", " ");
        serial_printf("%02X", (unsigned int)(byte));
    }
    serial_printf("%s", "\r\n");
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
    (void)frame;
    timer_on_tick();
    smp_broadcast_schedule_ipi();
    pic_send_eoi(0);
}

__attribute__((interrupt)) static void irq11_handler(interrupt_frame_t *frame)
{
    (void)frame;
    ahci_on_irq();
    rtl8139_on_irq();
    pic_send_eoi(11);
}

__attribute__((interrupt)) static void irq12_handler(interrupt_frame_t *frame)
{
    (void)frame;
    uint8_t status = inb(0x64);
    if (irq12_log_count < 16)
    {
        serial_printf("%s", "irq12 status=0x");
        static const char hex[] = "0123456789ABCDEF";
        serial_printf("%c", hex[(status >> 4) & 0xF]);
        serial_printf("%c", hex[status & 0xF]);
        serial_printf("%s", "\r\n");
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
        serial_printf("%s", "irq12 data=0x");
        static const char hex[] = "0123456789ABCDEF";
        serial_printf("%c", hex[(data >> 4) & 0xF]);
        serial_printf("%c", hex[data & 0xF]);
        serial_printf("%s", "\r\n");
    }
    mouse_on_irq(data);
    pic_send_eoi(12);
    irq12_log_count++;
}

__attribute__((interrupt)) static void divide_error_handler(interrupt_frame_t *frame)
{
    (void)frame;
    fault_report("divide_error", frame, 0, false, false, 0);
    if (process_handle_exception(frame, "divide_error", 0, false, 0))
    {
        return;
    }
    halt_forever();
}

__attribute__((interrupt)) static void invalid_opcode_handler(interrupt_frame_t *frame)
{
    fault_report("invalid_opcode", frame, 0, false, false, 0);
    if (frame && frame->rip >= SMP_BOOT_DATA_PHYS && frame->rip < SMP_BOOT_DATA_PHYS + 0x100)
    {
        serial_printf("%s", "  smp_boot data dump:\r\n");
        const uint64_t *words = (const uint64_t *)(uintptr_t)SMP_BOOT_DATA_PHYS;
        for (size_t i = 0; i < 6; ++i)
        {
            serial_printf("%s", "    word[");
            serial_printf("%016llX", (unsigned long long)(i));
            serial_printf("%s", "]=0x");
            serial_printf("%016llX", (unsigned long long)(words[i]));
            serial_printf("%s", "\r\n");
        }
    }
    dump_exception_stacktrace(frame);
    if (process_handle_exception(frame, "invalid_opcode", 0, false, 0))
    {
        return;
    }
    halt_forever();
}

__attribute__((interrupt)) static void general_protection_handler(interrupt_frame_t *frame, uint64_t error_code)
{
    fault_report("general_protection", frame, error_code, true, false, 0);
    dump_exception_stacktrace(frame);
    if (process_handle_exception(frame, "general_protection", error_code, false, 0))
    {
        return;
    }
    halt_forever();
}

__attribute__((interrupt)) static void stack_fault_handler(interrupt_frame_t *frame, uint64_t error_code)
{
    uint32_t cpu = smp_current_cpu_index();
    uint64_t rsp0 = arch_cpu_get_kernel_stack(cpu);
    fault_report("stack_fault", frame, error_code, true, false, 0);
    serial_printf("%s", "  cpu_index=0x");
    serial_printf("%016llX", (unsigned long long)(cpu));
    serial_printf("%s", " kernel_rsp0=0x");
    serial_printf("%016llX", (unsigned long long)(rsp0));
    serial_printf("%s", "\r\n");
    log_kernel_stack_bounds("stack_fault", frame);
    dump_exception_stacktrace(frame);
    if (process_handle_exception(frame, "stack_fault", error_code, false, 0))
    {
        return;
    }
    halt_forever();
}

__attribute__((interrupt)) static void page_fault_handler(interrupt_frame_t *frame, uint64_t error_code)
{
    uint64_t fault_address = read_cr2();
    fault_report("page_fault", frame, error_code, true, true, fault_address);
    if (frame && ((frame->cs & 0x3u) == 0))
    {
        log_kernel_stack_bounds("page_fault", frame);
    }
    if (process_handle_stack_watch_fault(fault_address, frame, error_code))
    {
        return;
    }
    dump_exception_stacktrace(frame);
    if (process_handle_exception(frame, "page_fault", error_code, true, fault_address))
    {
        return;
    }
    halt_forever();
}

__attribute__((interrupt)) static void smp_schedule_ipi_handler(interrupt_frame_t *frame)
{
    smp_handle_schedule_ipi(frame);
    lapic_eoi();
}

__attribute__((interrupt)) static void smp_tlb_flush_ipi_handler(interrupt_frame_t *frame)
{
    (void)frame;
    paging_handle_remote_tlb_flush();
    lapic_eoi();
}

void interrupts_init(void)
{
    idt_init();
    idt_set_gate(0, (void *)divide_error_handler);
    idt_set_gate(6, (void *)invalid_opcode_handler);
    idt_set_gate(12, (void *)stack_fault_handler);
    idt_set_gate(13, (void *)general_protection_handler);
    idt_set_gate(14, (void *)page_fault_handler);
    idt_set_gate(32, (void *)irq0_handler);
    idt_set_gate(33, (void *)irq1_handler);
    idt_set_gate(43, (void *)irq11_handler);
    idt_set_gate(44, (void *)irq12_handler);
    idt_set_gate(SMP_SCHEDULE_IPI_VECTOR, (void *)smp_schedule_ipi_handler);
    idt_set_gate(SMP_TLB_FLUSH_IPI_VECTOR, (void *)smp_tlb_flush_ipi_handler);
    idt_set_gate_dpl(0x80, syscall_entry, 3);
    idt_load();
    pic_remap();
    pic_set_masks();
    ahci_interrupts_activate();
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
        serial_printf("%s", "PIC masks: PIC1=0x");
        static const char hex[] = "0123456789ABCDEF";
        serial_printf("%c", hex[(pic1_mask >> 4) & 0xF]);
        serial_printf("%c", hex[pic1_mask & 0xF]);
        serial_printf("%s", " PIC2=0x");
        serial_printf("%c", hex[(pic2_mask >> 4) & 0xF]);
        serial_printf("%c", hex[pic2_mask & 0xF]);
        serial_printf("%s", " irq=");
        serial_printf("%c", hex[(irq >> 4) & 0xF]);
        serial_printf("%c", hex[irq & 0xF]);
        serial_printf("%s", "\r\n");
        log_count++;
    }
}

void interrupts_enable(void)
{
    __asm__ volatile ("sti");
}
