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

#if KERNEL_BUILD
static void serial_format_hex64(char *out, size_t cap, uint64_t value)
{
    if (!out || cap < 2)
    {
        return;
    }
    const char *digits = "0123456789ABCDEF";
    size_t len = (cap - 1 < 16) ? (cap - 1) : 16;
    for (size_t i = 0; i < len; ++i)
    {
        out[len - 1 - i] = digits[value & 0xF];
        value >>= 4;
    }
    out[len] = '\0';
}
#endif

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

static bool kernel_rsp_valid(uintptr_t rsp, uintptr_t *base_out, uintptr_t *top_out)
{
    if (!is_canonical_address(rsp) || !is_canonical_address(rsp + sizeof(uintptr_t) - 1))
    {
        return false;
    }
    thread_t *thread = thread_current();
    if (!thread)
    {
        return false;
    }
    uintptr_t base = 0;
    uintptr_t top = 0;
    if (!process_thread_stack_bounds(thread, &base, &top))
    {
        return false;
    }
    if (rsp < base || rsp >= top)
    {
        return false;
    }
    if (base_out)
    {
        *base_out = base;
    }
    if (top_out)
    {
        *top_out = top;
    }
    return true;
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
    uintptr_t base = 0;
    uintptr_t top = 0;
    if (!kernel_rsp_valid(rsp, &base, &top))
    {
        serial_printf("%s", "    <rsp unavailable>\r\n");
        return;
    }

    for (size_t i = 0; i < max_entries; ++i)
    {
        if (rsp < base + i * sizeof(uintptr_t))
        {
            break;
        }
        uintptr_t addr = rsp - (i * sizeof(uintptr_t));
        if (!is_canonical_address(addr) ||
            !is_canonical_address(addr + sizeof(uintptr_t) - 1) ||
            addr < base)
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

        /* Also emit kernel stack bounds/contents to catch bad return paths. */
        log_kernel_stack_bounds("exception", frame);
        thread_t *thread = thread_current();
        uintptr_t base = 0;
        uintptr_t top = 0;
        if (thread && process_thread_stack_bounds(thread, &base, &top))
        {
            uintptr_t probe = (top >= 8) ? (top - 8) : top;
            dump_kernel_stack(probe, 16);
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
    /* Emit synchronously with early serial to avoid queue loss before halting. */
    char buf[32];
    serial_early_write_string("\r\n=== CPU EXCEPTION ===\r\n");
    serial_early_write_string("reason: ");
    serial_early_write_string(reason ? reason : "<unknown>");
    serial_early_write_string("\r\n");

    uint32_t cpu_idx = smp_current_cpu_index();
    serial_early_write_string("  cpu_index=0x");
    serial_format_hex64(buf, sizeof(buf), cpu_idx);
    serial_early_write_string(buf);
    serial_early_write_string("\r\n");

    if (frame)
    {
        serial_early_write_string("  RIP=");
        serial_format_hex64(buf, sizeof(buf), frame->rip);
        serial_early_write_string(buf);

        serial_early_write_string(" RSP=");
        serial_format_hex64(buf, sizeof(buf), frame->rsp);
        serial_early_write_string(buf);

        serial_early_write_string(" RFLAGS=");
        serial_format_hex64(buf, sizeof(buf), frame->rflags);
        serial_early_write_string(buf);

        serial_early_write_string(" CS=");
        serial_format_hex64(buf, sizeof(buf), frame->cs);
        serial_early_write_string(buf);

        serial_early_write_string(" SS=");
        serial_format_hex64(buf, sizeof(buf), frame->ss);
        serial_early_write_string(buf);
        serial_early_write_string("\r\n");
    }
    if (has_error)
    {
        serial_early_write_string("  ERR=");
        serial_format_hex64(buf, sizeof(buf), error_code);
        serial_early_write_string(buf);
        serial_early_write_string("\r\n");
    }
    if (include_cr2)
    {
        serial_early_write_string("  CR2=");
        serial_format_hex64(buf, sizeof(buf), cr2_value);
        serial_early_write_string(buf);
        serial_early_write_string("\r\n");
    }
    uint64_t pid = process_current_pid();
    serial_early_write_string("  current_pid=0x");
    serial_format_hex64(buf, sizeof(buf), pid);
    serial_early_write_string(buf);
    serial_early_write_string("\r\n");

    if (frame)
    {
        serial_early_write_string("  stack (top 8 qwords):\r\n");
        bool user_mode = (frame->cs & 0x3u) != 0;
        if (user_mode)
        {
            process_t *proc = process_current();
            process_dump_user_stack(proc, frame->rsp, 0, 8);
        }
        else
        {
            uintptr_t base = 0;
            uintptr_t top = 0;
            if (!kernel_rsp_valid(frame->rsp, &base, &top))
            {
                serial_early_write_string("    <rsp unavailable>\r\n");
            }
            else
            {
                uint64_t *sp = (uint64_t *)(uintptr_t)frame->rsp;
                for (int i = 0; i < 8 && frame->rsp + (uint64_t)(i * 8) < top; ++i)
                {
                    serial_early_write_string("    [");
                    serial_format_hex64(buf, sizeof(buf), frame->rsp + (uint64_t)(i * 8));
                    serial_early_write_string(buf);
                    serial_early_write_string("] = 0x");
                    serial_format_hex64(buf, sizeof(buf), sp ? sp[i] : 0);
                    serial_early_write_string(buf);
                    serial_early_write_string("\r\n");
                }
            }
        }
    }

    process_dump_current_thread();
    if (frame)
    {
        fault_dump_bytes(frame->rip);
    }
    serial_early_write_string("======================\r\n");
}

static void fault_dump_bytes(uint64_t rip)
{
    const uintptr_t IDENTITY_DUMP_LIMIT = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    if (!is_canonical_address((uintptr_t)rip) || rip >= IDENTITY_DUMP_LIMIT)
    {
        return;
    }
    static const char hex[] = "0123456789ABCDEF";
    char buf[4] = { ' ', '0', '0', '\0' };
    serial_early_write_string("  instr bytes:");
    for (size_t i = 0; i < 16; ++i)
    {
        uintptr_t addr = (uintptr_t)(rip + i);
        uint8_t byte = *((volatile uint8_t *)addr);
        buf[1] = hex[(byte >> 4) & 0xF];
        buf[2] = hex[byte & 0xF];
        serial_early_write_string(buf);
    }
    serial_early_write_string("\r\n");
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
    log_kernel_stack_bounds("invalid_opcode", frame);
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
        serial_printf("PIC masks: PIC1=0x%02X PIC2=0x%02X irq=%02X\r\n",
                      (unsigned)(pic1_mask),
                      (unsigned)(pic2_mask),
                      (unsigned)irq);
        log_count++;
    }
}

void interrupts_enable(void)
{
    __asm__ volatile ("sti");
}
