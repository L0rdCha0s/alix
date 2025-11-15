#include "arch/x86/cpu.h"

#include "arch/x86/segments.h"
#include "smp.h"
#include "libc.h"
#include "serial.h"

#define ARCH_MAX_CPUS SMP_MAX_CPUS
#define GDT_ENTRY_COUNT 9
#define TSS_SELECTOR 0x38

typedef struct __attribute__((packed))
{
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap_base;
} tss64_layout_t;

static uint64_t gdt_template[GDT_ENTRY_COUNT] = {
    0x0000000000000000ULL,
    0x00CF9A000000FFFFULL,
    0x00CF92000000FFFFULL,
    0x00AF9A000000FFFFULL, /* kernel code 64-bit */
    0x00AF92000000FFFFULL, /* kernel data */
    0x00AFFA000000FFFFULL, /* user code 64-bit */
    0x00AFF2000000FFFFULL, /* user data */
    0x0000000000000000ULL,
    0x0000000000000000ULL
};

static uint64_t gdt_tables[ARCH_MAX_CPUS][GDT_ENTRY_COUNT];
static arch_gdtr_t gdt_descriptors[ARCH_MAX_CPUS];
static uint8_t tss_tables[ARCH_MAX_CPUS][sizeof(tss64_layout_t)] __attribute__((aligned(16)));
static uint64_t cpu_rsp0[ARCH_MAX_CPUS] = { 0 };
static bool gdt_prepared[ARCH_MAX_CPUS] = { false };

static void install_tss_descriptor(uint32_t cpu_index)
{
    uint64_t base = (uint64_t)(uintptr_t)tss_tables[cpu_index];
    uint16_t limit = (uint16_t)(sizeof(tss64_layout_t) - 1U);

    uint64_t low = ((uint64_t)limit) |
                   ((base & 0xFFFFFFULL) << 16) |
                   (0x89ULL << 40) |
                   (((uint64_t)limit & 0xF0000ULL) << 32) |
                   ((base >> 24) & 0xFFULL) << 56;
    uint64_t high = (base >> 32) & 0xFFFFFFFFULL;

    gdt_tables[cpu_index][7] = low;
    gdt_tables[cpu_index][8] = high;
}

static void prepare_gdt(uint32_t cpu_index)
{
    if (cpu_index >= ARCH_MAX_CPUS)
    {
        return;
    }
    memcpy(gdt_tables[cpu_index], gdt_template, sizeof(gdt_template));
    memset(tss_tables[cpu_index], 0, sizeof(tss64_layout_t));
    tss64_layout_t *tss = (tss64_layout_t *)tss_tables[cpu_index];
    tss->iomap_base = sizeof(tss64_layout_t);
    install_tss_descriptor(cpu_index);
    gdt_descriptors[cpu_index].limit = (uint16_t)(sizeof(gdt_tables[cpu_index]) - 1U);
    gdt_descriptors[cpu_index].base = (uint64_t)(uintptr_t)gdt_tables[cpu_index];
    gdt_prepared[cpu_index] = true;
}

static void load_gdt(uint32_t cpu_index)
{
    if (cpu_index >= ARCH_MAX_CPUS || !gdt_prepared[cpu_index])
    {
        return;
    }
    arch_gdtr_t *gdtr = &gdt_descriptors[cpu_index];
    __asm__ volatile ("lgdt %0" :: "m"(*gdtr));
}

static void load_segment_registers(void)
{
    uint16_t data_sel = GDT_SELECTOR_KERNEL_DATA;
    __asm__ volatile (
        "mov %0, %%ds\n\t"
        "mov %0, %%es\n\t"
        "mov %0, %%ss\n\t"
        "mov %0, %%fs\n\t"
        "mov %0, %%gs\n\t"
        :
        : "r"(data_sel)
        : "memory");

    uint16_t code_sel = GDT_SELECTOR_KERNEL_CODE;
    __asm__ volatile (
        "pushq %[cs_sel]\n\t"
        "leaq 1f(%%rip), %%rax\n\t"
        "pushq %%rax\n\t"
        "lretq\n"
        "1:\n"
        :
        : [cs_sel] "r"((uint64_t)code_sel)
        : "rax", "memory");
}

static void load_tss(void)
{
    uint16_t selector = TSS_SELECTOR;
    __asm__ volatile ("ltr %0" :: "r"(selector));
}

void arch_cpu_set_kernel_stack(uint32_t cpu_index, uint64_t rsp0)
{
    if (cpu_index >= ARCH_MAX_CPUS || !gdt_prepared[cpu_index])
    {
        return;
    }
    tss64_layout_t *tss = (tss64_layout_t *)tss_tables[cpu_index];
    tss->rsp0 = rsp0;
    cpu_rsp0[cpu_index] = rsp0;
}

static void activate_cpu(uint32_t cpu_index)
{
    load_gdt(cpu_index);
    load_segment_registers();
    load_tss();
}

void arch_cpu_init_bsp(uint64_t initial_rsp0)
{
    prepare_gdt(0);
    arch_cpu_set_kernel_stack(0, initial_rsp0);
    activate_cpu(0);
}

void arch_cpu_init_ap(uint32_t cpu_index, uint64_t initial_rsp0)
{
    prepare_gdt(cpu_index);
    arch_cpu_set_kernel_stack(cpu_index, initial_rsp0);
    activate_cpu(cpu_index);
}

uint64_t arch_cpu_get_kernel_stack(uint32_t cpu_index)
{
    if (cpu_index >= ARCH_MAX_CPUS || !gdt_prepared[cpu_index])
    {
        return 0;
    }
    return cpu_rsp0[cpu_index];
}

void arch_cpu_get_gdtr(uint32_t cpu_index, arch_gdtr_t *gdtr_out)
{
    if (!gdtr_out || cpu_index >= ARCH_MAX_CPUS || !gdt_prepared[cpu_index])
    {
        return;
    }
    *gdtr_out = gdt_descriptors[cpu_index];
}
