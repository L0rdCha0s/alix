#include "arch/x86/bootlayout.h"
#include "bootinfo.h"
#include "msr.h"
#include "serial.h"
#include "arch/x86/segments.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

extern void kernel_main(void);

extern uint8_t __kernel_text_start[];
extern uint8_t __kernel_text_end[];
extern uint8_t __kernel_data_start[];
extern uint8_t __kernel_data_end[];
extern uint8_t __bss_start[];
extern uint8_t __bss_end[];
extern bootinfo_t boot_info;

typedef struct
{
    uint32_t reserved0;
    uint32_t reserved1;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved2;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved3;
    uint16_t reserved4;
    uint16_t iomap_base;
} __attribute__((packed)) tss64_layout_t;

uintptr_t kernel_heap_base = KERNEL_HEAP_BASE;
uintptr_t kernel_heap_end = KERNEL_HEAP_BASE + KERNEL_HEAP_SIZE;
uintptr_t kernel_heap_size = KERNEL_HEAP_SIZE;

uint8_t tss64[sizeof(tss64_layout_t)] __attribute__((aligned(16)));
_Static_assert(sizeof(tss64) >= sizeof(tss64_layout_t), "TSS buffer too small");

static uint64_t gdt_entries[] = {
    0x0000000000000000ULL,
    0x00CF9A000000FFFFULL,
    0x00CF92000000FFFFULL,
    0x00A09A0000000000ULL,
    0x00A0920000000000ULL,
    0x00A0FA0000000000ULL,
    0x00A0F20000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL
};

typedef struct
{
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) gdtr_t;

static inline uint64_t read_cr0(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(value));
    return value;
}

static inline void write_cr0(uint64_t value)
{
    __asm__ volatile ("mov %0, %%cr0" :: "r"(value) : "memory");
}

static inline uint64_t read_cr3(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(value));
    return value;
}

static inline void write_cr3(uint64_t value)
{
    __asm__ volatile ("mov %0, %%cr3" :: "r"(value) : "memory");
}

static inline uint64_t read_cr4(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr4, %0" : "=r"(value));
    return value;
}

static inline void write_cr4(uint64_t value)
{
    __asm__ volatile ("mov %0, %%cr4" :: "r"(value) : "memory");
}

static void zero_bytes(uint8_t *ptr, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        ptr[i] = 0;
    }
}

static void copy_bytes(uint8_t *dst, const uint8_t *src, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        dst[i] = src[i];
    }
}

static void build_page_tables(void)
{
    uint64_t *pml4 = (uint64_t *)(uintptr_t)PML4_PHYS;
    uint64_t *pdp = (uint64_t *)(uintptr_t)PDP_PHYS;
    uint64_t *pd0 = (uint64_t *)(uintptr_t)PD0_PHYS;
    uint64_t *pd1 = (uint64_t *)(uintptr_t)PD1_PHYS;
    uint64_t *pd2 = (uint64_t *)(uintptr_t)PD2_PHYS;
    uint64_t *pd3 = (uint64_t *)(uintptr_t)PD3_PHYS;

    zero_bytes((uint8_t *)pml4, 4096);
    zero_bytes((uint8_t *)pdp, 4096);
    zero_bytes((uint8_t *)pd0, 4096);
    zero_bytes((uint8_t *)pd1, 4096);
    zero_bytes((uint8_t *)pd2, 4096);
    zero_bytes((uint8_t *)pd3, 4096);

    const uint64_t present_rw = 0x3ULL;
    const uint64_t large_page = 1ULL << 7;

    pml4[0] = (uint64_t)PDP_PHYS | present_rw;
    pdp[0] = (uint64_t)PD0_PHYS | present_rw;
    pdp[1] = (uint64_t)PD1_PHYS | present_rw;
    pdp[2] = (uint64_t)PD2_PHYS | present_rw;
    pdp[3] = (uint64_t)PD3_PHYS | present_rw;

    uint64_t addr = 0;
    for (int i = 0; i < 512; ++i)
    {
        pd0[i] = (addr & 0x000FFFFFFFFFF000ULL) | present_rw | large_page;
        addr += 0x200000ULL;
    }
    addr = 0x40000000ULL;
    for (int i = 0; i < 512; ++i)
    {
        pd1[i] = (addr & 0x000FFFFFFFFFF000ULL) | present_rw | large_page;
        addr += 0x200000ULL;
    }
    addr = 0x80000000ULL;
    for (int i = 0; i < 512; ++i)
    {
        pd2[i] = (addr & 0x000FFFFFFFFFF000ULL) | present_rw | large_page;
        addr += 0x200000ULL;
    }
    addr = 0xC0000000ULL;
    for (int i = 0; i < 512; ++i)
    {
        pd3[i] = (addr & 0x000FFFFFFFFFF000ULL) | present_rw | large_page;
        addr += 0x200000ULL;
    }

    uint64_t cr4 = read_cr4();
    cr4 |= (1ULL << 5) | (1ULL << 9) | (1ULL << 10);
    write_cr4(cr4);

    write_cr3((uint64_t)(uintptr_t)PML4_PHYS);

    uint64_t efer = rdmsr(0xC0000080U);
    efer |= (1ULL << 8);
    wrmsr(0xC0000080U, efer);

    uint64_t cr0 = read_cr0();
    cr0 |= (1ULL << 31) | (1ULL << 1);
    cr0 &= ~(1ULL << 2);
    write_cr0(cr0);
}

static void install_tss_descriptor(void)
{
    uint64_t base = (uint64_t)(uintptr_t)tss64;
    uint16_t limit = (uint16_t)(sizeof(tss64) - 1U);

    uint64_t low = ((uint64_t)limit) |
                   ((base & 0xFFFFFFULL) << 16) |
                   (0x89ULL << 40) |
                   (((uint64_t)limit & 0xF0000ULL) << 32) |
                   ((base >> 24) & 0xFFULL) << 56;
    uint64_t high = (base >> 32) & 0xFFFFFFFFULL;

    gdt_entries[7] = low;
    gdt_entries[8] = high;
}

static void load_gdt_and_segments(void)
{
    gdtr_t gdtr = {
        .limit = (uint16_t)(sizeof(gdt_entries) - 1U),
        .base = (uint64_t)(uintptr_t)gdt_entries
    };
    __asm__ volatile ("lgdt %0" :: "m"(gdtr));

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
    install_tss_descriptor();
    tss64_layout_t *tss = (tss64_layout_t *)(void *)tss64;
    zero_bytes((uint8_t *)tss, sizeof(tss64_layout_t));
    tss->rsp0 = STACK_TOP;
    tss->iomap_base = sizeof(tss64_layout_t);
    uint16_t tss_selector = 0x38U;
    __asm__ volatile ("ltr %0" :: "r"(tss_selector));
}

static void kernel_entry_main(bootinfo_t *loader_info)
{
    serial_init();
    serial_write_string("[alix] kernel_entry_main\n");

    size_t bss_size = (size_t)(__bss_end - __bss_start);

    zero_bytes(__bss_start, bss_size);
    if (loader_info)
    {
        copy_bytes((uint8_t *)&boot_info,
                   (const uint8_t *)loader_info,
                   sizeof(bootinfo_t));
    }

    build_page_tables();
    serial_write_string("[alix] page tables built\n");
    load_gdt_and_segments();
    serial_write_string("[alix] gdt loaded\n");
    load_tss();
    serial_write_string("[alix] tss loaded\n");

    serial_write_string("[alix] entering kernel_main\n");
    kernel_main();
}

void __attribute__((naked)) kernel_entry(bootinfo_t *loader_info)
{
    __asm__ volatile (
        "cli\n\t"
        "mov %%rdi, %%rsi\n\t"
        "mov %[stack_top], %%rax\n\t"
        "mov %%rax, %%rsp\n\t"
        "mov %%rsi, %%rdi\n\t"
        "call kernel_entry_main\n\t"
        "hlt\n\t"
        "jmp .-2\n\t"
        :
        : [stack_top] "r"(STACK_TOP)
        : "rax", "rsi", "memory");
}
