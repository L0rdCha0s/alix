#include "arch/x86/bootlayout.h"
#include "bootinfo.h"
#include "msr.h"
#include "serial.h"
#include "arch/x86/segments.h"
#include "arch/x86/cpu.h"

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

uintptr_t kernel_heap_base = KERNEL_HEAP_BASE;
uintptr_t kernel_heap_end = KERNEL_HEAP_BASE + KERNEL_HEAP_SIZE;
uintptr_t kernel_heap_size = KERNEL_HEAP_SIZE;

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

static void configure_heap_from_e820(void)
{
    const uint32_t max_entries = BOOTINFO_MAX_E820_ENTRIES;
    uint32_t count = boot_info.e820_entry_count;
    if (count > max_entries)
    {
        count = max_entries;
    }
    if (count == 0)
    {
        return;
    }

    const uint64_t desired_size = KERNEL_HEAP_SIZE;
    const uint64_t max_addr = 0xFFFFFFFFULL; /* identity mapped limit */
    const uint64_t min_base = 0x02000000ULL; /* avoid low memory */
    uint64_t best_base = 0;
    uint64_t best_size = 0;

    for (uint32_t i = 0; i < count; ++i)
    {
        if (boot_info.e820[i].type != 1)
        {
            continue;
        }
        uint64_t entry_base = boot_info.e820[i].base;
        uint64_t entry_end = entry_base + boot_info.e820[i].length;
        if (entry_end <= entry_base)
        {
            continue;
        }
        if (entry_base >= max_addr)
        {
            continue;
        }
        if (entry_end > max_addr)
        {
            entry_end = max_addr;
        }

        uint64_t candidate_base = entry_base;
        if (candidate_base < min_base)
        {
            candidate_base = min_base;
        }
        /* Align to 2 MiB to reduce fragmentation and respect hugepage boundaries. */
        const uint64_t align = 0x200000ULL;
        candidate_base = (candidate_base + (align - 1)) & ~(align - 1);
        if (candidate_base >= entry_end)
        {
            continue;
        }

        uint64_t available = entry_end - candidate_base;
        if (available >= desired_size)
        {
            /* Prefer a region that can fit the full desired size. Pick the largest. */
            if (available > best_size || best_size < desired_size)
            {
                best_base = candidate_base;
                best_size = desired_size;
                break;
            }
        }
        else if (available > best_size)
        {
            best_base = candidate_base;
            best_size = available;
        }
    }

    if (best_size > 0)
    {
        kernel_heap_base = (uintptr_t)best_base;
        kernel_heap_end = (uintptr_t)(best_base + best_size);
        kernel_heap_size = (uintptr_t)best_size;
    }

    serial_printf("%s", "[alix] heap range ");
    serial_printf("%016llX", (unsigned long long)(kernel_heap_base));
    serial_printf("%s", " - ");
    serial_printf("%016llX", (unsigned long long)(kernel_heap_end));
    serial_printf("%s", " (");
    serial_printf("%016llX", (unsigned long long)(kernel_heap_size));
    serial_printf("%s", " bytes)\r\n");
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


__attribute__((noinline, used))
static void kernel_entry_main(bootinfo_t *loader_info)
{
    serial_init();
    serial_printf("%s", "[alix] kernel_entry_main\n");

    size_t bss_size = (size_t)(__bss_end - __bss_start);

    zero_bytes(__bss_start, bss_size);
    if (loader_info)
    {
        copy_bytes((uint8_t *)&boot_info,
                   (const uint8_t *)loader_info,
                   sizeof(bootinfo_t));
    }
    configure_heap_from_e820();

    build_page_tables();
    serial_printf("%s", "[alix] page tables built\n");
    arch_cpu_init_bsp(STACK_TOP);
    serial_printf("%s", "[alix] cpu segments ready\n");

    serial_printf("%s", "[alix] entering kernel_main\n");
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
