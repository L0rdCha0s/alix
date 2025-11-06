#include "paging.h"

#include "libc.h"
#include "serial.h"
#include "msr.h"
#include "types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

extern uintptr_t kernel_heap_base;

#define IA32_EFER                     0xC0000080u
#define PAGE_SIZE_BYTES               4096ULL
#define PAGE_TABLE_PAGES              6ULL
#define PAGE_TABLE_ALIGNMENT          PAGE_SIZE_BYTES
#define PAGE_DIRECTORY_ENTRIES        512ULL
#define PAGE_LARGE_SIZE               0x200000ULL
#define PAGE_PRESENT                  (1ULL << 0)
#define PAGE_WRITABLE                 (1ULL << 1)
#define PAGE_GLOBAL                   (1ULL << 8)
#define PAGE_PAGE_SIZE                (1ULL << 7)
#define PAGE_NO_EXECUTE               (1ULL << 63)

typedef struct
{
    uint64_t *pml4;
    uint64_t *pdp;
    uint64_t *pd[4];
    void *raw_allocation;
    size_t raw_bytes;
} page_tables_t;

static paging_space_t g_kernel_space = { 0 };
static bool g_paging_ready = false;
static bool g_nx_supported = false;
static bool g_smep_supported = false;
static bool g_smap_supported = false;
static uintptr_t g_heap_nx_base = 0;

static inline uintptr_t align_up(uintptr_t value, uintptr_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline void write_cr3(uintptr_t value)
{
    __asm__ volatile ("mov %0, %%cr3" :: "r"(value) : "memory");
}

static inline uint64_t read_cr3(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(value));
    return value;
}

static void paging_panic(const char *msg) __attribute__((noreturn));
static void paging_panic(const char *msg)
{
    serial_write_string("paging panic: ");
    serial_write_string(msg);
    serial_write_string("\r\n");
    for (;;)
    {
        __asm__ volatile ("cli; hlt");
    }
}

static void cpuid(uint32_t leaf, uint32_t subleaf,
                  uint32_t *eax, uint32_t *ebx,
                  uint32_t *ecx, uint32_t *edx)
{
    uint32_t a = 0, b = 0, c = 0, d = 0;
    __asm__ volatile ("cpuid"
                      : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                      : "a"(leaf), "c"(subleaf));
    if (eax) { *eax = a; }
    if (ebx) { *ebx = b; }
    if (ecx) { *ecx = c; }
    if (edx) { *edx = d; }
}

static void detect_features(void)
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

    cpuid(0, 0, &eax, NULL, NULL, NULL);
    uint32_t max_basic = eax;

    cpuid(0x80000000u, 0, &eax, NULL, NULL, NULL);
    uint32_t max_extended = eax;

    if (max_extended >= 0x80000001u)
    {
        cpuid(0x80000001u, 0, &eax, &ebx, &ecx, &edx);
        g_nx_supported = (edx & (1u << 20)) != 0;
    }

    if (max_basic >= 7u)
    {
        cpuid(7u, 0, &eax, &ebx, &ecx, &edx);
        g_smep_supported = (ebx & (1u << 7)) != 0;
        g_smap_supported = (ebx & (1u << 20)) != 0;
    }
}

static void enable_protection_bits(void)
{
    uint64_t cr0;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= (1ULL << 16); /* WP */
    __asm__ volatile ("mov %0, %%cr0" :: "r"(cr0));

    uint64_t cr4;
    __asm__ volatile ("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1ULL << 7); /* PGE */
    if (g_smep_supported)
    {
        cr4 |= (1ULL << 20);
    }
    if (g_smap_supported)
    {
        cr4 |= (1ULL << 21);
    }
    __asm__ volatile ("mov %0, %%cr4" :: "r"(cr4));

    if (g_nx_supported)
    {
        uint64_t efer = rdmsr(IA32_EFER);
        efer |= (1ULL << 11); /* NXE */
        wrmsr(IA32_EFER, efer);
    }
}

static bool allocate_tables(page_tables_t *tables)
{
    if (!tables)
    {
        return false;
    }

    size_t table_bytes = (size_t)(PAGE_TABLE_PAGES * PAGE_SIZE_BYTES);
    size_t raw_bytes = table_bytes + PAGE_TABLE_ALIGNMENT;
    uint8_t *raw = (uint8_t *)malloc(raw_bytes);
    if (!raw)
    {
        return false;
    }
    uintptr_t base = align_up((uintptr_t)raw, PAGE_TABLE_ALIGNMENT);
    memset((void *)base, 0, table_bytes);

    tables->raw_allocation = raw;
    tables->raw_bytes = raw_bytes;
    tables->pml4 = (uint64_t *)base;
    tables->pdp = (uint64_t *)(base + PAGE_SIZE_BYTES);
    for (size_t i = 0; i < 4; ++i)
    {
        tables->pd[i] = (uint64_t *)(base + PAGE_SIZE_BYTES * (2 + i));
    }
    return true;
}

static void map_identity_large(page_tables_t *tables)
{
    uint64_t region_base = 0;
    for (size_t pd_index = 0; pd_index < 4; ++pd_index)
    {
        uint64_t *pd = tables->pd[pd_index];
        for (size_t entry = 0; entry < PAGE_DIRECTORY_ENTRIES; ++entry)
        {
            uint64_t addr = region_base + (entry * PAGE_LARGE_SIZE);
            uint64_t flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_PAGE_SIZE | PAGE_GLOBAL;
            if (g_nx_supported && addr >= g_heap_nx_base)
            {
                flags |= PAGE_NO_EXECUTE;
            }
            pd[entry] = addr | flags;
        }
        region_base += (uint64_t)PAGE_DIRECTORY_ENTRIES * PAGE_LARGE_SIZE;
    }

    for (size_t i = 0; i < 4; ++i)
    {
        tables->pdp[i] = ((uintptr_t)tables->pd[i]) | PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL;
    }

    tables->pml4[0] = ((uintptr_t)tables->pdp) | PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL;
}

static bool build_identity_space(paging_space_t *space)
{
    if (!space)
    {
        return false;
    }
    page_tables_t tables;
    memset(&tables, 0, sizeof(tables));
    if (!allocate_tables(&tables))
    {
        return false;
    }

    map_identity_large(&tables);

    space->cr3 = (uintptr_t)tables.pml4;
    space->allocation_base = tables.raw_allocation;
    space->allocation_size = tables.raw_bytes;
    space->tables_base = tables.pml4;
    return true;
}

void paging_init(void)
{
    if (g_paging_ready)
    {
        return;
    }

    detect_features();
    g_heap_nx_base = (uintptr_t)kernel_heap_base;

    paging_space_t kernel_space;
    memset(&kernel_space, 0, sizeof(kernel_space));
    if (!build_identity_space(&kernel_space))
    {
        paging_panic("kernel page table allocation failed");
    }

    write_cr3(kernel_space.cr3);
    enable_protection_bits();

    g_kernel_space = kernel_space;
    g_paging_ready = true;
}

bool paging_clone_kernel_space(paging_space_t *space)
{
    if (!g_paging_ready || !space)
    {
        return false;
    }
    memset(space, 0, sizeof(*space));
    if (!build_identity_space(space))
    {
        return false;
    }
    return true;
}

void paging_destroy_space(paging_space_t *space)
{
    if (!space || !space->allocation_base)
    {
        return;
    }
    if (space->allocation_base == g_kernel_space.allocation_base)
    {
        return;
    }
    free(space->allocation_base);
    space->allocation_base = NULL;
    space->allocation_size = 0;
    space->tables_base = NULL;
    space->cr3 = 0;
}

uintptr_t paging_kernel_cr3(void)
{
    if (!g_paging_ready)
    {
        return read_cr3();
    }
    return g_kernel_space.cr3;
}
