#include "paging.h"

#include "libc.h"
#include "serial.h"
#include "msr.h"
#include "types.h"

#include <stddef.h>
#include <stdint.h>

extern uint8_t __kernel_text_start[];
extern uint8_t __kernel_text_end[];
extern uint8_t __kernel_data_start[];
extern uint8_t __kernel_data_end[];

#define IA32_EFER                     0xC0000080u
#define PAGE_SIZE_BYTES               4096ULL
#define PAGE_TABLE_ALIGNMENT          PAGE_SIZE_BYTES
#define PAGE_DIRECTORY_ENTRIES        512ULL
#define PAGE_LARGE_SIZE               0x200000ULL
#define PAGE_PRESENT                  (1ULL << 0)
#define PAGE_WRITABLE                 (1ULL << 1)
#define PAGE_USER                     (1ULL << 2)
#define PAGE_PAGE_SIZE                (1ULL << 7)
#define PAGE_GLOBAL                   (1ULL << 8)
#define PAGE_NO_EXECUTE               (1ULL << 63)
#define PAGE_ADDRESS_MASK             0x000FFFFFFFFFF000ULL

#define IDENTITY_LIMIT                (4ULL * 1024ULL * 1024ULL * 1024ULL)

typedef struct
{
    uint64_t *pml4;
    uint64_t *pdp;
    uint64_t *pd[PAGE_DIRECTORY_ENTRIES];
    void *raw_allocation;
    size_t raw_bytes;
    paging_space_t *owner;
} page_tables_t;

static inline size_t required_pd_tables(void)
{
    const uint64_t span = (1ULL << 30); /* 1 GiB per PD */
    return (size_t)((IDENTITY_LIMIT + span - 1) / span);
}

static paging_space_t g_kernel_space = { 0 };
static bool g_paging_ready = false;
static bool g_nx_supported = false;
static bool g_smep_supported = false;
static bool g_smap_supported = false;

static inline uintptr_t align_up(uintptr_t value, uintptr_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline uintptr_t align_down(uintptr_t value, uintptr_t alignment)
{
    return value & ~(alignment - 1);
}

static inline size_t index_pml4(uintptr_t addr)
{
    return (size_t)((addr >> 39) & 0x1FF);
}

static inline size_t index_pdpt(uintptr_t addr)
{
    return (size_t)((addr >> 30) & 0x1FF);
}

static inline size_t index_pd(uintptr_t addr)
{
    return (size_t)((addr >> 21) & 0x1FF);
}

static inline size_t index_pt(uintptr_t addr)
{
    return (size_t)((addr >> 12) & 0x1FF);
}

static inline uint64_t *entry_to_table(uint64_t entry)
{
    return (uint64_t *)(entry & PAGE_ADDRESS_MASK);
}

static bool track_extra_page(paging_space_t *space, void *raw, void *aligned)
{
    if (!space || !raw || !aligned)
    {
        return false;
    }
    if (space->extra_page_count >= PAGING_MAX_EXTRA_PAGES)
    {
        return false;
    }
    space->extra_pages[space->extra_page_count].raw = raw;
    space->extra_pages[space->extra_page_count].aligned = aligned;
    space->extra_page_count++;
    return true;
}

static void *allocate_aligned_page(paging_space_t *space)
{
    size_t raw_bytes = (size_t)(PAGE_SIZE_BYTES + PAGE_TABLE_ALIGNMENT);
    uint8_t *raw = (uint8_t *)malloc(raw_bytes);
    if (!raw)
    {
        return NULL;
    }
    uintptr_t aligned = align_up((uintptr_t)raw, PAGE_TABLE_ALIGNMENT);
    memset((void *)aligned, 0, PAGE_SIZE_BYTES);
    if (!track_extra_page(space, raw, (void *)aligned))
    {
        free(raw);
        return NULL;
    }
    return (void *)aligned;
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

static bool allocate_tables(page_tables_t *tables, paging_space_t *space)
{
    if (!tables || !space)
    {
        return false;
    }

    size_t pd_tables = required_pd_tables();
    size_t table_pages = 2 + pd_tables;
    size_t table_bytes = (size_t)(table_pages * PAGE_SIZE_BYTES);
    size_t raw_bytes = table_bytes + PAGE_TABLE_ALIGNMENT;
    uint8_t *raw = (uint8_t *)malloc(raw_bytes);
    if (!raw)
    {
        return false;
    }
    uintptr_t base = align_up((uintptr_t)raw, PAGE_TABLE_ALIGNMENT);
    memset((void *)base, 0, table_bytes);

    tables->owner = space;
    tables->raw_allocation = raw;
    tables->raw_bytes = raw_bytes;
    tables->pml4 = (uint64_t *)base;
    tables->pdp = (uint64_t *)(base + PAGE_SIZE_BYTES);
    for (size_t i = 0; i < PAGE_DIRECTORY_ENTRIES; ++i)
    {
        tables->pd[i] = NULL;
    }
    uintptr_t cursor = base + PAGE_SIZE_BYTES * 2;
    const uint64_t pd_flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL | PAGE_USER;
    for (size_t i = 0; i < pd_tables; ++i)
    {
        tables->pd[i] = (uint64_t *)(cursor + PAGE_SIZE_BYTES * i);
        tables->pdp[i] = ((uintptr_t)tables->pd[i]) | pd_flags;
    }
    return true;
}

static uint64_t *ensure_pd(page_tables_t *tables, size_t index)
{
    if (!tables || index >= PAGE_DIRECTORY_ENTRIES)
    {
        return NULL;
    }
    if (!tables->pd[index])
    {
        void *page = allocate_aligned_page(tables->owner);
        if (!page)
        {
            return NULL;
        }
        tables->pd[index] = (uint64_t *)page;
        uint64_t flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL;
        tables->pdp[index] = ((uintptr_t)page) | flags;
    }
    return tables->pd[index];
}

static void apply_large_mapping(uint64_t *pd_entry,
                                uint64_t phys_addr,
                                bool executable)
{
    uint64_t flags = PAGE_PRESENT | PAGE_PAGE_SIZE | PAGE_GLOBAL;
    flags |= PAGE_WRITABLE;
    if (g_nx_supported && !executable)
    {
        flags |= PAGE_NO_EXECUTE;
    }
    *pd_entry = (phys_addr & ~(PAGE_LARGE_SIZE - 1)) | flags;
}

static void apply_small_mapping(uint64_t *pt_entry,
                                uint64_t phys_addr,
                                bool writable,
                                bool executable,
                                bool user_accessible)
{
    uint64_t flags = PAGE_PRESENT | PAGE_GLOBAL;
    if (writable)
    {
        flags |= PAGE_WRITABLE;
    }
    if (user_accessible)
    {
        flags |= PAGE_USER;
    }
    if (g_nx_supported && !executable)
    {
        flags |= PAGE_NO_EXECUTE;
    }
    *pt_entry = phys_addr | flags;
}

static bool split_large_page(paging_space_t *space,
                             uint64_t *pd_entry,
                             bool user_accessible)
{
    if (!space || !pd_entry || (*pd_entry & PAGE_PAGE_SIZE) == 0)
    {
        return true;
    }

    uintptr_t base = *pd_entry & PAGE_ADDRESS_MASK;
    base &= ~(PAGE_LARGE_SIZE - 1);
    bool writable = ((*pd_entry & PAGE_WRITABLE) != 0);
    bool executable = ((*pd_entry & PAGE_NO_EXECUTE) == 0);

    uint64_t *pt = (uint64_t *)allocate_aligned_page(space);
    if (!pt)
    {
        return false;
    }

    for (size_t i = 0; i < 512; ++i)
    {
        uintptr_t page_addr = base + (i * PAGE_SIZE_BYTES);
        apply_small_mapping(&pt[i], page_addr, writable, executable, false);
    }

    uint64_t flags = PAGE_PRESENT | PAGE_GLOBAL;
    if (writable)
    {
        flags |= PAGE_WRITABLE;
    }
    if (user_accessible)
    {
        flags |= PAGE_USER;
    }
    *pd_entry = ((uintptr_t)pt) | flags;
    return true;
}

static bool ensure_page_table(paging_space_t *space,
                              uintptr_t virt_addr,
                              bool user_accessible,
                              uint64_t **out_pt)
{
    if (!space || !space->tables_base || !out_pt)
    {
        return false;
    }

    uint64_t *pml4 = (uint64_t *)space->tables_base;
    size_t pml4_idx = index_pml4(virt_addr);
    size_t pdpt_idx = index_pdpt(virt_addr);
    size_t pd_idx = index_pd(virt_addr);

    if ((pml4[pml4_idx] & PAGE_PRESENT) == 0)
    {
        uint64_t *new_pdpt = (uint64_t *)allocate_aligned_page(space);
        if (!new_pdpt)
        {
            return false;
        }
        memset(new_pdpt, 0, PAGE_SIZE_BYTES);
        uint64_t flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL;
        if (user_accessible)
        {
            flags |= PAGE_USER;
        }
        pml4[pml4_idx] = ((uintptr_t)new_pdpt) | flags;
    }
    else if (user_accessible)
    {
        pml4[pml4_idx] |= PAGE_USER;
    }

    uint64_t *pdpt = entry_to_table(pml4[pml4_idx]);
    if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0)
    {
        uint64_t *new_pd = (uint64_t *)allocate_aligned_page(space);
        if (!new_pd)
        {
            return false;
        }
        memset(new_pd, 0, PAGE_SIZE_BYTES);
        uint64_t flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL;
        if (user_accessible)
        {
            flags |= PAGE_USER;
        }
        pdpt[pdpt_idx] = ((uintptr_t)new_pd) | flags;
    }
    else if (user_accessible)
    {
        pdpt[pdpt_idx] |= PAGE_USER;
    }

    uint64_t *pd = entry_to_table(pdpt[pdpt_idx]);
    if (!split_large_page(space, &pd[pd_idx], user_accessible))
    {
        return false;
    }

    if ((pd[pd_idx] & PAGE_PRESENT) == 0)
    {
        uint64_t *new_pt = (uint64_t *)allocate_aligned_page(space);
        if (!new_pt)
        {
            return false;
        }
        memset(new_pt, 0, PAGE_SIZE_BYTES);
        uint64_t flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL;
        if (user_accessible)
        {
            flags |= PAGE_USER;
        }
        pd[pd_idx] = ((uintptr_t)new_pt) | flags;
    }
    else if (user_accessible)
    {
        pd[pd_idx] |= PAGE_USER;
    }

    *out_pt = entry_to_table(pd[pd_idx]);
    return true;
}

static void map_identity_space(page_tables_t *tables)
{
    if (!tables)
    {
        return;
    }

    const uint64_t text_actual_start = (uint64_t)__kernel_text_start;
    const uint64_t text_actual_end = (uint64_t)__kernel_text_end;
    const uint64_t data_actual_start = (uint64_t)__kernel_data_start;
    const uint64_t data_actual_end = (uint64_t)__kernel_data_end;
    const uint64_t fine_start = align_down(text_actual_start, PAGE_LARGE_SIZE);
    const uint64_t fine_end = align_up(data_actual_end, PAGE_LARGE_SIZE);

    tables->pml4[0] = ((uintptr_t)tables->pdp) | PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL;

    for (uint64_t addr = 0; addr < IDENTITY_LIMIT; addr += PAGE_LARGE_SIZE)
    {
        size_t pd_index = (size_t)(addr >> 30);
        uint64_t *pd = ensure_pd(tables, pd_index);
        if (!pd)
        {
            paging_panic("unable to allocate page directory");
        }
        size_t pde_index = (size_t)((addr >> 21) & 0x1FF);
        uint64_t chunk_base = addr;
        uint64_t chunk_end = chunk_base + PAGE_LARGE_SIZE;
        bool chunk_executable = chunk_base < text_actual_end;

        bool needs_small = !(chunk_end <= fine_start || chunk_base >= fine_end);
        if (!needs_small)
        {
            apply_large_mapping(&pd[pde_index], chunk_base, chunk_executable);
            continue;
        }

        uint64_t *pt = (uint64_t *)allocate_aligned_page(tables->owner);
        if (!pt)
        {
            paging_panic("unable to allocate PT for fine mapping");
        }
        uint64_t pt_flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_GLOBAL;
        pd[pde_index] = ((uintptr_t)pt) | pt_flags;
        for (size_t i = 0; i < 512; ++i)
        {
            uint64_t page_addr = chunk_base + (i * PAGE_SIZE_BYTES);
            bool in_text = page_addr + PAGE_SIZE_BYTES > text_actual_start &&
                           page_addr < text_actual_end;
            bool in_data = page_addr + PAGE_SIZE_BYTES > data_actual_start &&
                           page_addr < data_actual_end;
            bool exec = in_text;
            bool writable = !in_text;
            if (in_data)
            {
                writable = true;
                exec = false;
            }
            apply_small_mapping(&pt[i], page_addr, writable, exec, false);
        }
    }
}

static bool build_identity_space(paging_space_t *space)
{
    if (!space)
    {
        return false;
    }
    space->extra_page_count = 0;
    for (size_t i = 0; i < PAGING_MAX_EXTRA_PAGES; ++i)
    {
        space->extra_pages[i].raw = NULL;
        space->extra_pages[i].aligned = NULL;
    }
    page_tables_t tables;
    memset(&tables, 0, sizeof(tables));
    if (!allocate_tables(&tables, space))
    {
        return false;
    }

    map_identity_space(&tables);

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

    paging_space_t kernel_space;
    memset(&kernel_space, 0, sizeof(kernel_space));
    if (!build_identity_space(&kernel_space))
    {
        paging_panic("kernel page table allocation failed");
    }

    enable_protection_bits();
    write_cr3(kernel_space.cr3);

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
    for (size_t i = 0; i < space->extra_page_count; ++i)
    {
        if (space->extra_pages[i].raw)
        {
            free(space->extra_pages[i].raw);
            space->extra_pages[i].raw = NULL;
            space->extra_pages[i].aligned = NULL;
        }
    }
    space->extra_page_count = 0;
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

bool paging_map_user_page(paging_space_t *space,
                          uintptr_t virtual_addr,
                          uintptr_t physical_addr,
                          bool writable,
                          bool executable)
{
    if (!space)
    {
        return false;
    }

    virtual_addr = align_down(virtual_addr, PAGE_SIZE_BYTES);
    physical_addr = align_down(physical_addr, PAGE_SIZE_BYTES);

    uint64_t *pt = NULL;
    if (!ensure_page_table(space, virtual_addr, true, &pt))
    {
        return false;
    }

    size_t pt_idx = index_pt(virtual_addr);
    apply_small_mapping(&pt[pt_idx], physical_addr, writable, executable, true);
    return true;
}

bool paging_map_user_range(paging_space_t *space,
                           uintptr_t virtual_addr,
                           uintptr_t physical_addr,
                           size_t length,
                           bool writable,
                           bool executable)
{
    if (!space || length == 0)
    {
        return false;
    }

    uintptr_t virt = align_down(virtual_addr, PAGE_SIZE_BYTES);
    uintptr_t phys = align_down(physical_addr, PAGE_SIZE_BYTES);
    size_t remaining = align_up(length, PAGE_SIZE_BYTES);

    while (remaining > 0)
    {
        if (!paging_map_user_page(space, virt, phys, writable, executable))
        {
            return false;
        }
        virt += PAGE_SIZE_BYTES;
        phys += PAGE_SIZE_BYTES;
        remaining -= PAGE_SIZE_BYTES;
    }
    return true;
}
