#include "paging.h"

#include "libc.h"
#include "serial.h"
#include "msr.h"
#include "types.h"
#include "arch/x86/smp_boot.h"
#include "smp.h"
#include "process.h"
#include "spinlock.h"
#include "heap.h"
#include "sched_log.h"
#include "build_features.h"

#include <stddef.h>
#include <stdint.h>

/*
 * src/arch/x86/paging.c
 *
 * Page table management for x86_64:
 * - Initializes kernel paging and CPU-side protection features (NX/SMEP/SMAP).
 * - Provides per-process address spaces (`paging_space_t`) used by the process subsystem.
 * - Supports mapping/unmapping user pages and flushing TLBs locally/remotely (SMP).
 *
 * Locking:
 * - Global paging lock for shared structures.
 * - Optional per-space locks for page table edits in a specific address space.
 *
 * See docs/kernel/memory.md.
 */

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
#define LOW_EXECUTABLE_LIMIT          PAGE_LARGE_SIZE /* keep low identity (e.g. SMP trampoline) executable */

#ifndef ENABLE_PAGING_DEBUG_LOGS
#define ENABLE_PAGING_DEBUG_LOGS 1
#endif

static bool g_paging_trace_active = false;

#if ENABLE_PAGING_DEBUG_LOGS
static uint32_t g_paging_debug_budget = 256;
void paging_set_clone_trace(bool enable)
{
    g_paging_trace_active = enable;
}
static void paging_debug_log(const char *msg)
{
    if (!msg)
    {
        return;
    }
    if (!g_paging_trace_active)
    {
        if (g_paging_debug_budget == 0)
        {
            return;
        }
        g_paging_debug_budget--;
    }
    serial_printf("%s", "[paging] ");
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
}
#else
void paging_set_clone_trace(bool enable)
{
    g_paging_trace_active = enable;
}
static inline void paging_debug_log(const char *msg)
{
    (void)msg;
}
#endif

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
static spinlock_t g_paging_lock;
static volatile uint32_t g_paging_lock_owner = UINT32_MAX;
static volatile void *g_paging_lock_owner_ra[SMP_MAX_CPUS];
static volatile uint64_t g_paging_lock_owner_tsc[SMP_MAX_CPUS];

static inline uint64_t read_tsc(void)
{
    uint32_t lo = 0;
    uint32_t hi = 0;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void paging_log_hex32(uint32_t value)
{
    char buf[9];
    for (int i = 0; i < 8; ++i)
    {
        uint8_t nibble = (uint8_t)((value >> (28 - (i * 4))) & 0xF);
        buf[i] = (char)(nibble < 10 ? ('0' + nibble) : ('A' + (nibble - 10)));
    }
    buf[8] = '\0';
    serial_early_write_string(buf);
}

static inline void paging_log_hex64(uint64_t value)
{
    char buf[17];
    for (int i = 0; i < 16; ++i)
    {
        uint8_t nibble = (uint8_t)((value >> (60 - (i * 4))) & 0xF);
        buf[i] = (char)(nibble < 10 ? ('0' + nibble) : ('A' + (nibble - 10)));
    }
    buf[16] = '\0';
    serial_early_write_string(buf);
}

static inline void paging_log_lock_event(const char *label, uint32_t cpu)
{
    if (!sched_paging_lock_log_enabled())
    {
        return;
    }
    serial_early_write_string("[paging][lock] ");
    serial_early_write_string(label ? label : "?");
    serial_early_write_string(" cpu=0x");
    paging_log_hex32(cpu);
    serial_early_write_string("\r\n");
}

static inline uint64_t paging_lock(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    uint32_t cpu = smp_current_cpu_index();
    __asm__ volatile ("cli" ::: "memory");
    spinlock_lock(&g_paging_lock);
    paging_log_lock_event("acquire", cpu);
    g_paging_lock_owner = cpu;
    if (cpu < SMP_MAX_CPUS)
    {
        g_paging_lock_owner_ra[cpu] = __builtin_return_address(0);
        g_paging_lock_owner_tsc[cpu] = read_tsc();
    }
    return flags;
}

static inline void paging_unlock(uint64_t flags)
{
    uint32_t cpu = smp_current_cpu_index();
    paging_log_lock_event("release", cpu);
    g_paging_lock_owner = UINT32_MAX;
    if (cpu < SMP_MAX_CPUS)
    {
        g_paging_lock_owner_ra[cpu] = NULL;
        g_paging_lock_owner_tsc[cpu] = 0;
    }
    spinlock_unlock(&g_paging_lock);
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc", "memory");
}

bool paging_global_lock_held_by_current_cpu(void)
{
    uint32_t cpu = smp_current_cpu_index();
    return __atomic_load_n(&g_paging_lock_owner, __ATOMIC_ACQUIRE) == cpu;
}

static inline uint64_t paging_space_lock(paging_space_t *space, bool *used_global)
{
    if (!space || !space->lock_inited)
    {
        if (used_global)
        {
            *used_global = true;
        }
        return paging_lock();
    }
    if (used_global)
    {
        *used_global = false;
    }
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    __asm__ volatile ("cli" ::: "memory");
    /* Lock ordering: never take paging locks while holding heap lock. */
    if (heap_lock_held_by_current_cpu())
    {
        serial_early_write_string("[paging] lock_order_violation: heap->paging\r\n");
    }
    spinlock_lock(&space->lock);
    paging_log_lock_event("acquire-space", smp_current_cpu_index());
    return flags;
}

static inline void paging_space_unlock(paging_space_t *space, bool used_global, uint64_t flags)
{
    if (used_global || !space || !space->lock_inited)
    {
        paging_unlock(flags);
        return;
    }
    paging_log_lock_event("release-space", smp_current_cpu_index());
    spinlock_unlock(&space->lock);
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc", "memory");
}

static void paging_log_lock_state(const char *context)
{
    uint32_t owner = __atomic_load_n(&g_paging_lock_owner, __ATOMIC_ACQUIRE);
    if (owner >= SMP_MAX_CPUS)
    {
        serial_printf("[paging] lock state context=%s owner=<none>\r\n", context ? context : "<none>");
        return;
    }
    uint64_t ra = (uint64_t)(uintptr_t)__atomic_load_n(&g_paging_lock_owner_ra[owner], __ATOMIC_ACQUIRE);
    uint64_t tsc = __atomic_load_n(&g_paging_lock_owner_tsc[owner], __ATOMIC_ACQUIRE);
    serial_printf("[paging] lock state context=%s owner_cpu=0x%08llX ra=0x%016llX tsc=0x%016llX\r\n",
                  context ? context : "<none>",
                  (unsigned long long)owner,
                  (unsigned long long)ra,
                  (unsigned long long)tsc);
}

static bool paging_check_lock_order(const char *context)
{
    if (heap_lock_held_by_current_cpu())
    {
        heap_lock_info_t info = { 0 };
        heap_lock_owner_snapshot(&info);
        serial_printf("[paging] lock-order violation context=%s while holding heap lock\r\n",
                      context ? context : "<none>");
        serial_printf("[paging] heap owner cpu=0x%08llX depth=0x%08llX ra=0x%016llX tsc=0x%016llX\r\n",
                      (unsigned long long)(info.owner_cpu),
                      (unsigned long long)(info.depth),
                      (unsigned long long)(info.owner_ra),
                      (unsigned long long)(info.acquired_tsc));
        paging_log_lock_state("lock_order_violation");
        return false;
    }
    return true;
}

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

static inline void invalidate_page(uintptr_t addr)
{
    __asm__ volatile ("invlpg (%0)" :: "r"(addr) : "memory");
}

static inline void flush_local_tlb(void)
{
    write_cr3(read_cr3());
}

static bool paging_map_user_page_internal(paging_space_t *space,
                                          uintptr_t virtual_addr,
                                          uintptr_t physical_addr,
                                          bool writable,
                                          bool executable);

static bool paging_unmap_user_page_internal(paging_space_t *space,
                                            uintptr_t virtual_addr);
static void paging_panic(const char *msg) __attribute__((noreturn));
static void paging_panic(const char *msg)
{
    serial_printf("%s", "paging panic: ");
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
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
    if (g_paging_trace_active)
    {
        serial_printf("%s", "[paging] allocate_tables malloc bytes=0x");
        serial_printf("%016llX", (unsigned long long)(raw_bytes));
        serial_printf("%s", "\r\n");
    }
    uint8_t *raw = (uint8_t *)malloc(raw_bytes);
    if (g_paging_trace_active)
    {
        serial_printf("%s", "[paging] allocate_tables malloc result=0x");
        serial_printf("%016llX", (unsigned long long)((uintptr_t)raw));
        serial_printf("%s", "\r\n");
    }
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
        if (g_paging_trace_active && ((addr & ((1ULL << 30) - 1)) == 0))
        {
            serial_printf("%s", "[paging] map_progress addr=0x");
            serial_printf("%016llX", (unsigned long long)(addr));
            serial_printf("%s", "\r\n");
        }
        size_t pd_index = (size_t)(addr >> 30);
        uint64_t *pd = ensure_pd(tables, pd_index);
        if (!pd)
        {
            paging_panic("unable to allocate page directory");
        }
        size_t pde_index = (size_t)((addr >> 21) & 0x1FF);
        uint64_t chunk_base = addr;
        uint64_t chunk_end = chunk_base + PAGE_LARGE_SIZE;
        bool chunk_executable = (chunk_base < LOW_EXECUTABLE_LIMIT) ||
                                (chunk_base < text_actual_end);

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
            bool exec = in_text || (page_addr < LOW_EXECUTABLE_LIMIT);
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
    paging_debug_log("build_identity_space start");
    space->active_cpu_mask = 0;
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
        paging_debug_log("build_identity_space alloc_tables_failed");
        return false;
    }

    map_identity_space(&tables);
    paging_debug_log("build_identity_space mapped");

    space->cr3 = (uintptr_t)tables.pml4;
    space->allocation_base = tables.raw_allocation;
    space->allocation_size = tables.raw_bytes;
    space->tables_base = tables.pml4;
    paging_debug_log("build_identity_space complete");
    return true;
}

/*
 * Initialise paging and install the kernel page tables.
 *
 * Builds an identity-mapped space for low physical memory and applies
 * execute/writable permissions for kernel text/data. Enables CPU protection
 * features (NX/SMEP/SMAP) when supported.
 */
void paging_init(void)
{
    if (g_paging_ready)
    {
        return;
    }

    spinlock_init(&g_paging_lock);
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
    spinlock_init(&g_kernel_space.lock);
    g_kernel_space.lock_inited = true;
    g_paging_ready = true;
}

/*
 * Create a new paging space by cloning the kernel's base mappings.
 *
 * The resulting `space` owns its page tables and can be modified independently
 * (used for user processes).
 */
bool paging_clone_kernel_space(paging_space_t *space)
{
    if (!g_paging_ready || !space)
    {
        return false;
    }
    paging_debug_log("clone_kernel_space begin");
    memset(space, 0, sizeof(*space));
    if (!build_identity_space(space))
    {
        paging_debug_log("clone_kernel_space build_failed");
        return false;
    }
    spinlock_init(&space->lock);
    space->lock_inited = true;
    paging_debug_log("clone_kernel_space success");
    return true;
}

/*
 * Point `space` at the shared kernel paging space.
 *
 * This is used for kernel-only threads that do not require a private CR3.
 * Shared spaces use the global paging lock.
 */
bool paging_share_kernel_space(paging_space_t *space)
{
    if (!g_paging_ready || !space)
    {
        return false;
    }
    memset(space, 0, sizeof(*space));
    space->cr3 = g_kernel_space.cr3;
    space->allocation_base = g_kernel_space.allocation_base;
    space->allocation_size = g_kernel_space.allocation_size;
    space->tables_base = g_kernel_space.tables_base;
    space->active_cpu_mask = 0;
    space->lock_inited = false; /* shared kernel space uses global lock */
    return true;
}

/*
 * Destroy a paging space and free its allocated page tables.
 *
 * Does nothing for spaces that reference the shared kernel tables.
 */
void paging_destroy_space(paging_space_t *space)
{
    if (!space || !space->allocation_base)
    {
        return;
    }
    bool used_global = false;
    uint64_t flags = 0;
    if (space->lock_inited)
    {
        flags = paging_space_lock(space, &used_global);
    }
    space->lock_inited = false;
    if (space->allocation_base == g_kernel_space.allocation_base)
    {
        if (space->lock_inited)
        {
            paging_space_unlock(space, used_global, flags);
        }
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
    space->active_cpu_mask = 0;
    if (space->lock_inited)
    {
        paging_space_unlock(space, used_global, flags);
    }
}

/*
 * Return the CR3 value used for the kernel paging space.
 */
uintptr_t paging_kernel_cr3(void)
{
    if (!g_paging_ready)
    {
        return read_cr3();
    }
    return g_kernel_space.cr3;
}

/*
 * Map a single user page into `space`.
 *
 * `virtual_addr` and `physical_addr` are page-aligned internally. Pages are
 * mapped as user-accessible and can be marked writable/executable.
 */
bool paging_map_user_page(paging_space_t *space,
                          uintptr_t virtual_addr,
                          uintptr_t physical_addr,
                          bool writable,
                          bool executable)
{
    if (!paging_check_lock_order("paging_map_user_page"))
    {
        return false;
    }
    bool used_global = false;
    uint64_t flags = paging_space_lock(space, &used_global);
    bool ok = paging_map_user_page_internal(space, virtual_addr, physical_addr, writable, executable);
    paging_space_unlock(space, used_global, flags);
    return ok;
}

static bool paging_map_user_page_internal(paging_space_t *space,
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
    if (space->cr3 == read_cr3())
    {
        invalidate_page(virtual_addr);
    }
    return true;
}

/*
 * Map a contiguous user virtual range to a contiguous physical range.
 *
 * The range is rounded to page boundaries. This is primarily used to map user
 * stacks, heap pages, and ELF segments.
 */
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

    if (!paging_check_lock_order("paging_map_user_range"))
    {
        return false;
    }

    bool used_global = false;
    uint64_t flags = paging_space_lock(space, &used_global);
    uintptr_t virt = align_down(virtual_addr, PAGE_SIZE_BYTES);
    uintptr_t phys = align_down(physical_addr, PAGE_SIZE_BYTES);
    size_t remaining = align_up(length, PAGE_SIZE_BYTES);

    while (remaining > 0)
    {
        if (!paging_map_user_page_internal(space, virt, phys, writable, executable))
        {
            paging_space_unlock(space, used_global, flags);
            return false;
        }
        virt += PAGE_SIZE_BYTES;
        phys += PAGE_SIZE_BYTES;
        remaining -= PAGE_SIZE_BYTES;
    }
    paging_space_unlock(space, used_global, flags);
    return true;
}

/*
 * Unmap a single user page from an address space.
 */
bool paging_unmap_user_page(paging_space_t *space,
                            uintptr_t virtual_addr)
{
    if (!paging_check_lock_order("paging_unmap_user_page"))
    {
        return false;
    }
    bool used_global = false;
    uint64_t flags = paging_space_lock(space, &used_global);
    bool ok = paging_unmap_user_page_internal(space, virtual_addr);
    paging_space_unlock(space, used_global, flags);
    return ok;
}

static bool paging_unmap_user_page_internal(paging_space_t *space,
                                            uintptr_t virtual_addr)
{
    if (!space || !space->tables_base)
    {
        return false;
    }
    virtual_addr = align_down(virtual_addr, PAGE_SIZE_BYTES);
    uint64_t *pml4 = (uint64_t *)space->tables_base;
    size_t pml4_idx = index_pml4(virtual_addr);
    if ((pml4[pml4_idx] & PAGE_PRESENT) == 0)
    {
        return false;
    }
    uint64_t *pdpt = entry_to_table(pml4[pml4_idx]);
    size_t pdpt_idx = index_pdpt(virtual_addr);
    if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0)
    {
        return false;
    }
    if ((pdpt[pdpt_idx] & PAGE_PAGE_SIZE) != 0)
    {
        return false;
    }
    uint64_t *pd = entry_to_table(pdpt[pdpt_idx]);
    size_t pd_idx = index_pd(virtual_addr);
    if ((pd[pd_idx] & PAGE_PRESENT) == 0 || (pd[pd_idx] & PAGE_PAGE_SIZE))
    {
        return false;
    }
    uint64_t *pt = entry_to_table(pd[pd_idx]);
    size_t pt_idx = index_pt(virtual_addr);
    if ((pt[pt_idx] & PAGE_PRESENT) == 0)
    {
        return false;
    }
    pt[pt_idx] = 0;
    __asm__ volatile ("invlpg (%0)" :: "r"(virtual_addr) : "memory");
    paging_flush_space_tlb(space);
    return true;
}

static bool paging_set_kernel_range_writable_internal(uintptr_t virtual_addr,
                                                      size_t length,
                                                      bool writable,
                                                      bool enforce_lock_order)
{
    if (!g_paging_ready || !g_kernel_space.tables_base || length == 0)
    {
        return false;
    }

    if (enforce_lock_order && !paging_check_lock_order("paging_set_kernel_range_writable"))
    {
        return false;
    }

    paging_space_t *space = &g_kernel_space;
    bool used_global = false;
    uint64_t lock_flags = paging_space_lock(space, &used_global);
    bool ok = false;

    /* Never flip permissions on the stack we are currently running on; doing so
     * would fault as soon as this function touches its own locals. */
    if (!writable)
    {
        thread_t *current = thread_current();
        uintptr_t stack_start = 0;
        uintptr_t stack_end = 0;
        if (current && process_thread_stack_bounds(current, &stack_start, &stack_end) && stack_end > stack_start)
        {
            uintptr_t range_start = align_down(virtual_addr, PAGE_SIZE_BYTES);
            uintptr_t range_end = align_up(virtual_addr + length, PAGE_SIZE_BYTES);
            if (!(range_end <= stack_start || range_start >= stack_end))
            {
                goto out;
            }
        }
    }

    uintptr_t start = align_down(virtual_addr, PAGE_SIZE_BYTES);
    uintptr_t end = align_up(virtual_addr + length, PAGE_SIZE_BYTES);
    bool changed = false;

    while (start < end)
    {
        uint64_t *pt = NULL;
        if (!ensure_page_table(space, start, false, &pt))
        {
            goto out;
        }
        size_t pt_idx = index_pt(start);
        if ((pt[pt_idx] & PAGE_PRESENT) == 0)
        {
            goto out;
        }
        if (writable)
        {
            if ((pt[pt_idx] & PAGE_WRITABLE) == 0)
            {
                pt[pt_idx] |= PAGE_WRITABLE;
                changed = true;
            }
        }
        else
        {
            if (pt[pt_idx] & PAGE_WRITABLE)
            {
                pt[pt_idx] &= ~PAGE_WRITABLE;
                changed = true;
            }
        }
        if (space->cr3 == read_cr3())
        {
            invalidate_page(start);
        }
        start += PAGE_SIZE_BYTES;
    }

    if (changed)
    {
        paging_flush_space_tlb(&g_kernel_space);
    }

    ok = true;

out:
    paging_space_unlock(space, used_global, lock_flags);
    return ok;
}

/*
 * Toggle write permission for an existing kernel mapping range.
 *
 * This is used by debugging/safety features (e.g. stack protection) to
 * temporarily unprotect/protect ranges.
 *
 * When `safe == true` (default), the implementation avoids changing mappings
 * that overlap the current thread stack.
 */
bool paging_set_kernel_range_writable(uintptr_t virtual_addr,
                                      size_t length,
                                      bool writable)
{
    return paging_set_kernel_range_writable_internal(virtual_addr, length, writable, true);
}

/*
 * Force-set write permission for a kernel mapping range.
 *
 * This variant skips the “avoid current stack” safety checks and should be
 * used with caution.
 */
bool paging_set_kernel_range_writable_force(uintptr_t virtual_addr,
                                            size_t length,
                                            bool writable)
{
    return paging_set_kernel_range_writable_internal(virtual_addr, length, writable, false);
}

/*
 * IPI handler: remote CPUs flush their local TLB on request.
 */
void paging_handle_remote_tlb_flush(void)
{
    flush_local_tlb();
}

/*
 * Flush the kernel TLB entries on all CPUs.
 */
void paging_flush_global_tlb(void)
{
    paging_flush_space_tlb(&g_kernel_space);
}

/*
 * Flush TLB entries for an address space.
 *
 * For the kernel space this broadcasts a TLB flush IPI; for user spaces it
 * flushes on CPUs where the space is currently active.
 */
void paging_flush_space_tlb(paging_space_t *space)
{
    flush_local_tlb();
    if (!space)
    {
        return;
    }
    if (space == &g_kernel_space)
    {
        smp_broadcast_tlb_flush();
        return;
    }
    uint32_t mask = __atomic_load_n(&space->active_cpu_mask, __ATOMIC_ACQUIRE);
    uint32_t self = smp_current_cpu_index();
    if (self < SMP_MAX_CPUS)
    {
        mask &= ~(1u << self);
    }
    if (mask)
    {
        smp_tlb_flush_mask(mask);
    }
}
