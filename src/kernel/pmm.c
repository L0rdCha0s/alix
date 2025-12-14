#include "pmm.h"

#include "arch/x86/bootlayout.h"
#include "arch/x86/smp_boot.h"
#include "bootinfo.h"
#include "heap.h"
#include "libc.h"
#include "serial.h"
#include "spinlock.h"
#include "video_backbuffer.h"

#define PMM_PAGE_SIZE 4096ULL

typedef struct pmm_range
{
    paddr_t base;
    uint64_t length;
    struct pmm_range *next;
} pmm_range_t;

static spinlock_t g_pmm_lock;
static pmm_range_t *g_free_ranges = NULL;
static uint64_t g_free_bytes = 0;
static bool g_pmm_ready = false;

extern uintptr_t kernel_heap_base;
extern uintptr_t kernel_heap_end;
extern uintptr_t boot_info_phys_addr;

extern uint8_t __kernel_vma_start[];
extern uint8_t __kernel_vma_end[];

static inline paddr_t pmm_align_up(paddr_t value, paddr_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline paddr_t pmm_align_down(paddr_t value, paddr_t alignment)
{
    return value & ~(alignment - 1);
}

static void pmm_merge_forward(pmm_range_t *range)
{
    if (!range)
    {
        return;
    }
    while (range->next && (range->base + range->length) == range->next->base)
    {
        pmm_range_t *next = range->next;
        range->length += next->length;
        range->next = next->next;
        free(next);
    }
}

static void pmm_insert_node(pmm_range_t *node)
{
    if (!node)
    {
        return;
    }

    pmm_range_t **cursor = &g_free_ranges;
    pmm_range_t *prev = NULL;
    while (*cursor && (*cursor)->base < node->base)
    {
        prev = *cursor;
        cursor = &(*cursor)->next;
    }

    node->next = *cursor;
    *cursor = node;

    pmm_merge_forward(node);
    if (prev && (prev->base + prev->length) == node->base)
    {
        prev->length += node->length;
        prev->next = node->next;
        free(node);
        pmm_merge_forward(prev);
    }
}

static void pmm_add_range(paddr_t base, paddr_t end)
{
    if (end <= base)
    {
        return;
    }
    base = pmm_align_up(base, PMM_PAGE_SIZE);
    end = pmm_align_down(end, PMM_PAGE_SIZE);
    if (end <= base)
    {
        return;
    }

    pmm_range_t *node = (pmm_range_t *)malloc(sizeof(*node));
    if (!node)
    {
        serial_printf("%s", "[pmm] failed to allocate range node\n");
        return;
    }
    node->base = base;
    node->length = (uint64_t)(end - base);
    node->next = NULL;
    g_free_bytes += node->length;
    pmm_insert_node(node);
}

bool pmm_is_ready(void)
{
    return g_pmm_ready;
}

void pmm_reserve_range(paddr_t base, size_t bytes)
{
    if (bytes == 0)
    {
        return;
    }

    paddr_t start = pmm_align_down(base, PMM_PAGE_SIZE);
    paddr_t end = pmm_align_up(base + (paddr_t)bytes, PMM_PAGE_SIZE);
    if (end <= start)
    {
        return;
    }

    spinlock_lock(&g_pmm_lock);
    pmm_range_t **cursor = &g_free_ranges;
    while (*cursor)
    {
        pmm_range_t *range = *cursor;
        paddr_t r_start = range->base;
        paddr_t r_end = range->base + range->length;
        if (r_end <= start)
        {
            cursor = &range->next;
            continue;
        }
        if (r_start >= end)
        {
            break;
        }

        paddr_t cut_start = (start > r_start) ? start : r_start;
        paddr_t cut_end = (end < r_end) ? end : r_end;
        if (cut_end <= cut_start)
        {
            cursor = &range->next;
            continue;
        }
        uint64_t cut_len = (uint64_t)(cut_end - cut_start);

        if (cut_start == r_start && cut_end == r_end)
        {
            *cursor = range->next;
            range->next = NULL;
            g_free_bytes -= range->length;
            free(range);
            continue;
        }
        if (cut_start == r_start)
        {
            range->base = cut_end;
            range->length = (uint64_t)(r_end - cut_end);
            g_free_bytes -= cut_len;
            cursor = &range->next;
            continue;
        }
        if (cut_end == r_end)
        {
            range->length = (uint64_t)(cut_start - r_start);
            g_free_bytes -= cut_len;
            cursor = &range->next;
            continue;
        }

        pmm_range_t *suffix = (pmm_range_t *)malloc(sizeof(*suffix));
        if (!suffix)
        {
            serial_printf("%s", "[pmm] reserve split failed (alloc)\n");
            break;
        }
        suffix->base = cut_end;
        suffix->length = (uint64_t)(r_end - cut_end);
        suffix->next = range->next;
        range->next = suffix;
        range->length = (uint64_t)(cut_start - r_start);
        g_free_bytes -= cut_len;
        cursor = &suffix->next;
    }
    spinlock_unlock(&g_pmm_lock);
}

size_t pmm_available_bytes(void)
{
    spinlock_lock(&g_pmm_lock);
    uint64_t available = g_free_bytes;
    spinlock_unlock(&g_pmm_lock);
    return (size_t)available;
}

bool pmm_alloc_range(size_t bytes,
                     size_t alignment,
                     pmm_alloc_flags_t flags,
                     paddr_t *out_base)
{
    if (!out_base || bytes == 0)
    {
        return false;
    }
    if (!g_pmm_ready)
    {
        return false;
    }

    size_t aligned_bytes = (size_t)pmm_align_up((paddr_t)bytes, PMM_PAGE_SIZE);
    if (aligned_bytes == 0)
    {
        return false;
    }
    paddr_t align = (alignment == 0) ? PMM_PAGE_SIZE : (paddr_t)alignment;
    if (align < PMM_PAGE_SIZE)
    {
        align = PMM_PAGE_SIZE;
    }

    paddr_t limit = 0;
    if (flags & PMM_ALLOC_DMA32)
    {
        limit = 0x100000000ULL;
    }

    spinlock_lock(&g_pmm_lock);
    pmm_range_t **cursor = &g_free_ranges;
    while (*cursor)
    {
        pmm_range_t *range = *cursor;
        paddr_t r_start = range->base;
        paddr_t r_end = range->base + range->length;
        paddr_t alloc_start = pmm_align_up(r_start, align);
        paddr_t alloc_end = alloc_start + (paddr_t)aligned_bytes;
        if (alloc_end <= alloc_start)
        {
            cursor = &range->next;
            continue;
        }
        if (limit && alloc_end > limit)
        {
            cursor = &range->next;
            continue;
        }
        if (alloc_end > r_end)
        {
            cursor = &range->next;
            continue;
        }

        if (alloc_start == r_start && alloc_end == r_end)
        {
            *cursor = range->next;
            g_free_bytes -= range->length;
            free(range);
        }
        else if (alloc_start == r_start)
        {
            range->base = alloc_end;
            range->length = (uint64_t)(r_end - alloc_end);
            g_free_bytes -= (uint64_t)aligned_bytes;
        }
        else if (alloc_end == r_end)
        {
            range->length = (uint64_t)(alloc_start - r_start);
            g_free_bytes -= (uint64_t)aligned_bytes;
        }
        else
        {
            pmm_range_t *suffix = (pmm_range_t *)malloc(sizeof(*suffix));
            if (!suffix)
            {
                spinlock_unlock(&g_pmm_lock);
                return false;
            }
            suffix->base = alloc_end;
            suffix->length = (uint64_t)(r_end - alloc_end);
            suffix->next = range->next;
            range->next = suffix;
            range->length = (uint64_t)(alloc_start - r_start);
            g_free_bytes -= (uint64_t)aligned_bytes;
        }
        spinlock_unlock(&g_pmm_lock);
        *out_base = alloc_start;
        return true;
    }
    spinlock_unlock(&g_pmm_lock);
    return false;
}

bool pmm_alloc_page(pmm_alloc_flags_t flags, paddr_t *out_base)
{
    return pmm_alloc_range(PMM_PAGE_SIZE, PMM_PAGE_SIZE, flags, out_base);
}

void pmm_free_range(paddr_t base, size_t bytes)
{
    if (!g_pmm_ready || bytes == 0)
    {
        return;
    }
    paddr_t start = pmm_align_down(base, PMM_PAGE_SIZE);
    paddr_t end = pmm_align_up(base + (paddr_t)bytes, PMM_PAGE_SIZE);
    if (end <= start)
    {
        return;
    }

    pmm_range_t *node = (pmm_range_t *)malloc(sizeof(*node));
    if (!node)
    {
        serial_printf("%s", "[pmm] free failed (alloc)\n");
        return;
    }
    node->base = start;
    node->length = (uint64_t)(end - start);
    node->next = NULL;

    spinlock_lock(&g_pmm_lock);
    g_free_bytes += node->length;
    pmm_insert_node(node);
    spinlock_unlock(&g_pmm_lock);
}

void pmm_free_page(paddr_t base)
{
    pmm_free_range(base, PMM_PAGE_SIZE);
}

void pmm_init(void)
{
    if (g_pmm_ready)
    {
        return;
    }

    spinlock_init(&g_pmm_lock);
    spinlock_lock(&g_pmm_lock);
    g_free_ranges = NULL;
    g_free_bytes = 0;

    uint32_t count = boot_info.e820_entry_count;
    if (count > BOOTINFO_MAX_E820_ENTRIES)
    {
        count = BOOTINFO_MAX_E820_ENTRIES;
    }
    uint64_t max_end = 0;
    for (uint32_t i = 0; i < count; ++i)
    {
        const bootinfo_e820_entry_t *entry = &boot_info.e820[i];
        if (entry->type != 1)
        {
            continue;
        }
        uint64_t start = entry->base;
        uint64_t end = entry->base + entry->length;
        if (end <= start)
        {
            continue;
        }
        if (end > max_end)
        {
            max_end = end;
        }
        pmm_add_range((paddr_t)start, (paddr_t)end);
    }

    spinlock_unlock(&g_pmm_lock);

    pmm_reserve_range(0, 0x200000ULL);
    pmm_reserve_range((paddr_t)VIDEO_BACKBUFFER_BASE, (size_t)VIDEO_BACKBUFFER_BYTES);
    pmm_reserve_range((paddr_t)(uintptr_t)__kernel_vma_start,
                      (size_t)((uintptr_t)__kernel_vma_end - (uintptr_t)__kernel_vma_start));
    pmm_reserve_range((paddr_t)(uintptr_t)(STACK_TOP - STACK_SIZE), (size_t)STACK_SIZE);
    pmm_reserve_range((paddr_t)(uintptr_t)PAGE_TABLE_BASE, (size_t)(PAGE_TABLE_PAGES * PMM_PAGE_SIZE));
    pmm_reserve_range((paddr_t)(uintptr_t)SMP_BOOT_DATA_PHYS, (size_t)0x1000);
    pmm_reserve_range((paddr_t)(uintptr_t)SMP_TRAMPOLINE_PHYS, (size_t)(64 * 1024u));

    if (kernel_heap_end > kernel_heap_base)
    {
        pmm_reserve_range((paddr_t)kernel_heap_base, (size_t)(kernel_heap_end - kernel_heap_base));
    }

    if (boot_info_phys_addr != 0)
    {
        pmm_reserve_range((paddr_t)boot_info_phys_addr, sizeof(bootinfo_t));
    }

    if (boot_info.framebuffer_enabled && boot_info.framebuffer_size != 0)
    {
        pmm_reserve_range((paddr_t)boot_info.framebuffer_base, (size_t)boot_info.framebuffer_size);
    }

    g_pmm_ready = true;
    serial_printf("[pmm] ready free_bytes=0x%016llX max_usable_end=0x%016llX\n",
                  (unsigned long long)g_free_bytes,
                  (unsigned long long)max_end);
}
