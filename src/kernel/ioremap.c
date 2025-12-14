#include "ioremap.h"

#include "paging.h"
#include "physmem.h"
#include "serial.h"
#include "spinlock.h"

#define IOREMAP_PAGE_SIZE 4096ULL

static spinlock_t g_ioremap_lock;
static uintptr_t g_ioremap_next = 0;
static bool g_ioremap_ready = false;

static inline uintptr_t align_up_uintptr(uintptr_t value, uintptr_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline paddr_t align_down_paddr(paddr_t value, paddr_t alignment)
{
    return value & ~(alignment - 1);
}

void ioremap_init(void)
{
    if (g_ioremap_ready)
    {
        return;
    }
    spinlock_init(&g_ioremap_lock);
    g_ioremap_next = (uintptr_t)KERNEL_IOREMAP_BASE;
    g_ioremap_ready = true;
    serial_printf("[ioremap] ready base=0x%016llX size=0x%016llX\n",
                  (unsigned long long)KERNEL_IOREMAP_BASE,
                  (unsigned long long)KERNEL_IOREMAP_MAX_BYTES);
}

static void *ioremap_internal(paddr_t physical_addr, size_t length, bool cache_disable)
{
    if (length == 0)
    {
        return NULL;
    }
    if (!g_ioremap_ready)
    {
        ioremap_init();
    }
    if (!g_ioremap_ready)
    {
        return NULL;
    }

    paddr_t phys_base = align_down_paddr(physical_addr, IOREMAP_PAGE_SIZE);
    size_t offset = (size_t)(physical_addr - phys_base);
    size_t bytes = length + offset;
    if (bytes < length)
    {
        return NULL;
    }
    size_t map_bytes = (size_t)align_up_uintptr((uintptr_t)bytes, IOREMAP_PAGE_SIZE);
    if (map_bytes == 0)
    {
        return NULL;
    }

    uintptr_t virt_base = 0;
    uintptr_t window_base = (uintptr_t)KERNEL_IOREMAP_BASE;
    uintptr_t window_end = window_base + (uintptr_t)KERNEL_IOREMAP_MAX_BYTES;
    if (window_end <= window_base)
    {
        return NULL;
    }

    spinlock_lock(&g_ioremap_lock);
    virt_base = g_ioremap_next;
    uintptr_t virt_end = virt_base + (uintptr_t)map_bytes;
    if (virt_end < virt_base || virt_end > window_end)
    {
        spinlock_unlock(&g_ioremap_lock);
        serial_printf("[ioremap] out of space phys=0x%016llX bytes=0x%016llX\n",
                      (unsigned long long)physical_addr,
                      (unsigned long long)map_bytes);
        return NULL;
    }
    g_ioremap_next = virt_end;
    spinlock_unlock(&g_ioremap_lock);

    if (!paging_map_kernel_ioremap_range(virt_base, phys_base, map_bytes, cache_disable))
    {
        serial_printf("[ioremap] map failed virt=0x%016llX phys=0x%016llX bytes=0x%016llX\n",
                      (unsigned long long)virt_base,
                      (unsigned long long)phys_base,
                      (unsigned long long)map_bytes);
        return NULL;
    }

    return (void *)(virt_base + offset);
}

void *ioremap(paddr_t physical_addr, size_t length)
{
    return ioremap_internal(physical_addr, length, true);
}

void *ioremap_cached(paddr_t physical_addr, size_t length)
{
    return ioremap_internal(physical_addr, length, false);
}
