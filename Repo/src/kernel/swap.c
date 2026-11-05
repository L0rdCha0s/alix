#include "swap.h"
#include "block.h"
#include "heap.h"
#include "libc.h"
#include "physmem.h"
#include "spinlock.h"
#include "serial.h"

static block_device_t *g_swap_device;
static uint32_t *g_swap_references;
static uint64_t *g_swap_checksums;
static size_t g_swap_pages, g_swap_used, g_swap_hint;
static spinlock_t g_swap_lock;
uint64_t g_swap_reads, g_swap_writes, g_swap_errors;

bool swap_available(void) { return __atomic_load_n(&g_swap_device, __ATOMIC_ACQUIRE) != NULL; }
size_t swap_used_pages(void) { return __atomic_load_n(&g_swap_used, __ATOMIC_ACQUIRE); }

/* Only explicitly signed, dedicated media qualify. Discovery never formats,
 * writes a header, or guesses unused space on an AlixFS/user disk. */
bool swap_discover(void)
{
    if (swap_available()) return true;
    uint8_t *header = malloc(4096);
    if (!header) return false;
    for (block_device_t *device = block_first(); device; device = block_next(device))
    {
        if (!device->write || device->sector_size > 4096 || !device->sector_size ||
            4096 % device->sector_size || device->sector_count < 8192 / device->sector_size) continue;
        if (!block_read(device, 0, 4096 / device->sector_size, header) || memcmp(header, "ALIXSWP1", 8)) continue;
        uint64_t pages; memcpy(&pages, header + 8, sizeof(pages));
        uint64_t capacity = device->sector_count / (4096 / device->sector_size) - 1;
        if (!pages || pages > capacity || pages > (1u << 24)) continue;
        uint32_t *references = calloc((size_t)pages, sizeof(*references));
        if (!references) break;
        uint64_t *checksums = calloc((size_t)pages, sizeof(*checksums));
        if (!checksums) { free(references); break; }
        g_swap_checksums = checksums;
        g_swap_pages = (size_t)pages; g_swap_references = references;
        __atomic_store_n(&g_swap_device, device, __ATOMIC_RELEASE);
        serial_printf("[swap] online device=%s pages=%llu bytes=%llu", device->name,
            (unsigned long long)pages, (unsigned long long)(pages * 4096));
        break;
    }
    free(header);
    return swap_available();
}

static bool swap_index(paddr_t token, size_t *index)
{
    if (!(token & USER_PAGE_SWAPPED) || !swap_available() || !(token >> 12)) return false;
    *index = (size_t)(token >> 12) - 1;
    return *index < g_swap_pages;
}

bool swap_retain(paddr_t token)
{
    size_t index;
    if (!swap_index(token, &index)) return false;
    uint64_t flags = spinlock_lock_irqsave(&g_swap_lock);
    bool okay = g_swap_references[index] && g_swap_references[index] != UINT32_MAX;
    if (okay) ++g_swap_references[index];
    spinlock_unlock_irqrestore(&g_swap_lock, flags);
    return okay;
}

void swap_release(paddr_t token)
{
    size_t index;
    if (!swap_index(token, &index)) return;
    uint64_t flags = spinlock_lock_irqsave(&g_swap_lock);
    if (g_swap_references[index] && !--g_swap_references[index]) --g_swap_used;
    spinlock_unlock_irqrestore(&g_swap_lock, flags);
}

static uint64_t swap_checksum(paddr_t physical)
{
    const uint64_t *words = phys_to_virt(physical);
    uint64_t value = 1469598103934665603ULL;
    for (size_t i = 0; i < 4096 / sizeof(*words); ++i)
        value = (value ^ words[i]) * 1099511628211ULL;
    return value;
}

paddr_t swap_store(paddr_t physical)
{
    if (!swap_available() || !physical || (physical & 4095)) return 0;
    uint64_t flags = spinlock_lock_irqsave(&g_swap_lock);
    size_t index = g_swap_hint, examined = 0;
    while (examined < g_swap_pages && g_swap_references[index])
    { index = (index + 1) % g_swap_pages; ++examined; }
    if (examined == g_swap_pages) { spinlock_unlock_irqrestore(&g_swap_lock, flags); return 0; }
    g_swap_references[index] = 1; ++g_swap_used;
    g_swap_hint = (index + 1) % g_swap_pages;
    spinlock_unlock_irqrestore(&g_swap_lock, flags);
    paddr_t token = ((paddr_t)(index + 1) << 12) | USER_PAGE_SWAPPED;
    uint32_t sectors = 4096 / g_swap_device->sector_size;
    g_swap_checksums[index] = swap_checksum(physical);
    if (!block_write(g_swap_device, (index + 1) * sectors, sectors, phys_to_virt(physical)))
    { __atomic_fetch_add(&g_swap_errors, 1, __ATOMIC_RELAXED); swap_release(token); return 0; }
    if (!__atomic_fetch_add(&g_swap_writes, 1, __ATOMIC_RELAXED))
        serial_printf("[swap] first page-out committed device=%s", g_swap_device->name);
    return token;
}

bool swap_load(paddr_t token, paddr_t physical)
{
    size_t index;
    if (!swap_index(token, &index) || !physical || (physical & 4095)) return false;
    uint32_t sectors = 4096 / g_swap_device->sector_size;
    bool okay = block_read(g_swap_device, (index + 1) * sectors, sectors, phys_to_virt(physical));
    if (okay && swap_checksum(physical) != g_swap_checksums[index])
    { serial_printf("[swap] checksum mismatch slot=%llu", (unsigned long long)index); okay = false; }
    uint64_t previous = __atomic_fetch_add(okay ? &g_swap_reads : &g_swap_errors, 1, __ATOMIC_RELAXED);
    if (okay && !previous) serial_printf("[swap] first disk demand page-in complete device=%s", g_swap_device->name);
    return okay;
}
