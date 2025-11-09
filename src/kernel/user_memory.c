#include "user_memory.h"

#include "arch/x86/bootlayout.h"
#include "bootinfo.h"
#include "heap.h"
#include "libc.h"
#include "serial.h"

#define USER_MEMORY_PAGE_SIZE 4096ULL
#define USER_MEMORY_MIN_ADDR (KERNEL_HEAP_BASE + KERNEL_HEAP_SIZE)
#define USER_MEMORY_IDENTITY_LIMIT (4ULL * 1024ULL * 1024ULL * 1024ULL)

typedef struct user_memory_range
{
    uintptr_t base;
    size_t length;
    struct user_memory_range *next;
} user_memory_range_t;

static user_memory_range_t *g_free_ranges = NULL;
static size_t g_free_bytes = 0;

#ifdef ENABLE_MEM_DEBUG_LOGS
static inline void usermem_log(const char *msg, uintptr_t value)
{
    serial_write_string("[umem] ");
    serial_write_string(msg);
    serial_write_string("0x");
    serial_write_hex64(value);
    serial_write_string("\r\n");
}
#else
static inline void usermem_log(const char *msg, uintptr_t value)
{
    (void)msg;
    (void)value;
}
#endif

static inline uintptr_t align_up_uintptr(uintptr_t value, uintptr_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline uintptr_t align_down_uintptr(uintptr_t value, uintptr_t alignment)
{
    return value & ~(alignment - 1);
}

static void user_memory_merge_forward(user_memory_range_t *range)
{
    if (!range)
    {
        return;
    }
    while (range->next &&
           (range->base + range->length) == range->next->base)
    {
        user_memory_range_t *next = range->next;
        range->length += next->length;
        range->next = next->next;
        free(next);
    }
}

static void user_memory_insert_node(user_memory_range_t *node)
{
    if (!node)
    {
        return;
    }

    user_memory_range_t **cursor = &g_free_ranges;
    user_memory_range_t *prev = NULL;
    while (*cursor && (*cursor)->base < node->base)
    {
        prev = *cursor;
        cursor = &(*cursor)->next;
    }

    node->next = *cursor;
    *cursor = node;

    user_memory_merge_forward(node);
    if (prev && (prev->base + prev->length) == node->base)
    {
        prev->length += node->length;
        prev->next = node->next;
        free(node);
        user_memory_merge_forward(prev);
    }
}

static void user_memory_detach_range(user_memory_range_t *node, user_memory_range_t *prev)
{
    if (!node)
    {
        return;
    }
    if (prev)
    {
        prev->next = node->next;
    }
    else
    {
        g_free_ranges = node->next;
    }
    g_free_bytes -= node->length;
    free(node);
}

static void user_memory_add_range(uintptr_t base, uintptr_t end)
{
    if (end <= base)
    {
        return;
    }
    base = align_up_uintptr(base, USER_MEMORY_PAGE_SIZE);
    end = align_down_uintptr(end, USER_MEMORY_PAGE_SIZE);
    if (end <= base)
    {
        return;
    }

    user_memory_range_t *node = (user_memory_range_t *)malloc(sizeof(user_memory_range_t));
    if (!node)
    {
        serial_write_string("user_memory: failed to allocate range node\r\n");
        return;
    }
    node->base = base;
    node->length = (size_t)(end - base);
    node->next = NULL;
    g_free_bytes += node->length;
    user_memory_insert_node(node);
    usermem_log("add base=", base);
    usermem_log("add end=", end);
}

void user_memory_init(void)
{
    g_free_ranges = NULL;
    g_free_bytes = 0;

    uint32_t count = boot_info.e820_entry_count;
    if (count > BOOTINFO_MAX_E820_ENTRIES)
    {
        count = BOOTINFO_MAX_E820_ENTRIES;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        const bootinfo_e820_entry_t *entry = &boot_info.e820[i];
        if (entry->type != 1)
        {
            continue;
        }

        uint64_t start = entry->base;
        uint64_t end = entry->base + entry->length;
        if (end <= USER_MEMORY_MIN_ADDR)
        {
            continue;
        }
        if (start < USER_MEMORY_MIN_ADDR)
        {
            start = USER_MEMORY_MIN_ADDR;
        }
        if (start >= USER_MEMORY_IDENTITY_LIMIT)
        {
            continue;
        }
        if (end > USER_MEMORY_IDENTITY_LIMIT)
        {
            end = USER_MEMORY_IDENTITY_LIMIT;
        }
        if (end <= start)
        {
            continue;
        }
        user_memory_add_range((uintptr_t)start, (uintptr_t)end);
    }

    serial_write_string("user_memory: available 0x");
    serial_write_hex64((uint64_t)g_free_bytes);
    serial_write_string(" bytes\r\n");
}

void *user_memory_alloc(size_t bytes)
{
    if (bytes == 0)
    {
        return NULL;
    }
    size_t aligned = (size_t)align_up_uintptr(bytes, USER_MEMORY_PAGE_SIZE);
    usermem_log("alloc req=", aligned);

    user_memory_range_t **cursor = &g_free_ranges;
    while (*cursor)
    {
        user_memory_range_t *range = *cursor;
        if (range->length >= aligned)
        {
            uintptr_t addr = range->base;
            range->base += aligned;
            range->length -= aligned;
            if (range->length == 0)
            {
                *cursor = range->next;
                free(range);
            }
            g_free_bytes -= aligned;
            usermem_log("alloc ptr=", addr);
            return (void *)addr;
        }
        cursor = &range->next;
    }
    serial_write_string("user_memory: allocation failed\r\n");
    serial_write_string("user_memory: free bytes 0x");
    serial_write_hex64((uint64_t)g_free_bytes);
    serial_write_string("\r\n");
    return NULL;
}

void user_memory_free(void *addr, size_t bytes)
{
    if (!addr || bytes == 0)
    {
        return;
    }

    uintptr_t base = align_down_uintptr((uintptr_t)addr, USER_MEMORY_PAGE_SIZE);
    size_t length = (size_t)align_up_uintptr(bytes, USER_MEMORY_PAGE_SIZE);
    usermem_log("free base=", base);
    usermem_log("free len=", length);

    user_memory_range_t *node = (user_memory_range_t *)malloc(sizeof(user_memory_range_t));
    if (!node)
    {
        serial_write_string("user_memory: failed to allocate free node\r\n");
        return;
    }
    node->base = base;
    node->length = length;
    node->next = NULL;
    g_free_bytes += length;
    user_memory_insert_node(node);
}

size_t user_memory_available(void)
{
    return g_free_bytes;
}

bool user_memory_alloc_page(uintptr_t *phys_out)
{
    if (!phys_out)
    {
        return false;
    }
    user_memory_range_t *prev = NULL;
    user_memory_range_t *range = g_free_ranges;
    while (range && range->length < USER_MEMORY_PAGE_SIZE)
    {
        prev = range;
        range = range->next;
    }
    if (!range)
    {
        serial_write_string("user_memory: no free pages\r\n");
        serial_write_string("user_memory: free bytes 0x");
        serial_write_hex64((uint64_t)g_free_bytes);
        serial_write_string("\r\n");
        return false;
    }
    uintptr_t addr = range->base;
    range->base += USER_MEMORY_PAGE_SIZE;
    range->length -= USER_MEMORY_PAGE_SIZE;
    if (range->length == 0)
    {
        if (prev)
        {
            prev->next = range->next;
        }
        else
        {
            g_free_ranges = range->next;
        }
        free(range);
    }
    g_free_bytes -= USER_MEMORY_PAGE_SIZE;
    *phys_out = addr;
    return true;
}

void user_memory_free_page(uintptr_t phys)
{
    user_memory_add_range(phys, phys + USER_MEMORY_PAGE_SIZE);
}
