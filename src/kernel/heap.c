#include "heap.h"
#include "libc.h"
#include "serial.h"
#include "spinlock.h"
#include "smp.h"

#include <stddef.h>
#include <stdint.h>

#ifndef ENABLE_HEAP_TRACE
#define ENABLE_HEAP_TRACE 1
#endif

#ifndef HEAP_TRACE_THRESHOLD
#define HEAP_TRACE_THRESHOLD (4096ULL)
#endif

#ifndef HEAP_FIND_WATCHDOG_THRESHOLD
#define HEAP_FIND_WATCHDOG_THRESHOLD (4096ULL)
#endif

#define ALIGNMENT 16UL
#define SIZE_MAX_VALUE ((size_t)-1)

typedef struct heap_block
{
    size_t size;
    struct heap_block *next;
    struct heap_block *prev;
    bool free;
} heap_block_t;

extern uintptr_t kernel_heap_base;
extern uintptr_t kernel_heap_end;
extern uintptr_t kernel_heap_size;

static heap_block_t *g_heap_head = NULL;
static uintptr_t g_heap_start = 0;
static uintptr_t g_heap_end = 0;
static bool g_heap_initialized = false;
static spinlock_t g_heap_lock;
#if ENABLE_HEAP_TRACE
static bool g_heap_trace_enabled = true;
static size_t g_heap_trace_threshold = HEAP_TRACE_THRESHOLD;
static size_t g_heap_trace_bytes_in_use = 0;
static size_t g_heap_trace_peak_bytes = 0;
static size_t g_heap_trace_allocations = 0;
static size_t g_heap_trace_frees = 0;
#endif

typedef struct
{
    uintptr_t addr;
    size_t size;
    uintptr_t next;
    uintptr_t prev;
    bool free;
} heap_block_snapshot_t;

#define HEAP_DUMP_SNAPSHOT_MAX 32U

static size_t heap_capture_snapshot(heap_block_snapshot_t *out, size_t max, bool *truncated);
static bool heap_verify_locked(const char *context);
#if ENABLE_HEAP_TRACE
static void heap_trace_log_alloc(size_t requested, const heap_block_t *block, void *caller);
static void heap_trace_log_free(size_t size, uintptr_t block_addr, void *caller);
static void heap_trace_log_stall(size_t requested, const heap_block_t *cursor, uint64_t iterations, void *caller);
#endif

#ifdef ENABLE_MEM_DEBUG_LOGS
static inline void heap_log(const char *msg, uintptr_t value)
{
    serial_printf("%s", "[heap] ");
    serial_printf("%s", msg);
    serial_printf("%s", "0x");
    serial_printf("%016llX", (unsigned long long)(value));
    serial_printf("%s", "\r\n");
}
#else
static inline void heap_log(const char *msg, uintptr_t value)
{
    (void)msg;
    (void)value;
}
#endif

static uint32_t g_heap_lock_owner = UINT32_MAX;
static uint32_t g_heap_lock_depth = 0;
static uint64_t g_heap_lock_saved_flags[SMP_MAX_CPUS];

static inline uint64_t heap_lock_acquire(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    uint32_t cpu = smp_current_cpu_index();

    if (g_heap_lock_owner == cpu)
    {
        g_heap_lock_depth++;
        return flags;
    }

    __asm__ volatile ("cli" ::: "memory");
    uint64_t spins = 0;
    while (__sync_lock_test_and_set(&g_heap_lock.value, 1) != 0)
    {
        while (g_heap_lock.value)
        {
            __asm__ volatile ("pause");
            spins++;
        }
    }
    g_heap_lock_owner = cpu;
    g_heap_lock_depth = 1;
    if (cpu < SMP_MAX_CPUS)
    {
        g_heap_lock_saved_flags[cpu] = flags;
    }
    heap_log("lock acquire flags=", flags);
    return flags;
}

static inline void heap_lock_release(uint64_t flags)
{
    uint32_t cpu = smp_current_cpu_index();
    if (g_heap_lock_owner == cpu && g_heap_lock_depth > 1)
    {
        g_heap_lock_depth--;
        return;
    }

    heap_log("lock release flags=", flags);
    g_heap_lock_owner = UINT32_MAX;
    g_heap_lock_depth = 0;
    spinlock_unlock(&g_heap_lock);

    uint64_t restore_flags = flags;
    if (cpu < SMP_MAX_CPUS)
    {
        restore_flags = g_heap_lock_saved_flags[cpu];
    }
    __asm__ volatile ("push %0; popfq" :: "r"(restore_flags) : "cc");
}

static size_t align_size(size_t size)
{
    if (size == 0)
    {
        return 0;
    }
    size_t mask = ALIGNMENT - 1;
    return (size + mask) & ~mask;
}

static bool pointer_in_heap(const void *ptr)
{
    uintptr_t addr = (uintptr_t)ptr;
    return addr >= g_heap_start && addr < g_heap_end;
}

static void merge_with_next(heap_block_t *block)
{
    if (!block)
    {
        return;
    }

    while (block->next && block->next->free)
    {
        heap_block_t *next = block->next;
        block->size += sizeof(heap_block_t) + next->size;
        block->next = next->next;
        if (block->next)
        {
            block->next->prev = block;
        }
    }
}

static void coalesce(heap_block_t *block)
{
    if (!block)
    {
        return;
    }

    merge_with_next(block);

    if (block->prev && block->prev->free)
    {
        merge_with_next(block->prev);
    }
}

static heap_block_t *payload_to_block(void *ptr)
{
    if (!ptr)
    {
        return NULL;
    }
    uintptr_t addr = (uintptr_t)ptr;
    if (addr < sizeof(heap_block_t))
    {
        return NULL;
    }
    return (heap_block_t *)(addr - sizeof(heap_block_t));
}

static void split_block(heap_block_t *block, size_t size)
{
    uintptr_t block_addr = (uintptr_t)block;
    uintptr_t new_block_addr = block_addr + sizeof(heap_block_t) + size;
    heap_block_t *new_block = (heap_block_t *)new_block_addr;

    new_block->size = block->size - size - sizeof(heap_block_t);
    new_block->free = true;
    new_block->next = block->next;
    new_block->prev = block;
    if (new_block->next)
    {
        new_block->next->prev = new_block;
    }

    block->size = size;
    block->next = new_block;
}

static heap_block_t *find_suitable_block(size_t size, void *caller)
{
    heap_block_t *block = g_heap_head;
    uint64_t iterations = 0;
    bool watchdog_triggered = false;
    while (block)
    {
        if (block->free && block->size >= size)
        {
            return block;
        }
        block = block->next;
        iterations++;
        if (!watchdog_triggered && iterations >= HEAP_FIND_WATCHDOG_THRESHOLD)
        {
#if ENABLE_HEAP_TRACE
            if (g_heap_trace_enabled)
            {
                heap_trace_log_stall(size, block, iterations, caller);
            }
#else
            serial_printf("%s", "[heap] find_suitable_block stall size=0x");
            serial_printf("%016llX", (unsigned long long)(size));
            serial_printf("%s", " block=0x");
            serial_printf("%016llX", (unsigned long long)((uintptr_t)(block ? block : 0)));
            serial_printf("%s", "\r\n");
#endif
            watchdog_triggered = true;
        }
    }
    return NULL;
}

void heap_init(void)
{
    if (g_heap_initialized)
    {
        return;
    }

    spinlock_init(&g_heap_lock);

    g_heap_start = (uintptr_t)kernel_heap_base;
    g_heap_end = (uintptr_t)kernel_heap_end;

    if (g_heap_end <= g_heap_start ||
        (g_heap_end - g_heap_start) <= sizeof(heap_block_t))
    {
        g_heap_head = NULL;
        g_heap_initialized = false;
        return;
    }

    g_heap_head = (heap_block_t *)g_heap_start;
    g_heap_head->size = (g_heap_end - g_heap_start) - sizeof(heap_block_t);
    g_heap_head->next = NULL;
    g_heap_head->prev = NULL;
    g_heap_head->free = true;

    g_heap_initialized = true;
}

static size_t heap_capture_snapshot(heap_block_snapshot_t *out,
                                    size_t max,
                                    bool *truncated)
{
    size_t count = 0;
    if (truncated)
    {
        *truncated = false;
    }
    heap_block_t *cursor = g_heap_head;
    while (cursor && count < max)
    {
        out[count].addr = (uintptr_t)cursor;
        out[count].size = cursor->size;
        out[count].next = (uintptr_t)cursor->next;
        out[count].prev = (uintptr_t)cursor->prev;
        out[count].free = cursor->free;
        cursor = cursor->next;
        count++;
    }
    if (cursor && truncated)
    {
        *truncated = true;
    }
    return count;
}

static void heap_print_snapshot(const char *context,
                                const heap_block_snapshot_t *blocks,
                                size_t count,
                                bool truncated)
{
    serial_printf("%s", "[heap] dump context=");
    serial_printf("%s", context ? context : "<none>");
    serial_printf("%s", "\r\n");
    for (size_t i = 0; i < count; ++i)
    {
        serial_printf("%s", "  block[");
        serial_printf("%016llX", (unsigned long long)(i));
        serial_printf("%s", "] addr=0x");
        serial_printf("%016llX", (unsigned long long)(blocks[i].addr));
        serial_printf("%s", " size=0x");
        serial_printf("%016llX", (unsigned long long)(blocks[i].size));
        serial_printf("%s", " free=");
        serial_printf("%s", blocks[i].free ? "true" : "false");
        serial_printf("%s", " next=0x");
        serial_printf("%016llX", (unsigned long long)(blocks[i].next));
        serial_printf("%s", " prev=0x");
        serial_printf("%016llX", (unsigned long long)(blocks[i].prev));
        serial_printf("%s", "\r\n");
    }
    if (truncated)
    {
        serial_printf("%s", "  ... truncated ...\r\n");
    }
}

static bool heap_verify_locked(const char *context)
{
    if (!g_heap_initialized)
    {
        return true;
    }
    heap_block_t *cursor = g_heap_head;
    uintptr_t expected_min = g_heap_start;
    size_t count = 0;
    while (cursor)
    {
        uintptr_t addr = (uintptr_t)cursor;
        if (addr < g_heap_start || addr >= g_heap_end)
        {
            serial_printf("%s", "[heap] verify out_of_bounds context=");
            serial_printf("%s", context ? context : "<none>");
            serial_printf("%s", " addr=0x");
            serial_printf("%016llX", (unsigned long long)(addr));
            serial_printf("%s", "\r\n");
            return false;
        }
        if (addr < expected_min)
        {
            serial_printf("%s", "[heap] verify order violation context=");
            serial_printf("%s", context ? context : "<none>");
            serial_printf("%s", " addr=0x");
            serial_printf("%016llX", (unsigned long long)(addr));
            serial_printf("%s", " expected_min=0x");
            serial_printf("%016llX", (unsigned long long)(expected_min));
            serial_printf("%s", "\r\n");
            return false;
        }
        if (cursor->next && cursor->next->prev != cursor)
        {
            serial_printf("%s", "[heap] verify linkage mismatch context=");
            serial_printf("%s", context ? context : "<none>");
            serial_printf("%s", " block=0x");
            serial_printf("%016llX", (unsigned long long)((uintptr_t)cursor));
            serial_printf("%s", " next=0x");
            serial_printf("%016llX", (unsigned long long)((uintptr_t)cursor->next));
            serial_printf("%s", "\r\n");
            return false;
        }
        expected_min = addr + sizeof(heap_block_t) + cursor->size;
        cursor = cursor->next;
        count++;
        if (count > 65536)
        {
            serial_printf("%s", "[heap] verify exceeded max nodes context=");
            serial_printf("%s", context ? context : "<none>");
            serial_printf("%s", "\r\n");
            return false;
        }
    }
    return true;
}

void heap_debug_dump(const char *context)
{
    if (!g_heap_initialized)
    {
        serial_printf("%s", "[heap] dump skipped; not initialized\r\n");
        return;
    }
    heap_block_snapshot_t snapshot[HEAP_DUMP_SNAPSHOT_MAX];
    bool truncated = false;
    uint64_t flags = heap_lock_acquire();
    size_t captured = heap_capture_snapshot(snapshot, HEAP_DUMP_SNAPSHOT_MAX, &truncated);
    heap_lock_release(flags);
    heap_print_snapshot(context, snapshot, captured, truncated);
}

bool heap_debug_verify(const char *context)
{
    if (!g_heap_initialized)
    {
        return true;
    }
    uint64_t flags = heap_lock_acquire();
    bool ok = heap_verify_locked(context);
    heap_lock_release(flags);
    if (!ok)
    {
        heap_block_snapshot_t snapshot[HEAP_DUMP_SNAPSHOT_MAX];
        bool truncated = false;
        uint64_t snap_flags = heap_lock_acquire();
        size_t captured = heap_capture_snapshot(snapshot, HEAP_DUMP_SNAPSHOT_MAX, &truncated);
        heap_lock_release(snap_flags);
        heap_print_snapshot(context, snapshot, captured, truncated);
    }
    return ok;
}

void *malloc(size_t size)
{
    size_t requested = size;
    void *trace_caller = __builtin_return_address(0);
#if ENABLE_HEAP_TRACE
    heap_block_t *trace_block = NULL;
    size_t trace_bytes = 0;
#endif
    uint64_t flags = heap_lock_acquire();
    if (!g_heap_initialized || size == 0)
    {
        heap_lock_release(flags);
        return NULL;
    }

    size = align_size(size);

    heap_block_t *block = find_suitable_block(size, trace_caller);
    if (!block)
    {
        heap_log("malloc fail size=", requested);
        heap_lock_release(flags);
        return NULL;
    }

    if (block->size >= size + sizeof(heap_block_t) + ALIGNMENT)
    {
        split_block(block, size);
    }

    block->free = false;
#if ENABLE_HEAP_TRACE
    if (g_heap_trace_enabled)
    {
        trace_block = block;
        trace_bytes = block->size;
        g_heap_trace_allocations++;
        g_heap_trace_bytes_in_use += trace_bytes;
        if (g_heap_trace_bytes_in_use > g_heap_trace_peak_bytes)
        {
            g_heap_trace_peak_bytes = g_heap_trace_bytes_in_use;
        }
    }
#endif
    void *result = (void *)((uintptr_t)block + sizeof(heap_block_t));
    heap_log("malloc ptr=", (uintptr_t)result);
    heap_log("malloc size=", requested);
    heap_lock_release(flags);
#if ENABLE_HEAP_TRACE
    if (trace_block && g_heap_trace_enabled && trace_bytes >= g_heap_trace_threshold)
    {
        heap_trace_log_alloc(requested, trace_block, trace_caller);
    }
#endif
    return result;
}

void free(void *ptr)
{
    heap_log("free req=", (uintptr_t)ptr);
    void *trace_caller = __builtin_return_address(0);
#if ENABLE_HEAP_TRACE
    size_t trace_size = 0;
    uintptr_t trace_addr = 0;
    bool trace_log = false;
#endif
    uint64_t flags = heap_lock_acquire();
    if (!g_heap_initialized || !ptr)
    {
        heap_lock_release(flags);
        return;
    }

    heap_block_t *block = payload_to_block(ptr);
    if (!block || !pointer_in_heap(block) || block->free)
    {
        heap_log("free invalid ptr=", (uintptr_t)ptr);
        heap_lock_release(flags);
        return;
    }
#if ENABLE_HEAP_TRACE
    if (g_heap_trace_enabled)
    {
        trace_log = true;
        trace_size = block->size;
        trace_addr = (uintptr_t)block;
        if (g_heap_trace_bytes_in_use >= block->size)
        {
            g_heap_trace_bytes_in_use -= block->size;
        }
        else
        {
            g_heap_trace_bytes_in_use = 0;
        }
        g_heap_trace_frees++;
    }
#endif

    block->free = true;
    coalesce(block);
    heap_lock_release(flags);
#if ENABLE_HEAP_TRACE
    if (trace_log && trace_size >= g_heap_trace_threshold)
    {
        heap_trace_log_free(trace_size, trace_addr, trace_caller);
    }
#endif
}

#if ENABLE_HEAP_TRACE
static void heap_trace_log_alloc(size_t requested, const heap_block_t *block, void *caller)
{
    if (!block)
    {
        return;
    }
    serial_printf("%s", "[heap] alloc requested=0x");
    serial_printf("%016llX", (unsigned long long)(requested));
    serial_printf("%s", " actual=0x");
    serial_printf("%016llX", (unsigned long long)(block->size));
    serial_printf("%s", " block=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)block));
    serial_printf("%s", " caller=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)caller));
    serial_printf("%s", " in_use=0x");
    serial_printf("%016llX", (unsigned long long)(g_heap_trace_bytes_in_use));
    serial_printf("%s", " peak=0x");
    serial_printf("%016llX", (unsigned long long)(g_heap_trace_peak_bytes));
    serial_printf("%s", "\r\n");
}

static void heap_trace_log_free(size_t size, uintptr_t block_addr, void *caller)
{
    serial_printf("%s", "[heap] free size=0x");
    serial_printf("%016llX", (unsigned long long)(size));
    serial_printf("%s", " block=0x");
    serial_printf("%016llX", (unsigned long long)(block_addr));
    serial_printf("%s", " caller=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)caller));
    serial_printf("%s", " in_use=0x");
    serial_printf("%016llX", (unsigned long long)(g_heap_trace_bytes_in_use));
    serial_printf("%s", "\r\n");
}

static void heap_trace_log_stall(size_t requested, const heap_block_t *cursor, uint64_t iterations, void *caller)
{
    serial_printf("%s", "[heap] find_suitable_block stall size=0x");
    serial_printf("%016llX", (unsigned long long)(requested));
    serial_printf("%s", " iterations=0x");
    serial_printf("%016llX", (unsigned long long)(iterations));
    serial_printf("%s", " cursor=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)(cursor ? cursor : 0)));
    serial_printf("%s", " caller=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)caller));
    serial_printf("%s", "\r\n");
}

void heap_trace_set_enabled(bool enable)
{
    g_heap_trace_enabled = enable;
}

void heap_trace_set_threshold(size_t threshold)
{
    if (threshold == 0)
    {
        threshold = 1;
    }
    g_heap_trace_threshold = threshold;
}

void heap_trace_dump_stats(const char *context)
{
    serial_printf("%s", "[heap] stats context=");
    serial_printf("%s", context ? context : "<none>");
    serial_printf("%s", " allocs=0x");
    serial_printf("%016llX", (unsigned long long)(g_heap_trace_allocations));
    serial_printf("%s", " frees=0x");
    serial_printf("%016llX", (unsigned long long)(g_heap_trace_frees));
    serial_printf("%s", " in_use=0x");
    serial_printf("%016llX", (unsigned long long)(g_heap_trace_bytes_in_use));
    serial_printf("%s", " peak=0x");
    serial_printf("%016llX", (unsigned long long)(g_heap_trace_peak_bytes));
    serial_printf("%s", "\r\n");
}
#else
void heap_trace_set_enabled(bool enable)
{
    (void)enable;
}

void heap_trace_set_threshold(size_t threshold)
{
    (void)threshold;
}

void heap_trace_dump_stats(const char *context)
{
    (void)context;
}
#endif

void *calloc(size_t count, size_t size)
{
    if (count != 0 && size > SIZE_MAX_VALUE / count)
    {
        return NULL;
    }
    size_t total = count * size;
    void *ptr = malloc(total);
    if (!ptr)
    {
        return NULL;
    }
    memset(ptr, 0, total);
    return ptr;
}

static heap_block_t *expand_block(heap_block_t *block, size_t size)
{
    if (!block)
    {
        return NULL;
    }

    if (block->size >= size)
    {
        return block;
    }

    if (block->next && block->next->free &&
        (block->size + sizeof(heap_block_t) + block->next->size) >= size)
    {
        merge_with_next(block);
        if (block->size >= size + sizeof(heap_block_t) + ALIGNMENT)
        {
            split_block(block, size);
        }
        return block;
    }

    return NULL;
}

void *realloc(void *ptr, size_t size)
{
    heap_log("realloc ptr=", (uintptr_t)ptr);
    heap_log("realloc size=", size);
    uint64_t flags = heap_lock_acquire();
    if (!g_heap_initialized)
    {
        heap_lock_release(flags);
        return NULL;
    }

    if (!ptr)
    {
        heap_lock_release(flags);
        return malloc(size);
    }

    if (size == 0)
    {
        heap_lock_release(flags);
        free(ptr);
        return NULL;
    }

    heap_block_t *block = payload_to_block(ptr);
    if (!block || !pointer_in_heap(block))
    {
        heap_lock_release(flags);
        return NULL;
    }

    size = align_size(size);

    if (block->size >= size)
    {
        if (block->size >= size + sizeof(heap_block_t) + ALIGNMENT)
        {
            split_block(block, size);
        }
        heap_lock_release(flags);
        return ptr;
    }

    heap_block_t *expanded = expand_block(block, size);
    if (expanded)
    {
        void *result = (void *)((uintptr_t)expanded + sizeof(heap_block_t));
        heap_lock_release(flags);
        return result;
    }

    heap_lock_release(flags);
    void *new_ptr = malloc(size);
    if (!new_ptr)
    {
        return NULL;
    }

    size_t copy_size = block->size < size ? block->size : size;
    memcpy(new_ptr, ptr, copy_size);
    free(ptr);
    return new_ptr;
}
