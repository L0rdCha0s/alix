#include "heap.h"
#include "libc.h"

#include <stddef.h>

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

static heap_block_t *find_suitable_block(size_t size)
{
    heap_block_t *block = g_heap_head;
    while (block)
    {
        if (block->free && block->size >= size)
        {
            return block;
        }
        block = block->next;
    }
    return NULL;
}

void heap_init(void)
{
    if (g_heap_initialized)
    {
        return;
    }

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

void *malloc(size_t size)
{
    if (!g_heap_initialized || size == 0)
    {
        return NULL;
    }

    size = align_size(size);

    heap_block_t *block = find_suitable_block(size);
    if (!block)
    {
        return NULL;
    }

    if (block->size >= size + sizeof(heap_block_t) + ALIGNMENT)
    {
        split_block(block, size);
    }

    block->free = false;
    return (void *)((uintptr_t)block + sizeof(heap_block_t));
}

void free(void *ptr)
{
    if (!g_heap_initialized || !ptr)
    {
        return;
    }

    heap_block_t *block = payload_to_block(ptr);
    if (!block || !pointer_in_heap(block) || block->free)
    {
        return;
    }

    block->free = true;
    coalesce(block);
}

void *calloc(size_t count, size_t size)
{
    if (!g_heap_initialized)
    {
        return NULL;
    }

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
    if (!g_heap_initialized)
    {
        return NULL;
    }

    if (!ptr)
    {
        return malloc(size);
    }

    if (size == 0)
    {
        free(ptr);
        return NULL;
    }

    heap_block_t *block = payload_to_block(ptr);
    if (!block || !pointer_in_heap(block))
    {
        return NULL;
    }

    size = align_size(size);

    if (block->size >= size)
    {
        if (block->size >= size + sizeof(heap_block_t) + ALIGNMENT)
        {
            split_block(block, size);
        }
        return ptr;
    }

    heap_block_t *expanded = expand_block(block, size);
    if (expanded)
    {
        return (void *)((uintptr_t)expanded + sizeof(heap_block_t));
    }

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
