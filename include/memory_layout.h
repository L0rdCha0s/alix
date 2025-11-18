#ifndef MEMORY_LAYOUT_H
#define MEMORY_LAYOUT_H

#include "types.h"

#define USER_DEFAULT_POINTER_BASE  0x0000000000400000ULL
#define USER_DEFAULT_POINTER_LIMIT 0x00000000FFFFFFFFULL
#define USER_DEFAULT_STACK_TOP_OFFSET 0x01000000ULL
#define USER_DEFAULT_STACK_SIZE   (64ULL * 1024ULL)
#define USER_DEFAULT_HEAP_BASE_OFFSET 0x02000000ULL
#define USER_DEFAULT_HEAP_SIZE    (1024ULL * 1024ULL * 1024ULL)

typedef struct memory_layout
{
    uintptr_t kernel_heap_base;
    uintptr_t kernel_heap_end;
    uintptr_t kernel_heap_size;

    uintptr_t user_pointer_base;
    uintptr_t user_pointer_limit;

    uintptr_t user_stack_top;
    size_t user_stack_size;

    uintptr_t user_heap_base;
    size_t user_heap_size;

    /* Physical addresses. */
    uintptr_t user_phys_min;
    uintptr_t identity_map_limit;
} memory_layout_t;

extern memory_layout_t g_mem_layout;

#endif /* MEMORY_LAYOUT_H */
