#ifndef HEAP_H
#define HEAP_H

#include "types.h"

#ifndef ENABLE_HEAP_TRACE
#define ENABLE_HEAP_TRACE 1
#endif

void heap_init(void);
void heap_sys_controls_init(void);

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);
void heap_debug_dump(const char *context);
bool heap_debug_verify(const char *context);
void heap_trace_set_enabled(bool enable);
void heap_trace_set_threshold(size_t threshold);
void heap_trace_dump_stats(const char *context);
typedef struct
{
    uint32_t owner_cpu;
    uint32_t depth;
    uint64_t owner_ra;
    uint64_t acquired_tsc;
} heap_lock_info_t;
bool heap_lock_owner_snapshot(heap_lock_info_t *info);
bool heap_lock_held_by_current_cpu(void);

#endif
