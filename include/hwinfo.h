#ifndef HWINFO_H
#define HWINFO_H

#include "types.h"

typedef struct
{
    char vendor[13];
    char brand[49];
    uint32_t base_mhz;
    uint32_t max_mhz;
    uint32_t bus_mhz;
} hwinfo_cpu_info_t;

typedef struct
{
    uint64_t usable_bytes;
    uint64_t total_bytes;
    uint32_t e820_entries;
} hwinfo_memory_info_t;

void hwinfo_init(void);
bool hwinfo_get_cpu_info(hwinfo_cpu_info_t *out);
bool hwinfo_get_memory_info(hwinfo_memory_info_t *out);
void hwinfo_print_boot_summary(void);

#endif
