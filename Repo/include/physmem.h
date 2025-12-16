#ifndef PHYSMEM_H
#define PHYSMEM_H

#include "types.h"

/*
 * Kernel physical memory mappings.
 *
 * The kernel maintains:
 * - a low identity map (0..4GiB) for early boot and legacy assumptions, and
 * - a high-half physmap (direct map) used to access arbitrary physical RAM.
 */

#define KERNEL_IDENTITY_MAP_BYTES (0x100000000ULL) /* 4 GiB */

/* High-half direct map base (covers up to 128 TiB of physical memory). */
#define KERNEL_PHYSMAP_BASE 0xFFFF800000000000ULL

/* High-half MMIO mapping window (ioremap). */
#define KERNEL_IOREMAP_BASE 0xFFFFC00000000000ULL
#define KERNEL_IOREMAP_MAX_BYTES (0x0000008000000000ULL) /* 512 GiB */

static inline void *phys_to_virt(paddr_t phys)
{
    return (void *)(uintptr_t)(KERNEL_PHYSMAP_BASE + (uint64_t)phys);
}

#endif /* PHYSMEM_H */
