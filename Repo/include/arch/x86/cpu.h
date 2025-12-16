#ifndef ARCH_X86_CPU_H
#define ARCH_X86_CPU_H

#include "types.h"

typedef struct
{
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) arch_gdtr_t;

typedef struct
{
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) arch_idtr_t;

void arch_cpu_init_bsp(uint64_t initial_rsp0);
void arch_cpu_init_ap(uint32_t cpu_index, uint64_t initial_rsp0);
void arch_cpu_set_kernel_stack(uint32_t cpu_index, uint64_t rsp0);
void arch_cpu_get_gdtr(uint32_t cpu_index, arch_gdtr_t *gdtr_out);
void arch_cpu_get_idtr(arch_idtr_t *idtr_out);
uint64_t arch_cpu_get_kernel_stack(uint32_t cpu_index);

#endif /* ARCH_X86_CPU_H */
