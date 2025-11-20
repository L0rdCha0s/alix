#ifndef SMP_H
#define SMP_H

#include "types.h"
#include "interrupts.h"

#define SMP_MAX_CPUS 32
#define SMP_SCHEDULE_IPI_VECTOR 0xF0
#define SMP_TLB_FLUSH_IPI_VECTOR 0xEF

typedef struct
{
    uint32_t apic_id;
    uint32_t processor_id;
    bool     present;
    bool     bsp;
    volatile bool online;
} smp_cpu_t;

bool smp_init(void);
bool smp_start_secondary_cpus(void);
uint32_t smp_cpu_count(void);
uint32_t smp_current_cpu_index(void);
const smp_cpu_t *smp_cpu_by_index(uint32_t index);
void smp_handle_schedule_ipi(interrupt_frame_t *frame);
void smp_broadcast_schedule_ipi(void);
void smp_broadcast_tlb_flush(void);
void smp_tlb_flush_mask(uint32_t cpu_mask);
void smp_secondary_entry(uint32_t apic_id);

#endif /* SMP_H */
