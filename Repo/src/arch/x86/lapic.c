#include "lapic.h"

#include "msr.h"
#include "serial.h"

#define IA32_APIC_BASE_MSR   0x1B
#define LAPIC_ENABLE_BIT     (1ULL << 11)
#define LAPIC_BASE_MASK      0xFFFFF000ULL

#define LAPIC_REG_ID         0x020
#define LAPIC_REG_VERSION    0x030
#define LAPIC_REG_TPR        0x080
#define LAPIC_REG_EOI        0x0B0
#define LAPIC_REG_SVR        0x0F0
#define LAPIC_REG_ICR_LOW    0x300
#define LAPIC_REG_ICR_HIGH   0x310

#define LAPIC_DELIVERY_FIXED     (0u << 8)
#define LAPIC_DELIVERY_INIT      (5u << 8)
#define LAPIC_DELIVERY_STARTUP   (6u << 8)
#define LAPIC_LEVEL_ASSERT       (1u << 14)
#define LAPIC_TRIGGER_LEVEL      (1u << 15)

#define LAPIC_SVR_ENABLE         0x100
#define LAPIC_SPURIOUS_VECTOR    0xFF

static volatile uint32_t *g_lapic_base = NULL;

static inline uint32_t lapic_cpuid_apic_id(void)
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile ("cpuid"
                      : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                      : "a"(1), "c"(0));
    (void)eax; (void)ecx; (void)edx;
    return ebx >> 24;
}

static inline void lapic_write(uint32_t reg, uint32_t value)
{
    if (!g_lapic_base)
    {
        return;
    }
    g_lapic_base[reg / 4] = value;
    (void)g_lapic_base[reg / 4];
}

static inline uint32_t lapic_read(uint32_t reg)
{
    if (!g_lapic_base)
    {
        return 0;
    }
    return g_lapic_base[reg / 4];
}

static void lapic_wait_for_icr(void)
{
    while (lapic_read(LAPIC_REG_ICR_LOW) & (1u << 12))
    {
        __asm__ volatile ("pause");
    }
}

bool lapic_init(void)
{
    uint64_t apic_base = rdmsr(IA32_APIC_BASE_MSR);
    apic_base |= LAPIC_ENABLE_BIT;
    wrmsr(IA32_APIC_BASE_MSR, apic_base);

    g_lapic_base = (volatile uint32_t *)(uintptr_t)(apic_base & LAPIC_BASE_MASK);
    if (!g_lapic_base)
    {
        serial_printf("%s", "[lapic] base pointer null\r\n");
        return false;
    }

    lapic_write(LAPIC_REG_SVR, LAPIC_SVR_ENABLE | LAPIC_SPURIOUS_VECTOR);
    lapic_write(LAPIC_REG_TPR, 0);
    return true;
}

void lapic_enable(void)
{
    if (!g_lapic_base)
    {
        lapic_init();
        return;
    }
    uint32_t svr = lapic_read(LAPIC_REG_SVR);
    lapic_write(LAPIC_REG_SVR, svr | LAPIC_SVR_ENABLE | LAPIC_SPURIOUS_VECTOR);
}

uint32_t lapic_get_id(void)
{
    if (!g_lapic_base)
    {
        return lapic_cpuid_apic_id();
    }
    uint32_t value = lapic_read(LAPIC_REG_ID);
    return value >> 24;
}

void lapic_eoi(void)
{
    lapic_write(LAPIC_REG_EOI, 0);
}

void lapic_send_ipi(uint32_t apic_id, uint8_t vector)
{
    lapic_wait_for_icr();
    lapic_write(LAPIC_REG_ICR_HIGH, apic_id << 24);
    lapic_write(LAPIC_REG_ICR_LOW, LAPIC_DELIVERY_FIXED | vector);
}

void lapic_send_init(uint32_t apic_id)
{
    lapic_wait_for_icr();
    lapic_write(LAPIC_REG_ICR_HIGH, apic_id << 24);
    lapic_write(LAPIC_REG_ICR_LOW, LAPIC_DELIVERY_INIT | LAPIC_LEVEL_ASSERT | LAPIC_TRIGGER_LEVEL);
    lapic_wait_for_icr();
}

void lapic_send_startup(uint32_t apic_id, uint8_t vector)
{
    lapic_wait_for_icr();
    lapic_write(LAPIC_REG_ICR_HIGH, apic_id << 24);
    lapic_write(LAPIC_REG_ICR_LOW, LAPIC_DELIVERY_STARTUP | (vector & 0xFFu));
    lapic_wait_for_icr();
}

void lapic_broadcast_ipi(uint8_t vector, bool include_self)
{
    uint32_t icr = LAPIC_DELIVERY_FIXED | vector;
    if (!include_self)
    {
        icr |= (1u << 18); /* shorthand: all excluding self */
    }
    else
    {
        icr |= (2u << 18); /* shorthand: all including self */
    }
    lapic_wait_for_icr();
    lapic_write(LAPIC_REG_ICR_HIGH, 0);
    lapic_write(LAPIC_REG_ICR_LOW, icr);
}

void lapic_set_tpr(uint8_t value)
{
    lapic_write(LAPIC_REG_TPR, (uint32_t)value);
}
