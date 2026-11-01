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
#define LAPIC_DEST_ALL_INCLUDING_SELF  (2u << 18)
#define LAPIC_DEST_ALL_EXCLUDING_SELF  (3u << 18)

#define LAPIC_SVR_ENABLE         0x100
#define LAPIC_SPURIOUS_VECTOR    0xFF

static volatile uint32_t *g_lapic_base = NULL;
static bool g_x2apic;

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
    if (g_x2apic) { wrmsr(0x800 + reg / 16, value); return; }
    if (!g_lapic_base)
    {
        return;
    }
    g_lapic_base[reg / 4] = value;
    (void)g_lapic_base[reg / 4];
}

static inline uint32_t lapic_read(uint32_t reg)
{
    if (g_x2apic) return (uint32_t)rdmsr(0x800 + reg / 16);
    if (!g_lapic_base)
    {
        return 0;
    }
    return g_lapic_base[reg / 4];
}

static void lapic_wait_for_icr(void)
{
    if (g_x2apic) return;
    unsigned polls = 1000000;
    while ((lapic_read(LAPIC_REG_ICR_LOW) & (1u << 12)) && --polls)
    {
        __asm__ volatile ("pause");
    }
    if (!polls)
    {
        serial_printf("[lapic] IPI delivery timed out");
        for (;;) __asm__ volatile ("cli; hlt");
    }
}

bool lapic_init(void)
{
    uint64_t apic_base = rdmsr(IA32_APIC_BASE_MSR);
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1), "c"(0));
    g_x2apic = (ecx & (1u << 21)) || (apic_base & (1ULL << 10));
    if (g_x2apic) apic_base |= 1ULL << 10;
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
    if (g_x2apic)
    {
        uint64_t base = rdmsr(IA32_APIC_BASE_MSR);
        wrmsr(IA32_APIC_BASE_MSR, base | (1ULL << 10) | LAPIC_ENABLE_BIT);
    }
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
    return g_x2apic ? value : value >> 24;
}

void lapic_eoi(void)
{
    lapic_write(LAPIC_REG_EOI, 0);
}

static void lapic_send_icr(uint32_t apic_id, uint32_t low)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0; cli" : "=r"(flags) :: "memory");
    lapic_wait_for_icr();
    if (g_x2apic) wrmsr(0x830, ((uint64_t)apic_id << 32) | low);
    else
    {
        lapic_write(LAPIC_REG_ICR_HIGH, apic_id << 24);
        lapic_write(LAPIC_REG_ICR_LOW, low);
    }
    lapic_wait_for_icr();
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "memory", "cc");
}

void lapic_send_ipi(uint32_t apic_id, uint8_t vector)
{ lapic_send_icr(apic_id, LAPIC_DELIVERY_FIXED | vector); }

void lapic_send_init(uint32_t apic_id)
{ lapic_send_icr(apic_id, LAPIC_DELIVERY_INIT | LAPIC_LEVEL_ASSERT | LAPIC_TRIGGER_LEVEL); }

void lapic_send_startup(uint32_t apic_id, uint8_t vector)
{ lapic_send_icr(apic_id, LAPIC_DELIVERY_STARTUP | vector); }

void lapic_broadcast_ipi(uint8_t vector, bool include_self)
{
    lapic_send_icr(0, LAPIC_DELIVERY_FIXED | vector |
        (include_self ? LAPIC_DEST_ALL_INCLUDING_SELF : LAPIC_DEST_ALL_EXCLUDING_SELF));
}

void lapic_set_tpr(uint8_t value)
{
    lapic_write(LAPIC_REG_TPR, (uint32_t)value);
}
