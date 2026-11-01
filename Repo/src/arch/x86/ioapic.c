/* Route the timer and legacy input using MADT global interrupt numbers and
 * source overrides. PCI INTx continues using the existing firmware PIC route;
 * routing PCI through IOAPIC additionally requires ACPI _PRT/link evaluation. */
#include "ioapic.h"
#include "acpi.h"
#include "ioremap.h"
#include "lapic.h"
#include "serial.h"
#include "spinlock.h"
#include "libc.h"

typedef struct { volatile uint32_t *base; uint32_t first, count; } ioapic_t;
static ioapic_t g_apics[8];
static unsigned g_count;
static uint32_t g_gsi[16];
static uint16_t g_flags[16];
static spinlock_t g_lock;
static uint32_t g_destination;

static uint32_t reg_read(ioapic_t *apic, uint32_t reg)
{ apic->base[0] = reg; return apic->base[4]; }
static void reg_write(ioapic_t *apic, uint32_t reg, uint32_t value)
{ apic->base[0] = reg; apic->base[4] = value; }

void ioapic_init(void)
{
    spinlock_init(&g_lock);
    g_destination = lapic_get_id();
    for (unsigned irq = 0; irq < 16; ++irq) g_gsi[irq] = irq;
    size_t length = 0;
    const uint8_t *madt = acpi_find_table_cached("APIC", &length);
    if (!madt || length < 44 || lapic_get_id() > 255) return;
    uint32_t table_length;
    memcpy(&table_length, madt + 4, 4);
    if (table_length > length || table_length < 44) return;
    for (size_t offset = 44; offset + 2 <= table_length;)
    {
        const uint8_t *entry = madt + offset;
        if (entry[1] < 2 || entry[1] > table_length - offset) break;
        if (entry[0] == 1 && entry[1] >= 12 && g_count < 8)
        {
            uint32_t physical, first;
            memcpy(&physical, entry + 4, 4);
            memcpy(&first, entry + 8, 4);
            ioapic_t *apic = &g_apics[g_count];
            apic->base = ioremap(physical, 4096);
            if (apic->base)
            {
                apic->first = first;
                apic->count = ((reg_read(apic, 1) >> 16) & 255) + 1;
                /* Mask stale firmware vectors before claiming ISA sources.
                 * PCI INTx retains its existing PIC path. */
                for (unsigned pin = 0; pin < apic->count; ++pin)
                    reg_write(apic, 0x10 + pin * 2, 1u << 16);
                ++g_count;
            }
        }
        if (entry[0] == 2 && entry[1] >= 10 && entry[2] == 0 && entry[3] < 16)
        {
            memcpy(&g_gsi[entry[3]], entry + 4, 4);
            memcpy(&g_flags[entry[3]], entry + 8, 2);
        }
        offset += entry[1];
    }
    serial_printf("[ioapic] controllers=%u; MADT routing for timer/legacy input", g_count);
}

bool ioapic_enable_isa_irq(uint8_t irq)
{
    if (irq != 0 && irq != 1 && irq != 8 && irq != 12) return false;
    uint32_t gsi = g_gsi[irq];
    uint16_t flags = g_flags[irq];
    if ((flags & 3) == 2 || ((flags >> 2) & 3) == 2) return false;
    /* This can be called by an AP driver thread; always target the BSP that
     * receives the timer and owns legacy IRQ routing, not the calling CPU. */
    uint32_t destination = g_destination;
    if (destination > 255) return false;
    for (unsigned i = 0; i < g_count; ++i)
    {
        ioapic_t *apic = &g_apics[i];
        if (gsi < apic->first || gsi - apic->first >= apic->count) continue;
        uint32_t low = 32u + irq;
        if ((flags & 3) == 3) low |= 1u << 13;
        if (((flags >> 2) & 3) == 3) low |= 1u << 15;
        uint64_t saved = spinlock_lock_irqsave(&g_lock);
        unsigned reg = 0x10 + 2 * (gsi - apic->first);
        reg_write(apic, reg, low | (1u << 16));
        reg_write(apic, reg + 1, destination << 24);
        reg_write(apic, reg, low);
        spinlock_unlock_irqrestore(&g_lock, saved);
        return true;
    }
    return false;
}

