#include "smp.h"

#include <stddef.h>
#include <stdint.h>

#include "acpi.h"
#include "arch/x86/cpu.h"
#include "arch/x86/smp_boot.h"
#include "heap.h"
#include "lapic.h"
#include "libc.h"
#include "paging.h"
#include "msr.h"
#include "process.h"
#include "serial.h"
#include "idt.h"

static inline uint32_t smp_cpuid_apic_id(void)
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile ("cpuid"
                      : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                      : "a"(1), "c"(0));
    (void)eax; (void)ecx; (void)edx;
    return ebx >> 24;
}

#define SMP_BOOT_STACK_SIZE (32 * 1024)
#define IA32_EFER 0xC0000080u

#define MADT_SIGNATURE "APIC"
#define MADT_LAPIC_ENTRY 0x00
#define LAPIC_FLAG_ENABLED 0x1

/*
 * Maximum allowed size of the AP trampoline blob.
 * Adjust if you reserve a different region size in your linker script.
 */
#ifndef SMP_TRAMPOLINE_MAX_SIZE
#define SMP_TRAMPOLINE_MAX_SIZE (64 * 1024u)
#endif

typedef struct __attribute__((packed))
{
    char     signature[4];
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    char     oem_id[6];
    char     oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} acpi_sdt_header_t;

typedef struct __attribute__((packed))
{
    acpi_sdt_header_t header;
    uint32_t lapic_address;
    uint32_t flags;
    uint8_t  entries[];
} acpi_madt_t;

typedef struct __attribute__((packed))
{
    uint8_t type;
    uint8_t length;
} acpi_madt_entry_t;

typedef struct __attribute__((packed))
{
    uint8_t type;
    uint8_t length;
    uint8_t processor_id;
    uint8_t apic_id;
    uint32_t flags;
} acpi_madt_lapic_t;

typedef struct __attribute__((packed))
{
    uint64_t stack;
    uint64_t entry;
    uint64_t pml4;
    uint64_t apic_id;
    volatile uint32_t stage;   /* updated by AP trampoline; read by BSP */
    uint32_t reserved;
    uint64_t cr4;
    uint64_t efer;
    uint64_t cr0;
    uint16_t idt_limit;
    uint64_t idt_base;
} smp_bootstrap_data_t;

static smp_bootstrap_data_t *const g_bootstrap_data =
    (smp_bootstrap_data_t *)(uintptr_t)SMP_BOOT_DATA_PHYS;

_Static_assert(offsetof(smp_bootstrap_data_t, stack)   == SMP_BOOT_STACK_OFFSET, "stack offset mismatch");
_Static_assert(offsetof(smp_bootstrap_data_t, entry)   == SMP_BOOT_ENTRY_OFFSET, "entry offset mismatch");
_Static_assert(offsetof(smp_bootstrap_data_t, pml4)    == SMP_BOOT_PML4_OFFSET, "pml4 offset mismatch");
_Static_assert(offsetof(smp_bootstrap_data_t, apic_id) == SMP_BOOT_APIC_ID_OFFSET, "apic_id offset mismatch");
_Static_assert(offsetof(smp_bootstrap_data_t, stage)   == SMP_BOOT_STAGE_OFFSET, "stage offset mismatch");
_Static_assert(offsetof(smp_bootstrap_data_t, cr4)     == SMP_BOOT_CR4_OFFSET, "cr4 offset mismatch");
_Static_assert(offsetof(smp_bootstrap_data_t, efer)    == SMP_BOOT_EFER_OFFSET, "efer offset mismatch");
_Static_assert(offsetof(smp_bootstrap_data_t, cr0)     == SMP_BOOT_CR0_OFFSET, "cr0 offset mismatch");
_Static_assert(offsetof(smp_bootstrap_data_t, idt_limit) == SMP_BOOT_IDT_LIMIT_OFFSET, "idt_limit offset mismatch");
_Static_assert(offsetof(smp_bootstrap_data_t, idt_base)  == SMP_BOOT_IDT_BASE_OFFSET, "idt_base offset mismatch");

extern uint8_t _binary_build_arch_x86_ap_trampoline_bin_start[];
extern uint8_t _binary_build_arch_x86_ap_trampoline_bin_end[];

/* smp_panic is used before its definition */
static void smp_panic(const char *msg, uint32_t apic_id);

static smp_cpu_t g_cpus[SMP_MAX_CPUS];
static uint32_t g_cpu_count = 0;
static uint32_t g_boot_cpu_index = 0;
static uint8_t g_apic_to_index[256];
static uint8_t g_bootstrap_stacks[SMP_MAX_CPUS][SMP_BOOT_STACK_SIZE] __attribute__((aligned(16))) = { 0 };
static uint64_t g_bootstrap_stack_tops[SMP_MAX_CPUS] = { 0 };
static uint32_t g_online_cpus = 0;
static uint32_t g_online_cpu_mask = 0;
static bool g_trampoline_ready = false;
static bool g_bootstrap_page_protected = false;
static bool g_warned_unmapped_apic = false;
static bool g_smp_initialized = false;

static inline uint64_t read_cr3(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(value));
    return value;
}

static inline uint64_t read_cr0(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(value));
    return value;
}

static inline uint64_t read_cr4(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr4, %0" : "=r"(value));
    return value;
}

static void smp_log(const char *msg)
{
    serial_printf("[smp] %s\r\n", msg);
}

static void smp_log_value(const char *prefix, uint64_t value)
{
    serial_printf("[smp] %s0x%016llX\r\n", prefix, (unsigned long long)(value));
}

static void copy_trampoline_blob(void)
{
    if (g_trampoline_ready)
    {
        return;
    }

    size_t size = (size_t)(_binary_build_arch_x86_ap_trampoline_bin_end -
                           _binary_build_arch_x86_ap_trampoline_bin_start);
    if (size == 0 || size > SMP_TRAMPOLINE_MAX_SIZE)
    {
        smp_panic("AP trampoline size invalid", UINT32_MAX);
    }

    uint8_t *dst = (uint8_t *)(uintptr_t)SMP_TRAMPOLINE_PHYS;
    memcpy(dst, _binary_build_arch_x86_ap_trampoline_bin_start, size);

    g_trampoline_ready = true;
}

static void protect_bootstrap_data_page(void)
{
    if (g_bootstrap_page_protected)
    {
        return;
    }

    const size_t bootstrap_bytes = 0x1000; /* single page covering SMP_BOOT_DATA_PHYS */

    if (paging_set_kernel_range_writable((uintptr_t)SMP_BOOT_DATA_PHYS, bootstrap_bytes, false))
    {
        g_bootstrap_page_protected = true;
        smp_log("SMP bootstrap data page locked read-only");
    }
    else
    {
        smp_log("failed to lock SMP bootstrap data page");
    }
}

static void map_cpu(uint32_t index, uint8_t apic_id, uint8_t processor_id, bool enabled)
{
    if (index >= SMP_MAX_CPUS)
    {
        return;
    }

    g_cpus[index].apic_id = apic_id;
    g_cpus[index].processor_id = processor_id;
    g_cpus[index].present = enabled;
    g_cpus[index].bsp = false;
    __atomic_store_n(&g_cpus[index].online, false, __ATOMIC_RELAXED);

    if (apic_id < sizeof(g_apic_to_index))
    {
        g_apic_to_index[apic_id] = (uint8_t)index;
    }
}

static void ensure_boot_cpu_present(void)
{
    uint32_t bsp_apic = lapic_get_id();
    uint32_t bsp_index = 0;

    if (bsp_apic < (uint32_t)sizeof(g_apic_to_index))
    {
        if (g_apic_to_index[bsp_apic] != 0xFF)
        {
            bsp_index = g_apic_to_index[bsp_apic];
        }
        else
        {
            bsp_index = g_cpu_count;
            if (g_cpu_count < SMP_MAX_CPUS)
            {
                map_cpu(bsp_index, (uint8_t)bsp_apic, 0, true);
                g_cpu_count++;
            }
        }
    }

    g_boot_cpu_index = bsp_index;
    g_cpus[bsp_index].bsp = true;
    g_cpus[bsp_index].present = true;
    __atomic_store_n(&g_cpus[bsp_index].online, true, __ATOMIC_RELEASE);
    g_online_cpus = 1;
    if (bsp_index < SMP_MAX_CPUS)
    {
        g_online_cpu_mask = (1u << bsp_index);
    }
}

bool smp_init(void)
{
    for (size_t i = 0; i < sizeof(g_apic_to_index); ++i)
    {
        g_apic_to_index[i] = 0xFF;
    }

    if (!lapic_init())
    {
        smp_log("lapic init failed");
        return false;
    }

    g_cpu_count = 0;

    size_t madt_length = 0;
    const acpi_madt_t *madt = (const acpi_madt_t *)acpi_find_table_cached(MADT_SIGNATURE, &madt_length);
    if (madt && madt_length >= sizeof(acpi_madt_t) && madt->header.length <= madt_length)
    {
        const uint8_t *cursor = madt->entries;
        const uint8_t *end = ((const uint8_t *)madt) + madt->header.length;

        while (cursor + sizeof(acpi_madt_entry_t) <= end)
        {
            const acpi_madt_entry_t *entry = (const acpi_madt_entry_t *)cursor;
            if (entry->length < sizeof(acpi_madt_entry_t))
            {
                break;
            }

            if (cursor + entry->length > end)
            {
                break;
            }

            if (entry->type == MADT_LAPIC_ENTRY && entry->length >= sizeof(acpi_madt_lapic_t))
            {
                const acpi_madt_lapic_t *lapic = (const acpi_madt_lapic_t *)entry;
                bool enabled = (lapic->flags & LAPIC_FLAG_ENABLED) != 0;

                if (g_cpu_count < SMP_MAX_CPUS)
                {
                    map_cpu(g_cpu_count, lapic->apic_id, lapic->processor_id, enabled);
                    g_cpu_count++;
                }
            }

            cursor += entry->length;
        }
    }

    if (g_cpu_count == 0)
    {
        g_cpu_count = 1;
        map_cpu(0, (uint8_t)lapic_get_id(), 0, true);
    }

    ensure_boot_cpu_present();
    g_smp_initialized = true;
    return true;
}

uint32_t smp_cpu_count(void)
{
    return (g_cpu_count == 0) ? 1u : g_cpu_count;
}

const smp_cpu_t *smp_cpu_by_index(uint32_t index)
{
    if (index >= smp_cpu_count())
    {
        return NULL;
    }
    return &g_cpus[index];
}

static void smp_panic(const char *msg, uint32_t apic_id)
{
    serial_printf("%s", "[smp] ");
    serial_printf("%s", msg ? msg : "fatal error");
    if (apic_id != UINT32_MAX)
    {
        serial_printf("%s", " apic=");
        serial_printf("%016llX", (unsigned long long)(apic_id));
    }
    serial_printf("%s", "\r\n");
    for (;;)
    {
        __asm__ volatile ("cli; hlt");
    }
}

static uint32_t resolve_apic_to_index(uint32_t apic_id, bool strict)
{
    /* Always linear-scan the CPU table; robust even if g_cpu_count is stale. */
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        if (!g_cpus[i].present && i >= g_cpu_count)
        {
            continue;
        }
        if (g_cpus[i].apic_id == (uint8_t)apic_id)
        {
            if (apic_id < (uint32_t)sizeof(g_apic_to_index))
            {
                g_apic_to_index[apic_id] = (uint8_t)i;
            }
            return i;
        }
    }

    if (strict)
    {
        smp_panic("unmapped APIC ID", apic_id);
    }

    if (!g_warned_unmapped_apic)
    {
        g_warned_unmapped_apic = true;
        serial_printf("%s", "[smp] warning: unmapped APIC ID encountered apic=0x");
        serial_printf("%016llX", (unsigned long long)(apic_id));
        serial_printf("%s", " falling back to BSP index\r\n");
    }

    return g_boot_cpu_index;
}

uint32_t smp_current_cpu_index(void)
{
    static bool warned_unmapped = false;
    static bool dumped_map = false;

    if (!g_smp_initialized)
    {
        return g_boot_cpu_index;
    }

    uint32_t apic = lapic_get_id();
    uint32_t idx = resolve_apic_to_index(apic, false);
    if (idx < SMP_MAX_CPUS && __atomic_load_n(&g_cpus[idx].online, __ATOMIC_ACQUIRE))
    {
        return idx;
    }

    if (!warned_unmapped)
    {
        serial_printf("%s", "[smp] warning: unmapped current CPU apic=0x");
        serial_printf("%016llX", (unsigned long long)apic);
        serial_printf("%s", " -> using BSP index\r\n");
        if (!dumped_map)
        {
            dumped_map = true;
            serial_printf("%s", "[smp] map dump g_cpu_count=0x");
            serial_printf("%016llX", (unsigned long long)g_cpu_count);
            serial_printf("%s", "\r\n");
            uint32_t max_dump = (g_cpu_count < SMP_MAX_CPUS) ? g_cpu_count : SMP_MAX_CPUS;
            if (max_dump > 8)
            {
                max_dump = 8;
            }
            for (uint32_t i = 0; i < max_dump; ++i)
            {
                serial_printf("%s", "  idx=0x");
                serial_printf("%016llX", (unsigned long long)i);
                serial_printf("%s", " apic=0x");
                serial_printf("%016llX", (unsigned long long)g_cpus[i].apic_id);
                serial_printf("%s", " present=");
                serial_printf("%s", g_cpus[i].present ? "1" : "0");
                serial_printf("%s", " online=");
                serial_printf("%s", __atomic_load_n(&g_cpus[i].online, __ATOMIC_ACQUIRE) ? "1" : "0");
                serial_printf("%s", "\r\n");
            }
            serial_printf("%s", "  apic_to_index[apic]=0x");
            uint8_t map = (apic < (uint32_t)sizeof(g_apic_to_index)) ? g_apic_to_index[apic] : 0xFF;
            serial_printf("%02X", (unsigned int)map);
            serial_printf("%s", "\r\n");
        }
        warned_unmapped = true;
    }
    return g_boot_cpu_index;
}

static void prepare_bootstrap_data(uint32_t cpu_index, uint64_t stack_top)
{
    memset(g_bootstrap_data, 0, sizeof(*g_bootstrap_data));
    g_bootstrap_data->stack   = stack_top;
    g_bootstrap_data->entry   = (uint64_t)(uintptr_t)smp_secondary_entry;
    g_bootstrap_data->pml4    = read_cr3();
    g_bootstrap_data->apic_id = g_cpus[cpu_index].apic_id;
    g_bootstrap_data->cr4     = read_cr4();
    g_bootstrap_data->efer    = rdmsr(IA32_EFER);
    g_bootstrap_data->cr0     = read_cr0();
    arch_idtr_t idtr = { 0 };
    arch_cpu_get_idtr(&idtr);
    g_bootstrap_data->idt_limit = idtr.limit;
    g_bootstrap_data->idt_base = idtr.base;
    g_bootstrap_data->stage   = 0;

    /* Ensure all writes are visible before sending SIPIs */
    __sync_synchronize();
}

bool smp_start_secondary_cpus(void)
{
    copy_trampoline_blob();

    if (smp_cpu_count() <= 1)
    {
        return true;
    }

    bool all_started = true;
    uint8_t vector = (uint8_t)(SMP_TRAMPOLINE_PHYS >> 12);

    for (uint32_t i = 0; i < smp_cpu_count(); ++i)
    {
        if (i == g_boot_cpu_index)
        {
            continue;
        }
        if (!g_cpus[i].present)
        {
            continue;
        }

        uint64_t stack_top = (uint64_t)(uintptr_t)(g_bootstrap_stacks[i] + SMP_BOOT_STACK_SIZE);
        g_bootstrap_stack_tops[i] = stack_top;
        prepare_bootstrap_data(i, stack_top);

        smp_log_value("starting CPU stack=", stack_top);
        smp_log_value(" starting CPU apic=", g_cpus[i].apic_id);

        lapic_send_init(g_cpus[i].apic_id);
        for (volatile int delay = 0; delay < 100000; ++delay)
        {
            __asm__ volatile ("pause");
        }

        lapic_send_startup(g_cpus[i].apic_id, vector);
        for (volatile int delay = 0; delay < 100000; ++delay)
        {
            __asm__ volatile ("pause");
        }

        lapic_send_startup(g_cpus[i].apic_id, vector);

        uint32_t wait_loops = 0;
        uint32_t last_stage = 0;
        while (!__atomic_load_n(&g_cpus[i].online, __ATOMIC_ACQUIRE) &&
               wait_loops++ < 5000000)
        {
            uint32_t stage = g_bootstrap_data->stage;
            if (stage != last_stage)
            {
                last_stage = stage;
                smp_log_value("cpu stage=", stage);
            }
            __asm__ volatile ("pause");
        }

        if (__atomic_load_n(&g_cpus[i].online, __ATOMIC_ACQUIRE))
        {
            smp_log_value("cpu online apic=", g_cpus[i].apic_id);
        }
        else
        {
            smp_log_value("cpu failed stage=", g_bootstrap_data->stage);
            all_started = false;
        }
    }

    if (all_started)
    {
        protect_bootstrap_data_page();
    }

    return all_started;
}

void smp_secondary_entry(uint32_t apic_id)
{
    uint32_t cpu_index = resolve_apic_to_index(apic_id, true);

    uint64_t stack_top = (cpu_index < SMP_MAX_CPUS) ? g_bootstrap_stack_tops[cpu_index] : g_bootstrap_data->stack;

    arch_cpu_init_ap(cpu_index, stack_top);
    idt_load();
    lapic_enable();
    lapic_set_tpr(0xFF); /* Mask AP interrupts until scheduler stack is live. */

    g_cpus[cpu_index].present = true;
    __atomic_store_n(&g_cpus[cpu_index].online, true, __ATOMIC_RELEASE);
    __sync_fetch_and_add(&g_online_cpus, 1);
    if (cpu_index < SMP_MAX_CPUS)
    {
        __atomic_fetch_or(&g_online_cpu_mask, (1u << cpu_index), __ATOMIC_RELEASE);
    }

    process_run_secondary_cpu(cpu_index);

    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}

void smp_handle_schedule_ipi(interrupt_frame_t *frame)
{
    process_on_timer_tick(frame);
}

void smp_broadcast_schedule_ipi(void)
{
    lapic_broadcast_ipi(SMP_SCHEDULE_IPI_VECTOR, true);
}

void smp_broadcast_tlb_flush(void)
{
    uint32_t online = __atomic_load_n(&g_online_cpus, __ATOMIC_ACQUIRE);
    if (online <= 1)
    {
        return;
    }
    lapic_broadcast_ipi(SMP_TLB_FLUSH_IPI_VECTOR, true);
}

void smp_tlb_flush_mask(uint32_t cpu_mask)
{
    if (cpu_mask == 0)
    {
        return;
    }

    uint32_t online_mask = __atomic_load_n(&g_online_cpu_mask, __ATOMIC_ACQUIRE);
    uint32_t cpu_count = smp_cpu_count();
    uint32_t self = smp_current_cpu_index();

    for (uint32_t i = 0; i < cpu_count && i < SMP_MAX_CPUS; ++i)
    {
        uint32_t bit = (1u << i);
        if ((cpu_mask & bit) == 0)
        {
            continue;
        }
        if ((online_mask & bit) == 0)
        {
            continue;
        }
        if (i == self)
        {
            continue;
        }
        lapic_send_ipi(g_cpus[i].apic_id, SMP_TLB_FLUSH_IPI_VECTOR);
    }
}
