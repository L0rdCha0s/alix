#include "acpi.h"

#include "bootinfo.h"
#include "io.h"
#include "libc.h"
#include "serial.h"

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

typedef struct __attribute__((packed))
{
    char     signature[8];
    uint8_t  checksum;
    char     oem_id[6];
    uint8_t  revision;
    uint32_t rsdt_address;
} acpi_rsdp_v1_t;

typedef struct __attribute__((packed))
{
    acpi_rsdp_v1_t first;
    uint32_t       length;
    uint64_t       xsdt_address;
    uint8_t        extended_checksum;
    uint8_t        reserved[3];
} acpi_rsdp_v2_t;

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
    uint8_t  address_space_id;
    uint8_t  register_bit_width;
    uint8_t  register_bit_offset;
    uint8_t  access_size;
    uint64_t address;
} acpi_gas_t;

typedef struct __attribute__((packed))
{
    acpi_sdt_header_t header;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t  reserved;
    uint8_t  preferred_pm_profile;
    uint16_t sci_interrupt;
    uint32_t smi_cmd;
    uint8_t  acpi_enable;
    uint8_t  acpi_disable;
    uint8_t  s4bios_req;
    uint8_t  pstate_control;
    uint32_t pm1a_event_block;
    uint32_t pm1b_event_block;
    uint32_t pm1a_control_block;
    uint32_t pm1b_control_block;
    uint32_t pm2_control_block;
    uint32_t pm_timer_block;
    uint32_t gpe0_block;
    uint32_t gpe1_block;
    uint8_t  pm1_event_length;
    uint8_t  pm1_control_length;
    uint8_t  pm2_control_length;
    uint8_t  pm_timer_length;
    uint8_t  gpe0_length;
    uint8_t  gpe1_length;
    uint8_t  gpe1_base;
    uint8_t  cstate_control;
    uint16_t worst_c2_latency;
    uint16_t worst_c3_latency;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t  duty_offset;
    uint8_t  duty_width;
    uint8_t  day_alarm;
    uint8_t  month_alarm;
    uint8_t  century;
    uint16_t boot_arch_flags;
    uint8_t  reserved2;
    uint32_t flags;
    acpi_gas_t reset_reg;
    uint8_t     reset_value;
    uint8_t     reserved3[3];
    uint64_t    x_firmware_ctrl;
    uint64_t    x_dsdt;
    acpi_gas_t  x_pm1a_event_block;
    acpi_gas_t  x_pm1b_event_block;
    acpi_gas_t  x_pm1a_control_block;
    acpi_gas_t  x_pm1b_control_block;
    acpi_gas_t  x_pm2_control_block;
    acpi_gas_t  x_pm_timer_block;
    acpi_gas_t  x_gpe0_block;
    acpi_gas_t  x_gpe1_block;
} acpi_fadt_t;

typedef struct
{
    uint64_t address;
    bool     is_io;
} acpi_pm_register_t;

static struct
{
    bool               initialized;
    bool               ready;
    acpi_pm_register_t pm1a;
    acpi_pm_register_t pm1b;
    uint16_t           slp_typa;
    uint16_t           slp_typb;
} g_acpi_state = { 0 };

static acpi_sdt_header_t *g_acpi_rsdt = NULL;
static acpi_sdt_header_t *g_acpi_xsdt = NULL;

static bool acpi_checksum(const void *table, size_t length);
static uintptr_t acpi_ebda_address(void);
static acpi_rsdp_v2_t *acpi_scan_region(uintptr_t start, uintptr_t end);
static acpi_rsdp_v2_t *acpi_find_rsdp(void);
static acpi_sdt_header_t *acpi_map_sdt(uint64_t phys, const char *expected_signature);
static acpi_sdt_header_t *acpi_find_table(acpi_sdt_header_t *root, bool use_64bit_entries, const char *signature);
static void acpi_assign_pm_register(acpi_pm_register_t *reg, uint32_t legacy, const acpi_gas_t *gas);
static bool acpi_extract_s5(const uint8_t *aml, size_t length, uint16_t *slp_typa, uint16_t *slp_typb);
static uint32_t acpi_read_pkg_length(const uint8_t **cursor, const uint8_t *end);
static bool acpi_read_integer(const uint8_t **cursor, const uint8_t *end, uint16_t *value);
static uint16_t acpi_read_pm(const acpi_pm_register_t *reg);
static void acpi_write_pm(const acpi_pm_register_t *reg, uint16_t value);
static bool acpi_sci_enabled(void);
static void acpi_enable_if_needed(const acpi_fadt_t *fadt);

static void acpi_log(const char *msg)
{
    serial_printf("%s", "[acpi] ");
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
}
static void acpi_log_hex(const char *prefix, uint64_t value)
{
    serial_printf("%s", "[acpi] ");
    serial_printf("%s", prefix);
    char buf[17];
    for (int i = 15; i >= 0; --i)
    {
        uint8_t nibble = (uint8_t)(value & 0xF);
        buf[i] = (char)((nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10));
        value >>= 4;
    }
    buf[16] = '\0';
    serial_printf("%s", buf);
    serial_printf("%s", "\r\n");
}

static bool acpi_checksum(const void *table, size_t length)
{
    if (!table || length == 0)
    {
        return false;
    }
    const uint8_t *bytes = (const uint8_t *)table;
    uint8_t sum = 0;
    for (size_t i = 0; i < length; ++i)
    {
        sum = (uint8_t)(sum + bytes[i]);
    }
    return sum == 0;
}

static uintptr_t acpi_ebda_address(void)
{
    const uint16_t *ebda_segment_ptr = (const uint16_t *)(uintptr_t)0x40E;
    uint16_t segment = ebda_segment_ptr ? *ebda_segment_ptr : 0;
    return (uintptr_t)segment << 4;
}

static acpi_rsdp_v2_t *acpi_scan_region(uintptr_t start, uintptr_t end)
{
    const uintptr_t step = 16;
    for (uintptr_t addr = start; addr + sizeof(acpi_rsdp_v1_t) <= end; addr += step)
    {
        const char *signature = (const char *)addr;
        if (memcmp(signature, "RSD PTR ", 8) != 0)
        {
            continue;
        }

        acpi_rsdp_v1_t *rsdp_v1 = (acpi_rsdp_v1_t *)addr;
        if (!acpi_checksum(rsdp_v1, sizeof(acpi_rsdp_v1_t)))
        {
            continue;
        }

        if (rsdp_v1->revision >= 2)
        {
            acpi_rsdp_v2_t *rsdp_v2 = (acpi_rsdp_v2_t *)addr;
            if (rsdp_v2->length == 0 || !acpi_checksum(rsdp_v2, rsdp_v2->length))
            {
                continue;
            }
            return rsdp_v2;
        }

        return (acpi_rsdp_v2_t *)addr;
    }
    return NULL;
}

static acpi_rsdp_v2_t *acpi_find_rsdp(void)
{
    acpi_log("Searching for RSDP");
    if (boot_info.acpi_rsdp_length >= sizeof(acpi_rsdp_v1_t))
    {
        acpi_log_hex("Checking bootinfo RSDP copy length ", boot_info.acpi_rsdp_length);
        acpi_rsdp_v2_t *rsdp = (acpi_rsdp_v2_t *)(void *)boot_info.acpi_rsdp_data;
        size_t length = boot_info.acpi_rsdp_length;
        if (length > sizeof(boot_info.acpi_rsdp_data))
        {
            length = sizeof(boot_info.acpi_rsdp_data);
        }
        if (length == sizeof(acpi_rsdp_v1_t) || length >= sizeof(acpi_rsdp_v2_t))
        {
            if (acpi_checksum(rsdp, length))
            {
                acpi_log("Using RSDP copy from bootinfo");
                return rsdp;
            }
            acpi_log("Bootinfo RSDP copy checksum failed");
        }
    }
    if (boot_info.magic == BOOTINFO_MAGIC && boot_info.acpi_rsdp != 0)
    {
        acpi_log_hex("Bootinfo RSDP pointer ", boot_info.acpi_rsdp);
        volatile acpi_rsdp_v2_t *rsdp_phys = (acpi_rsdp_v2_t *)(uintptr_t)boot_info.acpi_rsdp;
        acpi_rsdp_v2_t rsdp_copy_v2;
        memcpy(&rsdp_copy_v2, (const void *)(uintptr_t)boot_info.acpi_rsdp, sizeof(rsdp_copy_v2));
        acpi_rsdp_v2_t *rsdp = &rsdp_copy_v2;
        if (rsdp)
        {
            size_t length = (rsdp->length != 0) ? rsdp->length : sizeof(acpi_rsdp_v1_t);
            if (acpi_checksum(rsdp, length))
            {
                acpi_log("Bootinfo RSDP valid");
                return rsdp;
            }
            acpi_log("Bootinfo RSDP checksum failed");
        }
    }

    uintptr_t ebda = acpi_ebda_address();
    if (ebda >= 0x400 && ebda + 1024 <= 0x100000)
    {
        acpi_log_hex("Scanning EBDA at ", ebda);
        acpi_rsdp_v2_t *rsdp = acpi_scan_region(ebda, ebda + 1024);
        if (rsdp)
        {
            acpi_log("Found RSDP in EBDA");
            return rsdp;
        }
    }

    acpi_log("Scanning BIOS region 0xE0000-0x100000");
    acpi_rsdp_v2_t *rsdp = acpi_scan_region(0xE0000, 0x100000);
    if (rsdp)
    {
        acpi_log("Found RSDP in BIOS area");
    }
    else
    {
        acpi_log("RSDP not found in BIOS area");
    }
    return rsdp;
}

static acpi_sdt_header_t *acpi_map_sdt(uint64_t phys, const char *expected_signature)
{
    if (phys == 0)
    {
        return NULL;
    }
    acpi_sdt_header_t *table = (acpi_sdt_header_t *)(uintptr_t)phys;
    if (!table)
    {
        return NULL;
    }
    if (table->length < sizeof(acpi_sdt_header_t))
    {
        return NULL;
    }
    if (expected_signature && memcmp(table->signature, expected_signature, 4) != 0)
    {
        return NULL;
    }
    if (!acpi_checksum(table, table->length))
    {
        return NULL;
    }
    return table;
}

static acpi_sdt_header_t *acpi_find_table(acpi_sdt_header_t *root, bool use_64bit_entries, const char *signature)
{
    if (!root || root->length < sizeof(acpi_sdt_header_t))
    {
        return NULL;
    }

    size_t entry_size = use_64bit_entries ? sizeof(uint64_t) : sizeof(uint32_t);
    size_t entry_count = (root->length - sizeof(acpi_sdt_header_t)) / entry_size;
    uint8_t *entry_base = (uint8_t *)root + sizeof(acpi_sdt_header_t);

    for (size_t i = 0; i < entry_count; ++i)
    {
        uint64_t phys = use_64bit_entries ?
                        ((const uint64_t *)entry_base)[i] :
                        (uint64_t)((const uint32_t *)entry_base)[i];
        if (!phys)
        {
            continue;
        }

        acpi_sdt_header_t *candidate = (acpi_sdt_header_t *)(uintptr_t)phys;
        if (!candidate || candidate->length < sizeof(acpi_sdt_header_t))
        {
            continue;
        }
        if (memcmp(candidate->signature, signature, 4) != 0)
        {
            continue;
        }
        if (!acpi_checksum(candidate, candidate->length))
        {
            continue;
        }
        return candidate;
    }

    return NULL;
}

static void acpi_assign_pm_register(acpi_pm_register_t *reg, uint32_t legacy, const acpi_gas_t *gas)
{
    if (!reg)
    {
        return;
    }
    reg->address = 0;
    reg->is_io = true;

    if (gas && gas->address != 0 && gas->register_bit_width >= 16 &&
        (gas->address_space_id == 0 || gas->address_space_id == 1))
    {
        reg->address = gas->address;
        reg->is_io = (gas->address_space_id == 1);
        return;
    }

    if (legacy)
    {
        reg->address = legacy;
        reg->is_io = true;
    }
}

static uint32_t acpi_read_pkg_length(const uint8_t **cursor, const uint8_t *end)
{
    if (!cursor || !*cursor || *cursor >= end)
    {
        return 0;
    }
    uint8_t first = *(*cursor)++;
    uint32_t length = (uint32_t)(first & 0x3F);
    uint8_t follow = first >> 6;

    for (uint8_t i = 0; i < follow; ++i)
    {
        if (*cursor >= end)
        {
            return 0;
        }
        length |= (uint32_t)(*(*cursor)++) << (6 + 8 * i);
    }
    return length;
}

static bool acpi_read_integer(const uint8_t **cursor, const uint8_t *end, uint16_t *value)
{
    if (!cursor || !*cursor || *cursor >= end || !value)
    {
        return false;
    }

    uint8_t opcode = *(*cursor)++;
    if (opcode == 0x0A)
    {
        if (*cursor >= end)
        {
            return false;
        }
        *value = *(*cursor)++;
        return true;
    }
    if (opcode == 0x0B)
    {
        if ((size_t)(end - *cursor) < 2)
        {
            return false;
        }
        const uint8_t *ptr = *cursor;
        *value = (uint16_t)(ptr[0] | (ptr[1] << 8));
        *cursor += 2;
        return true;
    }

    return false;
}

static bool acpi_extract_s5(const uint8_t *aml, size_t length, uint16_t *slp_typa, uint16_t *slp_typb)
{
    if (!aml || length < 4)
    {
        return false;
    }

    const uint8_t *end = aml + length;

    for (size_t i = 0; i + 4 <= length; ++i)
    {
        if (memcmp(aml + i, "_S5_", 4) != 0)
        {
            continue;
        }

        bool has_nameop = false;
        if (i >= 1 && aml[i - 1] == 0x08)
        {
            has_nameop = true;
        }
        else if (i >= 2 && aml[i - 2] == 0x08 &&
                 (aml[i - 1] == '\\' || aml[i - 1] == '^'))
        {
            has_nameop = true;
        }
        if (!has_nameop)
        {
            continue;
        }

        const uint8_t *cursor = aml + i + 4;
        if (cursor >= end)
        {
            break;
        }
        if (*cursor != 0x12 && *cursor != 0x13)
        {
            continue;
        }
        ++cursor;

        uint32_t pkg_length = acpi_read_pkg_length(&cursor, end);
        if (pkg_length == 0)
        {
            continue;
        }
        const uint8_t *pkg_end = cursor + pkg_length;
        if (pkg_end < cursor || pkg_end > end)
        {
            continue;
        }
        if (cursor >= pkg_end)
        {
            continue;
        }

        uint8_t element_count = *cursor++;
        if (element_count < 2)
        {
            continue;
        }

        uint16_t typa = 0;
        uint16_t typb = 0;
        if (!acpi_read_integer(&cursor, pkg_end, &typa))
        {
            continue;
        }
        if (!acpi_read_integer(&cursor, pkg_end, &typb))
        {
            continue;
        }

        if (slp_typa)
        {
            *slp_typa = (uint16_t)(typa & 0x7);
        }
        if (slp_typb)
        {
            *slp_typb = (uint16_t)(typb & 0x7);
        }
        return true;
    }

    return false;
}

static uint16_t acpi_read_pm(const acpi_pm_register_t *reg)
{
    if (!reg || reg->address == 0)
    {
        return 0;
    }
    if (reg->is_io)
    {
        return inw((uint16_t)reg->address);
    }
    volatile uint16_t *ptr = (volatile uint16_t *)(uintptr_t)reg->address;
    return *ptr;
}

static void acpi_write_pm(const acpi_pm_register_t *reg, uint16_t value)
{
    if (!reg || reg->address == 0)
    {
        return;
    }
    if (reg->is_io)
    {
        outw((uint16_t)reg->address, value);
    }
    else
    {
        volatile uint16_t *ptr = (volatile uint16_t *)(uintptr_t)reg->address;
        *ptr = value;
    }
}

static bool acpi_sci_enabled(void)
{
    if (!g_acpi_state.pm1a.address)
    {
        return false;
    }
    uint16_t value = acpi_read_pm(&g_acpi_state.pm1a);
    return (value & 1u) != 0;
}

static void acpi_enable_if_needed(const acpi_fadt_t *fadt)
{
    if (!fadt || !g_acpi_state.pm1a.address)
    {
        return;
    }
    if (boot_info.version >= BOOTINFO_VERSION)
    {
        /* UEFI firmware already exposes ACPI in system mode, do not poke SMI. */
        return;
    }
    if (acpi_sci_enabled())
    {
        return;
    }
    if (!fadt->smi_cmd || !fadt->acpi_enable)
    {
        return;
    }

    outb((uint16_t)fadt->smi_cmd, fadt->acpi_enable);
    for (uint32_t i = 0; i < 100000; ++i)
    {
        if (acpi_sci_enabled())
        {
            break;
        }
    }
}

bool acpi_init(void)
{
    if (g_acpi_state.initialized)
    {
        acpi_log("init already run");
        return g_acpi_state.ready;
    }
    g_acpi_state.initialized = true;
    acpi_log("init start");

    acpi_rsdp_v2_t *rsdp = acpi_find_rsdp();
    if (!rsdp)
    {
        acpi_log("RSDP not found");
        return false;
    }
    acpi_log("RSDP located");

    acpi_sdt_header_t *xsdt = NULL;
    if (rsdp->first.revision >= 2 && rsdp->xsdt_address)
    {
        xsdt = acpi_map_sdt(rsdp->xsdt_address, "XSDT");
        if (xsdt)
        {
            acpi_log("XSDT mapped");
            g_acpi_xsdt = xsdt;
        }
    }
    acpi_sdt_header_t *rsdt = acpi_map_sdt(rsdp->first.rsdt_address, "RSDT");
    if (rsdt)
    {
        acpi_log("RSDT mapped");
        g_acpi_rsdt = rsdt;
    }

    acpi_sdt_header_t *fadt_header = NULL;
    if (xsdt)
    {
        fadt_header = acpi_find_table(xsdt, true, "FACP");
    }
    if (!fadt_header && rsdt)
    {
        fadt_header = acpi_find_table(rsdt, false, "FACP");
    }
    if (!fadt_header)
    {
        acpi_log("FADT not found");
        return false;
    }
    acpi_log("FADT located");

    acpi_fadt_t *fadt = (acpi_fadt_t *)fadt_header;
    if (fadt->pm1_control_length < 2)
    {
        acpi_log("FADT control length invalid");
        return false;
    }

    const acpi_gas_t *gas_pm1a = NULL;
    const acpi_gas_t *gas_pm1b = NULL;

    if (fadt->header.length >= (uint32_t)(offsetof(acpi_fadt_t, x_pm1a_control_block) + sizeof(fadt->x_pm1a_control_block)))
    {
        gas_pm1a = &fadt->x_pm1a_control_block;
    }
    if (fadt->header.length >= (uint32_t)(offsetof(acpi_fadt_t, x_pm1b_control_block) + sizeof(fadt->x_pm1b_control_block)))
    {
        gas_pm1b = &fadt->x_pm1b_control_block;
    }

    acpi_assign_pm_register(&g_acpi_state.pm1a, fadt->pm1a_control_block, gas_pm1a);
    acpi_assign_pm_register(&g_acpi_state.pm1b, fadt->pm1b_control_block, gas_pm1b);

    uint64_t dsdt_phys = fadt->dsdt;
    if (fadt->header.length >= (uint32_t)(offsetof(acpi_fadt_t, x_dsdt) + sizeof(fadt->x_dsdt)) &&
        fadt->x_dsdt)
    {
        dsdt_phys = fadt->x_dsdt;
    }
    acpi_sdt_header_t *dsdt = acpi_map_sdt(dsdt_phys, "DSDT");
    if (!dsdt)
    {
        acpi_log("DSDT map failed");
        return false;
    }
    acpi_log("DSDT mapped");
    size_t aml_length = dsdt->length > sizeof(acpi_sdt_header_t) ? dsdt->length - sizeof(acpi_sdt_header_t) : 0;
    const uint8_t *aml = (const uint8_t *)dsdt + sizeof(acpi_sdt_header_t);
    if (!acpi_extract_s5(aml, aml_length, &g_acpi_state.slp_typa, &g_acpi_state.slp_typb))
    {
        acpi_log("Failed to parse _S5");
        return false;
    }
    if (g_acpi_state.slp_typa == 0)
    {
        acpi_log("SLP_TYP A missing");
        return false;
    }
    if (g_acpi_state.slp_typb == 0)
    {
        g_acpi_state.slp_typb = g_acpi_state.slp_typa;
    }

    g_acpi_state.ready = (g_acpi_state.pm1a.address != 0);
    if (!g_acpi_state.ready)
    {
        acpi_log("PM1A address missing");
        return false;
    }

    acpi_enable_if_needed(fadt);
    acpi_log("init complete");
    return true;
}

bool acpi_shutdown(void)
{
    if (!g_acpi_state.ready || g_acpi_state.slp_typa == 0)
    {
        return false;
    }

    const uint16_t SLP_EN = (uint16_t)(1u << 13);
    const uint16_t SLP_TYP_MASK = (uint16_t)(0x7u << 10);

    uint16_t typa = (uint16_t)((g_acpi_state.slp_typa & 0x7u) << 10);
    uint16_t typb = (uint16_t)((g_acpi_state.slp_typb & 0x7u) << 10);

    uint16_t value_a = acpi_read_pm(&g_acpi_state.pm1a);
    value_a &= (uint16_t)~SLP_TYP_MASK;
    value_a |= (uint16_t)(typa | SLP_EN);
    acpi_write_pm(&g_acpi_state.pm1a, value_a);

    if (g_acpi_state.pm1b.address)
    {
        uint16_t value_b = acpi_read_pm(&g_acpi_state.pm1b);
        value_b &= (uint16_t)~SLP_TYP_MASK;
        value_b |= (uint16_t)(typb | SLP_EN);
        acpi_write_pm(&g_acpi_state.pm1b, value_b);
    }

    return true;
}

const void *acpi_find_table_cached(const char *signature, size_t *length_out)
{
    if (!signature)
    {
        return NULL;
    }

    acpi_sdt_header_t *table = NULL;
    if (g_acpi_xsdt)
    {
        table = acpi_find_table(g_acpi_xsdt, true, signature);
    }
    if (!table && g_acpi_rsdt)
    {
        table = acpi_find_table(g_acpi_rsdt, false, signature);
    }
    if (table && length_out)
    {
        *length_out = table->length;
    }
    return table;
}
