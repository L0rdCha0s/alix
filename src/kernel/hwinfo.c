#include "hwinfo.h"
#include "serial.h"
#include "console.h"
#include "pci.h"
#include "libc.h"
#include "types.h"
#include "bootinfo.h"
#include <stddef.h>

#define HWINFO_E820_MAX    BOOTINFO_MAX_E820_ENTRIES

typedef struct
{
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t attr;
} __attribute__((packed)) e820_entry_t;

static e820_entry_t g_e820[HWINFO_E820_MAX];
static uint32_t g_e820_count = 0;
static hwinfo_cpu_info_t g_cpu_info;
static bool g_hwinfo_ready = false;

static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    uint32_t a = 0, b = 0, c = 0, d = 0;
    __asm__ volatile ("cpuid"
                      : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                      : "a"(leaf), "c"(subleaf));
    if (eax) { *eax = a; }
    if (ebx) { *ebx = b; }
    if (ecx) { *ecx = c; }
    if (edx) { *edx = d; }
}

static void log_dual(const char *text)
{
    if (!text)
    {
        return;
    }
    console_write(text);
    serial_printf("%s", text);
}

static void log_dual_line(const char *text)
{
    log_dual(text);
    console_putc('\n');
    serial_printf("%s", "\r\n");
}

static void append_text(char *buffer, size_t *index, size_t capacity, const char *text)
{
    if (!buffer || !index || capacity == 0 || !text)
    {
        return;
    }
    while (*text && *index + 1 < capacity)
    {
        buffer[*index] = *text++;
        (*index)++;
    }
    buffer[*index] = '\0';
}

static void append_char(char *buffer, size_t *index, size_t capacity, char c)
{
    if (!buffer || !index || capacity == 0)
    {
        return;
    }
    if (*index + 1 < capacity)
    {
        buffer[*index] = c;
        (*index)++;
        buffer[*index] = '\0';
    }
}

static void append_decimal(char *buffer, size_t *index, size_t capacity, uint64_t value)
{
    if (!buffer || !index || capacity == 0)
    {
        return;
    }
    char tmp[32];
    size_t pos = 0;
    if (value == 0)
    {
        tmp[pos++] = '0';
    }
    else
    {
        while (value > 0 && pos < sizeof(tmp))
        {
            tmp[pos++] = (char)('0' + (value % 10));
            value /= 10;
        }
    }
    while (pos > 0 && *index + 1 < capacity)
    {
        buffer[*index] = tmp[--pos];
        (*index)++;
    }
    buffer[*index] = '\0';
}

static void append_hex(char *buffer, size_t *index, size_t capacity, uint64_t value, uint8_t digits)
{
    if (!buffer || !index || capacity == 0)
    {
        return;
    }
    static const char hex[] = "0123456789ABCDEF";
    for (int i = digits - 1; i >= 0; --i)
    {
        if (*index + 1 >= capacity)
        {
            break;
        }
        uint64_t shift = (uint64_t)i * 4;
        uint8_t nibble = (uint8_t)((value >> shift) & 0xF);
        buffer[*index] = hex[nibble];
        (*index)++;
    }
    buffer[*index] = '\0';
}

static void load_e820(void)
{
    if (boot_info.magic != BOOTINFO_MAGIC)
    {
        g_e820_count = 0;
        return;
    }
    uint32_t count = boot_info.e820_entry_count;
    if (count > HWINFO_E820_MAX)
    {
        count = HWINFO_E820_MAX;
    }
    for (uint32_t i = 0; i < count; ++i)
    {
        g_e820[i].base = boot_info.e820[i].base;
        g_e820[i].length = boot_info.e820[i].length;
        g_e820[i].type = boot_info.e820[i].type;
        g_e820[i].attr = boot_info.e820[i].attr;
    }
    g_e820_count = count;
}

static void query_cpu(void)
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    uint32_t max_basic = eax;
    ((uint32_t *)g_cpu_info.vendor)[0] = ebx;
    ((uint32_t *)g_cpu_info.vendor)[1] = edx;
    ((uint32_t *)g_cpu_info.vendor)[2] = ecx;
    g_cpu_info.vendor[12] = '\0';

    for (size_t i = 0; i < sizeof(g_cpu_info.brand); ++i)
    {
        g_cpu_info.brand[i] = '\0';
    }

    cpuid(0x80000000U, 0, &eax, NULL, NULL, NULL);
    uint32_t max_extended = eax;
    if (max_extended >= 0x80000004U)
    {
        uint32_t *brand_words = (uint32_t *)g_cpu_info.brand;
        for (uint32_t leaf = 0; leaf < 3; ++leaf)
        {
            cpuid(0x80000002U + leaf, 0,
                  &brand_words[leaf * 4 + 0],
                  &brand_words[leaf * 4 + 1],
                  &brand_words[leaf * 4 + 2],
                  &brand_words[leaf * 4 + 3]);
        }
        g_cpu_info.brand[48 - 1] = '\0';
    }

    if (max_basic >= 0x16U)
    {
        cpuid(0x16U, 0, &eax, &ebx, &ecx, NULL);
        g_cpu_info.base_mhz = eax;
        g_cpu_info.max_mhz = ebx;
        g_cpu_info.bus_mhz = ecx;
    }
    else
    {
        g_cpu_info.base_mhz = 0;
        g_cpu_info.max_mhz = 0;
        g_cpu_info.bus_mhz = 0;
    }
}

static void hwinfo_ensure_initialized(void)
{
    if (g_hwinfo_ready)
    {
        return;
    }
    load_e820();
    query_cpu();
    g_hwinfo_ready = true;
}

static uint64_t total_usable_bytes(void)
{
    uint64_t total = 0;
    for (uint32_t i = 0; i < g_e820_count; ++i)
    {
        if (g_e820[i].type == 1)
        {
            total += g_e820[i].length;
        }
    }
    return total;
}

static uint64_t total_physical_bytes(void)
{
    uint64_t total = 0;
    for (uint32_t i = 0; i < g_e820_count; ++i)
    {
        total += g_e820[i].length;
    }
    return total;
}

static void log_memory_summary(void)
{
    if (g_e820_count == 0)
    {
        log_dual_line("  RAM: (no E820 entries)");
        return;
    }

    uint64_t usable = total_usable_bytes();
    uint64_t total = total_physical_bytes();
    uint64_t usable_mib = usable / (1024ULL * 1024ULL);
    uint64_t total_mib = total / (1024ULL * 1024ULL);

    char line[160];
    size_t idx = 0;
    append_text(line, &idx, sizeof(line), "  RAM: ");
    append_decimal(line, &idx, sizeof(line), usable_mib);
    append_text(line, &idx, sizeof(line), " MiB usable");
    if (total_mib > usable_mib)
    {
        append_text(line, &idx, sizeof(line), " / ");
        append_decimal(line, &idx, sizeof(line), total_mib);
        append_text(line, &idx, sizeof(line), " MiB total");
    }
    append_text(line, &idx, sizeof(line), " (E820 entries: ");
    append_decimal(line, &idx, sizeof(line), g_e820_count);
    append_char(line, &idx, sizeof(line), ')');
    log_dual_line(line);

    /* Keep bring-up quiet: omit per-entry E820 dump for now. */
}

static void log_cpu_summary(void)
{
    char line[160];
    size_t idx = 0;

    append_text(line, &idx, sizeof(line), "  CPU: ");
    const char *brand = (g_cpu_info.brand[0] != '\0') ? g_cpu_info.brand : g_cpu_info.vendor;
    append_text(line, &idx, sizeof(line), brand);
    log_dual_line(line);

    idx = 0;
    append_text(line, &idx, sizeof(line), "  CPU Vendor: ");
    append_text(line, &idx, sizeof(line), g_cpu_info.vendor);
    log_dual_line(line);

    if (g_cpu_info.base_mhz != 0)
    {
        idx = 0;
        append_text(line, &idx, sizeof(line), "  CPU Base Frequency: ");
        append_decimal(line, &idx, sizeof(line), g_cpu_info.base_mhz);
        append_text(line, &idx, sizeof(line), " MHz");
        if (g_cpu_info.base_mhz >= 1000)
        {
            append_text(line, &idx, sizeof(line), " (~");
            uint32_t ghz_whole = g_cpu_info.base_mhz / 1000;
            uint32_t ghz_frac = (g_cpu_info.base_mhz % 1000) / 10;
            append_decimal(line, &idx, sizeof(line), ghz_whole);
            append_char(line, &idx, sizeof(line), '.');
            if (ghz_frac < 10)
            {
                append_char(line, &idx, sizeof(line), '0' + (ghz_frac / 1));
            }
            else
            {
                append_decimal(line, &idx, sizeof(line), ghz_frac);
            }
            append_text(line, &idx, sizeof(line), " GHz)");
        }
        log_dual_line(line);
    }
    if (g_cpu_info.max_mhz != 0 && g_cpu_info.max_mhz != g_cpu_info.base_mhz)
    {
        idx = 0;
        append_text(line, &idx, sizeof(line), "  CPU Max Frequency: ");
        append_decimal(line, &idx, sizeof(line), g_cpu_info.max_mhz);
        append_text(line, &idx, sizeof(line), " MHz");
        log_dual_line(line);
    }
    if (g_cpu_info.bus_mhz != 0)
    {
        idx = 0;
        append_text(line, &idx, sizeof(line), "  CPU Bus Frequency: ");
        append_decimal(line, &idx, sizeof(line), g_cpu_info.bus_mhz);
        append_text(line, &idx, sizeof(line), " MHz");
        log_dual_line(line);
    }
}

static void log_pci_devices(void)
{
    log_dual_line("  PCI devices:");
    bool any = false;

    /* Limit enumeration to bus 0 for stability during bring-up */
    for (uint16_t bus = 0; bus < 1; ++bus)
    {
        for (uint8_t device = 0; device < 32; ++device)
        {
            pci_device_t dev = { .bus = (uint8_t)bus, .device = device, .function = 0 };
            uint16_t vendor = pci_config_read16(dev, 0x00);
            if (vendor == 0xFFFF)
            {
                continue;
            }
            uint8_t header = pci_config_read8(dev, 0x0E);
            uint8_t last_function = (header & 0x80U) ? 7 : 0;
            for (uint8_t function = 0; function <= last_function; ++function)
            {
                dev.function = function;
                vendor = pci_config_read16(dev, 0x00);
                if (vendor == 0xFFFF)
                {
                    continue;
                }
                uint16_t device_id = pci_config_read16(dev, 0x02);
                uint8_t class_code = pci_config_read8(dev, 0x0B);
                uint8_t subclass = pci_config_read8(dev, 0x0A);
                uint8_t prog_if = pci_config_read8(dev, 0x09);

                char line[160];
                size_t idx = 0;
                append_text(line, &idx, sizeof(line), "    ");
                append_hex(line, &idx, sizeof(line), bus, 2);
                append_char(line, &idx, sizeof(line), ':');
                append_hex(line, &idx, sizeof(line), device, 2);
                append_char(line, &idx, sizeof(line), '.');
                append_hex(line, &idx, sizeof(line), function, 1);
                append_text(line, &idx, sizeof(line), " vendor ");
                const char *vendor_name = pci_vendor_name(vendor);
                if (vendor_name)
                {
                    append_text(line, &idx, sizeof(line), vendor_name);
                }
                else
                {
                    append_text(line, &idx, sizeof(line), "0x");
                    append_hex(line, &idx, sizeof(line), vendor, 4);
                }
                append_text(line, &idx, sizeof(line), " device 0x");
                append_hex(line, &idx, sizeof(line), device_id, 4);
                append_text(line, &idx, sizeof(line), " class ");
                append_hex(line, &idx, sizeof(line), class_code, 2);
                append_char(line, &idx, sizeof(line), '/');
                append_hex(line, &idx, sizeof(line), subclass, 2);
                append_char(line, &idx, sizeof(line), '/');
                append_hex(line, &idx, sizeof(line), prog_if, 2);
                log_dual_line(line);
                any = true;
            }
        }
    }

    if (!any)
    {
        log_dual_line("    (no PCI devices detected)");
    }
}

void hwinfo_print_boot_summary(void)
{
    hwinfo_ensure_initialized();

    log_dual_line("");
    log_dual_line("Hardware summary:");
    log_cpu_summary();
    log_memory_summary();
    log_pci_devices();
    log_dual_line("");
}

void hwinfo_init(void)
{
    hwinfo_ensure_initialized();
}

bool hwinfo_get_cpu_info(hwinfo_cpu_info_t *out)
{
    hwinfo_ensure_initialized();
    if (!out || !g_hwinfo_ready)
    {
        return false;
    }
    memcpy(out, &g_cpu_info, sizeof(hwinfo_cpu_info_t));
    return true;
}

bool hwinfo_get_memory_info(hwinfo_memory_info_t *out)
{
    hwinfo_ensure_initialized();
    if (!out || !g_hwinfo_ready)
    {
        return false;
    }
    out->usable_bytes = total_usable_bytes();
    out->total_bytes = total_physical_bytes();
    out->e820_entries = g_e820_count;
    return true;
}
