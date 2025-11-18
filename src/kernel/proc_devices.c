#include "proc_devices.h"

#include "hwinfo.h"
#include "libc.h"
#include "pci.h"
#include "procfs.h"
#include "serial.h"
#include "smp.h"
#include "vfs.h"

#define PROC_DEVICES_CPU_PATH    "devices/cpu/info"
#define PROC_DEVICES_MEMORY_PATH "devices/memory/info"
#define PROC_DEVICES_BLOCK_PATH  "devices/block/info"
#define PROC_DEVICES_NET_PATH    "devices/net/info"
#define PROC_DEVICES_PCI_PATH    "devices/pci/info"

static bool g_proc_devices_ready = false;

static ssize_t proc_devices_cpu_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);
static ssize_t proc_devices_memory_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);
static ssize_t proc_devices_block_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);
static ssize_t proc_devices_net_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);
static ssize_t proc_devices_pci_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);

static ssize_t copy_out(const char *data, size_t len, size_t offset, void *buffer, size_t count)
{
    if (!data || !buffer)
    {
        return -1;
    }
    if (offset >= len || count == 0)
    {
        return 0;
    }
    size_t available = len - offset;
    if (count > available)
    {
        count = available;
    }
    memcpy(buffer, data + offset, count);
    return (ssize_t)count;
}

static void append_text(char *buffer, size_t *index, size_t capacity, const char *text)
{
    if (!buffer || !index || !text || capacity == 0)
    {
        return;
    }
    while (*text && *index + 1 < capacity)
    {
        buffer[*index] = *text++;
        (*index)++;
    }
    if (*index < capacity)
    {
        buffer[*index] = '\0';
    }
}

static void append_char(char *buffer, size_t *index, size_t capacity, char ch)
{
    if (!buffer || !index || *index + 1 >= capacity)
    {
        return;
    }
    buffer[*index] = ch;
    (*index)++;
    buffer[*index] = '\0';
}

static void append_u64(char *buffer, size_t *index, size_t capacity, uint64_t value)
{
    if (!buffer || !index || capacity == 0)
    {
        return;
    }
    char tmp[32];
    size_t pos = 0;
    do
    {
        tmp[pos++] = (char)('0' + (value % 10ULL));
        value /= 10ULL;
    } while (value != 0 && pos < sizeof(tmp));

    while (pos > 0 && *index + 1 < capacity)
    {
        buffer[*index] = tmp[--pos];
        (*index)++;
    }
    if (*index >= capacity)
    {
        *index = capacity - 1;
    }
    buffer[*index] = '\0';
}

static void append_u32(char *buffer, size_t *index, size_t capacity, uint32_t value)
{
    append_u64(buffer, index, capacity, (uint64_t)value);
}

static void append_hex8(char *buffer, size_t *index, size_t capacity, uint8_t value)
{
    const char hex[] = "0123456789ABCDEF";
    if (!buffer || !index || *index + 2 >= capacity)
    {
        return;
    }
    buffer[*index] = hex[(value >> 4) & 0xF];
    buffer[*index + 1] = hex[value & 0xF];
    *index += 2;
    buffer[*index] = '\0';
}

static void append_line_kv(char *buffer, size_t *index, size_t capacity, const char *key, const char *value)
{
    if (!key || !value)
    {
        return;
    }
    append_text(buffer, index, capacity, key);
    append_text(buffer, index, capacity, ": ");
    append_text(buffer, index, capacity, value);
    append_char(buffer, index, capacity, '\n');
}

static ssize_t proc_devices_cpu_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    hwinfo_cpu_info_t cpu;
    if (!hwinfo_get_cpu_info(&cpu))
    {
        return -1;
    }

    char out[256];
    size_t idx = 0;

    const char *model = (cpu.brand[0] != '\0') ? cpu.brand : cpu.vendor;
    append_line_kv(out, &idx, sizeof(out), "model", model);
    append_line_kv(out, &idx, sizeof(out), "vendor", cpu.vendor);

    append_text(out, &idx, sizeof(out), "cores: ");
    append_u32(out, &idx, sizeof(out), smp_cpu_count());
    append_char(out, &idx, sizeof(out), '\n');

    append_text(out, &idx, sizeof(out), "base_mhz: ");
    append_u32(out, &idx, sizeof(out), cpu.base_mhz);
    append_char(out, &idx, sizeof(out), '\n');

    append_text(out, &idx, sizeof(out), "max_mhz: ");
    append_u32(out, &idx, sizeof(out), cpu.max_mhz);
    append_char(out, &idx, sizeof(out), '\n');

    append_text(out, &idx, sizeof(out), "bus_mhz: ");
    append_u32(out, &idx, sizeof(out), cpu.bus_mhz);
    append_char(out, &idx, sizeof(out), '\n');

    return copy_out(out, idx, offset, buffer, count);
}

static ssize_t proc_devices_memory_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    hwinfo_memory_info_t mem;
    if (!hwinfo_get_memory_info(&mem))
    {
        return -1;
    }

    uint64_t usable_mib = mem.usable_bytes / (1024ULL * 1024ULL);
    uint64_t total_mib = mem.total_bytes / (1024ULL * 1024ULL);

    char out[256];
    size_t idx = 0;

    append_text(out, &idx, sizeof(out), "usable_bytes: ");
    append_u64(out, &idx, sizeof(out), mem.usable_bytes);
    append_char(out, &idx, sizeof(out), '\n');

    append_text(out, &idx, sizeof(out), "total_bytes: ");
    append_u64(out, &idx, sizeof(out), mem.total_bytes);
    append_char(out, &idx, sizeof(out), '\n');

    append_text(out, &idx, sizeof(out), "usable_mib: ");
    append_u64(out, &idx, sizeof(out), usable_mib);
    append_char(out, &idx, sizeof(out), '\n');

    append_text(out, &idx, sizeof(out), "total_mib: ");
    append_u64(out, &idx, sizeof(out), total_mib);
    append_char(out, &idx, sizeof(out), '\n');

    append_text(out, &idx, sizeof(out), "e820_entries: ");
    append_u32(out, &idx, sizeof(out), mem.e820_entries);
    append_char(out, &idx, sizeof(out), '\n');

    return copy_out(out, idx, offset, buffer, count);
}

static ssize_t proc_devices_block_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;

    char out[1024];
    size_t idx = 0;
    bool any = false;

    for (block_device_t *dev = block_first(); dev; dev = block_next(dev))
    {
        any = true;
        uint64_t size_bytes = (uint64_t)dev->sector_size * dev->sector_count;
        uint64_t size_mib = size_bytes / (1024ULL * 1024ULL);

        append_text(out, &idx, sizeof(out), "name=");
        append_text(out, &idx, sizeof(out), dev->name);
        append_text(out, &idx, sizeof(out), " size_bytes=");
        append_u64(out, &idx, sizeof(out), size_bytes);
        append_text(out, &idx, sizeof(out), " size_mib=");
        append_u64(out, &idx, sizeof(out), size_mib);
        append_text(out, &idx, sizeof(out), " sector_size=");
        append_u32(out, &idx, sizeof(out), dev->sector_size);
        append_text(out, &idx, sizeof(out), " sector_count=");
        append_u64(out, &idx, sizeof(out), dev->sector_count);
        append_char(out, &idx, sizeof(out), '\n');
        if (idx >= sizeof(out) - 64)
        {
            break;
        }
    }

    if (!any)
    {
        append_text(out, &idx, sizeof(out), "(none)\n");
    }

    return copy_out(out, idx, offset, buffer, count);
}

static void format_mac_colon(const uint8_t mac[6], char *out, size_t len)
{
    if (!out || len == 0)
    {
        return;
    }
    static const char hex[] = "0123456789ABCDEF";
    size_t pos = 0;
    for (int i = 0; i < 6 && pos + 2 < len; ++i)
    {
        out[pos++] = hex[(mac[i] >> 4) & 0xF];
        out[pos++] = hex[mac[i] & 0xF];
        if (i != 5 && pos + 1 < len)
        {
            out[pos++] = ':';
        }
    }
    if (pos >= len)
    {
        pos = len - 1;
    }
    out[pos] = '\0';
}

static ssize_t proc_devices_net_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;

    net_interface_stats_t stats[NET_MAX_INTERFACES];
    size_t count_if = net_if_snapshot(stats, NET_MAX_INTERFACES);

    char out[1536];
    size_t idx = 0;

    if (count_if == 0)
    {
        append_text(out, &idx, sizeof(out), "(none)\n");
        return copy_out(out, idx, offset, buffer, count);
    }

    for (size_t i = 0; i < count_if && idx + 64 < sizeof(out); ++i)
    {
        net_interface_stats_t *entry = &stats[i];
        char mac[18];
        char ip[16];
        format_mac_colon(entry->mac, mac, sizeof(mac));
        net_format_ipv4(entry->ipv4_addr, ip);

        append_text(out, &idx, sizeof(out), "name=");
        append_text(out, &idx, sizeof(out), entry->name);
        append_text(out, &idx, sizeof(out), " present=");
        append_text(out, &idx, sizeof(out), entry->present ? "1" : "0");
        append_text(out, &idx, sizeof(out), " link_up=");
        append_text(out, &idx, sizeof(out), entry->link_up ? "1" : "0");
        append_text(out, &idx, sizeof(out), " mac=");
        append_text(out, &idx, sizeof(out), mac);
        append_text(out, &idx, sizeof(out), " ipv4=");
        append_text(out, &idx, sizeof(out), ip);
        append_text(out, &idx, sizeof(out), " rx_bytes=");
        append_u64(out, &idx, sizeof(out), entry->rx_bytes);
        append_text(out, &idx, sizeof(out), " tx_bytes=");
        append_u64(out, &idx, sizeof(out), entry->tx_bytes);
        append_text(out, &idx, sizeof(out), " rx_packets=");
        append_u64(out, &idx, sizeof(out), entry->rx_packets);
        append_text(out, &idx, sizeof(out), " tx_packets=");
        append_u64(out, &idx, sizeof(out), entry->tx_packets);
        append_char(out, &idx, sizeof(out), '\n');
    }

    return copy_out(out, idx, offset, buffer, count);
}

static ssize_t proc_devices_pci_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;

    char out[2048];
    size_t idx = 0;
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
                any = true;
                uint16_t device_id = pci_config_read16(dev, 0x02);
                uint8_t class_code = pci_config_read8(dev, 0x0B);
                uint8_t subclass = pci_config_read8(dev, 0x0A);
                uint8_t prog_if = pci_config_read8(dev, 0x09);
                const char *vendor_name = pci_vendor_name(vendor);

                append_text(out, &idx, sizeof(out), "bus=");
                append_u64(out, &idx, sizeof(out), bus);
                append_text(out, &idx, sizeof(out), " device=");
                append_u64(out, &idx, sizeof(out), device);
                append_text(out, &idx, sizeof(out), " function=");
                append_u64(out, &idx, sizeof(out), function);
                append_text(out, &idx, sizeof(out), " vendor=0x");
                append_hex8(out, &idx, sizeof(out), (uint8_t)(vendor >> 8));
                append_hex8(out, &idx, sizeof(out), (uint8_t)(vendor & 0xFF));
                append_text(out, &idx, sizeof(out), " device_id=0x");
                append_hex8(out, &idx, sizeof(out), (uint8_t)(device_id >> 8));
                append_hex8(out, &idx, sizeof(out), (uint8_t)(device_id & 0xFF));
                append_text(out, &idx, sizeof(out), " class=0x");
                append_hex8(out, &idx, sizeof(out), class_code);
                append_text(out, &idx, sizeof(out), " subclass=0x");
                append_hex8(out, &idx, sizeof(out), subclass);
                append_text(out, &idx, sizeof(out), " prog_if=0x");
                append_hex8(out, &idx, sizeof(out), prog_if);
                if (vendor_name)
                {
                    append_text(out, &idx, sizeof(out), " vendor_name=");
                    append_text(out, &idx, sizeof(out), vendor_name);
                }
                append_char(out, &idx, sizeof(out), '\n');

                if (idx > sizeof(out) - 96)
                {
                    break;
                }
            }
            if (idx > sizeof(out) - 96)
            {
                break;
            }
        }
        if (idx > sizeof(out) - 96)
        {
            break;
        }
    }

    if (!any)
    {
        append_text(out, &idx, sizeof(out), "(none)\n");
    }

    return copy_out(out, idx, offset, buffer, count);
}

static void ensure_directory(const char *path)
{
    if (!procfs_mkdir(path))
    {
        serial_printf("%s", "[proc_devices] failed to ensure /proc/");
        serial_printf("%s", path ? path : "<null>");
        serial_printf("%s", "\r\n");
    }
}

static void install_file(const char *path, vfs_read_cb_t read_cb)
{
    if (!procfs_create_file_at(path, read_cb, NULL, NULL))
    {
        serial_printf("%s", "[proc_devices] failed to create /proc/");
        serial_printf("%s", path ? path : "<null>");
        serial_printf("%s", "\r\n");
    }
}

void proc_devices_init(void)
{
    serial_printf("%s", "[proc_devices] init\r\n");
    if (g_proc_devices_ready)
    {
        return;
    }

    ensure_directory("devices");
    ensure_directory("devices/cpu");
    ensure_directory("devices/memory");
    ensure_directory("devices/block");
    ensure_directory("devices/net");
    ensure_directory("devices/pci");

    install_file(PROC_DEVICES_CPU_PATH, proc_devices_cpu_read);
    install_file(PROC_DEVICES_MEMORY_PATH, proc_devices_memory_read);
    install_file(PROC_DEVICES_BLOCK_PATH, proc_devices_block_read);
    install_file(PROC_DEVICES_NET_PATH, proc_devices_net_read);
    install_file(PROC_DEVICES_PCI_PATH, proc_devices_pci_read);

    g_proc_devices_ready = true;
    serial_printf("%s", "[proc_devices] ready\r\n");
}

void proc_devices_refresh_all(void)
{
    /* Entries are generated on read; nothing to refresh eagerly. */
}

void proc_devices_on_block_registered(block_device_t *device)
{
    (void)device;
    (void)g_proc_devices_ready;
}

void proc_devices_on_net_registered(net_interface_t *iface)
{
    (void)iface;
    (void)g_proc_devices_ready;
}
