#include "console.h"
#include "serial.h"
#include "keyboard.h"
#include "vfs.h"
#include "interrupts.h"
#include "timer.h"
#include "hwinfo.h"
#include "acpi.h"
#include "heap.h"
#include "paging.h"
#include "rtl8139.h"
#include "shell.h"
#include "net/interface.h"
#include "net/tcp.h"
#include "net/dns.h"
#include "net/ntp.h"
#include "idt.h"
#include "process.h"
#include "block.h"
#include "devfs.h"
#include "ata.h"
#include "ahci.h"
#include "logger.h"
#include "user_atk_host.h"
#include "user_memory.h"
#include "libc.h"
#include "procfs.h"
#include "startup.h"
#include "timekeeping.h"

typedef struct
{
    const char *device_name;
    const char *mount_path;
} fstab_entry_t;

static vfs_node_t *ensure_directory_path(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return NULL;
    }
    if (path[0] != '/')
    {
        return NULL;
    }
    if (path[1] == '\0')
    {
        return vfs_root();
    }

    size_t path_len = strlen(path);
    if (path_len >= 256)
    {
        return NULL;
    }

    char partial[256];
    size_t partial_len = 1;
    partial[0] = '/';
    partial[1] = '\0';
    vfs_node_t *last_dir = vfs_root();

    const char *cursor = path;
    while (*cursor == '/')
    {
        cursor++;
    }

    while (*cursor)
    {
        const char *start = cursor;
        while (*cursor && *cursor != '/')
        {
            cursor++;
        }
        size_t comp_len = (size_t)(cursor - start);
        if (comp_len == 0)
        {
            while (*cursor == '/')
            {
                cursor++;
            }
            continue;
        }

        if (partial_len > 1)
        {
            partial[partial_len++] = '/';
        }
        if (partial_len + comp_len >= sizeof(partial))
        {
            return NULL;
        }
        memcpy(partial + partial_len, start, comp_len);
        partial_len += comp_len;
        partial[partial_len] = '\0';

        vfs_node_t *dir = vfs_resolve(vfs_root(), partial);
        if (!dir)
        {
            dir = vfs_mkdir(vfs_root(), partial);
        }
        if (!dir)
        {
            return NULL;
        }
        last_dir = dir;

        while (*cursor == '/')
        {
            cursor++;
        }
    }

    return last_dir;
}

static void ensure_system_layout(void)
{
    if (!ensure_directory_path("/root"))
    {
        serial_write_string("[alix] warn: unable to ensure /root\r\n");
    }
    if (!ensure_directory_path("/root/etc"))
    {
        serial_write_string("[alix] warn: unable to ensure /root/etc\r\n");
    }
    if (!ensure_directory_path("/root/etc/timezone"))
    {
        serial_write_string("[alix] warn: unable to ensure /root/etc/timezone\r\n");
    }
    if (!ensure_directory_path("/root/etc/ntp"))
    {
        serial_write_string("[alix] warn: unable to ensure /root/etc/ntp\r\n");
    }
    if (!vfs_symlink(vfs_root(), "/root/etc", "/etc"))
    {
        serial_write_string("[alix] warn: unable to ensure /etc symlink\r\n");
    }
    vfs_node_t *ntp_server = vfs_open_file(vfs_root(), "/etc/ntp/server", false, false);
    if (!ntp_server)
    {
        ntp_server = vfs_open_file(vfs_root(), "/etc/ntp/server", true, true);
        if (ntp_server)
        {
            static const char default_ntp_server[] = "pool.ntp.org\n";
            if (!vfs_append(ntp_server, default_ntp_server, sizeof(default_ntp_server) - 1))
            {
                serial_write_string("[alix] warn: unable to write default ntp server\r\n");
            }
        }
        else
        {
            serial_write_string("[alix] warn: unable to create default ntp server file\r\n");
        }
    }
}

static void mount_default_fstab(void)
{
    static const fstab_entry_t g_default_fstab[] = {
        { "ahci1", "/root" },
    };

    const size_t entry_count = sizeof(g_default_fstab) / sizeof(g_default_fstab[0]);

    (void)ensure_directory_path("/root");

    for (size_t i = 0; i < entry_count; ++i)
    {
        const fstab_entry_t *entry = &g_default_fstab[i];
        vfs_node_t *mount_point = ensure_directory_path(entry->mount_path);
        if (!mount_point)
        {
            serial_write_string("[alix] fstab: failed to prepare mount point ");
            serial_write_string(entry->mount_path);
            serial_write_string("\r\n");
            continue;
        }
        if (vfs_is_mount_point(mount_point))
        {
            continue;
        }

        block_device_t *device = block_find(entry->device_name);
        if (!device)
        {
            serial_write_string("[alix] fstab: device ");
            serial_write_string(entry->device_name);
            serial_write_string(" not found\r\n");
            continue;
        }

        if (!vfs_mount_device(device, mount_point))
        {
            serial_write_string("[alix] fstab: mount failed for ");
            serial_write_string(entry->device_name);
            serial_write_string(" -> ");
            serial_write_string(entry->mount_path);
            serial_write_string(", attempting format\r\n");
            if (vfs_format(device))
            {
                if (!vfs_mount_device(device, mount_point))
                {
                    serial_write_string("[alix] fstab: mount still failing after format\r\n");
                }
            }
            else
            {
                serial_write_string("[alix] fstab: format failed\r\n");
            }
        }
        else
        {
            ensure_system_layout();
            if (!timekeeping_ensure_timezone_config())
            {
                serial_write_string("[alix] warn: timezone config missing and default creation failed\r\n");
            }
            else
            {
                if (!timekeeping_reload_timezone())
                {
                    serial_write_string("[alix] warn: failed to reload timezone config\r\n");
                }
            }
        }
    }
}

static void shell_process_entry(void *arg)
{
    (void)arg;
    shell_main();
    process_exit(0);
}

static void fstab_mount_process_entry(void *arg)
{
    (void)arg;
    ahci_set_interrupt_mode(false);
    mount_default_fstab();
    ahci_set_interrupt_mode(true);
    process_exit(0);
}

void kernel_main(void)
{
    serial_init();
    serial_write_string("[alix] kernel_main start\n");
    console_init();
    console_clear();

    heap_init();
    user_memory_init();
    paging_init();
    serial_write_string("[alix] after paging_init\n");
    process_system_init();
    serial_write_string("[alix] after process_system_init\n");
    user_atk_init();
    block_init();
    ahci_init();
    serial_write_string("[alix] after block_init\n");

    hwinfo_print_boot_summary();
    serial_write_string("[alix] after hwinfo\n");
    acpi_init();
    serial_write_string("[alix] after acpi_init\n");
    vfs_init();
    serial_write_string("[alix] after vfs_init\n");
    ensure_system_layout();
    startup_init();
    procfs_init();
    serial_write_string("[alix] after procfs_init\n");
    logger_init();
    devfs_init();
    serial_write_string("[alix] after devfs_init\n");
    interrupts_init();
    interrupts_enable_irq(1);
    serial_write_string("[alix] after interrupts_init\n");
    timer_init(100);
    timekeeping_init();
    keyboard_init();
    serial_write_string("[alix] after keyboard_init\n");
    ata_init();
    devfs_register_block_devices();
    serial_write_string("[alix] after storage init\n");

    net_if_init();
    net_dns_init();
    net_ntp_init();
    net_tcp_init();
    serial_write_string("[alix] after net init\n");

    rtl8139_init();
    interrupts_enable();
    serial_write_string("[alix] after rtl8139_init\n");

    process_t *fstab_process = process_create_kernel("fstab", fstab_mount_process_entry, NULL, 0, -1);
    if (!fstab_process)
    {
        serial_write_string("Failed to create fstab process\r\n");
    }

    process_t *shell_process = process_create_kernel("shell", shell_process_entry, NULL, 0, -1);
    if (!shell_process)
    {
        serial_write_string("Failed to create shell process\r\n");
        for (;;)
        {
            __asm__ volatile ("hlt");
        }
    }

    process_t *user_demo = process_create_user_dummy("user_demo", -1);
    if (!user_demo)
    {
        serial_write_string("Failed to create demo user process\r\n");
    }

    if (!startup_schedule())
    {
        serial_write_string("Failed to start startup scripts\r\n");
    }

    serial_write_string("[alix] starting scheduler\n");
    process_start_scheduler();

    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}
