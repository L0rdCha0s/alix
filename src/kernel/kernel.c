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
#include "dl_script.h"
#include "smp.h"
#include "build_features.h"

static void shell_process_entry(void *arg);
static void storage_flush_process_entry(void *arg);

static volatile bool g_fstab_ready =
#if ENABLE_FSTAB_MOUNT
    false;
#else
    true;
#endif
;

typedef struct
{
    const char *device_name;
    const char *mount_path;
} fstab_entry_t;

static block_device_t *fstab_find_device(const char *name)
{
    if (!name)
    {
        return NULL;
    }
    const char *device = name;
    const char prefix[] = "/dev/";
    if (strncmp(name, prefix, sizeof(prefix) - 1) == 0)
    {
        device = name + (sizeof(prefix) - 1);
        if (*device == '\0')
        {
            device = name;
        }
    }
    return block_find(device);
}

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
        if (dir && !vfs_is_dir(dir))
        {
            if (!vfs_remove_file(vfs_root(), partial))
            {
                return NULL;
            }
            dir = NULL;
        }
        if (!dir)
        {
            dir = vfs_mkdir(vfs_root(), partial);
        }
        if (!dir || !vfs_is_dir(dir))
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
        serial_printf("%s", "[alix] warn: unable to ensure /root\r\n");
    }
    if (!ensure_directory_path("/root/etc"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/etc\r\n");
    }
    if (!ensure_directory_path("/root/etc/timezone"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/etc/timezone\r\n");
    }
    if (!ensure_directory_path("/root/etc/ntp"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/etc/ntp\r\n");
    }
    if (!ensure_directory_path("/root/usr"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/usr\r\n");
    }
    if (!ensure_directory_path("/root/usr/bin"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/usr/bin\r\n");
    }
    if (!ensure_directory_path("/root/usr/share"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/usr/share\r\n");
    }
    if (!ensure_directory_path("/root/usr/share/zoneinfo"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/usr/share/zoneinfo\r\n");
    }
    if (!ensure_directory_path("/root/usr/share/zoneinfo/src"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/usr/share/zoneinfo/src\r\n");
    }
    if (!vfs_symlink(vfs_root(), "/root/etc", "/etc"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /etc symlink\r\n");
    }
    if (!vfs_symlink(vfs_root(), "/root/usr", "/usr"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /usr symlink\r\n");
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
                serial_printf("%s", "[alix] warn: unable to write default ntp server\r\n");
            }
        }
        else
        {
            serial_printf("%s", "[alix] warn: unable to create default ntp server file\r\n");
        }
    }

    if (!dl_script_install_default())
    {
        serial_printf("%s", "[alix] warn: unable to install dl.sh\r\n");
    }
}

static void vfs_spin_up(void)
{
    (void)ensure_directory_path("/root");
    (void)ensure_directory_path("/etc");
    (void)ensure_directory_path("/usr");
}

static void mount_default_fstab(void)
{
    static const fstab_entry_t g_default_fstab[] = {
        { "/dev/ahci1", "/root" },
    };

    const size_t entry_count = sizeof(g_default_fstab) / sizeof(g_default_fstab[0]);

    (void)ensure_directory_path("/root");

    for (size_t i = 0; i < entry_count; ++i)
    {
        const fstab_entry_t *entry = &g_default_fstab[i];
        vfs_node_t *mount_point = ensure_directory_path(entry->mount_path);
        if (!mount_point)
        {
            serial_printf("%s", "[alix] fstab: failed to prepare mount point ");
            serial_printf("%s", entry->mount_path);
            serial_printf("%s", "\r\n");
            continue;
        }
        if (vfs_is_mount_point(mount_point))
        {
            continue;
        }

        /*
         * Ensure we mount onto a clean directory tree. When the automatic
         * mounts were disabled we still created files under /root, which
         * now prevents vfs_mount_device from succeeding because the mount
         * point is not empty.
         */
        vfs_clear_directory(mount_point);

        block_device_t *device = fstab_find_device(entry->device_name);
        if (!device)
        {
            serial_printf("%s", "[alix] fstab: device ");
            serial_printf("%s", entry->device_name);
            serial_printf("%s", " not found\r\n");
            continue;
        }

        if (!vfs_mount_device(device, mount_point))
        {
            serial_printf("%s", "[alix] fstab: mount failed for ");
            serial_printf("%s", entry->device_name);
            serial_printf("%s", " -> ");
            serial_printf("%s", entry->mount_path);
            serial_printf("%s", ", attempting format\r\n");
            if (vfs_format(device))
            {
                if (!vfs_mount_device(device, mount_point))
                {
                    serial_printf("%s", "[alix] fstab: mount still failing after format\r\n");
                }
            }
            else
            {
                serial_printf("%s", "[alix] fstab: format failed\r\n");
            }
        }
        else
        {
            ensure_system_layout();
            if (!timekeeping_ensure_timezone_config())
            {
                serial_printf("%s", "[alix] warn: timezone config missing and default creation failed\r\n");
            }
            else
            {
                if (!timekeeping_reload_timezone())
                {
                    serial_printf("%s", "[alix] warn: failed to reload timezone config\r\n");
                }
            }
        }
    }
}

static void fstab_mount_run(void)
{
    ahci_set_interrupt_mode(false);
    mount_default_fstab();
    ahci_set_interrupt_mode(true);
}

static void warmup_run_sequence(void)
{
    serial_printf("%s", "[warmup] sequence start\r\n");
#if ENABLE_FSTAB_MOUNT
    vfs_spin_up();
    fstab_mount_run();
    g_fstab_ready = true;
#else
    g_fstab_ready = true;
    serial_printf("%s", "[alix] fstab mount disabled; skipping\r\n");
#endif

#if ENABLE_STARTUP_SCRIPT
    if (!startup_schedule())
    {
        serial_printf("%s", "Failed to start startup scripts\r\n");
    }
#endif

    serial_printf("%s", "[warmup] creating shell process\r\n");
    process_t *shell_process = process_create_kernel("shell", shell_process_entry, NULL, 0, -1);
    if (!shell_process)
    {
        serial_printf("%s", "Failed to create shell process; halting\r\n");
        for (;;)
        {
            __asm__ volatile ("hlt");
        }
    }
    serial_printf("%s", "[warmup] shell process created\r\n");
    process_stack_watch_process(shell_process, "shell_boot");

#if ENABLE_FLUSHD
    process_t *flush_process = process_create_kernel("flushd", storage_flush_process_entry, NULL, 0, -1);
    if (!flush_process)
    {
        serial_printf("%s", "Failed to create flush daemon\r\n");
    }
    else
    {
        process_stack_watch_process(flush_process, "flushd_boot");
        serial_printf("%s", "[warmup] flush daemon started\r\n");
    }
#else
    serial_printf("%s", "[alix] flushd disabled; skipping\r\n");
#endif
    serial_printf("%s", "[warmup] sequence complete\r\n");
}

static void warmup_process_entry(void *arg)
{
    (void)arg;
    warmup_run_sequence();
    process_exit(0);

}

static void shell_process_entry(void *arg)
{
    (void)arg;
    shell_main();
    process_exit(0);
}

static void storage_flush_process_entry(void *arg)
{
    (void)arg;
    const uint32_t interval_ms = 2000;
    while (!g_fstab_ready)
    {
        process_sleep_ms(100);
    }
    while (1)
    {
        process_sleep_ms(interval_ms);
        if (!vfs_sync_dirty())
        {
            serial_printf("%s", "[flushd] warning: partial sync failure\r\n");
        }
    }
}

void kernel_main(void)
{
    serial_init();
    serial_printf("%s", "[alix] kernel_main start\n");
    console_init();
    console_clear();

    heap_init();
    user_memory_init();
    paging_init();
    serial_printf("%s", "[alix] after paging_init\n");
    hwinfo_print_boot_summary();
    serial_printf("%s", "[alix] after hwinfo\n");
    acpi_init();
    serial_printf("%s", "[alix] after acpi_init\n");
    smp_init();
    serial_printf("%s", "[alix] after smp_init\n");
    process_system_init();
    serial_printf("%s", "[alix] after process_system_init\n");
    user_atk_init();
    block_init();
    ahci_init();
    serial_printf("%s", "[alix] after block_init\n");

    vfs_init();
    serial_printf("%s", "[alix] after vfs_init\n");
#if ENABLE_STARTUP_SCRIPT
    startup_init();
#endif
    procfs_init();
    serial_printf("%s", "[alix] after procfs_init\n");
    logger_init();
    devfs_init();
    serial_printf("%s", "[alix] after devfs_init\n");
    interrupts_init();
    interrupts_enable_irq(1);
    serial_printf("%s", "[alix] after interrupts_init\n");
    timer_init(100);
    timekeeping_init();
    keyboard_init();
    serial_printf("%s", "[alix] after keyboard_init\n");
    ata_init();
    devfs_register_block_devices();
    serial_printf("%s", "[alix] after storage init\n");

    net_if_init();
    net_dns_init();
    net_ntp_init();
    net_tcp_init();
    serial_printf("%s", "[alix] after net init\n");

    rtl8139_init();
    if (!smp_start_secondary_cpus())
    {
        serial_printf("%s", "[alix] warn: smp_start_secondary_cpus failed\r\n");
    }
    interrupts_enable();
    serial_printf("%s", "[alix] after rtl8139_init\n");

    process_t *warmup_process = process_create_kernel("warmup", warmup_process_entry, NULL, 0, -1);
    if (!warmup_process)
    {
        serial_printf("%s", "Failed to create warmup process; running inline\r\n");
        warmup_run_sequence();
    }
    else
    {
        process_stack_watch_process(warmup_process, "warmup_boot");
    }

    serial_start_async_worker();
    serial_printf("%s", "[alix] enabling scheduler\n");
    process_scheduler_set_ready();

    serial_printf("%s", "[alix] starting scheduler\n");
    process_start_scheduler();

    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}
