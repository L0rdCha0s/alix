/*
 * src/kernel/kernel.c
 *
 * Top-level kernel initialisation (entered via `kernel_main`) and a handful of
 * long-lived kernel service threads (shell, tcp timer, storage flush daemon).
 *
 * This is intentionally “wiring” code: it sequences subsystem init and kicks
 * off background processes once the scheduler is available.
 *
 * See:
 * - docs/kernel/boot.md (boot → kernel_entry → kernel_main)
 * - docs/kernel/process.md (scheduler bring-up and kernel processes)
 */

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
#include "ioremap.h"
#include "rtl8139.h"
#include "igb.h"
#include "shell.h"
#include "shell_service.h"
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
#include "pmm.h"
#include "libc.h"
#include "procfs.h"
#include "startup.h"
#include "timekeeping.h"
#include "dl_script.h"
#include "smp.h"
#include "proc_devices.h"
#include "build_features.h"
#include "audio.h"
#include "hda.h"
#include "stdio.h"
#include "serial_format.h"
#include <stdarg.h>
#if ENABLE_USB
#include "usb_hid.h"
#endif

static void shell_process_entry(void *arg);
static void storage_flush_process_entry(void *arg);
static void tcp_timer_process_entry(void *arg);
static void hda_init_process_entry(void *arg);
static uint32_t choose_non_ui_cpu(void);
#if 1
static void printer_a_process_entry(void *arg);
static void printer_b_process_entry(void *arg);
#endif
#if ENABLE_FLUSHD
static void storage_flush_wait(uint32_t interval_ms);
static volatile bool g_flushd_wake_requested = false;
static wait_queue_t g_flushd_wait_queue;
static volatile bool g_flushd_wait_queue_ready = false;
static volatile bool g_flushd_timer_registered = false;
static volatile bool g_flushd_timer_failed = false;
static volatile uint64_t g_flushd_wait_deadline = 0;
static void storage_flush_signal_init(void);
static bool storage_flush_should_wake(void *context);
static void storage_flush_timer_callback(void *context);
static uint64_t storage_flush_ms_to_ticks(uint32_t ms);
static uint32_t g_flushd_log_enable = 0;
static ssize_t flushd_log_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);
static ssize_t flushd_log_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context);
static inline bool flushd_log_enabled(void)
{
    return __atomic_load_n(&g_flushd_log_enable, __ATOMIC_ACQUIRE) != 0;
}

typedef struct flushd_buf_ctx
{
    char *buf;
    size_t len;
    size_t cap;
} flushd_buf_ctx_t;

static void flushd_buf_putc(void *ctx, char c)
{
    flushd_buf_ctx_t *b = (flushd_buf_ctx_t *)ctx;
    if (!b || !b->buf || b->cap == 0)
    {
        return;
    }
    if (b->len + 1 >= b->cap)
    {
        return;
    }
    b->buf[b->len++] = c;
}

static void flushd_logf(const char *fmt, ...)
{
    if (!flushd_log_enabled())
    {
        return;
    }
    char buffer[256];
    flushd_buf_ctx_t buf_ctx = {
        .buf = buffer,
        .len = 0,
        .cap = sizeof(buffer),
    };
    serial_format_ctx_t fmt_ctx = {
        .putc = flushd_buf_putc,
        .validate = NULL,
        .ctx = &buf_ctx,
        .count = 0,
        .error = false,
    };
    va_list ap;
    va_start(ap, fmt);
    serial_format_vprintf(&fmt_ctx, fmt, ap);
    va_end(ap);
    if (buf_ctx.len == 0)
    {
        return;
    }
    if (buf_ctx.len >= buf_ctx.cap)
    {
        buf_ctx.len = buf_ctx.cap - 1;
    }
    buffer[buf_ctx.len] = '\0';
    serial_printf("%s", buffer);
}

static uint32_t choose_non_ui_cpu(void)
{
    uint32_t ui = process_get_ui_cpu();
    uint32_t count = smp_cpu_count();
    if (count < 2)
    {
        return PROCESS_CPU_ANY;
    }

    bool avoid_bsp = (count > 2);
    for (uint32_t idx = 0; idx < count; ++idx)
    {
        if (idx == ui)
        {
            continue;
        }
        const smp_cpu_t *cpu = smp_cpu_by_index(idx);
        if (!cpu || !cpu->present)
        {
            continue;
        }
        if (!__atomic_load_n(&cpu->online, __ATOMIC_ACQUIRE))
        {
            continue;
        }
        if (avoid_bsp && cpu->bsp)
        {
            continue;
        }
        return idx;
    }

    for (uint32_t idx = 0; idx < count; ++idx)
    {
        if (idx == ui)
        {
            continue;
        }
        const smp_cpu_t *cpu = smp_cpu_by_index(idx);
        if (!cpu || !cpu->present)
        {
            continue;
        }
        if (!__atomic_load_n(&cpu->online, __ATOMIC_ACQUIRE))
        {
            continue;
        }
        return idx;
    }

    return PROCESS_CPU_ANY;
}

static ssize_t flushd_log_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    if (!buffer)
    {
        return -1;
    }
    char tmp[3];
    tmp[0] = flushd_log_enabled() ? '1' : '0';
    tmp[1] = '\n';
    tmp[2] = '\0';
    size_t len = 2;
    if (offset >= len)
    {
        return 0;
    }
    size_t to_copy = len - offset;
    if (to_copy > count)
    {
        to_copy = count;
    }
    memcpy(buffer, tmp + offset, to_copy);
    return (ssize_t)to_copy;
}

static ssize_t flushd_log_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    (void)offset;
    if (!buffer || count == 0)
    {
        return -1;
    }
    const char *cbuf = (const char *)buffer;
    size_t idx = 0;
    while (idx < count && (cbuf[idx] == ' ' || cbuf[idx] == '\t'))
    {
        ++idx;
    }
    if (idx >= count)
    {
        return -1;
    }
    int value = -1;
    if (cbuf[idx] == '0')
    {
        value = 0;
    }
    else if (cbuf[idx] == '1')
    {
        value = 1;
    }
    if (value < 0)
    {
        return -1;
    }
    for (size_t tail = idx + 1; tail < count; ++tail)
    {
        char t = cbuf[tail];
        if (t == ' ' || t == '\t' || t == '\r' || t == '\n')
        {
            continue;
        }
        return -1;
    }
    __atomic_store_n(&g_flushd_log_enable, (uint32_t)value, __ATOMIC_RELEASE);
    return (ssize_t)count;
}
#endif

static volatile bool g_fstab_ready =
#if ENABLE_FSTAB_MOUNT
    false;
#else
    true;
#endif
;
static bool g_slash_locked = false;

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

static void lock_slash_root_once(void)
{
    if (g_slash_locked)
    {
        return;
    }
    vfs_node_t *proc_root = procfs_root();
    if (proc_root)
    {
        vfs_set_subtree_mutable(proc_root, true);
    }
    vfs_set_subtree_mutable(vfs_root(), false);
    g_slash_locked = true;
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
    if (!ensure_directory_path("/root/usr/share/fonts"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/usr/share/fonts\r\n");
    }
    if (!ensure_directory_path("/root/usr/share/zoneinfo"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/usr/share/zoneinfo\r\n");
    }
    if (!ensure_directory_path("/root/usr/share/zoneinfo/src"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /root/usr/share/zoneinfo/src\r\n");
    }
    if (!vfs_force_symlink(vfs_root(), "/root/etc", "/etc"))
    {
        serial_printf("%s", "[alix] warn: unable to ensure /etc symlink\r\n");
    }
    if (!vfs_force_symlink(vfs_root(), "/root/usr", "/usr"))
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


    lock_slash_root_once();
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
#if ENABLE_USB
    serial_printf("%s", "[warmup] calling usb_hid_init\r\n");
    process_t *usb_init = process_create_kernel("usb_initd", (thread_entry_t)usb_hid_init, NULL, 0, -1);
    if (!usb_init)
    {
        serial_printf("%s", "[usb] failed to spawn usb_initd\r\n");
    }
    else
    {
        serial_printf("%s", "[warmup] usb_initd spawned\r\n");
        /* Let the USB init thread run immediately so it doesn't starve behind warmup work. */
        process_yield();
    }
#else
    serial_printf("%s", "[warmup] usb disabled; skipping usb_hid_init\r\n");
#endif
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
    uint32_t non_ui_cpu = choose_non_ui_cpu();
    process_set_priority(shell_process, THREAD_PRIORITY_BACKGROUND);
    if (non_ui_cpu != PROCESS_CPU_ANY)
    {
        process_set_affinity(shell_process, non_ui_cpu);
    }

#if ENABLE_FLUSHD
    process_t *flush_process = process_create_kernel("flushd", storage_flush_process_entry, NULL, 0, -1);
    if (!flush_process)
    {
        serial_printf("%s", "Failed to create flush daemon\r\n");
    }
    else
    {
        process_stack_watch_process(flush_process, "flushd_boot");
        if (flushd_log_enabled())
        {
            flushd_logf("%s", "[warmup] flush daemon started\r\n");
        }
        process_set_priority(flush_process, THREAD_PRIORITY_BACKGROUND);
        if (non_ui_cpu != PROCESS_CPU_ANY)
        {
            process_set_affinity(flush_process, non_ui_cpu);
        }
    }
#else
    if (flushd_log_enabled())
    {
        flushd_logf("%s", "[alix] flushd disabled; skipping\r\n");
    }
#endif
    serial_printf("%s", "[warmup] sequence complete\r\n");
}

static void warmup_process_entry(void *arg)
{
    (void)arg;
    warmup_run_sequence();
    process_exit(0);

}

/*
 * Kernel shell entrypoint: runs the interactive shell on a kernel thread.
 * This thread never returns; it exits the process when `shell_main()` returns.
 */
static void shell_process_entry(void *arg)
{
    (void)arg;
    shell_main();
    process_exit(0);
}

/*
 * Periodic TCP maintenance thread.
 *
 * The TCP stack uses timer-driven retransmit/timeouts; this thread provides a
 * simple polling loop that calls `net_tcp_poll()` at a fixed cadence.
 */
static void tcp_timer_process_entry(void *arg)
{
    (void)arg;
    const uint32_t interval_ms = 10;
    while (1)
    {
        net_tcp_poll();
        process_sleep_ms(interval_ms);
    }
}

/*
 * Deferred HDA initialisation.
 *
 * Some devices/codecs may appear slightly after boot; doing this work on its
 * own thread avoids stalling the main bring-up path.
 */
static void hda_init_process_entry(void *arg)
{
    (void)arg;
    hda_init();
    process_exit(0);
}

#if ENABLE_FLUSHD
static uint64_t storage_flush_ms_to_ticks(uint32_t ms)
{
    if (ms == 0)
    {
        return 0;
    }
    uint64_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 1000ULL;
    }
    uint64_t ticks = ((uint64_t)ms * freq + 999ULL) / 1000ULL;
    if (ticks == 0)
    {
        ticks = 1;
    }
    return ticks;
}

static bool storage_flush_should_wake(void *context)
{
    (void)context;
    if (__atomic_load_n(&g_flushd_wake_requested, __ATOMIC_ACQUIRE))
    {
        return true;
    }
    uint64_t deadline = __atomic_load_n(&g_flushd_wait_deadline, __ATOMIC_ACQUIRE);
    if (deadline == 0)
    {
        return false;
    }
    return timer_ticks() >= deadline;
}

static void storage_flush_timer_callback(void *context)
{
    (void)context;
    if (!__atomic_load_n(&g_flushd_wait_queue_ready, __ATOMIC_ACQUIRE))
    {
        return;
    }
    if (storage_flush_should_wake(NULL))
    {
        static volatile uint32_t g_flushd_timer_wake_log = 0;
        uint32_t count = __atomic_add_fetch(&g_flushd_timer_wake_log, 1, __ATOMIC_RELAXED);
        if (count <= 16)
        {
            uint64_t ticks = timer_ticks();
            uint64_t deadline = __atomic_load_n(&g_flushd_wait_deadline, __ATOMIC_ACQUIRE);
            flushd_logf("[flushd] timer wake at tick=%llu deadline=%llu req=%u\r\n",
                        (unsigned long long)ticks,
                        (unsigned long long)deadline,
                        (unsigned int)__atomic_load_n(&g_flushd_wake_requested, __ATOMIC_ACQUIRE));
        }
        wait_queue_wake_all(&g_flushd_wait_queue);
    }
}

static void storage_flush_signal_init(void)
{
    if (!__atomic_load_n(&g_flushd_wait_queue_ready, __ATOMIC_ACQUIRE))
    {
        wait_queue_init(&g_flushd_wait_queue);
        __atomic_store_n(&g_flushd_wait_queue_ready, true, __ATOMIC_RELEASE);
    }
    if (!__atomic_load_n(&g_flushd_timer_registered, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&g_flushd_timer_failed, __ATOMIC_ACQUIRE))
    {
        uint32_t freq = timer_frequency();
        if (freq == 0)
        {
            freq = 1000;
        }
        uint32_t interval = freq / 100U;
        if (interval == 0)
        {
            interval = 1;
        }
        if (timer_register_periodic(storage_flush_timer_callback, NULL, interval))
        {
            __atomic_store_n(&g_flushd_timer_registered, true, __ATOMIC_RELEASE);
        }
        else
        {
            flushd_logf("%s", "[flushd] warn: unable to register wake timer\r\n");
            __atomic_store_n(&g_flushd_timer_failed, true, __ATOMIC_RELEASE);
        }
    }
}

static void storage_flush_wait(uint32_t interval_ms)
{
    storage_flush_signal_init();
    bool queue_ready = __atomic_load_n(&g_flushd_wait_queue_ready, __ATOMIC_ACQUIRE);
    bool timer_ready = __atomic_load_n(&g_flushd_timer_registered, __ATOMIC_ACQUIRE);
    bool timer_failed = __atomic_load_n(&g_flushd_timer_failed, __ATOMIC_ACQUIRE);

    /* If we failed to register a periodic wake timer, fall back to polling sleeps. */
    if (!queue_ready || !timer_ready || timer_failed)
    {
        flushd_logf("%s", "[flushd] warn: timer not ready; using sleep fallback\r\n");
        const uint32_t step_ms = (interval_ms < 100) ? interval_ms : 100;
        uint32_t remaining = interval_ms;
        while (remaining > 0)
        {
            if (__atomic_load_n(&g_flushd_wake_requested, __ATOMIC_ACQUIRE))
            {
                return;
            }
            uint32_t slice = remaining < step_ms ? remaining : step_ms;
            process_sleep_ms(slice);
            remaining -= slice;
        }
        return;
    }

    __atomic_store_n(&g_flushd_wait_deadline, 0, __ATOMIC_RELEASE);
    if (storage_flush_should_wake(NULL))
    {
        return;
    }
    uint64_t ticks = storage_flush_ms_to_ticks(interval_ms);
    if (ticks == 0)
    {
        return;
    }
    uint64_t deadline = timer_ticks() + ticks;
    static uint32_t g_flushd_wait_log = 0;
    uint32_t log_idx = g_flushd_wait_log++;
    if (log_idx < 8)
    {
        flushd_logf("[flushd] wait start tick=%llu deadline=%llu\r\n",
                    (unsigned long long)timer_ticks(),
                    (unsigned long long)deadline);
    }
    __atomic_store_n(&g_flushd_wait_deadline, deadline, __ATOMIC_RELEASE);

    while (!storage_flush_should_wake(NULL))
    {
        wait_queue_wait(&g_flushd_wait_queue, storage_flush_should_wake, NULL);
    }

    __atomic_store_n(&g_flushd_wait_deadline, 0, __ATOMIC_RELEASE);
}
#endif

#if ENABLE_FLUSHD
/*
 * Request a background flush of dirty mounts/files.
 *
 * This is called by storage code (and VFS writeback logic) to nudge the flush
 * daemon; it is safe to call from any CPU.
 */
void storage_request_flush(void)
{
    __atomic_store_n(&g_flushd_wake_requested, true, __ATOMIC_RELEASE);
    if (__atomic_load_n(&g_flushd_wait_queue_ready, __ATOMIC_ACQUIRE))
    {
        wait_queue_wake_all(&g_flushd_wait_queue);
    }
}
#else
void storage_request_flush(void)
{
}
#endif

/*
 * Background filesystem flush daemon.
 *
 * Periodically scans mounted devices and calls `vfs_sync_dirty()` to push
 * outstanding dirty data/metadata to their backing block devices.
 */
static void storage_flush_process_entry(void *arg)
{
    (void)arg;
    const uint32_t interval_ms = 200;
    while (!g_fstab_ready)
    {
        process_sleep_ms(100);
    }
    //serial_printf("%s", "[flushd] entering loop\r\n");
    while (1)
    {
#if ENABLE_FLUSHD
        storage_flush_wait(interval_ms);
        __atomic_store_n(&g_flushd_wake_requested, false, __ATOMIC_RELEASE);
        static uint32_t g_flushd_awake_log = 0;
        uint32_t awake_idx = g_flushd_awake_log++;
        if (awake_idx < 8)
        {
            //serial_printf("[flushd] awake tick=%llu\r\n", (unsigned long long)timer_ticks());
        }
#else
        process_sleep_ms(interval_ms);
#endif
        const size_t max_mounts = 8;
        vfs_mount_info_t mounts[max_mounts];
        size_t total_mounts = vfs_snapshot_mounts(mounts, max_mounts);
        size_t dirty_mounts = 0;
        for (size_t i = 0; i < total_mounts && i < max_mounts; ++i)
        {
            if (mounts[i].dirty)
            {
                dirty_mounts++;
                char path[128];
                vfs_build_path(mounts[i].mount_point, path, sizeof(path));
                // serial_printf("%s", "[flushd] dirty: ");
                // serial_printf("%s", dev);
                // serial_printf("%s", " -> ");
                // serial_printf("%s", path);
                // if (mounts[i].needs_full_sync)
                // {
                //     serial_printf("%s", " (full)");
                // }
                // serial_printf("%s", "\r\n");
            }
        }
        if (flushd_log_enabled())
        {
            bool sync_ok = vfs_sync_dirty();
            if (dirty_mounts == 0)
            {
                flushd_logf("%s", "[flushd] no dirty mounts\r\n");
            }
            if (!sync_ok)
            {
                flushd_logf("%s", "[flushd] warning: partial sync failure\r\n");
            }
            else if (dirty_mounts)
            {
                flushd_logf("%s", "[flushd] sync complete\r\n");
            }
            else
            {
                flushd_logf("%s", "[flushd] nothing to sync\r\n");
            }
        }
        else
        {
            (void)vfs_sync_dirty();
        }
    }
}

void kernel_main(void)
{
    /*
     * `kernel_main` is entered from `src/arch/x86/kernel_entry.c` after:
     * - `.bss` has been zeroed
     * - `boot_info` has been copied from the UEFI loader
     * - bootstrap page tables are active
     *
     * This function performs subsystem init, starts APs, then transitions into
     * the scheduler loop. It does not return.
     */
    serial_init();
    serial_printf("%s", "[alix] kernel_main start\n");
    console_init();
    console_clear();

    heap_init();
    paging_init();
    ioremap_init();
    pmm_init();
    user_memory_init();
    serial_printf("%s", "[alix] after paging/pmm/user_memory init\n");
    acpi_init();
    serial_printf("%s", "[alix] after acpi_init\n");
    smp_init();
    process_system_init();

#if ENABLE_INIT_HWINFO
    hwinfo_print_boot_summary();
    serial_printf("%s", "[alix] after hwinfo\n");
#endif

#if ENABLE_INIT_USER_ATK
    user_atk_init();
#endif

#if ENABLE_INIT_BLOCK
    block_init();
    ahci_init();
    serial_printf("%s", "[alix] after block_init\n");
#endif

#if ENABLE_INIT_VFS
    vfs_init();
    serial_printf("%s", "[alix] after vfs_init\n");
#if ENABLE_STARTUP_SCRIPT
    startup_init();
#endif
    procfs_init();
    serial_printf("%s", "[alix] after procfs_init\n");
    shell_service_sys_controls_init();
    vfs_sys_controls_init();
    heap_sys_controls_init();
    audio_sys_controls_init();
    scheduler_log_controls_init();
#if ENABLE_FLUSHD
    (void)procfs_create_file_at("sys/vfs/flushd_log_enable", flushd_log_read, flushd_log_write, &g_flushd_log_enable);
#endif
    logger_init();
    devfs_init();
    serial_printf("%s", "[alix] after devfs_init\n");
#endif

    interrupts_init();
#if ENABLE_INIT_BLOCK
    ahci_interrupts_activate();
#endif
    interrupts_enable_irq(1);
    timer_init(100);
#if ENABLE_INIT_KEYBOARD
    timekeeping_init();
    keyboard_init();
    serial_printf("%s", "[alix] after keyboard_init\n");
#else
    timekeeping_init();
#endif

#if ENABLE_INIT_BLOCK
    ata_init();
    devfs_register_block_devices();
    serial_printf("%s", "[alix] after storage init\n");
#endif

#if ENABLE_INIT_NET
    net_if_init();
    net_dns_init();
    net_ntp_init();
    net_tcp_init();
    serial_printf("%s", "[alix] after net init\n");
    igb_init();
    rtl8139_init();
#endif

#if ENABLE_INIT_PROC_DEVICES
    proc_devices_init();
    serial_printf("%s", "[alix] after net devices init\n");
#endif

    /* Defer HDA bring-up to its own kernel thread so codecs have time to appear. */
#if ENABLE_INIT_HDA
    process_t *hda_process = process_create_kernel("hda_init",
                                                   hda_init_process_entry,
                                                   NULL,
                                                   0,
                                                   -1);
    if (!hda_process)
    {
        serial_printf("%s", "[alix] warn: failed to create hda_init\r\n");
    }
#endif

    // /* Spawn only the two demo printers; everything else stays disabled. */
    // process_t *printer_a = process_create_kernel("printerA",
    //                                              printer_a_process_entry,
    //                                              NULL,
    //                                              0,
    //                                              -1);
    // if (!printer_a)
    // {
    //     serial_printf("%s", "[alix] failed to create printerA\r\n");
    // }

    // process_t *printer_b = process_create_kernel("printerB",
    //                                              printer_b_process_entry,
    //                                              NULL,
    //                                              0,
    //                                              -1);
    // if (!printer_b)
    // {
    //     serial_printf("%s", "[alix] failed to create printerB\r\n");
    // }

#if ENABLE_INIT_TCP_TIMER
    process_t *tcp_timer_process = process_create_kernel("tcp_timerd",
                                                         tcp_timer_process_entry,
                                                         NULL,
                                                         0,
                                                         -1);
    if (!tcp_timer_process)
    {
        serial_printf("%s", "[alix] warn: failed to create tcp_timerd\r\n");
    }
    else
    {
        uint32_t non_ui_cpu = choose_non_ui_cpu();
        process_set_priority(tcp_timer_process, THREAD_PRIORITY_BACKGROUND);
        if (non_ui_cpu != PROCESS_CPU_ANY)
        {
            process_set_affinity(tcp_timer_process, non_ui_cpu);
        }
    }
#endif

#if ENABLE_INIT_WARMUP
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
#endif

    if (!smp_start_secondary_cpus())
    {
        serial_printf("%s", "[alix] warn: smp_start_secondary_cpus failed\r\n");
    }
    else
    {
        uint32_t ui_cpu = 0;
        uint32_t count = smp_cpu_count();
        if (count > 1)
        {
            ui_cpu = 1;
        }
        process_set_ui_cpu(ui_cpu);
        serial_printf("[alix] ui cpu reserved=%u\r\n", (unsigned)ui_cpu);
    }

#if ENABLE_INIT_SERIAL_ASYNC
    serial_start_async_worker();
#endif
    process_bind_idle_to_bsp();
    process_scheduler_set_ready();
    interrupts_enable();
    process_start_scheduler();

    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}

static void printer_emit(const char *msg)
{
    if (!msg)
    {
        return;
    }
    uint64_t switches = scheduler_switch_count();
    serial_printf("%s switch=%llu\r\n", msg, (unsigned long long)switches);
}

static void __attribute__((unused)) printer_a_process_entry(void *arg)
{
    (void)arg;
    while (1)
    {
        printer_emit("A");
        process_sleep_ms(1);
    }
}

static void __attribute__((unused)) printer_b_process_entry(void *arg)
{
    (void)arg;
    while (1)
    {
        printer_emit("B");
        process_sleep_ms(1);
    }
}
