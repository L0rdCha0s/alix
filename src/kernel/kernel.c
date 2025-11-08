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
#include "idt.h"
#include "process.h"
#include "block.h"
#include "devfs.h"
#include "ata.h"
#include "ahci.h"
#include "logger.h"

static void shell_process_entry(void *arg)
{
    (void)arg;
    shell_main();
    process_exit(0);
}

void kernel_main(void)
{
    serial_init();
    serial_write_string("[alix] kernel_main start\n");
    keyboard_init();
    console_init();
    console_clear();

    heap_init();
    paging_init();
    serial_write_string("[alix] after paging_init\n");
    process_system_init();
    serial_write_string("[alix] after process_system_init\n");
    block_init();
    ahci_init();
    serial_write_string("[alix] after block_init\n");

    hwinfo_print_boot_summary();
    serial_write_string("[alix] after hwinfo\n");
    acpi_init();
    serial_write_string("[alix] after acpi_init\n");
    vfs_init();
    serial_write_string("[alix] after vfs_init\n");
    logger_init();
    devfs_init();
    serial_write_string("[alix] after devfs_init\n");
    interrupts_init();
    interrupts_enable_irq(1);
    serial_write_string("[alix] after interrupts_init\n");
    timer_init(100);
    ata_init();
    devfs_register_block_devices();
    serial_write_string("[alix] after storage init\n");

    net_if_init();
    net_dns_init();
    net_tcp_init();
    serial_write_string("[alix] after net init\n");

    rtl8139_init();
    interrupts_enable();
    serial_write_string("[alix] after rtl8139_init\n");

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

    serial_write_string("[alix] starting scheduler\n");
    process_start_scheduler();

    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}
