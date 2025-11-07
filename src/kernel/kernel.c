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
    keyboard_init();
    console_init();
    console_clear();

    heap_init();
    paging_init();
    process_system_init();
    block_init();

    hwinfo_print_boot_summary();
    acpi_init();
    vfs_init();
    logger_init();
    devfs_init();
    interrupts_init();
    interrupts_enable_irq(1);
    timer_init(100);
    ata_init();
    devfs_register_block_devices();

    net_if_init();
    net_dns_init();
    net_tcp_init();

    rtl8139_init();
    interrupts_enable();

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

    process_start_scheduler();

    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}
