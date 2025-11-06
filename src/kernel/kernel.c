#include "console.h"
#include "serial.h"
#include "keyboard.h"
#include "vfs.h"
#include "interrupts.h"
#include "timer.h"
#include "hwinfo.h"
#include "heap.h"
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
    process_system_init();
    block_init();

    serial_write_char('k');
    serial_write_string("IDT base pre-init=\r\n");
    serial_write_hex64(idt_current_base());
    serial_write_string("\r\n");
    hwinfo_print_boot_summary();
    serial_write_char('h');
    serial_write_char('v');
    vfs_init();
    devfs_init();
    serial_write_char('Q');
    serial_write_hex64((uint64_t)vfs_root());
    serial_write_char('\n');
    serial_write_char('f');
    interrupts_init();
    interrupts_enable_irq(1);
    serial_write_char('I');
    timer_init(100);
    serial_write_char('T');
    ata_init();
    devfs_register_block_devices();

    net_if_init();
    net_dns_init();
    net_tcp_init();

    rtl8139_init();
    serial_write_char('N');
    serial_write_char('m');
    serial_write_char('E');
    interrupts_enable();
    serial_write_char('e');

    process_t *shell_process = process_create_kernel("shell", shell_process_entry, NULL, 0, -1);
    if (!shell_process)
    {
        serial_write_string("Failed to create shell process\r\n");
        for (;;)
        {
            __asm__ volatile ("hlt");
        }
    }

    process_start_scheduler();

    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}
