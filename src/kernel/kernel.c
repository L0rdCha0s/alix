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

void kernel_main(void)
{
    serial_init();
    keyboard_init();
    console_init();
    console_clear();

    heap_init();

    serial_write_char('k');
    serial_write_string("IDT base pre-init=\r\n");
    serial_write_hex64(idt_current_base());
    serial_write_string("\r\n");
    hwinfo_print_boot_summary();
    serial_write_char('h');
    serial_write_char('v');
    vfs_init();
    serial_write_char('Q');
    serial_write_hex64((uint64_t)vfs_root());
    serial_write_char('\n');
    serial_write_char('f');
    interrupts_init();
    serial_write_char('I');
    timer_init(100);
    serial_write_char('T');

    net_if_init();
    net_dns_init();
    net_tcp_init();

    rtl8139_init();
    serial_write_char('N');
    serial_write_char('m');
    serial_write_char('E');
    interrupts_enable();
    serial_write_char('e');
    shell_main();

    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}
