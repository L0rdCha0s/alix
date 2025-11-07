#include "power.h"

#include "acpi.h"
#include "io.h"

static void power_write(uint16_t port, uint16_t value)
{
    outw(port, value);
}

void power_shutdown(void)
{
    if (!acpi_shutdown())
    {
        /* VMM-specific fallbacks (QEMU/Bochs). */
        power_write(0x604, 0x2000);
        power_write(0xB004, 0x2000);
        power_write(0x4004, 0x3400);
        power_write(0x2000, 0x1000);
    }

    __asm__ volatile ("cli");
    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}
