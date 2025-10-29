#include "timer.h"
#include "io.h"
#include "interrupts.h"

#define PIT_CHANNEL0 0x40
#define PIT_COMMAND  0x43
#define PIT_INPUT_HZ 1193182

static volatile uint64_t g_ticks = 0;
static uint32_t g_frequency_hz = 0;

void timer_init(uint32_t frequency_hz)
{
    if (frequency_hz == 0)
    {
        frequency_hz = 1000;
    }
    g_frequency_hz = frequency_hz;
    uint16_t divisor = (uint16_t)(PIT_INPUT_HZ / frequency_hz);
    outb(PIT_COMMAND, 0x36);
    outb(PIT_CHANNEL0, (uint8_t)(divisor & 0xFF));
    outb(PIT_CHANNEL0, (uint8_t)((divisor >> 8) & 0xFF));
    interrupts_enable_irq(0);
}

void timer_on_tick(void)
{
    g_ticks++;
}

uint64_t timer_ticks(void)
{
    return g_ticks;
}

uint32_t timer_frequency(void)
{
    if (g_frequency_hz == 0)
    {
        return 1000;
    }
    return g_frequency_hz;
}
