#include "timer.h"
#include "io.h"
#include "interrupts.h"
#include "spinlock.h"
#include "acpi.h"
#include "serial.h"
#include <stdint.h>

#define PIT_CHANNEL0 0x40
#define PIT_COMMAND  0x43
#define PIT_INPUT_HZ 1193182
#define TIMER_MAX_TASKS 16

/* PIT channel 2 one-shot, usable before IRQs/scheduling. Unlike a CPU loop,
 * this observes a hardware duration. Preserve the speaker/gate register. */
bool timer_early_delay_us(uint32_t microseconds)
{
    while (microseconds)
    {
        uint32_t chunk = microseconds > 50000 ? 50000 : microseconds;
        uint16_t ticks = (uint16_t)(((uint64_t)chunk * PIT_INPUT_HZ + 999999) / 1000000);
        uint8_t saved = inb(0x61);
        outb(0x61, (saved & ~3u));
        outb(PIT_COMMAND, 0xb0);
        outb(0x42, ticks & 255);
        outb(0x42, ticks >> 8);
        outb(0x61, (saved & ~2u) | 1u);
        unsigned spins = 10000000;
        while (!(inb(0x61) & 0x20) && --spins) __asm__ volatile ("pause");
        outb(0x61, saved);
        if (!spins) return false;
        microseconds -= chunk;
    }
    return true;
}

typedef struct
{
    timer_callback_t callback;
    void *context;
    uint32_t interval;
    uint64_t next_tick;
    bool in_use;
} timer_task_t;

static volatile uint64_t g_ticks = 0;
static uint32_t g_frequency_hz = 0;
static timer_task_t g_tasks[TIMER_MAX_TASKS];
#define ACPI_PM_FREQUENCY 3579545u
static spinlock_t g_clock_lock = {0};
static uint16_t g_pm_port;
static uint32_t g_pm_mask, g_pm_previous;
static uint64_t g_pm_cycles;
static bool g_pm_ready;
static uint64_t g_timer_delivered_irqs, g_timer_caught_up_ticks, g_timer_max_catchup_ticks;
static volatile uint64_t g_timer_clock_reads;

static uint64_t timer_clock_cycles(void)
{
    uint64_t flags = spinlock_lock_irqsave(&g_clock_lock);
    uint32_t now = inl(g_pm_port) & g_pm_mask;
    ++g_timer_clock_reads; /* Serialized here; inspect without logging on the hot path. */
    g_pm_cycles += (now - g_pm_previous) & g_pm_mask;
    g_pm_previous = now;
    uint64_t cycles = g_pm_cycles;
    spinlock_unlock_irqrestore(&g_clock_lock, flags);
    return cycles;
}

static void timer_tasks_reset(void)
{
    for (size_t i = 0; i < TIMER_MAX_TASKS; ++i)
    {
        g_tasks[i].callback = 0;
        g_tasks[i].context = 0;
        g_tasks[i].interval = 0;
        g_tasks[i].next_tick = 0;
        g_tasks[i].in_use = false;
    }
}

void timer_init(uint32_t frequency_hz)
{
    if (frequency_hz == 0)
    {
        frequency_hz = 1000;
    }
    g_frequency_hz = frequency_hz;
    g_ticks = 0;
    timer_tasks_reset();
    g_pm_ready = false;
    if (acpi_pm_timer_port(&g_pm_port, &g_pm_mask))
    {
        uint32_t first = inl(g_pm_port) & g_pm_mask;
        if (timer_early_delay_us(1000))
        {
            uint32_t second = inl(g_pm_port) & g_pm_mask;
            uint32_t elapsed = (second - first) & g_pm_mask;
            if (elapsed && elapsed < ACPI_PM_FREQUENCY / 10u)
            {
                g_pm_previous = second;
                g_pm_cycles = 0;
                g_pm_ready = true;
            }
        }
    }
    serial_printf("[timer] source=%s port=0x%x bits=%u irq_hz=%u",
                  g_pm_ready ? "acpi-pm" : "pit", g_pm_ready ? g_pm_port : 0,
                  g_pm_ready ? (g_pm_mask == UINT32_MAX ? 32u : 24u) : 0u, frequency_hz);
    uint16_t divisor = (uint16_t)(PIT_INPUT_HZ / frequency_hz);
    /* Rate-generator mode supplies one short IRQ pulse per reload period. */
    outb(PIT_COMMAND, 0x34);
    outb(PIT_CHANNEL0, (uint8_t)(divisor & 0xFF));
    outb(PIT_CHANNEL0, (uint8_t)((divisor >> 8) & 0xFF));
    interrupts_enable_irq(0);
}

void timer_on_tick(void)
{
    ++g_timer_delivered_irqs;
    if (g_pm_ready)
    {
        uint64_t cycles = timer_clock_cycles();
        uint64_t ticks = (cycles / ACPI_PM_FREQUENCY) * g_frequency_hz +
                         (cycles % ACPI_PM_FREQUENCY) * g_frequency_hz / ACPI_PM_FREQUENCY;
        if (ticks > g_ticks && ticks - g_ticks > 1)
        {
            uint64_t missed = ticks - g_ticks - 1;
            g_timer_caught_up_ticks += missed;
            if (missed > g_timer_max_catchup_ticks) g_timer_max_catchup_ticks = missed;
        }
        g_ticks = ticks;
    }
    else g_ticks++;

    /* IRQ0 can interrupt code which already owns a generic kernel spinlock.
     * Timer tasks enter the scheduler, storage and network stacks, so running
     * them in that state creates an interrupt-side lock-order inversion.  Keep
     * time monotonic, but defer task dispatch until a later safe tick. */
    if (spinlock_preempt_disabled())
    {
        return;
    }

    for (size_t i = 0; i < TIMER_MAX_TASKS; ++i)
    {
        timer_task_t *task = &g_tasks[i];
        if (!task->in_use || task->callback == 0)
        {
            continue;
        }
        if (g_ticks >= task->next_tick)
        {
            task->next_tick = g_ticks + task->interval;
            task->callback(task->context);
        }
    }
}

uint64_t timer_ticks(void)
{
    return g_ticks;
}

uint64_t timer_monotonic_millis(void)
{
    if (g_pm_ready)
    {
        uint64_t cycles = timer_clock_cycles();
        return (cycles / ACPI_PM_FREQUENCY) * 1000u +
               (cycles % ACPI_PM_FREQUENCY) * 1000u / ACPI_PM_FREQUENCY;
    }
    uint64_t ticks = timer_ticks();
    uint32_t frequency = timer_frequency();
    if (frequency == 0)
    {
        return 0;
    }
    /* Divide first so ordinary uptimes do not overflow ticks * 1000. */
    return (ticks / frequency) * 1000u + ((ticks % frequency) * 1000u) / frequency;
}

uint64_t timer_monotonic_resolution_ns(void)
{
    if (g_pm_ready) return 1000000u;
    uint64_t frequency = g_frequency_hz;
    if (!frequency) return 0;
    uint64_t resolution = (1000000000u + frequency - 1u) / frequency;
    return resolution < 1000000u ? 1000000u : resolution;
}

uint64_t timer_deadline_after_millis(uint64_t milliseconds)
{
    uint64_t frequency = g_frequency_hz;
    if (!frequency) return g_ticks == UINT64_MAX ? UINT64_MAX : g_ticks + 1;
    uint64_t seconds = milliseconds / 1000u, fraction;
    uint64_t scale = 1000u, base = 0;
    if (g_pm_ready)
    {
        uint64_t cycles = timer_clock_cycles();
        if (seconds > UINT64_MAX - cycles / ACPI_PM_FREQUENCY) return UINT64_MAX;
        seconds += cycles / ACPI_PM_FREQUENCY;
        scale *= ACPI_PM_FREQUENCY;
        fraction = (cycles % ACPI_PM_FREQUENCY) * 1000u +
                   (milliseconds % 1000u) * ACPI_PM_FREQUENCY;
        seconds += fraction / scale;
        fraction %= scale;
    }
    else
    {
        base = g_ticks;
        fraction = milliseconds % 1000u;
    }
    if (seconds > UINT64_MAX / frequency) return UINT64_MAX;
    uint64_t ticks = seconds * frequency;
    uint64_t partial = (fraction * frequency + scale - 1u) / scale;
    if (!g_pm_ready) ++partial; /* The current PIT tick may be almost over. */
    if (partial > UINT64_MAX - ticks) return UINT64_MAX;
    ticks += partial;
    return ticks > UINT64_MAX - base ? UINT64_MAX : base + ticks;
}

uint32_t timer_frequency(void)
{
    if (g_frequency_hz == 0)
    {
        return 1000;
    }
    return g_frequency_hz;
}

bool timer_register_periodic(timer_callback_t callback, void *context, uint32_t interval_ticks)
{
    if (callback == 0)
    {
        return false;
    }
    if (interval_ticks == 0)
    {
        interval_ticks = 1;
    }

    for (size_t i = 0; i < TIMER_MAX_TASKS; ++i)
    {
        if (!g_tasks[i].in_use)
        {
            g_tasks[i].callback = callback;
            g_tasks[i].context = context;
            g_tasks[i].interval = interval_ticks;
            g_tasks[i].next_tick = g_ticks + interval_ticks;
            g_tasks[i].in_use = true;
            return true;
        }
    }
    return false;
}

bool timer_unregister(timer_callback_t callback, void *context)
{
    if (!callback)
    {
        return false;
    }

    bool removed = false;
    for (size_t i = 0; i < TIMER_MAX_TASKS; ++i)
    {
        timer_task_t *task = &g_tasks[i];
        if (task->in_use && task->callback == callback && task->context == context)
        {
            task->in_use = false;
            task->callback = 0;
            task->context = 0;
            task->interval = 0;
            task->next_tick = 0;
            removed = true;
        }
    }
    return removed;
}
