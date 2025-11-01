#include "timer.h"
#include "io.h"
#include "interrupts.h"

#define PIT_CHANNEL0 0x40
#define PIT_COMMAND  0x43
#define PIT_INPUT_HZ 1193182
#define TIMER_MAX_TASKS 16

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
    uint16_t divisor = (uint16_t)(PIT_INPUT_HZ / frequency_hz);
    outb(PIT_COMMAND, 0x36);
    outb(PIT_CHANNEL0, (uint8_t)(divisor & 0xFF));
    outb(PIT_CHANNEL0, (uint8_t)((divisor >> 8) & 0xFF));
    interrupts_enable_irq(0);
}

void timer_on_tick(void)
{
    g_ticks++;
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
