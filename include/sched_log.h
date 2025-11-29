#ifndef SCHED_LOG_H
#define SCHED_LOG_H

#include "types.h"
#include "serial.h"

extern uint32_t g_sched_log_enable;
extern uint32_t g_sched_dbg_enable;
extern uint32_t g_sched_sleep_log_enable;

static inline bool sched_log_enabled(void)
{
    return __atomic_load_n(&g_sched_log_enable, __ATOMIC_ACQUIRE) != 0;
}

static inline bool sched_dbg_enabled(void)
{
    return __atomic_load_n(&g_sched_dbg_enable, __ATOMIC_ACQUIRE) != 0;
}

static inline bool sched_sleep_log_enabled(void)
{
    return __atomic_load_n(&g_sched_sleep_log_enable, __ATOMIC_ACQUIRE) != 0;
}

#define SCHED_LOG(...) do { if (sched_log_enabled()) { serial_printf(__VA_ARGS__); } } while (0)
#define SCHED_DBG(...) do { if (sched_dbg_enabled()) { serial_printf(__VA_ARGS__); } } while (0)
#define SCHED_SLEEP_LOG(...) do { if (sched_sleep_log_enabled()) { serial_printf(__VA_ARGS__); } } while (0)

#endif /* SCHED_LOG_H */
