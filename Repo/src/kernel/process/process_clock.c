#include "process_internal.h"
#include "user_copy.h"
#include "errno.h"

_Static_assert(sizeof(syscall_cpu_clock_t) == 16, "CPU clock snapshot ABI");

int process_user_cpu_clock(int which, uintptr_t output, size_t bytes)
{
    if ((which != SYSCALL_USAGE_CLOCK_PROCESS && which != SYSCALL_USAGE_CLOCK_THREAD) ||
        bytes != sizeof(syscall_cpu_clock_t)) return -EINVAL;
    if (!user_ptr_range_valid((void *)output, bytes)) return -EFAULT;
    spinlock_preempt_disable();
    process_t *process = current_process_local();
    thread_t *thread = current_thread_local();
    if (!process || !process->is_user || !thread)
    { spinlock_preempt_enable(); return -ESRCH; }
    syscall_cpu_clock_t *snapshot = calloc(1, sizeof(*snapshot));
    int result = -ENOMEM;
    if (snapshot)
    {
        /* These existing total counters are updated by cpu_account_tick.
         * An atomic value snapshot needs no cross-CPU stack or borrowed owner.
         * Current process/thread ownership stays pinned by this bounded guard. */
        snapshot->ticks = which == SYSCALL_USAGE_CLOCK_THREAD ?
            __atomic_load_n(&thread->runtime_ticks, __ATOMIC_RELAXED) :
            __atomic_load_n(&process->runtime_ticks, __ATOMIC_RELAXED);
        snapshot->tick_frequency = timer_frequency();
        result = !snapshot->tick_frequency ? -EAGAIN :
            user_copy_to_user((void *)output, snapshot, sizeof(*snapshot)) ? 0 : -EFAULT;
        free(snapshot);
    }
    spinlock_preempt_enable();
    return result;
}
