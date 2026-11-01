#include "process_internal.h"

bool process_creation_watch_init(process_creation_watch_t *watch)
{
    if (!watch || !spinlock_preempt_disabled()) return false;
    thread_t *creator = current_thread_local();
    if (!creator) return false;
    watch->creator_pid = creator->owner_pid;
    watch->creator_tid = creator->tid;
    watch->pid = 0;
    watch->owner = NULL;
    watch->constructed = false;
    watch->complete = false;
    return true;
}

void process_creation_watch_complete(process_creation_watch_t *watch)
{
    if (watch) __atomic_store_n(&watch->complete, true, __ATOMIC_RELEASE);
}

bool process_creation_watch_creator_stopped(const process_creation_watch_t *watch)
{
    if (!watch) return true;
    bool stopped = true;
    uint64_t flags = scheduler_lock_acquire("creation_watch_creator");
    spinlock_lock(&g_thread_registry_lock);
    for (thread_t *thread = g_thread_registry_head; thread; thread = thread->registry_next)
    {
        if (thread->owner_pid != watch->creator_pid || thread->tid != watch->creator_tid) continue;
        stopped = thread->state == THREAD_STATE_ZOMBIE &&
                  __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE) == RUN_QUEUE_CPU_INVALID &&
                  !thread->in_transition && !thread_in_run_queue_load(thread) &&
                  !thread->waiting_queue && !thread->sleeping;
        for (uint32_t cpu = 0; stopped && cpu < SMP_MAX_CPUS; ++cpu)
            if (__atomic_load_n(&g_current_threads[cpu], __ATOMIC_ACQUIRE) == thread ||
                __atomic_load_n(&g_switch_out_threads[cpu], __ATOMIC_ACQUIRE) == thread) stopped = false;
        break;
    }
    spinlock_unlock(&g_thread_registry_lock);
    scheduler_lock_release(flags);
    return stopped;
}

bool process_creation_watch_quiescent(const process_creation_watch_t *watch)
{
    /* complete also covers a creator that could not allocate its arguments
     * and never entered the factory. No future constructor may use it. */
    if (!watch || !__atomic_load_n(&watch->complete, __ATOMIC_ACQUIRE)) return false;
    /* Record ownership (or its containing lock) must serialize disposal. */
    process_t *owner = __atomic_load_n(&watch->owner, __ATOMIC_ACQUIRE);
    if (!owner) return true;
    uint64_t flags = scheduler_lock_acquire("creation_watch_target");
    bool stopped = owner->state == PROCESS_STATE_ZOMBIE && process_threads_quiescent_locked(owner);
    scheduler_lock_release(flags);
    return stopped;
}
