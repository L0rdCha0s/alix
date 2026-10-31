#include "process_internal.h"
#include "io_request.h"
#include "errno.h"

/* Static zero initialization is the wait_queue initializer. Its lifetime is
 * global: requests never store a pointer to a thread, process or stack queue. */
static wait_queue_t g_io_completion_queue;

static bool process_io_thread_terminal(const thread_t *thread)
{
    return !thread || !thread_lifetime_active(thread) || thread->pending_destroy ||
           thread->exited || thread->state == THREAD_STATE_ZOMBIE ||
           (thread->process && thread->process->state == PROCESS_STATE_ZOMBIE);
}

int process_io_register_current(io_request_t *request)
{
    if (!request || !spinlock_preempt_disabled()) return -EINVAL;
    thread_t *thread = current_thread_local();
    uint64_t flags = scheduler_lock_acquire("io_register");
    int result = 0;
    io_request_status_t status;
    if (process_io_thread_terminal(thread)) result = -ECANCELED;
    else if (thread->io_request) result = -EBUSY;
    else if (io_request_status(request, &status) != 0 || status.state != IO_REQUEST_NEW || status.cancelled)
        result = -EINVAL;
    else thread->io_request = request; /* Transfer the existing WAITER owner. */
    scheduler_lock_release(flags);
    return result;
}

void process_io_cancel_thread_locked(thread_t *thread)
{
    if (thread && thread->io_request) (void)io_request_cancel(thread->io_request);
}

/* The scheduler's reaper already proves these conditions before calling us.
 * Keep the ownership boundary explicit so no later caller can detach a live
 * syscall's buffer simply because process_kill marked its thread ZOMBIE. */
bool process_io_abandon_thread_locked(thread_t *thread)
{
    if (!thread || !thread->io_request) return true;
    if (thread->state != THREAD_STATE_ZOMBIE || thread->in_transition ||
        __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE) != RUN_QUEUE_CPU_INVALID || thread->waiting_queue ||
        thread->sleeping || thread_in_run_queue_load(thread)) return false;
    for (uint32_t cpu = 0; cpu < SMP_MAX_CPUS; ++cpu)
    {
        if (__atomic_load_n(&g_current_threads[cpu], __ATOMIC_ACQUIRE) == thread ||
            __atomic_load_n(&g_switch_out_threads[cpu], __ATOMIC_ACQUIRE) == thread) return false;
    }
    io_request_t *request = thread->io_request;
    thread->io_request = NULL;
    return io_request_waiter_abandon(request) == 0;
}

int process_io_wait_current(io_request_status_t *out)
{
    if (!out || spinlock_preempt_disabled()) return -EINVAL;
    uint64_t flags = scheduler_lock_acquire("io_wait");
    thread_t *thread = current_thread_local();
    for (;;)
    {
        if (process_io_thread_terminal(thread))
        {
            /* Never turn a killed waiter back into RUNNING/READY. The normal
             * termination path has removed its completion-queue membership. */
            if (thread && thread->waiting_queue == &g_io_completion_queue)
                thread_remove_from_wait_queue(thread);
            scheduler_lock_release(flags);
            return -ECANCELED;
        }
        io_request_t *request = thread->io_request;
        if (!request)
        {
            scheduler_lock_release(flags);
            return -EINVAL;
        }
        int result = io_request_status(request, out);
        if (result || out->cancelled || out->state == IO_REQUEST_COMPLETED)
        {
            if (thread->waiting_queue == &g_io_completion_queue)
                thread_remove_from_wait_queue(thread);
            thread->state = THREAD_STATE_RUNNING;
            scheduler_lock_release(flags);
            return result ? result : out->cancelled ? -ECANCELED : 0;
        }
        if (thread->waiting_queue && thread->waiting_queue != &g_io_completion_queue)
        {
            scheduler_lock_release(flags);
            return -EBUSY;
        }
        if (thread_in_run_queue_load(thread)) remove_from_run_queue_locked(thread);
        spinlock_lock(&g_io_completion_queue.lock);
        if (!thread->waiting_queue)
        {
            thread->waiting_queue = &g_io_completion_queue;
            thread->wait_queue_next = NULL;
            if (g_io_completion_queue.tail) g_io_completion_queue.tail->wait_queue_next = thread;
            else g_io_completion_queue.head = thread;
            g_io_completion_queue.tail = thread;
        }
        thread->state = THREAD_STATE_BLOCKED;
        spinlock_unlock(&g_io_completion_queue.lock);
        /* Completion publication may happen before this insertion, but its
         * global wake cannot pass scheduler_lock until insertion is visible. */
        scheduler_lock_release(flags);
        scheduler_schedule(false);
        flags = scheduler_lock_acquire("io_wait");
    }
}

int process_io_result_current(io_request_t **request_out, io_request_status_t *out)
{
    if (!request_out || !out) return -EINVAL;
    *request_out = NULL;
    if (!spinlock_preempt_disabled()) return -EINVAL;
    thread_t *thread = current_thread_local();
    uint64_t flags = scheduler_lock_acquire("io_result");
    int result = 0;
    if (process_io_thread_terminal(thread)) result = -ECANCELED;
    else if (!thread->io_request) result = -EINVAL;
    else
    {
        result = io_request_status(thread->io_request, out);
        if (!result)
        {
            if (out->cancelled) result = -ECANCELED;
            else if (out->state != IO_REQUEST_COMPLETED) result = -EAGAIN;
            else *request_out = thread->io_request;
        }
    }
    scheduler_lock_release(flags);
    return result;
}

int process_io_finish_current(bool abandon)
{
    if (!spinlock_preempt_disabled()) return -EINVAL;
    thread_t *thread = current_thread_local();
    uint64_t flags = scheduler_lock_acquire("io_finish");
    int result = -EINVAL;
    if (thread && thread->io_request)
    {
        io_request_t *request = thread->io_request;
        io_request_status_t status = {0};
        result = io_request_status(request, &status);
        bool cancel = abandon || process_io_thread_terminal(thread) || status.cancelled;
        if (!result && !cancel && status.state != IO_REQUEST_COMPLETED) result = -EAGAIN;
        if (!result)
        {
            thread->io_request = NULL;
            result = cancel ? io_request_waiter_abandon(request) : io_request_waiter_release(request);
        }
    }
    scheduler_lock_release(flags);
    return result;
}

void process_io_notify_completion(void)
{
    wait_queue_wake_all(&g_io_completion_queue);
}

int process_io_complete_request(io_request_t *request, int64_t result,
                                fd_description_t *result_description_owned)
{
    int status = io_request_publish_complete(request, result, result_description_owned);
    if (status) return status;
    /* EXECUTOR remains owned through the wake even if a cancelled caller was
     * already reaped, or a woken caller immediately consumes its result. */
    process_io_notify_completion();
    return io_request_worker_release(request);
}
