#include "process_internal.h"
#include "io_request.h"
#include "errno.h"

/* Static zero initialization is the wait_queue initializer. Its lifetime is
 * global: requests never store a pointer to a thread, process or stack queue. */
static wait_queue_t g_io_completion_queue;
static wait_queue_t g_io_cleanup_queue;
static uint64_t g_io_cleanup_sequence;
/* Static lifetime avoids retaining a service/thread/stack pointer in a late
 * completion. Only an opaque queue address is hashed; collisions just wake an
 * extra cleanup worker, whose own predicate rechecks actual readiness. */
static wait_queue_t g_io_cleanup_buckets[128];
uint64_t g_io_completion_requests, g_io_completion_matched, g_io_completion_broadcasts;
void process_io_notify_cleanup(void);
void process_io_notify_cleanup_for(uintptr_t key);

static bool process_io_thread_terminal(const thread_t *thread)
{
    return !thread || !thread_lifetime_active(thread) || thread->pending_destroy ||
           thread->exited || thread->state == THREAD_STATE_ZOMBIE ||
           (thread->process && thread->process->state == PROCESS_STATE_ZOMBIE);
}

uint64_t process_io_admission_sequence(void)
{
    return __atomic_load_n(&g_io_cleanup_sequence, __ATOMIC_ACQUIRE);
}

void process_io_record_admission(uint64_t sequence)
{
    thread_t *thread = current_thread_local();
    if (thread && spinlock_preempt_disabled())
    {
        thread->io_admission_sequence = sequence;
        thread->io_admission_pending = true;
    }
}

bool process_io_wait_admission(void)
{
    thread_t *thread = current_thread_local();
    if (!thread || !thread->io_admission_pending || spinlock_preempt_disabled()) return false;
    thread->io_admission_pending = false;
    uint64_t now = timer_ticks(), deadline = now + 1;
    uint64_t flags = scheduler_lock_acquire("io_admission");
    for (;;)
    {
        /* Like registered I/O waits, never revive a killed caller. The heap
         * thread owns its token; no request, service or stack context waits. */
        if (process_io_thread_terminal(thread))
        {
            if (thread->waiting_queue == &g_io_cleanup_queue) thread_remove_from_wait_queue(thread);
            if (thread->sleeping) sleep_queue_remove(thread);
            scheduler_lock_release(flags);
            return true;
        }
        now = timer_ticks();
        if (process_io_admission_sequence() != thread->io_admission_sequence || now >= deadline)
        {
            if (thread->waiting_queue == &g_io_cleanup_queue) thread_remove_from_wait_queue(thread);
            if (thread->sleeping) sleep_queue_remove(thread);
            thread->state = THREAD_STATE_RUNNING;
            scheduler_lock_release(flags);
            return true;
        }
        if (thread->waiting_queue && thread->waiting_queue != &g_io_cleanup_queue)
        {
            scheduler_lock_release(flags);
            return false;
        }
        if (thread_in_run_queue_load(thread)) remove_from_run_queue_locked(thread);
        spinlock_lock(&g_io_cleanup_queue.lock);
        if (!thread->waiting_queue)
        {
            thread->waiting_queue = &g_io_cleanup_queue;
            thread->wait_queue_next = NULL;
            if (g_io_cleanup_queue.tail) g_io_cleanup_queue.tail->wait_queue_next = thread;
            else g_io_cleanup_queue.head = thread;
            g_io_cleanup_queue.tail = thread;
        }
        thread->state = THREAD_STATE_BLOCKED;
        thread->sleep_until_tick = deadline;
        if (!thread->sleeping) sleep_queue_insert(thread);
        spinlock_unlock(&g_io_cleanup_queue.lock);
        /* A cleanup publication cannot pass scheduler_lock between checking
         * its sequence and making this queue membership visible. */
        scheduler_lock_release(flags);
        scheduler_schedule(false);
        flags = scheduler_lock_acquire("io_admission");
    }
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

static int process_io_wait_current_mode(io_request_status_t *out, bool interruptible)
{
    if (!out || spinlock_preempt_disabled()) return -EINVAL;
    uint64_t flags = scheduler_lock_acquire("io_wait");
    thread_t *thread = current_thread_local();
    if (thread) thread->io_interruptible = interruptible;
    for (;;)
    {
        if (process_io_thread_terminal(thread))
        {
            /* Never turn a killed waiter back into RUNNING/READY. The normal
             * termination path has removed its completion-queue membership. */
            if (thread && thread->waiting_queue == &g_io_completion_queue)
                thread_remove_from_wait_queue(thread);
            if (thread) thread->io_interruptible = false;
            scheduler_lock_release(flags);
            return -ECANCELED;
        }
        io_request_t *request = thread->io_request;
        if (!request)
        {
            thread->io_interruptible = false;
            scheduler_lock_release(flags);
            return -EINVAL;
        }
        if (interruptible && process_signal_pending_locked(thread))
        {
            (void)io_request_cancel(request);
            if (thread->waiting_queue == &g_io_completion_queue)
                thread_remove_from_wait_queue(thread);
            thread->state = THREAD_STATE_RUNNING;
            thread->io_interruptible = false;
            scheduler_lock_release(flags);
            return -EINTR;
        }
        int result = io_request_status(request, out);
        if (result || out->cancelled || out->state == IO_REQUEST_COMPLETED)
        {
            if (thread->waiting_queue == &g_io_completion_queue)
                thread_remove_from_wait_queue(thread);
            thread->state = THREAD_STATE_RUNNING;
            thread->io_interruptible = false;
            scheduler_lock_release(flags);
            return result ? result : out->cancelled ? -ECANCELED : 0;
        }
        if (thread->waiting_queue && thread->waiting_queue != &g_io_completion_queue)
        {
            thread->io_interruptible = false;
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

int process_io_wait_current(io_request_status_t *out)
{
    return process_io_wait_current_mode(out, false);
}

int process_io_wait_current_interruptible(io_request_status_t *out)
{
    return process_io_wait_current_mode(out, true);
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
    bool cleanup_ready = false;
    uintptr_t cleanup_key = 0;
    if (thread && thread->io_request)
    {
        io_request_t *request = thread->io_request;
        io_request_status_t status = {0};
        result = io_request_status(request, &status);
        bool cancel = abandon || process_io_thread_terminal(thread) || status.cancelled;
        if (!result && !cancel && status.state != IO_REQUEST_COMPLETED) result = -EAGAIN;
        if (!result)
        {
            cleanup_key = io_request_queue_key(request);
            thread->io_request = NULL;
            result = io_request_waiter_finish(request, cancel, &cleanup_ready);
        }
    }
    scheduler_lock_release(flags);
    if (!result && cleanup_ready) process_io_notify_cleanup_for(cleanup_key);
    return result;
}

bool process_io_wait_cleanup(bool (*predicate)(void *), void *context, uint64_t timeout_ticks)
{
    return wait_queue_wait_timeout(&g_io_cleanup_queue, predicate, context, timeout_ticks);
}

static wait_queue_t *process_io_cleanup_bucket(uintptr_t key)
{
    uint64_t mixed = (uint64_t)(key >> 4) ^ (uint64_t)(key >> 27);
    mixed *= UINT64_C(0x9e3779b97f4a7c15);
    return &g_io_cleanup_buckets[mixed >> 57];
}

bool process_io_wait_cleanup_for(uintptr_t key, bool (*predicate)(void *), void *context, uint64_t timeout_ticks)
{
    return wait_queue_wait_timeout(process_io_cleanup_bucket(key), predicate, context, timeout_ticks);
}

void process_io_notify_cleanup_for(uintptr_t key)
{
    wait_queue_wake_all(process_io_cleanup_bucket(key));
}

void process_io_notify_cleanup(void)
{
    __atomic_add_fetch(&g_io_cleanup_sequence, 1, __ATOMIC_RELEASE);
    wait_queue_wake_all(&g_io_cleanup_queue);
}

void process_io_notify_completion(void)
{
    __atomic_add_fetch(&g_io_completion_broadcasts, 1, __ATOMIC_RELAXED);
    wait_queue_wake_all(&g_io_completion_queue);
}

static void process_io_notify_request(io_request_t *request)
{
    /* EXECUTOR keeps request alive. Scheduler ownership keeps each queued
     * thread alive throughout lookup/wake; no worker retains a thread or a
     * pointer into its stack after releasing the lock. */
    uint64_t flags = scheduler_lock_acquire("io_complete_request");
    ++g_io_completion_requests;
    spinlock_lock(&g_io_completion_queue.lock);
    thread_t *previous = NULL;
    for (thread_t *thread = g_io_completion_queue.head; thread; thread = thread->wait_queue_next)
    {
        if (thread->io_request != request) { previous = thread; continue; }
        ++g_io_completion_matched;
        if (previous) previous->wait_queue_next = thread->wait_queue_next;
        else g_io_completion_queue.head = thread->wait_queue_next;
        if (g_io_completion_queue.tail == thread) g_io_completion_queue.tail = previous;
        thread->wait_queue_next = NULL;
        thread->waiting_queue = NULL;
        if (!process_io_thread_terminal(thread) && thread->state == THREAD_STATE_BLOCKED &&
            !thread_in_run_queue_load(thread))
        {
            if (__atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE) != RUN_QUEUE_CPU_INVALID ||
                thread->in_transition)
                thread->wake_pending = true;
            else
            {
                thread->wake_pending = false;
                thread->state = THREAD_STATE_READY;
                enqueue_thread_on_cpu_locked(thread, scheduler_select_target_cpu(thread));
            }
        }
        break; /* A request has exactly one WAITER owner. */
    }
    spinlock_unlock(&g_io_completion_queue.lock);
    scheduler_lock_release(flags);
}

int process_io_complete_request(io_request_t *request, int64_t result,
                                fd_description_t *result_description_owned)
{
    uintptr_t cleanup_key = io_request_queue_key(request);
    int status = io_request_publish_complete(request, result, result_description_owned);
    if (status) return status;
    /* EXECUTOR remains owned through the wake even if a cancelled caller was
     * already reaped, or a woken caller immediately consumes its result. */
    process_io_notify_request(request);
    bool cleanup_ready = false;
    status = io_request_worker_release_ready(request, &cleanup_ready);
    if (!status && cleanup_ready) process_io_notify_cleanup_for(cleanup_key);
    return status;
}
