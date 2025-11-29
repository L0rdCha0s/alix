static thread_priority_t thread_effective_priority(const thread_t *thread);

static inline uint32_t scheduler_cpu_limit(void)
{
    uint32_t online = smp_cpu_count();
    if (online == 0)
    {
        online = 1;
    }
    if (online > SMP_MAX_CPUS)
    {
        online = SMP_MAX_CPUS;
    }
    static uint32_t limit_log_budget = 4;
    if (limit_log_budget > 0)
    {
        serial_printf("[sched dbg] cpu_limit online=%u\r\n", (unsigned)online);
        limit_log_budget--;
    }
    return online;
}

static inline bool scheduler_cpu_online(uint32_t cpu_index)
{
    const smp_cpu_t *cpu = smp_cpu_by_index(cpu_index);
    if (!cpu || !cpu->present)
    {
        return false;
    }
    return __atomic_load_n(&cpu->online, __ATOMIC_ACQUIRE);
}

static inline run_queue_t *scheduler_run_queue(uint32_t cpu_index)
{
    if (cpu_index >= SMP_MAX_CPUS)
    {
        fatal("scheduler_run_queue: cpu index out of range");
    }
    return &g_run_queues[cpu_index];
}

#if ENABLE_RUN_QUEUE_DEBUG
static void scheduler_verify_run_queue_locked(run_queue_t *queue, const char *where)
{
    if (!queue)
    {
        return;
    }

    uint32_t cpu_index = queue->cpu_index;
    uint32_t counted_total = 0;

    for (int pr = THREAD_PRIORITY_COUNT - 1; pr >= THREAD_PRIORITY_IDLE; --pr)
    {
        thread_t *thread = queue->heads[pr];
        uint32_t safety = 0;
        while (thread)
        {
            counted_total++;
            if (!thread_in_run_queue_load(thread))
            {
                serial_printf("[sched] runq invariant (%s): thread=%s pid=0x%016llX in cpu=%u list but flag=false\r\n",
                              where ? where : "<unset>",
                              thread->name[0] ? thread->name : "<unnamed>",
                              (unsigned long long)(thread->process ? thread->process->pid : 0),
                              cpu_index);
            }
            if (thread->run_queue_cpu != cpu_index)
            {
                serial_printf("[sched] runq invariant (%s): thread=%s pid=0x%016llX in cpu=%u list but run_queue_cpu=%u\r\n",
                              where ? where : "<unset>",
                              thread->name[0] ? thread->name : "<unnamed>",
                              (unsigned long long)(thread->process ? thread->process->pid : 0),
                              cpu_index,
                              thread->run_queue_cpu);
            }
            thread = thread->queue_next;
            if (++safety > 100000)
            {
                serial_printf("[sched] runq invariant (%s): possible queue loop cpu=%u prio=%d\r\n",
                              where ? where : "<unset>",
                              cpu_index,
                              pr);
                break;
            }
        }
    }

    uint32_t reported_total = __atomic_load_n(&queue->total, __ATOMIC_RELAXED);
    if (reported_total != counted_total)
    {
        serial_printf("[sched] runq invariant (%s): cpu=%u total=%u counted=%u\r\n",
                      where ? where : "<unset>",
                      cpu_index,
                      (unsigned)reported_total,
                      (unsigned)counted_total);
    }
}
#else
#define scheduler_verify_run_queue_locked(queue, where) (void)0
#endif

static inline const char *scheduler_thread_name(const thread_t *thread)
{
    if (!thread)
    {
        return "<none>";
    }
    return (thread->name[0] != '\0') ? thread->name : "<unnamed>";
}

static inline uint64_t scheduler_thread_pid(const thread_t *thread)
{
    if (!thread || !thread->process)
    {
        return 0;
    }
    return thread->process->pid;
}

extern uint64_t g_scheduler_switch_count;

uint64_t scheduler_switch_count(void)
{
    return __atomic_load_n(&g_scheduler_switch_count, __ATOMIC_RELAXED);
}

static uint32_t scheduler_rand32(void)
{
    /* Simple xorshift with timer noise mixed in to vary CPU selection. */
    static uint32_t seed = 0xC0FFEEu;
    uint64_t ticks = timer_ticks();
    seed ^= (uint32_t)ticks ^ (uint32_t)(ticks >> 32);
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed ? seed : 1u;
}

static void scheduler_log_enqueue(thread_t *thread, uint32_t cpu_index, const char *reason)
{
    serial_printf("[sched] enqueue cpu=%u thread=%s pid=0x%016llX reason=%s\r\n",
                  cpu_index,
                  scheduler_thread_name(thread),
                  (unsigned long long)scheduler_thread_pid(thread),
                  reason ? reason : "<none>");
}

static void scheduler_log_pick(thread_t *prev, thread_t *next, uint32_t cpu_index, const char *reason)
{
    serial_printf("[sched] pick cpu=%u prev=%s pid=0x%016llX next=%s pid=0x%016llX reason=%s\r\n",
                  cpu_index,
                  scheduler_thread_name(prev),
                  (unsigned long long)scheduler_thread_pid(prev),
                  scheduler_thread_name(next),
                  (unsigned long long)scheduler_thread_pid(next),
                  reason ? reason : "<none>");
}

static void __attribute__((unused)) scheduler_log_thread_brief(const thread_t *thread)
{
    if (!thread)
    {
        serial_printf("%s", "<none>");
        return;
    }
    const char *name = (thread->name[0] != '\0') ? thread->name : "<unnamed>";
    uint64_t pid = thread->process ? thread->process->pid : 0;
    serial_printf("%s pid=0x%016llX", name, (unsigned long long)pid);
}

static void scheduler_log_switch_latency(uint64_t ms,
                                         const thread_t *prev,
                                         const thread_t *next,
                                         bool deferred_work,
                                         const deferred_free_stats_t *stats)
{
    const char *pname = scheduler_thread_name(prev);
    uint64_t ppid = (prev && thread_pointer_valid(prev) && process_pointer_valid(prev->process))
                    ? prev->process->pid
                    : 0;
    const char *nname = scheduler_thread_name(next);
    uint64_t npid = (next && thread_pointer_valid(next) && process_pointer_valid(next->process))
                    ? next->process->pid
                    : 0;

    if (stats && stats->grabbed > 0)
    {
        uint64_t df_ms = scheduler_ticks_to_ms(stats->duration_ticks);
        serial_printf("[sched] switch latency %llu ms prev=%s pid=0x%016llX next=%s pid=0x%016llX deferred=%s grabbed=0x%016llX freed=0x%016llX requeued=0x%016llX df_ms=%llu\r\n",
                      (unsigned long long)ms,
                      pname,
                      (unsigned long long)ppid,
                      nname,
                      (unsigned long long)npid,
                      deferred_work ? "true" : "false",
                      (unsigned long long)stats->grabbed,
                      (unsigned long long)stats->freed,
                      (unsigned long long)stats->requeued,
                      (unsigned long long)df_ms);
    }
    else
    {
        serial_printf("[sched] switch latency %llu ms prev=%s pid=0x%016llX next=%s pid=0x%016llX deferred=%s\r\n",
                      (unsigned long long)ms,
                      pname,
                      (unsigned long long)ppid,
                      nname,
                      (unsigned long long)npid,
                      deferred_work ? "true" : "false");
    }
}

static inline uint64_t run_queue_lock_acquire(run_queue_t *queue, const char *label)
{
    (void)label;
    if (!queue)
    {
        return 0;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_lock(&queue->lock);
    queue->lock_owner = current_thread_local();
    queue->lock_owner_label = label;
    queue->lock_owner_caller = __builtin_return_address(0);
    queue->lock_acquired_ticks = timer_ticks();
    return flags;
}

static inline void run_queue_lock_release(run_queue_t *queue, uint64_t flags)
{
    if (!queue)
    {
        return;
    }
    queue->lock_owner = NULL;
    queue->lock_owner_label = NULL;
    queue->lock_owner_caller = NULL;
    queue->lock_acquired_ticks = 0;
    spinlock_unlock(&queue->lock);
    cpu_restore_flags(flags);
}

static inline __attribute__((unused)) void thread_release_running_claim(thread_t *thread)
{
    (void)thread;
}

static inline uint64_t scheduler_lock_acquire(const char *where)
{
    (void)where;
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_lock(&g_scheduler_lock);
    return flags;
}

static inline void scheduler_lock_release(uint64_t flags)
{
    spinlock_unlock(&g_scheduler_lock);
    cpu_restore_flags(flags);
}

static void scheduler_log_running_cpu_change(const thread_t *thread,
                                             uint32_t value,
                                             const char *reason)
{
    serial_printf("[sched dbg] running_cpu_change thread=%s pid=0x%016llX value=%u reason=%s\r\n",
                  scheduler_thread_name(thread),
                  (unsigned long long)scheduler_thread_pid(thread),
                  (unsigned)value,
                  reason ? reason : "<none>");
}

static void scheduler_log_current_slot(uint32_t cpu_index, const char *tag)
{
    thread_t *slot = g_current_threads[cpu_index];
    serial_printf("[sched dbg] current_slot cpu=%u thread=%s pid=0x%016llX tag=%s\r\n",
                  (unsigned)cpu_index,
                  scheduler_thread_name(slot),
                  (unsigned long long)scheduler_thread_pid(slot),
                  tag ? tag : "<none>");
}

static uint32_t scheduler_select_target_cpu(thread_t *thread)
{
    uint32_t limit = scheduler_cpu_limit();
    if (limit == 0)
    {
        return 0;
    }

    /* Spread work; hash by pid for stability, otherwise random. */
    uint32_t start = 0;
    if (thread && thread->process)
    {
        start = (uint32_t)(thread->process->pid % (uint64_t)limit);
    }
    else
    {
        start = scheduler_rand32() % limit;
    }

    for (uint32_t attempt = 0; attempt < limit; ++attempt)
    {
        uint32_t idx = (start + attempt) % limit;
        if (scheduler_cpu_online(idx))
        {
            return idx;
        }
    }
    return 0;
}

static inline thread_priority_t scheduler_queue_priority(void)
{
    return THREAD_PRIORITY_NORMAL;
}

static void run_queue_push_locked(run_queue_t *queue, thread_t *thread)
{
    if (!queue || !thread)
    {
        return;
    }

    thread_priority_t priority = scheduler_queue_priority();
    thread->queue_prev = queue->tails[priority];
    thread->queue_next = NULL;
    thread->run_queue_cpu = queue->cpu_index;
    thread_in_run_queue_store(thread, true);

    if (queue->tails[priority])
    {
        queue->tails[priority]->queue_next = thread;
    }
    else
    {
        queue->heads[priority] = thread;
    }
    queue->tails[priority] = thread;
    queue->counts[priority]++;
    queue->total++;
}

static bool run_queue_detach_locked(run_queue_t *queue, thread_t *thread)
{
    if (!queue || !thread)
    {
        return false;
    }

    thread_priority_t priority = scheduler_queue_priority();
    thread_t *prev = NULL;
    thread_t *cursor = queue->heads[priority];
    while (cursor && cursor != thread)
    {
        prev = cursor;
        cursor = cursor->queue_next;
    }
    if (!cursor)
    {
        return false;
    }

    thread_t *next = cursor->queue_next;
    if (prev)
    {
        prev->queue_next = next;
    }
    else
    {
        queue->heads[priority] = next;
    }

    if (next)
    {
        next->queue_prev = prev;
    }
    else
    {
        queue->tails[priority] = prev;
    }

    if (queue->counts[priority] > 0)
    {
        queue->counts[priority]--;
    }
    if (queue->total > 0)
    {
        queue->total--;
    }

    thread_in_run_queue_store(thread, false);
    thread->run_queue_cpu = RUN_QUEUE_CPU_INVALID;
    thread->queue_next = NULL;
    thread->queue_prev = NULL;
    return true;
}

static thread_t *run_queue_pop_locked(run_queue_t *queue)
{
    if (!queue)
    {
        return NULL;
    }

    thread_priority_t priority = scheduler_queue_priority();
    for (thread_t *thread = queue->heads[priority]; thread; )
    {
        thread_t *next = thread->queue_next;
        uint32_t expected = RUN_QUEUE_CPU_INVALID;
        if (!__atomic_compare_exchange_n(&thread->running_cpu,
                                         &expected,
                                         queue->cpu_index,
                                         false,
                                         __ATOMIC_ACQ_REL,
                                         __ATOMIC_ACQUIRE))
        {
            thread = next;
            continue;
        }
        if (!thread_can_run(thread))
        {
            (void)run_queue_detach_locked(queue, thread);
            thread = next;
            continue;
        }
        if (!run_queue_detach_locked(queue, thread))
        {
            /* Failed to detach; undo the running_cpu claim and continue. */
            __atomic_store_n(&thread->running_cpu, RUN_QUEUE_CPU_INVALID, __ATOMIC_RELEASE);
            thread = next;
            continue;
        }
        thread->in_transition = true;
        thread->run_queue_cpu = queue->cpu_index;
        thread->wake_pending = false;
        scheduler_log_running_cpu_change(thread, queue->cpu_index, "claim_dequeue");
        return thread;
    }
    return NULL;
}

static thread_t *dequeue_thread_for_cpu(uint32_t cpu_index)
{
    uint32_t limit = scheduler_cpu_limit();
    if (cpu_index >= limit)
    {
        return NULL;
    }

    /* First try the local queue. */
    run_queue_t *local = scheduler_run_queue(cpu_index);
    if (local)
    {
        uint64_t flags = run_queue_lock_acquire(local, "dequeue");
        thread_t *thread = run_queue_pop_locked(local);
        scheduler_verify_run_queue_locked(local, "dequeue_thread_for_cpu");
        run_queue_lock_release(local, flags);
        if (thread)
        {
            thread->run_queue_cpu = cpu_index;
            /* run_queue_pop_locked already marked running_cpu to the queue's CPU;
             * ensure it reflects where we will actually run the thread. */
            scheduler_log_running_cpu_change(thread, cpu_index, "claim_local");
            __atomic_store_n(&thread->running_cpu, cpu_index, __ATOMIC_RELEASE);
            return thread;
        }
    }

    return NULL;
}

static void enqueue_current_thread_local_locked(thread_t *thread)
{
    if (!thread || thread->is_idle)
    {
        return;
    }

    uint32_t cpu_index = current_cpu_index();
    uint32_t limit = scheduler_cpu_limit();
    if (cpu_index >= limit || !scheduler_cpu_online(cpu_index))
    {
        cpu_index = 0;
    }
    run_queue_t *queue = scheduler_run_queue(cpu_index);
    if (!queue)
    {
        return;
    }

    uint64_t flags = run_queue_lock_acquire(queue, "enqueue_current");
    if (thread_in_run_queue_load(thread))
    {
        run_queue_lock_release(queue, flags);
        return;
    }

    thread->state = THREAD_STATE_READY;
    thread->wake_pending = false;
    thread->in_transition = false;

    spinlock_lock(&thread->context_lock);
    thread->context_valid = true;
    spinlock_unlock(&thread->context_lock);

    run_queue_push_locked(queue, thread);

    scheduler_verify_run_queue_locked(queue, "enqueue_current_thread_local");
    run_queue_lock_release(queue, flags);
    scheduler_log_enqueue(thread, cpu_index, "current");
    scheduler_shell_log("enqueued", thread);
}

static void enqueue_current_thread_local(thread_t *thread)
{
    enqueue_current_thread_local_locked(thread);
}

static void enqueue_thread_on_cpu_locked(thread_t *thread, uint32_t cpu_index)
{
    if (!thread || thread->is_idle || !thread_lifetime_active(thread) || thread->pending_destroy)
    {
        return;
    }

    uint32_t target_cpu = cpu_index;
    uint32_t limit = scheduler_cpu_limit();
    if (target_cpu >= limit || !scheduler_cpu_online(target_cpu))
    {
        target_cpu = scheduler_select_target_cpu(thread);
    }
    run_queue_t *queue = scheduler_run_queue(target_cpu);
    if (!queue)
    {
        return;
    }

    uint64_t flags = run_queue_lock_acquire(queue, "enqueue");

    if (!thread_lifetime_active(thread) ||
        thread->pending_destroy ||
        thread_in_run_queue_load(thread))
    {
        thread_debug_check_ownership(thread, "enqueue_reconcile");
        run_queue_lock_release(queue, flags);
        return;
    }

    uint32_t rc = __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE);
    if (rc != RUN_QUEUE_CPU_INVALID)
    {
        thread_debug_check_ownership(thread, "enqueue_running");
        thread_t *slot = (rc < SMP_MAX_CPUS) ? g_current_threads[rc] : NULL;
        serial_printf("[sched dbg] enqueue_blocked rc=%u slot_thread=%s slot_pid=0x%016llX\r\n",
                      rc,
                      scheduler_thread_name(slot),
                      (unsigned long long)scheduler_thread_pid(slot));
        run_queue_lock_release(queue, flags);
        return;
    }

    thread->in_transition = false;
    thread->wake_pending = false;
    thread->state = THREAD_STATE_READY;
    thread_clear_running_cpu(thread);
    spinlock_lock(&thread->context_lock);
    thread->context_valid = true;
    spinlock_unlock(&thread->context_lock);
    run_queue_push_locked(queue, thread);

    scheduler_verify_run_queue_locked(queue, "enqueue_thread_on_cpu");
    run_queue_lock_release(queue, flags);
    scheduler_log_enqueue(thread, target_cpu, "enqueue");
    scheduler_shell_log("enqueued", thread);
}

static void enqueue_thread_on_cpu(thread_t *thread, uint32_t cpu_index)
{
    uint64_t flags = scheduler_lock_acquire("enqueue_thread_on_cpu");
    enqueue_thread_on_cpu_locked(thread, cpu_index);
    scheduler_lock_release(flags);
}


static void enqueue_thread(thread_t *thread)
{
    if (!thread || thread->is_idle)
    {
        return;
    }
    uint32_t cpu_index = scheduler_select_target_cpu(thread);
    enqueue_thread_on_cpu(thread, cpu_index);
}

static void __attribute__((unused)) thread_freeze_for_stack_watch(thread_t *thread, const char *context)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread)
    {
        return;
    }
    /* Ensure the thread is not present in any run queue before marking blocked. */
    if (thread_in_run_queue_load(thread))
    {
        remove_from_run_queue(thread);
    }
    uint64_t now = timer_ticks();
    uint64_t timeout_ticks = timer_frequency();
    if (timeout_ticks == 0)
    {
        timeout_ticks = 100;
    }
    timeout_ticks /= 2; /* ~500ms default */
    if (timeout_ticks == 0)
    {
        timeout_ticks = 50;
    }
    if (!thread->stack_watch_blocked)
    {
        thread->stack_watch_blocked = true;
        thread->stack_watch_timeout_logged = false;
        thread->context_guard_frozen = true;
        thread->context_guard_freeze_label = context;
        thread->state = THREAD_STATE_BLOCKED;
        thread_in_run_queue_store(thread, false);
        thread->stack_watch_next = g_stack_watch_frozen_head;
        g_stack_watch_frozen_head = thread;
        serial_printf("%s", "[sched] stack watch freeze thread=");
        if (thread->name[0])
        {
            serial_printf("%s", thread->name);
        }
        else
        {
            serial_printf("%s", "<unnamed>");
        }
        serial_printf("%s", " pid=0x");
        serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
        serial_printf("%s", " context=");
        serial_printf("%s", context ? context : "<none>");
        serial_printf("%s", "\r\n");
    }
    thread->stack_watch_freeze_deadline = now + timeout_ticks;
#else
    (void)thread;
    (void)context;
#endif
}

static void stack_watch_remove_frozen(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread)
    {
        return;
    }
    thread_t **cursor = &g_stack_watch_frozen_head;
    while (*cursor)
    {
        if (*cursor == thread)
        {
            *cursor = thread->stack_watch_next;
            thread->stack_watch_next = NULL;
            return;
        }
        cursor = &(*cursor)->stack_watch_next;
    }
#else
    (void)thread;
#endif
}

static void thread_unfreeze_after_stack_watch(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread)
    {
        return;
    }
    bool was_blocked = thread->stack_watch_blocked;
    thread->stack_watch_blocked = false;
    thread->stack_watch_timeout_logged = false;
    thread->context_guard_frozen = false;
    thread->context_guard_freeze_label = NULL;
    if (!was_blocked || thread->exited || thread->state == THREAD_STATE_ZOMBIE)
    {
        stack_watch_remove_frozen(thread);
        thread->stack_watch_next = NULL;
        thread->stack_watch_freeze_deadline = 0;
        return;
    }
    stack_watch_remove_frozen(thread);
    thread->stack_watch_next = NULL;
    thread->stack_watch_freeze_deadline = 0;
    if (!thread_lifetime_active(thread) || thread->pending_destroy)
    {
        return;
    }
    thread_clear_running_cpu(thread);
    thread->state = THREAD_STATE_READY;
    thread->preempt_pending = false;
#if ENABLE_CONTEXT_GUARD
    thread_context_guard_update(thread, "stack_watch_resume");
#endif
    enqueue_thread(thread);
#else
    (void)thread;
#endif
}

static void stack_watch_check_timeouts(void)
{
#if ENABLE_STACK_WRITE_DEBUG
    uint64_t now = timer_ticks();
    thread_t **cursor = &g_stack_watch_frozen_head;
    while (*cursor)
    {
        thread_t *thread = *cursor;
        if (!thread_lifetime_active(thread))
        {
            *cursor = thread->stack_watch_next;
            thread->stack_watch_next = NULL;
            continue;
        }
        if (!thread->stack_watch_blocked)
        {
            *cursor = thread->stack_watch_next;
            thread->stack_watch_next = NULL;
            continue;
        }
        if (now >= thread->stack_watch_freeze_deadline)
        {
            uintptr_t delta_addr = 0;
            uint8_t old_byte = 0;
            uint8_t new_byte = 0;
            if (thread_stack_watch_snapshot_changed(thread, &delta_addr, &old_byte, &new_byte))
            {
                serial_printf("%s", "[sched] stack watch delta thread=");
                if (thread->name[0])
                {
                    serial_printf("%s", thread->name);
                }
                else
                {
                    serial_printf("%s", "<unnamed>");
                }
                serial_printf("%s", " pid=0x");
                serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
                serial_printf("%s", " addr=0x");
                serial_printf("%016llX", (unsigned long long)(delta_addr));
                serial_printf("%s", " old=0x");
                serial_printf("%02X", (unsigned int)(old_byte));
                serial_printf("%s", " new=0x");
                serial_printf("%02X", (unsigned int)(new_byte));
                serial_printf("%s", "\r\n");
                thread_scan_stack_for_suspicious_values(thread,
                                                        delta_addr,
                                                        true,
                                                        "stack_watch_delta");
                thread_stack_watch_deactivate(thread);
                thread_unfreeze_after_stack_watch(thread);
                continue;
            }

            if (!thread->stack_watch_timeout_logged)
            {
                serial_printf("[sched] stack watch timeout thread=%s pid=0x%016llX suspect=0x%016llX\r\n",
                              thread->name[0] ? thread->name : "<unnamed>",
                              (unsigned long long)(thread->process ? thread->process->pid : 0),
                              (unsigned long long)(thread->stack_watch_suspect));
                thread->stack_watch_timeout_logged = true;
            }

            thread->stack_watch_timeout_count++;
            if (thread->stack_watch_timeout_count >= STACK_WATCH_TIMEOUT_LIMIT)
            {
                serial_printf("[sched] stack watch release thread=%s pid=0x%016llX reason=timeout_limit\r\n",
                              thread->name[0] ? thread->name : "<unnamed>",
                              (unsigned long long)(thread->process ? thread->process->pid : 0));
                thread_stack_watch_deactivate(thread);
                thread_unfreeze_after_stack_watch(thread);
                continue;
            }

            uint64_t extension = timer_frequency();
            if (extension == 0)
            {
                extension = 100;
            }
            extension /= 2;
            if (extension == 0)
            {
                extension = 50;
            }
            thread->stack_watch_freeze_deadline = now + extension;
            cursor = &thread->stack_watch_next;
            continue;
        }
        cursor = &thread->stack_watch_next;
    }
#else
    (void)0;
#endif
}

static bool thread_can_run(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    if (thread->in_transition)
    {
        return false;
    }
    if (thread->state != THREAD_STATE_READY)
    {
        return false;
    }
    return true;
}

static void remove_from_run_queue(thread_t *thread)
{
    if (!thread)
    {
        return;
    }

    if (!thread_in_run_queue_load(thread))
    {
        return;
    }

    uint32_t cpu_count = scheduler_cpu_limit();
    uint32_t start = (thread->run_queue_cpu < cpu_count) ? thread->run_queue_cpu : 0;
    for (uint32_t attempt = 0; attempt < cpu_count; ++attempt)
    {
        uint32_t target = (start + attempt) % cpu_count;
        run_queue_t *queue = scheduler_run_queue(target);
        if (!queue)
        {
            continue;
        }
        uint64_t sched_flags = scheduler_lock_acquire("remove_from_run_queue");
        uint64_t flags = run_queue_lock_acquire(queue, "remove");
        if (!thread_in_run_queue_load(thread))
        {
            run_queue_lock_release(queue, flags);
            scheduler_lock_release(sched_flags);
            return;
        }
        bool removed = run_queue_detach_locked(queue, thread);
        if (removed)
        {
            scheduler_verify_run_queue_locked(queue, "remove_from_run_queue");
            run_queue_lock_release(queue, flags);
            scheduler_lock_release(sched_flags);
            return;
        }
        run_queue_lock_release(queue, flags);
        scheduler_lock_release(sched_flags);
    }
#if ENABLE_RUN_QUEUE_DEBUG
    serial_printf("[sched] remove_from_run_queue: thread=%s pid=0x%016llX flagged but not in any queue\r\n",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0));
#endif
}

static bool scheduler_thread_in_any_queue(thread_t *thread)
{
    if (!thread)
    {
        return false;
    }

    if (!thread_in_run_queue_load(thread))
    {
        return false;
    }

    uint32_t cpu_count = scheduler_cpu_limit();
    for (uint32_t cpu = 0; cpu < cpu_count; ++cpu)
    {
        run_queue_t *queue = scheduler_run_queue(cpu);
        if (!queue)
        {
            continue;
        }
        uint64_t flags = run_queue_lock_acquire(queue, "contains");
        thread_priority_t priority = scheduler_queue_priority();
        for (thread_t *cursor = queue->heads[priority]; cursor; cursor = cursor->queue_next)
        {
            if (cursor == thread)
            {
                run_queue_lock_release(queue, flags);
                return true;
            }
        }
        run_queue_lock_release(queue, flags);
    }

    return false;
}

static thread_priority_t thread_clamp_priority(thread_priority_t priority)
{
    if (priority < THREAD_PRIORITY_IDLE)
    {
        return THREAD_PRIORITY_IDLE;
    }
    if (priority >= THREAD_PRIORITY_COUNT)
    {
        return (thread_priority_t)(THREAD_PRIORITY_COUNT - 1);
    }
    return priority;
}

static thread_priority_t thread_effective_priority(const thread_t *thread)
{
    if (!thread)
    {
        return THREAD_PRIORITY_NORMAL;
    }
    thread_priority_t priority = thread->priority_override_active
                                 ? thread->priority_override
                                 : thread->base_priority;
    return thread_clamp_priority(priority);
}

static void thread_refresh_priority(thread_t *thread)
{
    if (!thread_pointer_valid(thread))
    {
        return;
    }
    thread_priority_t desired = thread_effective_priority(thread);
    if (thread->priority == desired)
    {
        return;
    }
    if (thread_in_run_queue_load(thread))
    {
        remove_from_run_queue(thread);
    }
    thread->priority = desired;
    if (thread->state == THREAD_STATE_READY)
    {
        enqueue_thread(thread);
    }
}

static void thread_set_base_priority(thread_t *thread, thread_priority_t priority)
{
    if (!thread_pointer_valid(thread))
    {
        return;
    }
    thread->base_priority = thread_clamp_priority(priority);
    if (!thread->priority_override_active)
    {
        thread_refresh_priority(thread);
    }
}

static void thread_set_priority_override(thread_t *thread, bool enabled, thread_priority_t priority)
{
    if (!thread_pointer_valid(thread))
    {
        return;
    }
    if (enabled)
    {
        thread->priority_override_active = true;
        thread->priority_override = thread_clamp_priority(priority);
    }
    else
    {
        thread->priority_override_active = false;
    }
    thread_refresh_priority(thread);
}

static void thread_remove_from_wait_queue(thread_t *thread)
{
    wait_queue_t *queue = (thread && thread->waiting_queue) ? thread->waiting_queue : NULL;
    if (!queue)
    {
        return;
    }

    thread_t *prev = NULL;
    thread_t *cursor = queue->head;
    while (cursor)
    {
        if (cursor == thread)
        {
            if (prev)
            {
                prev->wait_queue_next = cursor->wait_queue_next;
            }
            else
            {
                queue->head = cursor->wait_queue_next;
            }
            if (queue->tail == cursor)
            {
                queue->tail = prev;
            }
            break;
        }
        prev = cursor;
        cursor = cursor->wait_queue_next;
    }

    thread->waiting_queue = NULL;
    thread->wait_queue_next = NULL;
}

static void sleep_queue_insert(thread_t *thread)
{
    if (!thread)
    {
        return;
    }
    spinlock_lock(&g_sleep_queue_lock);
    thread->sleeping = true;
    thread->sleep_queue_next = NULL;

    if (!g_sleep_queue_head || thread->sleep_until_tick < g_sleep_queue_head->sleep_until_tick)
    {
        thread->sleep_queue_next = g_sleep_queue_head;
        g_sleep_queue_head = thread;
        spinlock_unlock(&g_sleep_queue_lock);
        return;
    }

    thread_t *prev = g_sleep_queue_head;
    thread_t *cursor = g_sleep_queue_head->sleep_queue_next;
    while (cursor && cursor->sleep_until_tick <= thread->sleep_until_tick)
    {
        prev = cursor;
        cursor = cursor->sleep_queue_next;
    }
    prev->sleep_queue_next = thread;
    thread->sleep_queue_next = cursor;
    spinlock_unlock(&g_sleep_queue_lock);
}

static void sleep_queue_remove(thread_t *thread)
{
    if (!thread || !thread->sleeping)
    {
        return;
    }

    spinlock_lock(&g_sleep_queue_lock);
    if (g_sleep_queue_head == thread)
    {
        g_sleep_queue_head = thread->sleep_queue_next;
        thread->sleep_queue_next = NULL;
        thread->sleeping = false;
        spinlock_unlock(&g_sleep_queue_lock);
        return;
    }

    thread_t *prev = g_sleep_queue_head;
    thread_t *cursor = g_sleep_queue_head ? g_sleep_queue_head->sleep_queue_next : NULL;
    while (cursor)
    {
        if (cursor == thread)
        {
            prev->sleep_queue_next = cursor->sleep_queue_next;
            thread->sleep_queue_next = NULL;
            thread->sleeping = false;
            spinlock_unlock(&g_sleep_queue_lock);
            return;
        }
        prev = cursor;
        cursor = cursor->sleep_queue_next;
    }
    thread->sleeping = false;
    thread->sleep_queue_next = NULL;
    spinlock_unlock(&g_sleep_queue_lock);
}

static void sleep_queue_wake_due(uint64_t now)
{
    uint64_t sched_flags = scheduler_lock_acquire("sleep_queue_wake_due");
    spinlock_lock(&g_sleep_queue_lock);
    while (g_sleep_queue_head && g_sleep_queue_head->sleep_until_tick <= now)
    {
        thread_t *thread = g_sleep_queue_head;
        g_sleep_queue_head = thread->sleep_queue_next;
        thread->sleep_queue_next = NULL;
        thread->sleeping = false;
        spinlock_unlock(&g_sleep_queue_lock);
        serial_printf("[sleep] wake thread=%s pid=0x%016llX now=%llu wake_tick=%llu\r\n",
                      thread->name[0] ? thread->name : "<unnamed>",
                      (unsigned long long)(thread->process ? thread->process->pid : 0),
                      (unsigned long long)now,
                      (unsigned long long)thread->sleep_until_tick);
        if (thread_lifetime_active(thread) &&
            !thread->pending_destroy &&
            thread->state == THREAD_STATE_BLOCKED)
        {
            uint32_t rc = __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE);
            if (rc != RUN_QUEUE_CPU_INVALID)
            {
                thread->wake_pending = true;
                serial_printf("[sleep] wake_pending thread=%s pid=0x%016llX running_cpu=%u state=%s\r\n",
                              thread->name[0] ? thread->name : "<unnamed>",
                              (unsigned long long)(thread->process ? thread->process->pid : 0),
                              rc,
                              thread_state_name(thread->state));
            }
            else
            {
                thread->state = THREAD_STATE_READY;
                serial_printf("[sleep] wake_enqueue thread=%s pid=0x%016llX\r\n",
                              thread->name[0] ? thread->name : "<unnamed>",
                              (unsigned long long)(thread->process ? thread->process->pid : 0));
                uint32_t target = scheduler_select_target_cpu(thread);
                /* scheduler_lock is already held; use the locked enqueue path to avoid deadlock. */
                enqueue_thread_on_cpu_locked(thread, target);
            }
        }
        spinlock_lock(&g_sleep_queue_lock);
    }
    spinlock_unlock(&g_sleep_queue_lock);
    scheduler_lock_release(sched_flags);
}

static void process_attach_child(process_t *parent, process_t *child)
{
    if (!child)
    {
        return;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    child->parent = parent;
    child->sibling_prev = NULL;
    if (parent)
    {
        child->sibling_next = parent->first_child;
        if (child->sibling_next)
        {
            child->sibling_next->sibling_prev = child;
        }
        parent->first_child = child;
    }
    else
    {
        child->sibling_next = NULL;
    }

    cpu_restore_flags(flags);
}

static void process_detach_child(process_t *child)
{
    if (!child)
    {
        return;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    process_t *parent = child->parent;
    if (parent && parent->first_child == child)
    {
        parent->first_child = child->sibling_next;
    }
    if (child->sibling_prev)
    {
        child->sibling_prev->sibling_next = child->sibling_next;
    }
    if (child->sibling_next)
    {
        child->sibling_next->sibling_prev = child->sibling_prev;
    }

    child->parent = NULL;
    child->sibling_prev = NULL;
    child->sibling_next = NULL;

    cpu_restore_flags(flags);
}

static process_t *process_detach_first_child(process_t *parent)
{
    if (!parent)
    {
        return NULL;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    process_t *child = parent->first_child;
    if (child)
    {
        if (parent->first_child == child)
        {
            parent->first_child = child->sibling_next;
        }
        if (child->sibling_prev)
        {
            child->sibling_prev->sibling_next = child->sibling_next;
        }
        if (child->sibling_next)
        {
            child->sibling_next->sibling_prev = child->sibling_prev;
        }
        child->parent = NULL;
        child->sibling_prev = NULL;
        child->sibling_next = NULL;
    }

    cpu_restore_flags(flags);
    return child;
}

static void process_reap_orphans(void)
{
    while (1)
    {
        process_t *target = NULL;

        uint64_t flags = cpu_save_flags();
        cpu_cli();

        spinlock_lock(&g_process_lock);
        for (process_t *proc = g_process_list; proc; proc = proc->next)
        {
            if (proc->state == PROCESS_STATE_ZOMBIE &&
                proc->parent == NULL &&
                proc != g_idle_process)
            {
                target = proc;
                break;
            }
        }
        spinlock_unlock(&g_process_lock);

        cpu_restore_flags(flags);

        if (!target)
        {
            break;
        }

        process_destroy(target);
    }
}

static void thread_quarantine_corrupt(thread_t *thread, const char *reason)
{
    if (!thread || thread->pending_destroy)
    {
        return;
    }

    const char *name = thread->name[0] ? thread->name : "<unnamed>";
    uint64_t pid = thread->process ? thread->process->pid : 0;
    serial_printf("[sched] quarantine thread=%s pid=0x%016llX reason=%s\r\n",
                  name,
                  (unsigned long long)pid,
                  reason ? reason : "<unknown>");

    thread_stack_watch_deactivate(thread);
#if ENABLE_STACK_WRITE_DEBUG
    stack_watch_remove_frozen(thread);
#endif
    thread_context_guard_release_pages(thread);
    thread_remove_from_wait_queue(thread);
    if (thread->sleeping)
    {
        sleep_queue_remove(thread);
    }
    if (thread_in_run_queue_load(thread))
    {
        remove_from_run_queue(thread);
    }

    thread->fault_reason = reason;
    thread->fault_error_code = 0;
    thread->fault_has_address = false;
    thread->fault_address = 0;
    thread->exited = true;
    thread->exit_status = -1;
    thread->state = THREAD_STATE_ZOMBIE;
    thread->preempt_pending = false;
    thread->time_slice_remaining = 0;
    thread->in_transition = false;
    thread->context_valid = false;
    thread->running_cpu = RUN_QUEUE_CPU_INVALID;

    process_t *proc = thread->process;
    if (proc && proc->state != PROCESS_STATE_ZOMBIE)
    {
        proc->exit_status = -1;
        proc->state = PROCESS_STATE_ZOMBIE;
        wait_queue_wake_all(&proc->wait_queue);
    }

    thread_enqueue_deferred_free(thread);
}

static bool switch_to_thread(thread_t *next)
{
    uint64_t switch_start_ticks = timer_ticks();
    deferred_free_stats_t deferred_stats = { 0 };
    bool deferred_work = false;

    thread_t *prev = current_thread_local();
    process_t *prev_process = prev ? prev->process : NULL;
    process_t *next_process = next ? next->process : NULL;
    uint32_t cpu_idx = current_cpu_index();
    uint64_t sched_lock_enter = scheduler_lock_acquire("switch_to_thread");
    scheduler_log_current_slot(cpu_idx, "switch_enter");

    if (!next || !thread_pointer_valid(next))
    {
        if (next)
        {
            scheduler_log_running_cpu_change(next, RUN_QUEUE_CPU_INVALID, "switch_to_thread_invalid");
            __atomic_store_n(&next->running_cpu, RUN_QUEUE_CPU_INVALID, __ATOMIC_RELEASE);
            next->in_transition = false;
        }
        scheduler_lock_release(sched_lock_enter);
        return false;
    }

    if (!next->is_idle && (next->state == THREAD_STATE_ZOMBIE || next->pending_destroy))
    {
        thread_quarantine_corrupt(next, "switch_to_zombie");
        scheduler_lock_release(sched_lock_enter);
        return false;
    }

    if (!next->is_idle && (!next->context || !next->stack_base || next->kernel_stack_top == 0))
    {
        thread_quarantine_corrupt(next, "switch_to_missing_context");
        scheduler_lock_release(sched_lock_enter);
        return false;
    }

    if (!thread_context_in_bounds(next, "switch_to"))
    {
        thread_quarantine_corrupt(next, "switch_to_ctx_bounds");
        scheduler_lock_release(sched_lock_enter);
        return false;
    }

    if (!thread_stack_guard_intact(next))
    {
        thread_quarantine_corrupt(next, "stack_guard_corrupt");
        scheduler_lock_release(sched_lock_enter);
        return false;
    }

    if (!thread_fpu_region_valid(next))
    {
        thread_quarantine_corrupt(next, "fpu_region_invalid");
        scheduler_lock_release(sched_lock_enter);
        return false;
    }

    if (prev && !thread_context_in_bounds(prev, "switch_from"))
    {
        scheduler_lock_release(sched_lock_enter);
        fatal("context pointer out of bounds (switch_from)");
    }

    if (prev)
    {
        prev->last_cpu_index = cpu_idx;
        thread_assert_stack_current(prev, "switch_from");
        fpu_save_state(&prev->fpu_state);
        prev->fs_base = rdmsr(MSR_FS_BASE);
        prev->gs_base = rdmsr(MSR_GS_BASE);
        if (prev_process)
        {
            prev_process->current_thread = prev;
        }
    }

    if (prev_process && prev_process->state != PROCESS_STATE_ZOMBIE && prev != next)
    {
        prev_process->state = PROCESS_STATE_READY;
    }

    next->last_cpu_index = cpu_idx;
    next->state = THREAD_STATE_RUNNING;
    next->preempt_pending = false;
    next->wake_pending = false;
    next->time_slice_remaining = scheduler_time_slice_ticks();
    next->in_transition = true;
    scheduler_log_running_cpu_change(next, cpu_idx, "claim");
    __atomic_store_n(&next->running_cpu, cpu_idx, __ATOMIC_RELEASE);

    if (next_process)
    {
        next_process->state = PROCESS_STATE_RUNNING;
        next_process->current_thread = next;
    }

    thread_context_guard_release_pages(next);
    thread_stack_watch_deactivate(next);
    spinlock_lock(&next->context_lock);
    next->context_valid = true;
    spinlock_unlock(&next->context_lock);

    uint64_t desired_cr3 = next_process ? next_process->cr3 : read_cr3();
    if (desired_cr3 && desired_cr3 != read_cr3())
    {
        write_cr3(desired_cr3);
    }

    arch_cpu_set_kernel_stack(cpu_idx, next->kernel_stack_top);
    wrmsr(MSR_FS_BASE, next->fs_base);
    wrmsr(MSR_GS_BASE, sanitize_gs_base(next));
    fpu_restore_state(&next->fpu_state);

    cpu_context_t **prev_ctx = prev ? &prev->context : &g_bootstrap_context;
    cpu_context_t *next_ctx = next->context;
    if (!next_ctx)
    {
        scheduler_log_running_cpu_change(next, RUN_QUEUE_CPU_INVALID, "switch_to_thread_missing_ctx");
        __atomic_store_n(&next->running_cpu, RUN_QUEUE_CPU_INVALID, __ATOMIC_RELEASE);
        next->in_transition = false;
        scheduler_lock_release(sched_lock_enter);
        return false;
    }
    /* Log upcoming context pointer and stack info. */
    uint64_t rsp_now = 0;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(rsp_now));
    serial_printf("[sched dbg] switch_ctx cpu=%u next=%s pid=0x%016llX next_ctx=0x%016llX next_stack_base=0x%016llX next_stack_top=0x%016llX current_rsp=0x%016llX\r\n",
                  (unsigned)cpu_idx,
                  scheduler_thread_name(next),
                  (unsigned long long)scheduler_thread_pid(next),
                  (unsigned long long)(uintptr_t)next_ctx,
                  (unsigned long long)((uintptr_t)next->stack_base),
                  (unsigned long long)next->kernel_stack_top,
                  (unsigned long long)rsp_now);

    uint8_t *prev_transition_flag = NULL;
    if (prev && prev != next)
    {
        prev->in_transition = true;
        prev_transition_flag = (uint8_t *)&prev->in_transition;
#if ENABLE_CONTEXT_GUARD
        thread_context_guard_update(prev, "switch_from_saved");
#endif
#if ENABLE_STACK_WRITE_DEBUG
        thread_stack_watch_maybe_arm(prev);
#endif
    }

    /* Advertise the incoming thread as current on this CPU before switching. */
    set_current_thread_local(next);
    set_current_process_local(next_process);

    scheduler_log_state_event("context_switch_enter", next, "switch_to_thread");
    scheduler_lock_release(sched_lock_enter);
    context_switch(prev_ctx, next_ctx, prev_transition_flag, NULL);

    thread_t *resumed = current_thread_local();
    if (!resumed)
    {
        fatal("context_switch return with no current thread");
    }

    process_t *resumed_process = resumed->process;
    uint32_t resumed_cpu = current_cpu_index();
    uint64_t sched_lock_resume = scheduler_lock_acquire("switch_to_thread_resume");
    set_current_thread_local(resumed);
    set_current_process_local(resumed_process);
    scheduler_log_current_slot(resumed_cpu, "switch_resume");
    if (prev && prev != resumed)
    {
        uint32_t expected = cpu_idx;
        uint32_t observed = __atomic_load_n(&prev->running_cpu, __ATOMIC_ACQUIRE);
        if (observed == expected)
        {
            scheduler_log_running_cpu_change(prev, RUN_QUEUE_CPU_INVALID, "clear_prev");
            __atomic_store_n(&prev->running_cpu, RUN_QUEUE_CPU_INVALID, __ATOMIC_RELEASE);
        }
        else
        {
            thread_debug_check_ownership(prev, "switch_clear_mismatch");
        }
        if (prev->wake_pending &&
            prev->state == THREAD_STATE_BLOCKED &&
            thread_lifetime_active(prev) &&
            !prev->pending_destroy &&
            !thread_in_run_queue_load(prev))
        {
            prev->wake_pending = false;
            prev->state = THREAD_STATE_READY;
            prev->in_transition = false;
            enqueue_thread_on_cpu_locked(prev, resumed_cpu);
        }
    }

    if (prev_process && prev_process != resumed_process)
    {
        paging_space_clear_active_cpu(&prev_process->address_space, resumed_cpu);
    }
    if (resumed_process)
    {
        paging_space_mark_active_cpu(&resumed_process->address_space, resumed_cpu);
    }

    resumed->in_transition = false;
    scheduler_log_running_cpu_change(resumed, resumed_cpu, "resume");
    __atomic_store_n(&resumed->running_cpu, resumed_cpu, __ATOMIC_RELEASE);
    resumed->state = THREAD_STATE_RUNNING;
    if (resumed_process)
    {
        resumed_process->state = PROCESS_STATE_RUNNING;
        resumed_process->current_thread = resumed;
    }

    arch_cpu_set_kernel_stack(resumed_cpu, resumed->kernel_stack_top);
    wrmsr(MSR_FS_BASE, resumed->fs_base);
    wrmsr(MSR_GS_BASE, sanitize_gs_base(resumed));

    spinlock_lock(&resumed->context_lock);
    resumed->context_valid = true;
    spinlock_unlock(&resumed->context_lock);

#if ENABLE_CONTEXT_GUARD
    if (resumed->context_guard_enabled)
    {
        thread_context_guard_update(resumed, "resumed");
    }
#endif
    scheduler_shell_log("context_valid=true (resumed)", resumed);

    if (resumed_process)
    {
        paging_space_mark_active_cpu(&resumed_process->address_space, resumed_cpu);
    }

    deferred_work = thread_process_deferred_frees(cpu_idx, &deferred_stats);

    uint64_t switch_elapsed_ms = scheduler_ticks_to_ms(timer_ticks() - switch_start_ticks);
    if (switch_elapsed_ms >= SCHED_SWITCH_WARN_MS)
    {
        scheduler_log_switch_latency(switch_elapsed_ms, prev, next, deferred_work, &deferred_stats);
    }

    scheduler_lock_release(sched_lock_resume);
    return true;
}

__attribute__((visibility("default"))) void scheduler_schedule(bool requeue_current)
{
    uint64_t sched_watch = timer_ticks();

    while (1)
    {
        uint64_t sched_flags = scheduler_lock_acquire("schedule");

        uint32_t cpu_index = current_cpu_index();
        thread_t *current = current_thread_local();

        if (!current || current->is_idle)
        {
            requeue_current = false;
        }

        if (current && current->wake_pending)
        {
            requeue_current = true;
        }

        bool have_current = current &&
                            !current->is_idle &&
                            current->state == THREAD_STATE_RUNNING;
        bool wake_blocked_current = current &&
                                    !current->is_idle &&
                                    current->wake_pending &&
                                    current->state == THREAD_STATE_BLOCKED;

        if (requeue_current && (have_current || wake_blocked_current))
        {
            current->wake_pending = false;
            current->state = THREAD_STATE_READY;
            current->time_slice_remaining = scheduler_time_slice_ticks();
            current->preempt_pending = false;
            current->in_transition = false;
            /* Clear ownership before putting back in a run queue. */
            __atomic_store_n(&current->running_cpu, RUN_QUEUE_CPU_INVALID, __ATOMIC_RELEASE);
            enqueue_current_thread_local(current);
            have_current = false;
        }

        thread_t *next = dequeue_thread_for_cpu(cpu_index);
        if (!next && have_current)
        {
            current->preempt_pending = false;
            current->time_slice_remaining = scheduler_time_slice_ticks();
            scheduler_lock_release(sched_flags);
            scheduler_log_if_stalled("scheduler_schedule(run_current)", sched_watch);
            return;
        }

        if (!next)
        {
            thread_t *idle = g_idle_threads[cpu_index];
            if (!idle)
            {
                fatal("no idle thread for cpu");
            }
            next = idle;
        }

        if (next == current && current)
        {
            current->state = THREAD_STATE_RUNNING;
            current->preempt_pending = false;
            current->wake_pending = false;
            current->time_slice_remaining = scheduler_time_slice_ticks();
            current->in_transition = false;
        scheduler_log_running_cpu_change(current, cpu_index, "run_current_fast");
        __atomic_store_n(&current->running_cpu, cpu_index, __ATOMIC_RELEASE);
        spinlock_lock(&current->context_lock);
        current->context_valid = true;
        spinlock_unlock(&current->context_lock);
        scheduler_lock_release(sched_flags);
        scheduler_log_if_stalled("scheduler_schedule(run_current)", sched_watch);
        return;
    }

    if (next && next->is_idle && !current)
    {
        /* Nothing runnable; stay idle and return. */
        serial_printf("[sched] idle return cpu=%u\r\n", (unsigned)cpu_index);
        scheduler_lock_release(sched_flags);
        scheduler_log_if_stalled("scheduler_schedule(idle_return)", sched_watch);
        return;
    }

        scheduler_log_pick(current, next, cpu_index, requeue_current ? "requeue" : "switch");
        if (next != current)
        {
            __atomic_fetch_add(&g_scheduler_switch_count, 1ULL, __ATOMIC_RELAXED);
        }
        scheduler_lock_release(sched_flags);

        while (next && !switch_to_thread(next))
        {
            scheduler_trace("[sched] switch_to failed; retry", next);
            sched_flags = scheduler_lock_acquire("schedule-retry");
            next = dequeue_thread_for_cpu(cpu_index);
            if (!next)
            {
                next = g_idle_threads[cpu_index];
            }
            scheduler_lock_release(sched_flags);
        }

        scheduler_log_if_stalled("scheduler_schedule", sched_watch);
        process_reap_orphans();
        return;
    }
}

static void idle_thread_entry(void *arg)
{
    (void)arg;
    while (1)
    {
        __asm__ volatile ("hlt");
        scheduler_schedule(false);
    }
}

void process_preempt_hook(void)
{
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        return;
    }

    thread->preempt_pending = false;

    process_yield();

    thread = current_thread_local();
    if (thread)
    {
        thread->preempt_pending = false;
    }
}

static __attribute__((noreturn)) void process_jump_to_user(uintptr_t entry,
                                                           uintptr_t user_stack_top,
                                                           uint64_t argc,
                                                           uintptr_t argv_ptr)
{
    uintptr_t aligned_stack = align_down_uintptr(user_stack_top, 16ULL);
    uintptr_t stack_value = aligned_stack;
    uintptr_t entry_value = entry;
    uint64_t rflags = RFLAGS_DEFAULT;
    uint64_t cs = (uint64_t)(GDT_SELECTOR_USER_CODE | 0x3u);
    uint64_t ss = (uint64_t)(GDT_SELECTOR_USER_DATA | 0x3u);
    uint64_t data_sel = (uint64_t)(GDT_SELECTOR_USER_DATA | 0x3u);

    __asm__ volatile (
        "mov %[ds], %%rax\n\t"
        "mov %%ax, %%ds\n\t"
        "mov %%ax, %%es\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "mov %[ss], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[stack], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[rflags], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[cs], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[entry], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[argc], %%rdi\n\t"
        "mov %[argv], %%rsi\n\t"
        "iretq\n\t"
        :
        : [ds]"r"(data_sel),
          [ss]"r"(ss),
          [stack]"m"(stack_value),
          [rflags]"r"(rflags),
          [cs]"r"(cs),
          [entry]"m"(entry_value),
          [argc]"r"(argc),
          [argv]"r"(argv_ptr)
        : "rax", "rdx", "rcx", "r8", "r9", "r10", "r11", "memory");
    __builtin_unreachable();
}

static void user_thread_entry(void *arg)
{
    user_thread_bootstrap_t params = { 0 };
    if (arg)
    {
        memcpy(&params, arg, sizeof(params));
        free(arg);
    }
    if (!params.entry || !params.stack_top)
    {
        fatal("user thread bootstrap missing entry/stack");
    }
    process_jump_to_user(params.entry, params.stack_top, params.argc, params.argv_ptr);
}

static void thread_trampoline(void)
{
    thread_t *self = current_thread_local();
    if (self)
    {
        serial_printf("[thread_trampoline] start name=%s arg=0x%016llX entry=0x%016llX\r\n",
                      self->name[0] ? self->name : "<unnamed>",
                      (unsigned long long)((uintptr_t)self->arg),
                      (unsigned long long)((uintptr_t)self->entry));
    }
    if (self && self->entry)
    {
        self->entry(self->arg);
    }
    process_exit(0);
}

static void process_handle_stack_guard_fault(void)
{
    thread_t *current = current_thread_local();
    if (!current)
    {
        fatal("stack guard fault with no current thread");
    }

    serial_printf("%s", "process: stack guard violation in thread ");
    if (current->name[0] != '\0')
    {
        serial_printf("%s", current->name);
    }
    else
    {
        serial_printf("%s", "(anon)");
    }
    if (current->stack_guard_reason)
    {
        serial_printf("%s", " reason=");
        serial_printf("%s", current->stack_guard_reason);
    }
    serial_printf("%s", "\r\n");

    current->exit_status = -1;
    current->exited = true;
    current->state = THREAD_STATE_ZOMBIE;
    current->preempt_pending = false;
    current->time_slice_remaining = 0;

    process_t *proc = current->process;
    if (proc)
    {
        proc->exit_status = -1;
        proc->state = PROCESS_STATE_ZOMBIE;
        wait_queue_wake_all(&proc->wait_queue);
    }

    scheduler_schedule(false);
    fatal("stack guard handler returned");
}

static void process_handle_fatal_fault(void)
{
    thread_t *current = current_thread_local();
    if (!current)
    {
        fatal("fatal fault handler without current thread");
    }

    current->exit_status = -1;
    current->exited = true;
    current->state = THREAD_STATE_ZOMBIE;
    current->preempt_pending = false;
    current->time_slice_remaining = 0;
    if (current->process)
    {
        current->process->exit_status = -1;
        current->process->state = PROCESS_STATE_ZOMBIE;
        wait_queue_wake_all(&current->process->wait_queue);
    }

    serial_printf("%s", "process: fatal fault in thread ");
    if (current->name[0] != '\0')
    {
        serial_printf("%s", current->name);
    }
    else
    {
        serial_printf("%s", "(anon)");
    }
    serial_printf("%s", " reason=");
    if (current->fault_reason)
    {
        serial_printf("%s", current->fault_reason);
    }
    else
    {
        serial_printf("%s", "unknown");
    }
    serial_printf("%s", " error=0x");
    serial_printf("%016llX", (unsigned long long)(current->fault_error_code));
    if (current->fault_has_address)
    {
        serial_printf("%s", " addr=0x");
        serial_printf("%016llX", (unsigned long long)(current->fault_address));
    }
    serial_printf("%s", "\r\n");

    scheduler_schedule(false);
    fatal("fatal fault handler returned");
}

bool process_handle_exception(interrupt_frame_t *frame,
                              const char *reason,
                              uint64_t error_code,
                              bool has_address,
                              uint64_t address)
{
    bool user_mode = frame && ((frame->cs & 0x3u) == 0x3u);
    if (!frame)
    {
        return false;
    }
    thread_t *thread = current_thread_local();
    if (!thread || !(thread->is_user || user_mode))
    {
        return false;
    }
    /* If the thread came from CPL=3 but was mislabeled, forgive the flag so we can unwind it. */
    if (user_mode)
    {
        thread->is_user = true;
    }

    thread->exit_status = -1;
    thread->exited = true;
    thread->state = THREAD_STATE_ZOMBIE;
    thread->preempt_pending = false;
    thread->time_slice_remaining = 0;

    process_t *proc = thread->process;
    if (proc)
    {
        proc->exit_status = -1;
        proc->state = PROCESS_STATE_ZOMBIE;
        wait_queue_wake_all(&proc->wait_queue);
    }

    process_trigger_fatal_fault(thread, frame, reason, error_code, has_address, address);
    return true;
}
