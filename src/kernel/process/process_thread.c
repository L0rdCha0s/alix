static void scheduler_trace(const char *prefix, thread_t *thread)
{
    if (!prefix || !thread)
    {
        return;
    }

    const char *name = thread->name[0] ? thread->name : "<unnamed>";
    uint64_t pid = thread->process ? thread->process->pid : 0;
    serial_printf("%s thread=%s pid=0x%016llX state=%s ctx_valid=%s stack=0x%016llX\r\n",
                  prefix,
                  name,
                  (unsigned long long)pid,
                  thread_state_name(thread->state),
                  thread->context_valid ? "true" : "false",
                  (unsigned long long)((uintptr_t)thread->stack_base));
}

static void scheduler_log_state_event(const char *tag,
                                      const thread_t *thread,
                                      const char *where)
{
    if (!thread)
    {
        return;
    }
    uint32_t cpu_idx = current_cpu_index();
    uint32_t running = __atomic_load_n(&((thread_t *)thread)->running_cpu, __ATOMIC_ACQUIRE);
    const char *name = thread->name[0] ? thread->name : "<unnamed>";
    uint64_t rsp_now = 0;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(rsp_now));
    serial_printf("[sched dbg] %s where=%s cpu=%u thread=%s pid=0x%016llX state=%s running_cpu=%u in_run_queue=%s rq_cpu=%u in_transition=%s wake_pending=%s ctx_valid=%s\r\n",
                  tag ? tag : "<none>",
                  where ? where : "<unknown>",
                  (unsigned)cpu_idx,
                  name,
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  thread_state_name(thread->state),
                  running,
                  thread_in_run_queue_load(thread) ? "true" : "false",
                  thread->run_queue_cpu,
                  thread->in_transition ? "true" : "false",
                  thread->wake_pending ? "true" : "false",
                  thread->context_valid ? "true" : "false");
    serial_printf("[sched dbg] stack_ctx cpu=%u thread=%s pid=0x%016llX stack_base=0x%016llX stack_top=0x%016llX rsp=0x%016llX tag=%s\r\n",
                  (unsigned)cpu_idx,
                  name,
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  (unsigned long long)((uintptr_t)thread->stack_base),
                  (unsigned long long)thread->kernel_stack_top,
                  (unsigned long long)rsp_now,
                  where ? where : "<unknown>");
}

static bool __attribute__((unused)) thread_name_equals(const thread_t *thread, const char *name)
{
    if (!thread || !name)
    {
        return false;
    }
    return strncmp(thread->name, name, PROCESS_NAME_MAX) == 0;
}

static bool string_name_equals(const char *lhs, const char *rhs)
{
    if (!lhs || !rhs)
    {
        return false;
    }
    return strncmp(lhs, rhs, PROCESS_NAME_MAX) == 0;
}

#define ENABLE_SHELL_TRACE 0

static void process_create_log(const char *name, const char *event)
{
    if (!ENABLE_SHELL_TRACE)
    {
        return;
    }

    serial_printf("%s", "[proc-trace] process_create ");
    serial_printf("%s", event ? event : "<none>");
    serial_printf("%s", " name=");
    serial_printf("%s", name ? name : "<none>");
    serial_printf("%s", "\r\n");
}

static void scheduler_shell_log(const char *event, thread_t *thread)
{
    if (!ENABLE_SHELL_TRACE || !thread)
    {
        return;
    }

    serial_printf("%s", "[sched-trace] ");
    serial_printf("%s", event);
    serial_printf("%s", " state=");
    serial_printf("%s", thread_state_name(thread->state));
    serial_printf("%s", " ctx_valid=");
    serial_printf("%s", thread->context_valid ? "true" : "false");
    serial_printf("%s", " name=");
    serial_printf("%s", thread->name[0] ? thread->name : "<unnamed>");
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", " rsp0=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)thread->kernel_stack_top));
    serial_printf("%s", "\r\n");
}

static void scheduler_wait_for_boot_ready(void)
{
    while (!__atomic_load_n(&g_scheduler_boot_ready, __ATOMIC_ACQUIRE))
    {
        __asm__ volatile ("hlt");
    }
}

static process_t *process_finalize_new_process(process_t *proc,
                                               thread_t *thread,
                                               int stdout_fd,
                                               process_t *parent)
{
    if (!proc || !thread)
    {
        return NULL;
    }

    if (stdout_fd >= 0)
    {
        proc->stdout_fd = stdout_fd;
    }
    else
    {
        proc->stdout_fd = g_console_stdout_fd;
    }

    proc->main_thread = thread;
    proc->current_thread = thread;
    spinlock_lock(&g_process_lock);
    proc->next = g_process_list;
    g_process_list = proc;
    spinlock_unlock(&g_process_lock);

    process_t *actual_parent = parent ? parent : current_process_local();
    vfs_node_t *inherit_cwd = NULL;
    if (actual_parent)
    {
        process_attach_child(actual_parent, proc);
        inherit_cwd = actual_parent->cwd;
    }

    if (!inherit_cwd)
    {
        inherit_cwd = vfs_root();
    }
    proc->cwd = inherit_cwd;

    enqueue_thread(thread);
    return proc;
}

static thread_t *thread_create(process_t *process,
                               const char *name,
                               thread_entry_t entry,
                               void *arg,
                               size_t stack_size,
                               bool is_idle,
                               bool user_mode)
{
    if (!process || !entry)
    {
        return NULL;
    }

    serial_printf("[thread_create] entry name=%s pre-malloc\r\n", name ? name : "<null>");
    thread_t *thread = (thread_t *)malloc(sizeof(thread_t));
    if (!thread)
    {
        serial_printf("%s", "[thread_create] malloc thread struct failed\r\n");
        return NULL;
    }
    serial_printf("[thread_create] thread struct=0x%016llX\r\n",
                  (unsigned long long)((uintptr_t)thread));
    memset(thread, 0, sizeof(*thread));
    thread->last_cpu_index = RUN_QUEUE_CPU_INVALID;
    thread->deferred_next = NULL;
    thread->pending_destroy = false;
    __atomic_store_n(&thread->lifetime_state, THREAD_LIFETIME_ALIVE, __ATOMIC_RELEASE);
    bool is_user_thread = user_mode;
    if (!is_user_thread && process)
    {
        is_user_thread = process->is_user;
    }

    size_t requested_stack = stack_size ? stack_size : PROCESS_DEFAULT_STACK_SIZE;
    size_t guard_bytes = align_up_uintptr(PROCESS_STACK_GUARD_SIZE, PAGE_SIZE_BYTES_LOCAL);
    size_t aligned_stack = align_up_uintptr(requested_stack, PAGE_SIZE_BYTES_LOCAL);
    size_t allocation_size = guard_bytes + aligned_stack + PAGE_SIZE_BYTES_LOCAL;
    const uintptr_t heap_limit = (uintptr_t)kernel_heap_end;
#if THREAD_CREATE_DEBUG
    serial_printf("[thread_create] begin name=%s stack=0x%016llX aligned=0x%016llX alloc=0x%016llX "
                  "is_user=%s is_idle=%s\r\n",
                  name ? name : "<null>",
                  (unsigned long long)requested_stack,
                  (unsigned long long)aligned_stack,
                  (unsigned long long)allocation_size,
                  is_user_thread ? "true" : "false",
                  is_idle ? "true" : "false");
#endif
    uint8_t *raw_allocation = NULL;
    uint8_t *guard_base = NULL;
    const int max_layout_attempts = 4;
    for (int attempt = 0; attempt < max_layout_attempts; ++attempt)
    {
        raw_allocation = (uint8_t *)malloc(allocation_size);
#if THREAD_CREATE_DEBUG
        serial_printf("[thread_create] attempt=%016llX raw=%016llX\r\n",
                      (unsigned long long)attempt,
                      (unsigned long long)((uintptr_t)raw_allocation));
#endif
        if (!raw_allocation)
        {
            break;
        }
        guard_base = (uint8_t *)align_up_uintptr((uintptr_t)raw_allocation, PAGE_SIZE_BYTES_LOCAL);
        uintptr_t stack_end = (uintptr_t)(guard_base + guard_bytes + aligned_stack);
#if THREAD_CREATE_DEBUG
        serial_printf("[thread_create] layout raw=%016llX guard_base=%016llX stack_end=0x%016llX "
                      "heap_limit=0x%016llX\r\n",
                      (unsigned long long)((uintptr_t)raw_allocation),
                      (unsigned long long)((uintptr_t)guard_base),
                      (unsigned long long)stack_end,
                      (unsigned long long)heap_limit);
#endif
        if (stack_end <= heap_limit)
        {
            break;
        }
        free(raw_allocation);
        raw_allocation = NULL;
    }

    if (!raw_allocation)
    {
#if THREAD_CREATE_DEBUG
        serial_printf("[thread_create] alloc_failed name=%s alloc_size=0x%016llX\r\n",
                      name ? name : "<null>",
                      (unsigned long long)allocation_size);
#endif
        free(thread);
        return NULL;
    }

#if THREAD_CREATE_DEBUG
    serial_printf("[thread_create] using_allocation raw=%016llX guard_base=%016llX guard_bytes=0x%016llX "
                  "aligned_stack=0x%016llX\r\n",
                  (unsigned long long)((uintptr_t)raw_allocation),
                  (unsigned long long)((uintptr_t)guard_base),
                  (unsigned long long)guard_bytes,
                  (unsigned long long)aligned_stack);
#endif

    memset(guard_base, STACK_GUARD_PATTERN, guard_bytes);
    thread->stack_allocation_raw = raw_allocation;
    thread->stack_allocation_size = allocation_size;
    thread->stack_guard_base = guard_base;
    thread->stack_base = guard_base + guard_bytes;
    thread->stack_size = aligned_stack;
    serial_printf("[thread_create] stack prepared base=0x%016llX top=0x%016llX size=0x%016llX\r\n",
                  (unsigned long long)((uintptr_t)thread->stack_base),
                  (unsigned long long)((uintptr_t)(thread->stack_base + aligned_stack)),
                  (unsigned long long)aligned_stack);
#if THREAD_CREATE_DEBUG
    serial_printf("[thread_create] guard_filled base=%016llX size=0x%016llX\r\n",
                  (unsigned long long)((uintptr_t)thread->stack_base),
                  (unsigned long long)thread->stack_size);
#endif

    uintptr_t stack_limit = ((uintptr_t)thread->stack_base + aligned_stack) & ~(uintptr_t)0xF;
    uintptr_t usable_limit = stack_limit;
    uintptr_t redzone = THREAD_CONTEXT_REDZONE_BYTES;
    if (aligned_stack <= redzone + 64)
    {
        redzone = 64;
    }
    if (usable_limit > (uintptr_t)thread->stack_base + redzone)
    {
        usable_limit -= redzone;
        usable_limit &= ~(uintptr_t)0xF;
    }
    uintptr_t stack_ptr = usable_limit;
    uint64_t *stack64 = (uint64_t *)stack_ptr;

    /*
     * Build the initial context frame to mirror context_switch save order:
     * low addresses -> r15, r14, r13, r12, rbx, rbp, rflags, return RIP <- high.
     * After the first return, RSP will be restored to usable_limit.
     */
    *(--stack64) = (uint64_t)thread_trampoline; /* return address (above saved frame) */
    *(--stack64) = RFLAGS_DEFAULT;              /* rflags */
    *(--stack64) = 0;                           /* rbp */
    *(--stack64) = 0;                           /* rbx */
    *(--stack64) = 0;                           /* r12 */
    *(--stack64) = 0;                           /* r13 */
    *(--stack64) = 0;                           /* r14 */
    *(--stack64) = 0;                           /* r15 */

    thread->tls.preempt_resume_rip = 0;
    thread->context = (cpu_context_t *)stack64;
    thread->context_valid = true;
    thread->kernel_stack_top = stack_limit;
    thread->process = process;
    thread->entry = entry;
    thread->arg = arg;
    thread->state = THREAD_STATE_READY;
    thread->queue_next = NULL;
    thread->run_queue_cpu = RUN_QUEUE_CPU_INVALID;
    thread_in_run_queue_store(thread, false);
    thread->is_idle = is_idle;
    thread->exited = false;
    thread->exit_status = 0;
    thread->time_slice_remaining = scheduler_time_slice_ticks();
    thread_priority_t default_priority = is_idle ? THREAD_PRIORITY_IDLE : THREAD_PRIORITY_NORMAL;
    thread->base_priority = default_priority;
    thread->priority = default_priority;
    thread->priority_override = default_priority;
    thread->priority_override_active = false;
    thread->in_transition = false;
    thread->preempt_pending = false;
    thread->fs_base = 0;
    thread->gs_base = (uint64_t)&thread->tls;
    thread->running_cpu = RUN_QUEUE_CPU_INVALID;
    thread->fpu_initialized = true;
    spinlock_init(&thread->context_lock);
    thread->waiting_queue = NULL;
    thread->wait_queue_next = NULL;
    thread->magic = THREAD_MAGIC;
    thread->stack_guard_failed = false;
    thread->stack_guard_reason = NULL;
    thread->is_user = is_user_thread;
    thread->context_guard_enabled = !is_idle;
    thread->fault_reason = NULL;
    thread->fault_error_code = 0;
    thread->fault_address = 0;
    thread->fault_has_address = false;
    thread->sleeping = false;
    thread->wake_pending = false;
    memcpy(&thread->fpu_state, &g_fpu_initial_state, sizeof(fpu_state_t));
#if THREAD_CREATE_DEBUG
    serial_printf("[thread_create] stack_frame built sp=0x%016llX limit=0x%016llX usable_limit=0x%016llX\r\n",
                  (unsigned long long)((uintptr_t)stack64),
                  (unsigned long long)stack_limit,
                  (unsigned long long)usable_limit);
    serial_printf("[thread_create] context set name=%s stack_base=0x%016llX stack_top=0x%016llX context=0x%016llX\r\n",
                  name ? name : "<null>",
                  (unsigned long long)((uintptr_t)thread->stack_base),
                  (unsigned long long)((uintptr_t)thread->kernel_stack_top),
                  (unsigned long long)((uintptr_t)thread->context));
#endif

#if THREAD_CREATE_DEBUG
    serial_printf("[thread_create] pre_watch name=%s\r\n", name ? name : "<null>");
#endif

    if (name)
    {
        size_t len = strlen(name);
        if (len >= PROCESS_NAME_MAX)
        {
            len = PROCESS_NAME_MAX - 1;
        }
        memcpy(thread->name, name, len);
        thread->name[len] = '\0';
    }
    else
    {
        thread->name[0] = '\0';
    }

    static int thread_log_count = 0;
    if (thread_log_count < 8)
    {
        serial_printf("process: thread created gs base=0x%016llX name=%s\r\n",
                      (unsigned long long)(thread->gs_base),
                      thread->name);
        thread_log_count++;
    }

#if ENABLE_STACK_WRITE_DEBUG
    const char *watch_context = thread->name[0] ? thread->name : "thread";
    if (!thread->is_idle && __atomic_load_n(&g_scheduler_boot_ready, __ATOMIC_ACQUIRE))
    {
        uintptr_t watch_addr = thread->context
                               ? (uintptr_t)thread->context
                               : (uintptr_t)thread->stack_base;
#if THREAD_CREATE_DEBUG
        serial_printf("[thread_create] activating_stack_watch ctx=%s addr=0x%016llX\r\n",
                      watch_context,
                      (unsigned long long)watch_addr);
#endif
        thread_stack_watch_activate(thread, watch_context, watch_addr);
        /* Always arm on the saved context region so we catch self-writes into the frame. */
        thread_stack_watch_activate(thread, watch_context, (uintptr_t)thread->context);
    }
#endif

#if ENABLE_CONTEXT_GUARD
    if (thread->context_guard_enabled)
    {
#if THREAD_CREATE_DEBUG
        serial_printf("[thread_create] context_guard_update name=%s\r\n", thread->name);
#endif
        thread_context_guard_update(thread, "thread_create");
    }
#endif

    stack_owner_register(thread);
    thread_registry_add(thread);
    scheduler_shell_log("created", thread);
#if THREAD_CREATE_DEBUG
    serial_printf("[thread_create] done name=%s thread=0x%016llX\r\n",
                  thread->name,
                  (unsigned long long)((uintptr_t)thread));
#endif
    return thread;
}
