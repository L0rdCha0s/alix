static process_t *process_create_kernel_internal(const char *name,
                                                 thread_entry_t entry,
                                                 void *arg,
                                                 size_t stack_size,
                                                 int stdout_fd,
                                                 process_t *parent)
{
    process_create_log(name, "begin");
    if (!entry)
    {
        process_create_log(name, "no_entry");
        return NULL;
    }

    process_create_log(name, "alloc_start");
    process_t *proc = allocate_process(name, false);
    if (!proc)
    {
        process_create_log(name, "alloc_fail");
        return NULL;
    }

    process_create_log(name, "thread_create_start");
    if (string_name_equals(name, "usb_initd"))
    {
        serial_printf("%s", "[proc usb_initd] thread_create start\r\n");
    }
    thread_t *thread = thread_create(proc, name, entry, arg, stack_size, false, proc->is_user);
    if (!thread)
    {
        paging_destroy_space(&proc->address_space);
        free(proc);
        process_create_log(name, "thread_create_fail");
        if (string_name_equals(name, "usb_initd"))
        {
            serial_printf("%s", "[proc usb_initd] thread_create failed\r\n");
        }
        return NULL;
    }

    process_create_log(name, "thread_create_done");
    process_create_log(name, "finalize_start");
    if (string_name_equals(name, "usb_initd"))
    {
        serial_printf("%s", "[proc usb_initd] finalize start\r\n");
    }
    process_t *result = process_finalize_new_process(proc, thread, stdout_fd, parent);
    process_create_log(name, result ? "success" : "finalize_fail");
    if (string_name_equals(name, "usb_initd"))
    {
        serial_printf("[proc usb_initd] finalize %s\r\n", result ? "success" : "fail");
    }
    return result;
}

static process_t *process_create_user_dummy_internal(const char *name,
                                                     size_t stack_size,
                                                     int stdout_fd,
                                                     process_t *parent)
{
    process_t *proc = allocate_process(name, true);
    if (!proc)
    {
        return NULL;
    }

    if (!process_setup_dummy_user_space(proc))
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    if (!process_store_args(proc, NULL, 0) || !process_prepare_stack_with_args(proc))
    {
        process_clear_args(proc);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    user_thread_bootstrap_t *bootstrap = (user_thread_bootstrap_t *)malloc(sizeof(user_thread_bootstrap_t));
    if (!bootstrap)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }
    bootstrap->entry = proc->user_entry_point;
    bootstrap->stack_top = proc->user_initial_stack ? proc->user_initial_stack : proc->user_stack_top;
    bootstrap->argc = proc->user_argc;
    bootstrap->argv_ptr = proc->user_argv_ptr;

    thread_t *thread = thread_create(proc,
                                     name,
                                     user_thread_entry,
                                     bootstrap,
                                     stack_size,
                                     false,
                                     true);
    if (!thread)
    {
        free(bootstrap);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    return process_finalize_new_process(proc, thread, stdout_fd, parent);
}

static process_t *process_create_user_elf_internal(const char *name,
                                                   const uint8_t *image,
                                                   size_t size,
                                                   int stdout_fd,
                                                   process_t *parent,
                                                   const char *const *argv,
                                                   size_t argc)
{
    if (!image || size == 0)
    {
        return NULL;
    }

    process_t *proc = allocate_process(name, true);
    if (!proc)
    {
        return NULL;
    }

    if (!process_setup_basic_user_memory(proc))
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    if (!process_store_args(proc, argv, argc) || !process_prepare_stack_with_args(proc))
    {
        process_clear_args(proc);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    uintptr_t entry_point = 0;
    if (!elf_load_process(proc, image, size, &entry_point))
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    if (entry_point == 0)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    proc->user_entry_point = entry_point;

    user_thread_bootstrap_t *bootstrap = (user_thread_bootstrap_t *)malloc(sizeof(user_thread_bootstrap_t));
    if (!bootstrap)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }
    bootstrap->entry = proc->user_entry_point;
    bootstrap->stack_top = proc->user_initial_stack ? proc->user_initial_stack : proc->user_stack_top;
    bootstrap->argc = proc->user_argc;
    bootstrap->argv_ptr = proc->user_argv_ptr;

    thread_t *thread = thread_create(proc,
                                     name,
                                     user_thread_entry,
                                     bootstrap,
                                     PROCESS_DEFAULT_STACK_SIZE,
                                     false,
                                     true);
    if (!thread)
    {
        free(bootstrap);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    return process_finalize_new_process(proc, thread, stdout_fd, parent);
}

process_t *process_create_kernel(const char *name,
                                 thread_entry_t entry,
                                 void *arg,
                                 size_t stack_size,
                                 int stdout_fd)
{
    return process_create_kernel_internal(name, entry, arg, stack_size, stdout_fd, NULL);
}

process_t *process_create_kernel_with_parent(const char *name,
                                             thread_entry_t entry,
                                             void *arg,
                                             size_t stack_size,
                                             int stdout_fd,
                                             process_t *parent)
{
    return process_create_kernel_internal(name, entry, arg, stack_size, stdout_fd, parent);
}

process_t *process_create_user_dummy(const char *name,
                                     int stdout_fd)
{
    return process_create_user_dummy_internal(name,
                                              PROCESS_DEFAULT_STACK_SIZE,
                                              stdout_fd,
                                              NULL);
}

process_t *process_create_user_dummy_with_parent(const char *name,
                                                 int stdout_fd,
                                                 process_t *parent)
{
    return process_create_user_dummy_internal(name,
                                              PROCESS_DEFAULT_STACK_SIZE,
                                              stdout_fd,
                                              parent);
}

process_t *process_create_user_elf(const char *name,
                                   const uint8_t *image,
                                   size_t size,
                                   int stdout_fd,
                                   const char *const *argv,
                                   size_t argc)
{
    return process_create_user_elf_internal(name, image, size, stdout_fd, NULL, argv, argc);
}

process_t *process_create_user_elf_with_parent(const char *name,
                                               const uint8_t *image,
                                               size_t size,
                                               int stdout_fd,
                                               process_t *parent,
                                               const char *const *argv,
                                               size_t argc)
{
    return process_create_user_elf_internal(name, image, size, stdout_fd, parent, argv, argc);
}

void process_yield(void)
{
    scheduler_schedule(true);
}

void process_sleep_ticks(uint64_t ticks)
{
    if (ticks == 0)
    {
        process_yield();
        return;
    }

    thread_t *thread = current_thread_local();
    if (!thread || thread->is_idle)
    {
        process_yield();
        return;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint64_t now = timer_ticks();
    uint64_t wake_tick = now + ticks;
    if (wake_tick <= now)
    {
        wake_tick = now + 1;
    }
    thread->state = THREAD_STATE_BLOCKED;
    thread->sleep_until_tick = wake_tick;
    thread_clear_running_cpu(thread);
    thread->in_transition = false;
    thread->wake_pending = false;
    SCHED_SLEEP_LOG("[sleep] enqueue thread=%s pid=0x%016llX wake_tick=%llu now=%llu\r\n",
                    thread->name[0] ? thread->name : "<unnamed>",
                    (unsigned long long)(thread->process ? thread->process->pid : 0),
                    (unsigned long long)wake_tick,
                    (unsigned long long)now);
    sleep_queue_insert(thread);
    scheduler_schedule(false);
    cpu_restore_flags(flags);
}

void process_sleep_ms(uint32_t ms)
{
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        process_sleep_ticks(1);
        return;
    }
    uint64_t ticks = ((uint64_t)ms * (uint64_t)freq + 999ULL) / 1000ULL;
    if (ticks == 0)
    {
        ticks = 1;
    }
    process_sleep_ticks(ticks);
}

void process_destroy(process_t *process)
{
    if (!process || process->state != PROCESS_STATE_ZOMBIE || process == g_idle_process)
    {
        return;
    }

    serial_printf("[proc] destroy pid=0x%016llX name=%s main_thread=0x%016llX\r\n",
                  (unsigned long long)process->pid,
                  process->name,
                  (unsigned long long)(uintptr_t)process->main_thread);

    user_atk_on_process_destroy(process);
    shell_service_cleanup_process(process);

    if (process->first_child)
    {
        process_t *child = process->first_child;
        while (child)
        {
            process_t *next = child->sibling_next;
            process_detach_child(child);
            child = next;
        }
    }

    process_detach_child(process);

    thread_t *thread = process->main_thread;
    if (thread)
    {
        process->main_thread = NULL;
        process->current_thread = NULL;
        thread_clear_running_cpu(thread);
        thread_remove_from_wait_queue(thread);
        if (thread->sleeping)
        {
            sleep_queue_remove(thread);
        }
        if (thread_in_run_queue_load(thread))
        {
            remove_from_run_queue(thread);
        }
        thread_context_guard_release_pages(thread);
        thread->magic = 0;
        thread_enqueue_deferred_free(thread);
        thread = NULL;
    }

    spinlock_lock(&g_process_lock);
    process_t **cursor = &g_process_list;
    while (*cursor)
    {
        if (*cursor == process)
        {
            *cursor = process->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    spinlock_unlock(&g_process_lock);

    process->magic = 0;
    process_free_user_regions(process);
    paging_destroy_space(&process->address_space);
    free(process);
}

void process_exit(int status)
{
    thread_t *current = current_thread_local();
    if (!current)
    {
        fatal("process_exit with no current thread");
    }

    current->exit_status = status;
    current->exited = true;
    current->state = THREAD_STATE_ZOMBIE;

    if (current->process)
    {
        current->process->exit_status = status;
        current->process->state = PROCESS_STATE_ZOMBIE;
        wait_queue_wake_all(&current->process->wait_queue);
    }

    scheduler_schedule(false);
    fatal("process_exit returned");
}

static bool process_has_exited(void *context)
{
    process_t *proc = (process_t *)context;
    return !proc || !process_pointer_valid(proc) || proc->state == PROCESS_STATE_ZOMBIE;
}

int process_join_with_hook(process_t *process,
                          int *status_out,
                          process_wait_hook_t hook,
                          void *context)
{
    if (!process)
    {
        return -1;
    }

    while (process->state != PROCESS_STATE_ZOMBIE)
    {
        if (hook)
        {
            hook(context);
            if (process->state == PROCESS_STATE_ZOMBIE)
            {
                break;
            }
            process_yield();
            continue;
        }
        process_yield();
    }

    if (status_out)
    {
        *status_out = process->exit_status;
    }
    return process->exit_status;
}

int process_join(process_t *process, int *status_out)
{
    return process_join_with_hook(process, status_out, NULL, NULL);
}

bool process_kill(process_t *process, int status)
{
    if (!process)
    {
        return false;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    thread_t *thread = process->current_thread ? process->current_thread : process->main_thread;
    if (!thread)
    {
        cpu_restore_flags(flags);
        return false;
    }

    if (process->state == PROCESS_STATE_ZOMBIE || thread->state == THREAD_STATE_ZOMBIE)
    {
        process->state = PROCESS_STATE_ZOMBIE;
        process->exit_status = status;
        cpu_restore_flags(flags);
        return true;
    }

    bool target_running = (thread == current_thread_local());

    if (thread_in_run_queue_load(thread))
    {
        remove_from_run_queue(thread);
    }

    thread->exit_status = status;
    thread->exited = true;
    thread->state = THREAD_STATE_ZOMBIE;
    thread->preempt_pending = false;
    thread->time_slice_remaining = 0;

    process->exit_status = status;
    process->state = PROCESS_STATE_ZOMBIE;
    wait_queue_wake_all(&process->wait_queue);

    cpu_restore_flags(flags);

    if (target_running)
    {
        process_exit(status);
    }

    return true;
}

void process_kill_tree(process_t *process)
{
    if (!process)
    {
        return;
    }

    process_t *child = NULL;
    while ((child = process_detach_first_child(process)) != NULL)
    {
        process_kill_tree(child);
        process_destroy(child);
    }

    process_kill(process, -1);
}

process_t *process_current(void)
{
    return current_process_local();
}

thread_t *thread_current(void)
{
    return current_thread_local();
}

bool process_thread_stack_bounds(const thread_t *thread,
                                 uintptr_t *base_out,
                                 uintptr_t *top_out)
{
    if (!thread || !thread->stack_base)
    {
        return false;
    }
    if (base_out)
    {
        *base_out = (uintptr_t)thread->stack_base;
    }
    if (top_out)
    {
        *top_out = thread->kernel_stack_top;
    }
    return true;
}

const char *process_thread_name_const(const thread_t *thread)
{
    if (!thread || thread->name[0] == '\0')
    {
        return NULL;
    }
    return thread->name;
}

process_t *process_thread_owner(const thread_t *thread)
{
    return thread ? thread->process : NULL;
}

void process_detach_parent(process_t *process)
{
    process_detach_child(process);
}

bool process_is_zombie(const process_t *process)
{
    return process && process->state == PROCESS_STATE_ZOMBIE;
}

uint64_t process_current_pid(void)
{
    process_t *proc = current_process_local();
    return proc ? proc->pid : 0;
}

vfs_node_t *process_current_cwd(void)
{
    process_t *proc = process_current();
    if (!proc || !proc->cwd)
    {
        return vfs_root();
    }
    return proc->cwd;
}

void process_set_cwd(process_t *process, vfs_node_t *dir)
{
    if (!process)
    {
        return;
    }

    vfs_node_t *target = dir;
    if (target && !vfs_is_dir(target))
    {
        return;
    }
    if (!target)
    {
        target = vfs_root();
    }
    process->cwd = target;
}

static void wait_queue_enqueue_locked(wait_queue_t *queue, thread_t *thread)
{
    if (!queue || !thread)
    {
        return;
    }
    thread->wait_queue_next = NULL;
    if (queue->tail)
    {
        queue->tail->wait_queue_next = thread;
    }
    else
    {
        queue->head = thread;
    }
    queue->tail = thread;
}

static thread_t *wait_queue_dequeue_locked(wait_queue_t *queue)
{
    if (!queue)
    {
        return NULL;
    }
    thread_t *thread = queue->head;
    if (!thread)
    {
        return NULL;
    }
    queue->head = thread->wait_queue_next;
    if (!queue->head)
    {
        queue->tail = NULL;
    }
    thread->wait_queue_next = NULL;
    return thread;
}

void wait_queue_init(wait_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
    spinlock_init(&queue->lock);
    queue->head = NULL;
    queue->tail = NULL;
}

static void wait_queue_remove_thread_locked(wait_queue_t *queue, thread_t *thread)
{
    if (!queue || !thread)
    {
        return;
    }
    if (queue->head == thread)
    {
        queue->head = thread->wait_queue_next;
        if (!queue->head)
        {
            queue->tail = NULL;
        }
        thread->wait_queue_next = NULL;
        return;
    }
    thread_t *prev = queue->head;
    while (prev && prev->wait_queue_next != thread)
    {
        prev = prev->wait_queue_next;
    }
    if (prev)
    {
        prev->wait_queue_next = thread->wait_queue_next;
        if (queue->tail == thread)
        {
            queue->tail = prev;
        }
        thread->wait_queue_next = NULL;
    }
}

void wait_queue_wait(wait_queue_t *queue, wait_queue_predicate_t predicate, void *context)
{
    if (!queue)
    {
        process_yield();
        return;
    }
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        process_yield();
        return;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint64_t sched_flags = scheduler_lock_acquire("wait_queue_wait");

    for (;;)
    {
        spinlock_lock(&queue->lock);

        if (!predicate || predicate(context))
        {
            if (thread->waiting_queue == queue)
            {
                wait_queue_remove_thread_locked(queue, thread);
                thread->waiting_queue = NULL;
            }
            thread->state = THREAD_STATE_RUNNING;
            spinlock_unlock(&queue->lock);
            scheduler_lock_release(sched_flags);
            cpu_restore_flags(flags);
            return;
        }

        if (thread_in_run_queue_load(thread))
        {
            remove_from_run_queue(thread);
        }
        thread->state = THREAD_STATE_BLOCKED;
        thread->waiting_queue = queue;
        wait_queue_enqueue_locked(queue, thread);

        spinlock_unlock(&queue->lock);
        scheduler_lock_release(sched_flags);

        scheduler_schedule(false);
        /* Loop and re-check predicate under lock after waking. */
        sched_flags = scheduler_lock_acquire("wait_queue_wait");
    }
}

void wait_queue_wake_one(wait_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint64_t sched_flags = scheduler_lock_acquire("wait_queue_wake_one");
    spinlock_lock(&queue->lock);

    thread_t *thread = wait_queue_dequeue_locked(queue);
    if (thread)
    {
        thread->waiting_queue = NULL;
        if (thread_lifetime_active(thread) &&
            !thread->pending_destroy &&
            thread->state == THREAD_STATE_BLOCKED &&
            !thread->exited &&
            !thread_in_run_queue_load(thread))
        {
            uint32_t rc = __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE);
            if (rc != RUN_QUEUE_CPU_INVALID)
            {
                thread->wake_pending = true;
            }
            else
            {
                thread->state = THREAD_STATE_READY;
                enqueue_thread(thread);
            }
        }
    }

    spinlock_unlock(&queue->lock);
    scheduler_lock_release(sched_flags);
    cpu_restore_flags(flags);
}

void wait_queue_wake_all(wait_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint64_t sched_flags = scheduler_lock_acquire("wait_queue_wake_all");
    spinlock_lock(&queue->lock);

    thread_t *thread = wait_queue_dequeue_locked(queue);
    while (thread)
    {
        thread->waiting_queue = NULL;
        if (thread_lifetime_active(thread) &&
            !thread->pending_destroy &&
            thread->state == THREAD_STATE_BLOCKED &&
            !thread->exited &&
            !thread_in_run_queue_load(thread))
        {
            uint32_t rc = __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE);
            if (rc != RUN_QUEUE_CPU_INVALID)
            {
                thread->wake_pending = true;
            }
            else
            {
                thread->state = THREAD_STATE_READY;
                enqueue_thread(thread);
            }
        }
        thread = wait_queue_dequeue_locked(queue);
    }

    spinlock_unlock(&queue->lock);
    scheduler_lock_release(sched_flags);
    cpu_restore_flags(flags);
}

void process_set_priority(process_t *process, thread_priority_t priority)
{
    if (!process_pointer_valid(process) || !thread_pointer_valid(process->main_thread))
    {
        return;
    }
    thread_set_base_priority(process->main_thread, priority);
}

void process_set_priority_override(process_t *process, thread_priority_t priority)
{
    if (!process_pointer_valid(process) || !thread_pointer_valid(process->main_thread))
    {
        return;
    }
    thread_set_priority_override(process->main_thread, true, priority);
}

void process_clear_priority_override(process_t *process)
{
    if (!process_pointer_valid(process) || !thread_pointer_valid(process->main_thread))
    {
        return;
    }
    thread_set_priority_override(process->main_thread, false, THREAD_PRIORITY_NORMAL);
}

uint64_t process_take_preempt_resume_rip(void)
{
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        return 0;
    }
    uint64_t rip = thread->tls.preempt_resume_rip;
    thread->tls.preempt_resume_rip = 0;
    return rip;
}

uint64_t process_get_pid(const process_t *process)
{
    if (!process)
    {
        return 0;
    }
    return process->pid;
}

int process_current_stdout_fd(void)
{
    process_t *proc = current_process_local();
    if (proc && proc->stdout_fd >= 0)
    {
        return proc->stdout_fd;
    }
    return g_console_stdout_fd;
}

bool process_query_user_layout(const process_t *process,
                               process_user_layout_t *layout)
{
    if (!process || !layout)
    {
        return false;
    }

    layout->is_user = process->is_user;
    layout->cr3 = process->cr3;
    layout->entry_point = process->user_entry_point;
    layout->stack_top = process->user_stack_top;
    layout->stack_size = process->user_stack_size;
    return process->is_user && process->user_entry_point != 0 && process->user_stack_top != 0;
}

int64_t process_user_sbrk(process_t *process, int64_t increment)
{
    if (!process || !process->is_user || process->user_heap_base == 0)
    {
        return -1;
    }

    uintptr_t base = process->user_heap_base;
    uintptr_t limit = process->user_heap_limit;
    uintptr_t current = process->user_heap_brk;
    process_log("sbrk pid=", process->pid);
    process_log("sbrk inc=", (uint64_t)increment);
    process_log("sbrk current=", current);
    if (base == 0 || limit <= base || current < base || current > limit)
    {
        process_log("sbrk invalid bounds pid=", process->pid);
        return -1;
    }
    uintptr_t new_brk = current;

    if (increment > 0)
    {
        uint64_t inc = (uint64_t)increment;
        if (inc > (limit - current))
        {
            process_log("sbrk clamp inc=", inc);
            process_log("sbrk avail=", limit - current);
            return -1;
        }
        new_brk = current + inc;
        uintptr_t commit_start = process->user_heap_committed;
        uintptr_t commit_end = align_up_uintptr(new_brk, PAGE_SIZE_BYTES_LOCAL);
        if (commit_end > limit)
        {
            commit_end = limit;
        }
        if (commit_end > commit_start)
        {
            if (!process_heap_commit_range(process, commit_start, commit_end))
            {
                process_log("sbrk commit failed pid=", process->pid);
                process_log("sbrk commit avail=", user_memory_available());
                return -1;
            }
        }
        if (!process_heap_zero_range(process, current, inc))
        {
            process_log("sbrk zero failed pid=", process->pid);
            return -1;
        }
    }
    else if (increment < 0)
    {
        uint64_t dec = (uint64_t)(-increment);
        if (dec > (current - base))
        {
            process_log("sbrk negative clamp dec=", dec);
            return -1;
        }
        new_brk = current - dec;
        uintptr_t new_commit = align_up_uintptr(new_brk, PAGE_SIZE_BYTES_LOCAL);
        if (new_commit < process->user_heap_committed)
        {
            process_heap_release_from(process, new_commit);
            process->user_heap_committed = new_commit;
        }
    }

    process->user_heap_brk = new_brk;
    process_log("sbrk new=", new_brk);
    process_log("sbrk return=", current);
    return (int64_t)current;
}

ssize_t process_stdout_write(const char *data, size_t len)
{
    int fd = process_current_stdout_fd();
    if (fd < 0)
    {
        return -1;
    }
    return fd_write(fd, data, len);
}

size_t process_snapshot(process_info_t *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    size_t count = 0;
    spinlock_lock(&g_process_lock);
    process_t *proc_iter = g_process_list;
    while (proc_iter && count < capacity)
    {
        process_t *proc = proc_iter;
        proc_iter = proc_iter->next;
        process_info_t *info = &buffer[count++];
        info->pid = proc->pid;
        info->state = proc->state;
        info->name = proc->name[0] ? proc->name : "(anon)";
        info->stdout_fd = proc->stdout_fd;
        thread_t *thread = proc->current_thread ? proc->current_thread : proc->main_thread;
        if (thread)
        {
            info->thread_state = thread->state;
            info->thread_name = thread->name[0] ? thread->name : "";
            info->is_idle = thread->is_idle;
            info->time_slice_remaining = thread->time_slice_remaining;
        }
        else
        {
            info->thread_state = THREAD_STATE_ZOMBIE;
            info->thread_name = "";
            info->is_idle = false;
            info->time_slice_remaining = 0;
        }
        info->is_current = (proc == current_process_local());

        if (proc->is_user && proc->user_heap_base != 0 && proc->user_heap_brk >= proc->user_heap_base)
        {
            uintptr_t committed = proc->user_heap_committed;
            if (committed < proc->user_heap_base)
            {
                committed = proc->user_heap_base;
            }
            info->heap_used_bytes = (uint64_t)(proc->user_heap_brk - proc->user_heap_base);
            info->heap_committed_bytes = (uint64_t)(committed - proc->user_heap_base);
        }
        else
        {
            info->heap_used_bytes = 0;
            info->heap_committed_bytes = 0;
        }
    }
    spinlock_unlock(&g_process_lock);

    cpu_restore_flags(flags);
    return count;
}

const char *process_state_name(process_state_t state)
{
    switch (state)
    {
        case PROCESS_STATE_READY:   return "ready";
        case PROCESS_STATE_RUNNING: return "running";
        case PROCESS_STATE_ZOMBIE:  return "zombie";
    }
    return "unknown";
}

const char *thread_state_name(thread_state_t state)
{
    switch (state)
    {
        case THREAD_STATE_READY:   return "ready";
        case THREAD_STATE_RUNNING: return "running";
        case THREAD_STATE_BLOCKED: return "blocked";
        case THREAD_STATE_ZOMBIE:  return "zombie";
    }
    return "unknown";
}

void process_dump_current_thread(void)
{
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        serial_printf("%s", "  thread: <none>\r\n");
        return;
    }
    serial_printf("%s", "  thread name=");
    if (thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " state=");
    serial_printf("%s", thread_state_name(thread->state));
    serial_printf("%s", " stack_base=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->stack_base));
    serial_printf("%s", " stack_top=0x");
    serial_printf("%016llX", (unsigned long long)(thread->kernel_stack_top));
    serial_printf("%s", " guard=");
    serial_printf("%s", thread_stack_guard_intact(thread) ? "ok" : "CORRUPT");
    serial_printf("%s", "\r\n");
}

void process_debug_scan_current_kernel_stack(const char *context,
                                             uintptr_t rsp_hint,
                                             bool full_stack)
{
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        return;
    }
    uintptr_t hint = rsp_hint ? rsp_hint : (uintptr_t)thread->stack_base;
    thread_scan_stack_for_suspicious_values(thread, hint, full_stack, context);
}

bool process_handle_stack_watch_fault(uintptr_t fault_addr,
                                      interrupt_frame_t *frame,
                                      uint64_t error_code)
{
#if ENABLE_STACK_WRITE_DEBUG
    thread_t *target = thread_find_stack_owner(fault_addr, 0);
    if (!target || !target->stack_watch_active)
    {
        return false;
    }

    thread_t *writer = current_thread_local();
    SCHED_LOG("%s", "[sched] stack watch fault hit\r\n");
    serial_printf("%s", "  target=");
    if (target->name[0])
    {
        serial_printf("%s", target->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(target->process ? target->process->pid : 0));
    serial_printf("%s", " addr=0x");
    serial_printf("%016llX", (unsigned long long)(fault_addr));
    serial_printf("%s", " watch_base=0x");
    serial_printf("%016llX", (unsigned long long)(target->stack_watch_base));
    serial_printf("%s", " watch_len=0x");
    serial_printf("%016llX", (unsigned long long)(target->stack_watch_len));
    serial_printf("%s", " suspect=0x");
    serial_printf("%016llX", (unsigned long long)(target->stack_watch_suspect));
    serial_printf("%s", " context=");
    serial_printf("%s", target->stack_watch_context ? target->stack_watch_context : "<none>");
    serial_printf("%s", "\r\n");

    serial_printf("%s", "  writer=");
    if (writer && writer->name[0])
    {
        serial_printf("%s", writer->name);
    }
    else
    {
        serial_printf("%s", writer ? "<unnamed>" : "<none>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(writer && writer->process ? writer->process->pid : 0));
    serial_printf("%s", " rip=0x");
    serial_printf("%016llX", (unsigned long long)(frame ? frame->rip : 0));
    serial_printf("%s", " err=0x");
    serial_printf("%016llX", (unsigned long long)(error_code));
    serial_printf("%s", "\r\n");

    target->stack_watch_enabled = false;
    thread_stack_watch_deactivate(target);
    thread_unfreeze_after_stack_watch(target);

    if (writer && frame)
    {
        process_trigger_fatal_fault(writer,
                                    frame,
                                    "stack_watch_fault",
                                    error_code,
                                    true,
                                    fault_addr);
    }
    else
    {
        fatal("stack watch fault without writer/frame");
    }
    return true;
#else
    (void)fault_addr;
    (void)frame;
    (void)error_code;
    return false;
#endif
}

bool process_stack_watch_thread(thread_t *thread, const char *context)
{
#if ENABLE_STACK_WRITE_DEBUG
    return thread_stack_watch_activate(thread, context, 0);
#else
    (void)thread;
    (void)context;
    return false;
#endif
}

bool process_stack_watch_process(process_t *process, const char *context)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!process || !process->main_thread)
    {
        return false;
    }
    return process_stack_watch_thread(process->main_thread, context);
#else
    (void)process;
    (void)context;
    return false;
#endif
}

void process_on_timer_tick(interrupt_frame_t *frame)
{
    if (!frame)
    {
        return;
    }

    sleep_queue_wake_due(timer_ticks());
    stack_watch_check_timeouts();

    thread_t *thread = current_thread_local();
    if (!thread || thread->is_idle)
    {
        return;
    }
    if (thread->in_transition)
    {
        return;
    }

    uint64_t kernel_rsp = 0;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(kernel_rsp));

    if (!thread_stack_pointer_valid(thread, kernel_rsp))
    {
        thread_trigger_stack_guard(thread, frame, "rsp_out_of_bounds");
        return;
    }

    if (!thread_stack_guard_intact(thread))
    {
        thread_trigger_stack_guard(thread, frame, "guard_corrupted");
        return;
    }

    thread_scan_stack_for_suspicious_values(thread, kernel_rsp, false, "timer_tick");

    sanitize_gs_base(thread);

    /* If another CPU tried to enqueue us while we were running there, force an
     * immediate preempt so we can clear wake_pending and requeue cleanly. */
    if (thread->wake_pending && thread->time_slice_remaining > 0)
    {
        thread->time_slice_remaining = 0;
    }

    if (thread->preempt_pending)
    {
        return;
    }

    if (thread->time_slice_remaining > 0)
    {
        thread->time_slice_remaining--;
    }

    if (thread->time_slice_remaining > 0)
    {
        return;
    }

    thread->preempt_pending = true;
    thread->time_slice_remaining = scheduler_time_slice_ticks();

    bool user_mode = frame && ((frame->cs & 0x3u) == 0x3u);
    if (!frame)
    {
        return;
    }

    thread->tls.preempt_resume_rip = frame->rip;
    if (user_mode)
    {
        frame->rip = USER_PREEMPT_STUB_BASE;
    }
    else
    {
        frame->rip = (uint64_t)process_preempt_trampoline;
    }
}

#if ENABLE_STACK_WRITE_DEBUG
#define STACK_WRITE_SELF_WINDOW_BYTES (THREAD_CONTEXT_REDZONE_BYTES + 1024ULL)

void process_debug_log_stack_write(const char *label,
                                   const void *caller,
                                   void *dest,
                                   size_t len)
{
    if (!g_stack_write_debug_enabled ||
        !__atomic_load_n(&g_scheduler_boot_ready, __ATOMIC_ACQUIRE) ||
#if ENABLE_STACK_WRITE_DEBUG
        !g_stack_owner_ready ||
#endif
        !dest || len == 0)
    {
        return;
    }

    uintptr_t addr = (uintptr_t)dest;
    thread_t *owner = thread_find_stack_owner(addr, len);
    thread_t *writer = current_thread_local();

    if (writer)
    {
        uint64_t rsp_now = 0;
        __asm__ volatile ("mov %%rsp, %0" : "=r"(rsp_now));
        thread_t *rsp_owner = thread_find_stack_owner((uintptr_t)rsp_now, 1);
        if (rsp_owner && rsp_owner != writer)
        {
            serial_printf("[stack-owner-mismatch] ctx=%s writer=%s pid=0x%016llX rsp=0x%016llX owner=%s owner_pid=0x%016llX\r\n",
                          label ? label : "<none>",
                          writer->name[0] ? writer->name : "<unnamed>",
                          (unsigned long long)(writer->process ? writer->process->pid : 0),
                          (unsigned long long)rsp_now,
                          (rsp_owner->name[0]) ? rsp_owner->name : "<unnamed>",
                          (unsigned long long)(rsp_owner->process ? rsp_owner->process->pid : 0));
        }
    }

    if (!owner || !writer)
    {
        return;
    }

    uintptr_t ctx = (uintptr_t)writer->context;
    uintptr_t ctx_end = ctx + CTX_WORD_COUNT * sizeof(uint64_t);
    bool overlaps_self_context = (owner == writer) && ctx && addr < ctx_end && (addr + len) > ctx;

    /* Ignore self-writes unless they overlap the saved context frame. */
    if (owner == writer && !overlaps_self_context)
    {
        return;
    }

    const char *prefix = (owner == writer) ? "[stack-write-self]" : "[stack-write-cross]";
    const char *writer_name = (writer && writer->name[0]) ? writer->name : "<none>";
    const char *owner_name = owner->name[0] ? owner->name : "<unnamed>";
    serial_printf("%s label=%s writer=%s writer_pid=0x%016llX target=%s target_pid=0x%016llX dest=0x%016llX len=0x%016llX stack_base=0x%016llX stack_top=0x%016llX caller=0x%016llX\r\n",
                  prefix,
                  label ? label : "<none>",
                  writer_name,
                  (unsigned long long)(writer && writer->process ? writer->process->pid : 0),
                  owner_name,
                  (unsigned long long)(owner->process ? owner->process->pid : 0),
                  (unsigned long long)addr,
                  (unsigned long long)len,
                  (unsigned long long)((uintptr_t)owner->stack_base),
                  (unsigned long long)(owner->kernel_stack_top),
                  (unsigned long long)((uintptr_t)caller));
}
#else
void process_debug_log_stack_write(const char *label,
                                   const void *caller,
                                   void *dest,
                                   size_t len)
{
    (void)label;
    (void)caller;
    (void)dest;
    (void)len;
}
#endif
