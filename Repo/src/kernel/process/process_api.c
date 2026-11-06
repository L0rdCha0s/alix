#include "process_internal.h"
#include "errno.h"

/*
 * src/kernel/process/process_api.c
 *
 * Public-facing process/thread APIs (see `include/process.h`):
 * - process creation (kernel threads, user ELF processes)
 * - join/kill/tree management
 * - sleep/yield helpers and snapshots for /proc/syscalls
 * - timer-tick preemption hook (`process_on_timer_tick`)
 *
 * See docs/kernel/process.md for scheduler details and docs/kernel/memory.md
 * for user address space/mapping behavior.
 */

static process_t *process_create_kernel_internal(const char *name,
                                                 thread_entry_t entry,
                                                 void *arg,
                                                 size_t stack_size,
                                                 int stdout_fd,
                                                 process_t *parent,
                                                 bool kernel_service,
                                                 process_creation_watch_t *watch)
{
    process_create_log(name, "begin");
    if (!entry)
    {
        process_create_log(name, "no_entry");
        if (watch) __atomic_store_n(&watch->constructed, true, __ATOMIC_RELEASE);
        return NULL;
    }

    process_create_log(name, "alloc_start");
    /* Kernel allocation only allocates process metadata and shares existing
     * kernel page tables; protect that bounded allocation-to-registration gap. */
    if (watch) spinlock_preempt_disable();
    process_t *proc = allocate_process(name, false);
    if (watch && proc)
    {
        proc->join_waiters = 1;
        __atomic_store_n(&watch->pid, proc->pid, __ATOMIC_RELEASE);
        __atomic_store_n(&watch->owner, proc, __ATOMIC_RELEASE);
    }
    if (watch) spinlock_preempt_enable();
    if (!proc)
    {
        process_create_log(name, "alloc_fail");
        if (watch) __atomic_store_n(&watch->constructed, true, __ATOMIC_RELEASE);
        return NULL;
    }

    /* These fields must precede thread publication and process enqueue. An
     * immediately exiting parentless worker still retains its factory owner. */
    proc->kernel_service = kernel_service;
    if (kernel_service) proc->join_waiters = 1;
    if (!process_prepare_inherited_context(proc, parent, kernel_service))
    {
        if (watch)
        {
            proc->state = PROCESS_STATE_ZOMBIE;
            proc->exit_status = -1;
            proc->wait_status = 255u << 8;
            __atomic_store_n(&watch->constructed, true, __ATOMIC_RELEASE);
            return NULL; /* Registered owner rolls back on the protected worker. */
        }
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
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
        if (watch)
        {
            proc->state = PROCESS_STATE_ZOMBIE;
            proc->exit_status = -1;
            proc->wait_status = 255u << 8;
            __atomic_store_n(&watch->constructed, true, __ATOMIC_RELEASE);
            return NULL;
        }
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
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
    if (watch) __atomic_store_n(&watch->constructed, true, __ATOMIC_RELEASE);
    return result;
}

static process_t *process_create_user_dummy_internal(const char *name,
                                                     size_t stack_size,
                                                     int stdout_fd,
                                                     process_t *parent);
static process_priority_info_t process_priority_info(const process_t *process);

static void process_snapshot_copy_name(char *dest, const char *source)
{
    if (!dest)
    {
        return;
    }
    const char *value = source ? source : "";
    size_t i = 0;
    while (i + 1 < PROCESS_NAME_MAX && value[i])
    {
        dest[i] = value[i];
        ++i;
    }
    dest[i] = '\0';
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
    if (!process_prepare_inherited_context(proc, parent, false) || !process_prepare_user_fds(proc, parent, stdout_fd))
    {
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }


    if (!process_setup_dummy_user_space(proc))
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }

    if (!process_store_args(proc, NULL, 0) || !process_prepare_stack_with_args(proc))
    {
        process_clear_args(proc);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }

    user_thread_bootstrap_t *bootstrap = (user_thread_bootstrap_t *)malloc(sizeof(user_thread_bootstrap_t));
    if (!bootstrap)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }
    bootstrap->entry = proc->user_entry_point;
    bootstrap->stack_top = proc->user_initial_stack ? proc->user_initial_stack : proc->user_stack_top;
    bootstrap->rdi = proc->user_argc;
    bootstrap->rsi = proc->user_argv_ptr;
    bootstrap->rdx = proc->user_envp_ptr;

    process_tls_allocation_t tls = {0};
    if (!process_allocate_user_tls(proc, &tls))
    {
        free(bootstrap);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }

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
        process_release_context(proc);
        free(proc);
        return NULL;
    }

    thread->fs_base = tls.thread_pointer;
    thread->user_tls_base = tls.base;
    thread->user_tls_size = tls.size;
    return process_finalize_new_process(proc, thread, stdout_fd, parent);
}

static process_t *process_create_user_elf_internal(const char *name,
                                                   const uint8_t *image,
                                                   size_t size,
                                                   int stdout_fd,
                                                   process_t *parent,
                                                   const char *const *argv,
                                                   size_t argc, const char *executable_path)
{
    if (!image || size == 0)
    {
        return NULL;
    }
    size_t path_length = executable_path ? strnlen(executable_path, SYSCALL_EXECUTABLE_PATH_MAX) : 0;
    if (executable_path && (!path_length || path_length == SYSCALL_EXECUTABLE_PATH_MAX || executable_path[0] != '/')) return NULL;

    process_t *proc = allocate_process(name, true);
    if (!proc)
    {
        return NULL;
    }
    if (executable_path) memcpy(proc->executable_path, executable_path, path_length + 1);
    if (!process_prepare_inherited_context(proc, parent, false) || !process_prepare_user_fds(proc, parent, stdout_fd))
    {
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }


    if (!process_setup_basic_user_memory(proc))
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }

    if (!process_store_args(proc, argv, argc) || !process_prepare_stack_with_args(proc))
    {
        process_clear_args(proc);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }

    uintptr_t entry_point = 0;
    if (!elf_load_process(proc, image, size, &entry_point))
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }

    if (entry_point == 0)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }

    proc->user_entry_point = entry_point;

    user_thread_bootstrap_t *bootstrap = (user_thread_bootstrap_t *)malloc(sizeof(user_thread_bootstrap_t));
    if (!bootstrap)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }
    bootstrap->entry = proc->user_entry_point;
    bootstrap->stack_top = proc->user_initial_stack ? proc->user_initial_stack : proc->user_stack_top;
    bootstrap->rdi = proc->user_argc;
    bootstrap->rsi = proc->user_argv_ptr;
    bootstrap->rdx = proc->user_envp_ptr;

    process_tls_allocation_t tls = {0};
    if (!process_allocate_user_tls(proc, &tls))
    {
        free(bootstrap);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        process_release_context(proc);
        free(proc);
        return NULL;
    }

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
        process_release_context(proc);
        free(proc);
        return NULL;
    }

    thread->fs_base = tls.thread_pointer;
    thread->user_tls_base = tls.base;
    thread->user_tls_size = tls.size;
    return process_finalize_new_process(proc, thread, stdout_fd, parent);
}

process_t *process_create_kernel(const char *name,
                                 thread_entry_t entry,
                                 void *arg,
                                 size_t stack_size,
                                 int stdout_fd)
{
    return process_create_kernel_internal(name, entry, arg, stack_size, stdout_fd, NULL, false, NULL);
}

process_t *process_create_kernel_with_parent(const char *name,
                                             thread_entry_t entry,
                                             void *arg,
                                             size_t stack_size,
                                             int stdout_fd,
                                             process_t *parent)
{
    return process_create_kernel_internal(name, entry, arg, stack_size, stdout_fd, parent, false, NULL);
}

process_t *process_create_kernel_service(const char *name, thread_entry_t entry,
                                         void *argument, size_t stack_size)
{
    return process_create_kernel_internal(name, entry, argument, stack_size, -1, NULL, true, NULL);
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
    return process_create_user_elf_internal(name, image, size, stdout_fd, NULL, argv, argc, NULL);
}

process_t *process_create_user_elf_with_parent(const char *name,
                                               const uint8_t *image,
                                               size_t size,
                                               int stdout_fd,
                                               process_t *parent,
                                               const char *const *argv,
                                               size_t argc)
{
    return process_create_user_elf_internal(name, image, size, stdout_fd, parent, argv, argc, NULL);
}

process_t *process_create_user_elf_from_path(const char *name, const char *executable_path,
                                            const uint8_t *image, size_t size, int stdout_fd,
                                            process_t *parent, const char *const *argv, size_t argc)
{
    if (!executable_path) return NULL;
    return process_create_user_elf_internal(name, image, size, stdout_fd, parent, argv, argc, executable_path);
}

static volatile uint32_t g_bootstrap_preempt_depth[SMP_MAX_CPUS];

void spinlock_preempt_disable(void)
{
    thread_t *thread = current_thread_local();
    if (thread)
    {
        __atomic_add_fetch(&thread->preempt_disable_depth, 1u, __ATOMIC_ACQ_REL);
        return;
    }
    uint32_t cpu = smp_current_cpu_index();
    if (cpu < SMP_MAX_CPUS)
    {
        __atomic_add_fetch(&g_bootstrap_preempt_depth[cpu], 1u, __ATOMIC_ACQ_REL);
    }
}

void spinlock_preempt_enable(void)
{
    thread_t *thread = current_thread_local();
    if (thread)
    {
        uint32_t depth = __atomic_load_n(&thread->preempt_disable_depth, __ATOMIC_ACQUIRE);
        if (depth > 0)
        {
            __atomic_sub_fetch(&thread->preempt_disable_depth, 1u, __ATOMIC_ACQ_REL);
        }
        return;
    }
    uint32_t cpu = smp_current_cpu_index();
    if (cpu >= SMP_MAX_CPUS)
    {
        return;
    }
    uint32_t depth = __atomic_load_n(&g_bootstrap_preempt_depth[cpu], __ATOMIC_ACQUIRE);
    if (depth > 0)
    {
        __atomic_sub_fetch(&g_bootstrap_preempt_depth[cpu], 1u, __ATOMIC_ACQ_REL);
    }
}

bool spinlock_preempt_disabled(void)
{
    thread_t *thread = current_thread_local();
    if (thread)
    {
        return __atomic_load_n(&thread->preempt_disable_depth, __ATOMIC_ACQUIRE) != 0;
    }
    uint32_t cpu = smp_current_cpu_index();
    return cpu < SMP_MAX_CPUS &&
           __atomic_load_n(&g_bootstrap_preempt_depth[cpu], __ATOMIC_ACQUIRE) != 0;
}

void process_yield(void)
{
    /* A voluntary yield is not permitted while this CPU owns a spinlock. In
     * particular, storage polling can be reached while the VFS tree lock is
     * held; switching there would strand the lock owner behind its waiters. */
    if (spinlock_preempt_disabled())
    {
        return;
    }
    scheduler_schedule(true);
}

static void process_sleep_ticks_impl(uint64_t ticks, bool absolute)
{
    /* A lock owner cannot block, but ordinary sleepers must register under the
     * same scheduler lock used by termination and remote timer wakeups. */
    if (spinlock_preempt_disabled()) return;
    if (ticks == 0) { process_yield(); return; }

    uint64_t flags = scheduler_lock_acquire("process_sleep_ticks");
    thread_t *thread = current_thread_local();
    if (!thread || thread->is_idle)
    {
        scheduler_lock_release(flags);
        process_yield();
        return;
    }
    if (!thread_lifetime_active(thread) || thread->exited || thread->pending_destroy ||
        thread->state == THREAD_STATE_ZOMBIE ||
        (thread->process && thread->process->state == PROCESS_STATE_ZOMBIE))
    {
        scheduler_lock_release(flags);
        scheduler_schedule(false);
        return;
    }

    uint64_t now = timer_ticks();
    uint64_t wake_tick = absolute ? ticks : ticks > UINT64_MAX - now ? UINT64_MAX : now + ticks;
    if (wake_tick <= now)
    {
        scheduler_lock_release(flags);
        process_yield();
        return;
    }
    thread->state = THREAD_STATE_BLOCKED;
    thread->sleep_until_tick = wake_tick;
    thread->wake_pending = false;
    SCHED_SLEEP_LOG("[sleep] enqueue thread=%s pid=0x%016llX wake_tick=%llu now=%llu\r\n",
                    thread->name[0] ? thread->name : "<unnamed>",
                    (unsigned long long)(thread->process ? thread->process->pid : 0),
                    (unsigned long long)wake_tick,
                    (unsigned long long)now);
    sleep_queue_insert(thread);
    scheduler_lock_release(flags);
    scheduler_schedule(false);
}

void process_sleep_ticks(uint64_t ticks)
{
    process_sleep_ticks_impl(ticks, false);
}

void process_sleep_ms(uint32_t ms)
{
    if (!ms) process_sleep_ticks(1);
    else process_sleep_ticks_impl(timer_deadline_after_millis(ms), true);
}

void process_destroy_marked(process_t *process)
{
    serial_printf("[proc] destroy pid=0x%016llX name=%s main_thread=0x%016llX wait_status=%u\r\n",
                  (unsigned long long)process->pid,
                  process->name,
                  (unsigned long long)(uintptr_t)process->main_thread,
                  (unsigned)process->wait_status);

    user_atk_on_process_destroy(process);
    shell_service_cleanup_process(process);
    procfs_unregister_process(process);

    process_orphan_children(process);

    process_detach_child(process);

    /* Deferred reclamation also runs under g_scheduler_lock. Detach the whole
     * list and sever every thread->process link while holding that lock so a
     * reclaimer cannot retain a process pointer across address-space teardown. */
    uint64_t sched_flags = scheduler_lock_acquire("process_destroy_detach_threads");
    spinlock_lock(&process->threads_lock);
    thread_t *thread = process->threads;
    process->threads = NULL;
    process->thread_count = 0;
    process->main_thread = NULL;
    process->current_thread = NULL;
    for (thread_t *cursor = thread; cursor; cursor = cursor->process_next)
    {
        process_futex_cancel_wait_locked(cursor);
        cursor->process = NULL;
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(sched_flags);

    while (thread)
    {
        thread_t *next = thread->process_next;
        thread->process_next = NULL;
        thread_context_guard_release_pages(thread);
        thread_enqueue_deferred_free(thread);
        thread = next;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();
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
    cpu_restore_flags(flags);

    process_release_context(process);
    process->magic = 0;
    process_free_user_regions(process);
    paging_destroy_space(&process->address_space);
    __atomic_store_n(&process->lifetime_state, PROCESS_LIFETIME_FREED, __ATOMIC_RELEASE);
    free(process);
}

void process_destroy(process_t *process)
{
    if (!process || process == g_idle_process)
    {
        return;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint64_t sched_flags = scheduler_lock_acquire("process_destroy");
    spinlock_lock(&g_process_lock);
    bool ready = process->magic == PROCESS_MAGIC &&
                 process->state == PROCESS_STATE_ZOMBIE &&
                 __atomic_load_n(&process->join_waiters, __ATOMIC_ACQUIRE) == 0 &&
                 process_threads_quiescent_locked(process) &&
                 process_try_mark_destroying(process);
    spinlock_unlock(&g_process_lock);
    scheduler_lock_release(sched_flags);
    cpu_restore_flags(flags);
    if (!ready)
    {
        return;
    }

    process_destroy_marked(process);
}

/* Consume a reference retained under g_process_lock and, when it is the last
 * reference, atomically hand the process to teardown.  Callers must not touch
 * process after this returns: another owner may destroy it when this function
 * only releases the reference. */
static void process_destroy_retained(process_t *process)
{
    if (!process)
    {
        return;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint64_t sched_flags = scheduler_lock_acquire("process_destroy_retained");
    spinlock_lock(&g_process_lock);
    bool ready = process->magic == PROCESS_MAGIC &&
                 process->state == PROCESS_STATE_ZOMBIE &&
                 __atomic_load_n(&process->join_waiters, __ATOMIC_ACQUIRE) == 1 &&
                 process_threads_quiescent_locked(process) &&
                 process_try_mark_destroying(process);
    if (process->join_waiters > 0)
    {
        __atomic_sub_fetch(&process->join_waiters, 1u, __ATOMIC_ACQ_REL);
    }
    spinlock_unlock(&g_process_lock);
    scheduler_lock_release(sched_flags);
    cpu_restore_flags(flags);

    if (ready)
    {
        process_destroy_marked(process);
    }
}

static void process_mark_terminated(process_t *process, int status, uint32_t wait_status)
{
    if (!process)
    {
        return;
    }

    uint64_t sched_flags = scheduler_lock_acquire("process_mark_terminated");
    if (process->state == PROCESS_STATE_ZOMBIE)
    {
        scheduler_lock_release(sched_flags);
        return;
    }
    process->exit_status = status;
    process->wait_status = wait_status;
    process->state = PROCESS_STATE_ZOMBIE;

    process_alarm_cancel_locked(process);

    spinlock_lock(&process->threads_lock);
    for (thread_t *thread = process->threads; thread; thread = thread->process_next)
    {
        process_io_cancel_thread_locked(thread);
        if (thread_in_run_queue_load(thread))
        {
            remove_from_run_queue_locked(thread);
        }
        thread_remove_from_wait_queue(thread);
        if (thread->sleeping)
        {
            sleep_queue_remove(thread);
        }
        thread->exit_status = status;
        thread->exited = true;
        thread->state = THREAD_STATE_ZOMBIE;
        thread->preempt_pending = false;
        thread->time_slice_remaining = 0;
        thread->wake_pending = false;
        wait_queue_wake_all_locked(&thread->join_queue);
    }
    spinlock_unlock(&process->threads_lock);

    /* Process joiners are released last, once the entire thread list has been
     * made terminal. */
    wait_queue_wake_all_locked(&process->wait_queue);
    scheduler_lock_release(sched_flags);
}

static void process_exit_with_status(int status, uint32_t wait_status) __attribute__((noreturn));
static void process_exit_with_status(int status, uint32_t wait_status)
{
    thread_t *current = current_thread_local();
    if (!current)
    {
        fatal("process_exit with no current thread");
    }

    process_t *proc = current->process;
    if (proc)
    {
        process_mark_terminated(proc, status, wait_status);
    }
    else
    {
        current->exit_status = status;
        current->exited = true;
        current->state = THREAD_STATE_ZOMBIE;
        current->preempt_pending = false;
        current->time_slice_remaining = 0;
        wait_queue_wake_all(&current->join_queue);
    }
    smp_broadcast_schedule_ipi(false);

    scheduler_schedule(false);
    fatal("process_exit returned");
}

void process_exit(int status)
{
    process_exit_with_status(status, (uint32_t)(status & 255) << 8);
}

void process_exit_signal(int number)
{
    if (number <= 0 || number >= (int)ALIX_SIGNAL_COUNT) fatal("invalid process exit signal");
    process_exit_with_status(128 + number, (uint32_t)number);
}

int process_wait_status_snapshot(process_t *process, uint32_t *output)
{
    /* The caller owns a retained process, so no raw lookup or borrowed
     * process pointer is carried across a wait. Terminal state and cause are
     * published under this lock and never change after publication. */
    if (!process || !output) return -EINVAL;
    uint64_t flags = scheduler_lock_acquire("process_wait_status");
    int result = process->state == PROCESS_STATE_ZOMBIE && process_threads_quiescent_locked(process) ? 0 : -EAGAIN;
    if (!result) *output = process->wait_status;
    scheduler_lock_release(flags);
    return result;
}

static bool process_join_ready(void *context)
{
    process_t *proc = (process_t *)context;
    return !proc ||
           (proc->state == PROCESS_STATE_ZOMBIE && process_threads_quiescent_locked(proc));
}

static bool process_join_begin(process_t *process)
{
    if (!process || process == current_process_local())
    {
        return false;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_lock(&g_process_lock);
    bool valid = process->magic == PROCESS_MAGIC &&
                 __atomic_load_n(&process->lifetime_state, __ATOMIC_ACQUIRE) == PROCESS_LIFETIME_ALIVE;
    if (valid)
    {
        __atomic_add_fetch(&process->join_waiters, 1u, __ATOMIC_ACQ_REL);
    }
    spinlock_unlock(&g_process_lock);
    cpu_restore_flags(flags);
    return valid;
}

static void process_join_end(process_t *process)
{
    process_release_reference(process);
}

int process_join_with_hook(process_t *process,
                          int *status_out,
                          process_wait_hook_t hook,
                          void *context)
{
    if (!process_join_begin(process))
    {
        return -1;
    }

    if (hook)
    {
        while (1)
        {
            uint64_t sched_flags = scheduler_lock_acquire("process_join_hook_check");
            bool ready = process_join_ready(process);
            scheduler_lock_release(sched_flags);
            if (ready)
            {
                break;
            }
            hook(context);
            /* Poll input at most once per tick while retaining the ordinary
             * child-exit wakeup. Yielding here leaves the parent runnable and
             * spins an otherwise idle CPU for the entire child's lifetime. */
            (void)wait_queue_wait_timeout(&process->wait_queue,
                                         process_join_ready, process, 1);
        }
    }
    else
    {
        wait_queue_wait(&process->wait_queue, process_join_ready, process);
    }

    int status = process->exit_status;
    if (status_out)
    {
        *status_out = status;
    }
    process_join_end(process);
    return status;
}

int process_join(process_t *process, int *status_out)
{
    return process_join_with_hook(process, status_out, NULL, NULL);
}

int process_join_kernel_service(process_t *process, int *status_out)
{
    if (!process || !process->kernel_service || process == current_process_local()) return -22;
    /* The factory reference remains owned through this temporary join ref. */
    if (!process_join_begin(process)) return -3;
    wait_queue_wait(&process->wait_queue, process_join_ready, process);
    if (status_out) *status_out = process->exit_status;
    process_join_end(process);
    process_destroy_retained(process);
    return 0;
}

process_t *process_create_kernel_observed(const char *name, thread_entry_t entry,
                                           void *argument, size_t stack_size, int stdout_fd,
                                           process_creation_watch_t *watch)
{
    if (!watch || __atomic_load_n(&watch->owner, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&watch->constructed, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&watch->complete, __ATOMIC_ACQUIRE)) return NULL;
    /* Inherit the actual creator, never a borrowed session-owner process
     * pointer retained across potentially blocking construction. */
    return process_create_kernel_internal(name, entry, argument, stack_size, stdout_fd, NULL, false, watch);
}

int process_creation_watch_stop(process_creation_watch_t *watch)
{
    if (!watch || spinlock_preempt_disabled()) return -22;
    /* The descriptor cleanup worker is persistent. A constructor may be
     * asleep inside VFS, or may have been killed before publication. */
    while (!__atomic_load_n(&watch->constructed, __ATOMIC_ACQUIRE) &&
           !__atomic_load_n(&watch->complete, __ATOMIC_ACQUIRE) &&
           !process_creation_watch_creator_stopped(watch)) process_sleep_ms(1);
    process_t *owner = __atomic_load_n(&watch->owner, __ATOMIC_ACQUIRE);
    if (owner)
    {
        if (owner == current_process_local() || owner->kernel_service) return -22;
        /* Stop before waiting for creator completion: that creator may itself
         * be joining this actor. The retained factory owner keeps metadata
         * valid until the creator's last access or terminal handoff. */
        process_kill_tree(owner);
        wait_queue_wait(&owner->wait_queue, process_join_ready, owner);
    }
    while (!__atomic_load_n(&watch->complete, __ATOMIC_ACQUIRE) &&
           !process_creation_watch_creator_stopped(watch)) process_sleep_ms(1);
    return 0;
}

void process_creation_watch_release(process_creation_watch_t *watch)
{
    /* Protected cleanup only, after stop and after all containing raw-pointer
     * slots have been cleared. No caller can resume using this record. */
    if (!watch) return;
    process_t *owner = __atomic_exchange_n(&watch->owner, NULL, __ATOMIC_ACQ_REL);
    if (owner) process_destroy_retained(owner);
}


static bool process_kill_with_status(process_t *process, int status, uint32_t wait_status)
{
    if (!process)
    {
        return false;
    }

    if (process == current_process_local())
    {
        if (process->kernel_service) return false;
        process_exit_with_status(status, wait_status);
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_lock(&g_process_lock);
    bool valid = process->magic == PROCESS_MAGIC && !process->kernel_service &&
                 __atomic_load_n(&process->lifetime_state, __ATOMIC_ACQUIRE) == PROCESS_LIFETIME_ALIVE;
    if (valid)
    {
        __atomic_add_fetch(&process->join_waiters, 1u, __ATOMIC_ACQ_REL);
    }
    spinlock_unlock(&g_process_lock);
    cpu_restore_flags(flags);
    if (!valid)
    {
        return false;
    }

    process_mark_terminated(process, status, wait_status);
    smp_broadcast_schedule_ipi(false);
    process_join_end(process);
    return true;
}

bool process_kill(process_t *process, int status)
{
    return process_kill_with_status(process, status, (uint32_t)(status & 255) << 8);
}

bool process_kill_signal(process_t *process, int number)
{
    if (number <= 0 || number >= (int)ALIX_SIGNAL_COUNT) return false;
    return process_kill_with_status(process, 128 + number, (uint32_t)number);
}

void process_kill_tree(process_t *process)
{
    if (!process || process->kernel_service)
    {
        return;
    }

    process_t *child = NULL;
    while ((child = process_retain_first_child(process)) != NULL)
    {
        process_kill_tree(child);
        process_join(child, NULL);
        /* Another registered owner may intentionally retain a quiescent
         * child. Detach before dropping our traversal ref so the loop advances. */
        process_detach_child(child);
        process_destroy_retained(child);
    }

    if (!process_is_zombie(process)) process_kill(process, -1);
}

process_t *process_current(void)
{
    return current_process_local();
}

bool process_current_is_kernel_service(void)
{
    process_t *process = current_process_local();
    return process && process->kernel_service;
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
            remove_from_run_queue_locked(thread);
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

bool wait_queue_wait_timeout(wait_queue_t *queue,
                             wait_queue_predicate_t predicate,
                             void *context,
                             uint64_t timeout_ticks)
{
    if (!queue)
    {
        process_sleep_ticks(timeout_ticks ? timeout_ticks : 1);
        return predicate ? predicate(context) : true;
    }
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        process_sleep_ticks(timeout_ticks ? timeout_ticks : 1);
        return predicate ? predicate(context) : false;
    }

    uint64_t now = timer_ticks();
    uint64_t deadline = 0;
    if (timeout_ticks > 0)
    {
        deadline = timeout_ticks > UINT64_MAX - now ? UINT64_MAX : now + timeout_ticks;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint64_t sched_flags = scheduler_lock_acquire("wait_queue_wait_timeout");

    for (;;)
    {
        spinlock_lock(&queue->lock);

        bool ready = !predicate || predicate(context);
        now = timer_ticks();
        bool timed_out = (timeout_ticks > 0 && now >= deadline);
        if (ready || timed_out)
        {
            if (thread->waiting_queue == queue)
            {
                wait_queue_remove_thread_locked(queue, thread);
                thread->waiting_queue = NULL;
            }
            if (thread->sleeping)
            {
                sleep_queue_remove(thread);
            }
            thread->state = THREAD_STATE_RUNNING;
            spinlock_unlock(&queue->lock);
            scheduler_lock_release(sched_flags);
            cpu_restore_flags(flags);
            return ready;
        }

        if (thread_in_run_queue_load(thread))
        {
            remove_from_run_queue_locked(thread);
        }
        thread->state = THREAD_STATE_BLOCKED;
        thread->waiting_queue = queue;
        wait_queue_enqueue_locked(queue, thread);
        if (timeout_ticks > 0)
        {
            thread->sleep_until_tick = deadline;
            if (!thread->sleeping)
            {
                sleep_queue_insert(thread);
            }
        }

        spinlock_unlock(&queue->lock);
        scheduler_lock_release(sched_flags);

        scheduler_schedule(false);
        sched_flags = scheduler_lock_acquire("wait_queue_wait_timeout");
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
            uint32_t running_cpu = __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE);
            if (running_cpu != RUN_QUEUE_CPU_INVALID || thread->in_transition)
            {
                thread->wake_pending = true;
            }
            else
            {
                thread->wake_pending = false;
                thread->state = THREAD_STATE_READY;
                enqueue_thread_on_cpu_locked(thread, scheduler_select_target_cpu(thread));
            }
        }
    }

    spinlock_unlock(&queue->lock);
    scheduler_lock_release(sched_flags);
    cpu_restore_flags(flags);
}

void wait_queue_wake_all_locked(wait_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
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
            uint32_t running_cpu = __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE);
            if (running_cpu != RUN_QUEUE_CPU_INVALID || thread->in_transition)
            {
                thread->wake_pending = true;
            }
            else
            {
                thread->wake_pending = false;
                thread->state = THREAD_STATE_READY;
                enqueue_thread_on_cpu_locked(thread, scheduler_select_target_cpu(thread));
            }
        }
        thread = wait_queue_dequeue_locked(queue);
    }

    spinlock_unlock(&queue->lock);
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
    wait_queue_wake_all_locked(queue);
    scheduler_lock_release(sched_flags);
    cpu_restore_flags(flags);
}

void process_set_priority(process_t *process, thread_priority_t priority)
{
    if (!process_pointer_valid(process))
    {
        return;
    }
    if (priority >= THREAD_PRIORITY_COUNT)
    {
        priority = THREAD_PRIORITY_NORMAL;
    }
    uint64_t sched_flags = scheduler_lock_acquire("process_set_priority");
    spinlock_lock(&process->threads_lock);
    process->default_priority = priority;
    for (thread_t *thread = process->threads; thread; thread = thread->process_next)
    {
        thread_set_base_priority_locked(thread, priority);
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(sched_flags);
}

void process_set_thread_priority(thread_t *thread, thread_priority_t priority)
{
    if (!thread_pointer_valid(thread))
    {
        return;
    }
    thread_set_base_priority(thread, priority);
}

void process_set_affinity(process_t *process, uint32_t cpu_index)
{
    if (!process_pointer_valid(process) ||
        cpu_index >= smp_cpu_count() ||
        !smp_cpu_by_index(cpu_index) ||
        !__atomic_load_n(&smp_cpu_by_index(cpu_index)->online, __ATOMIC_ACQUIRE))
    {
        return;
    }
    uint64_t sched_flags = scheduler_lock_acquire("process_set_affinity");
    spinlock_lock(&process->threads_lock);
    process->default_affinity_enabled = true;
    process->default_affinity_cpu = cpu_index;
    for (thread_t *thread = process->threads; thread; thread = thread->process_next)
    {
        thread_set_affinity_locked(thread, true, cpu_index);
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(sched_flags);
}

void process_clear_affinity(process_t *process)
{
    if (!process_pointer_valid(process))
    {
        return;
    }
    uint64_t sched_flags = scheduler_lock_acquire("process_clear_affinity");
    spinlock_lock(&process->threads_lock);
    process->default_affinity_enabled = false;
    process->default_affinity_cpu = RUN_QUEUE_CPU_INVALID;
    for (thread_t *thread = process->threads; thread; thread = thread->process_next)
    {
        thread_set_affinity_locked(thread, false, RUN_QUEUE_CPU_INVALID);
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(sched_flags);
}

void process_set_priority_override(process_t *process, thread_priority_t priority)
{
    if (!process_pointer_valid(process))
    {
        return;
    }
    if (priority >= THREAD_PRIORITY_COUNT)
    {
        priority = THREAD_PRIORITY_NORMAL;
    }
    uint64_t sched_flags = scheduler_lock_acquire("process_set_priority_override");
    spinlock_lock(&process->threads_lock);
    process->default_priority_override_active = true;
    process->default_priority_override = priority;
    for (thread_t *thread = process->threads; thread; thread = thread->process_next)
    {
        thread_set_priority_override_locked(thread, true, priority);
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(sched_flags);
}

void process_set_main_thread_priority_override(process_t *process, bool enabled,
                                                thread_priority_t priority)
{
    if (!process_pointer_valid(process)) return;
    if (priority >= THREAD_PRIORITY_COUNT) priority = THREAD_PRIORITY_NORMAL;
    uint64_t sched_flags = scheduler_lock_acquire("main_thread_priority_override");
    spinlock_lock(&process->threads_lock);
    thread_t *main = process->main_thread;
    if (thread_pointer_valid(main) && thread_lifetime_active(main))
    {
        if (!enabled)
        {
            enabled = process->default_priority_override_active;
            priority = process->default_priority_override;
        }
        else if (process->default_priority_override_active &&
                 process->default_priority_override > priority)
            priority = process->default_priority_override;
        thread_set_priority_override_locked(main, enabled, priority);
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(sched_flags);
}

void process_clear_priority_override(process_t *process)
{
    if (!process_pointer_valid(process))
    {
        return;
    }
    uint64_t sched_flags = scheduler_lock_acquire("process_clear_priority_override");
    spinlock_lock(&process->threads_lock);
    process->default_priority_override_active = false;
    for (thread_t *thread = process->threads; thread; thread = thread->process_next)
    {
        thread_set_priority_override_locked(thread, false, THREAD_PRIORITY_NORMAL);
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(sched_flags);
}


uint64_t process_take_preempt_resume_rip(void)
{
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        return 0;
    }
    return __atomic_exchange_n(&thread->tls.preempt_resume_rip, 0, __ATOMIC_ACQ_REL);
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
    layout->stack_top = process->user_initial_stack ? process->user_initial_stack : process->user_stack_top;
    layout->stack_size = process->user_stack_size;
    return process->is_user && process->user_entry_point != 0 && layout->stack_top != 0;
}

static uint64_t g_sbrk_zero_bytes_avoided;

/*
 * User-mode `sbrk(2)` implementation.
 *
 * Grows/shrinks the user heap break within the reserved user heap window.
 * Growth commits additional pages (mapping physical backing via
 * `process_heap_commit_range`) and zeroes the new bytes.
 *
 * Returns the previous break on success; returns -1 on failure.
 */
static int64_t process_user_sbrk_locked(process_t *process, int64_t increment)
{
    if (!process || !process->is_user || process->user_heap_base == 0)
    {
        return -1;
    }

    uintptr_t base = process->user_heap_base;
    uintptr_t limit = process->user_heap_limit;
    uintptr_t current = process->user_heap_brk;
    if (base == 0 || limit <= base || current < base || current > limit)
    {
        serial_printf("[sbrk] invalid bounds pid=0x%016llX base=0x%016llX limit=0x%016llX cur=0x%016llX\n",
                      (unsigned long long)process->pid,
                      (unsigned long long)base,
                      (unsigned long long)limit,
                      (unsigned long long)current);
        return -1;
    }
    uintptr_t new_brk = current;

    if (increment > 0)
    {
        uint64_t inc = (uint64_t)increment;
        if (inc > (limit - current))
        {
            serial_printf("[sbrk] clamp pid=0x%016llX inc=0x%016llX avail=0x%016llX\n",
                          (unsigned long long)process->pid,
                          (unsigned long long)inc,
                          (unsigned long long)(limit - current));
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
                serial_printf("[sbrk] commit failed pid=0x%016llX commit=[0x%016llX,0x%016llX) avail=0x%016llX\n",
                              (unsigned long long)process->pid,
                              (unsigned long long)commit_start,
                              (unsigned long long)commit_end,
                              (unsigned long long)user_memory_available());
                return -1;
            }
        }
        /* Commit already zeroed every fresh page. Only bytes exposed within
         * the old final page need another clear, including shrink/regrow. */
        uintptr_t zero_end = new_brk < commit_start ? new_brk : commit_start;
        size_t zero_bytes = zero_end > current ? zero_end - current : 0;
        if (!process_heap_zero_range(process, current, zero_bytes))
        {
            serial_printf("[sbrk] zero failed pid=0x%016llX range=[0x%016llX,0x%016llX)\n",
                          (unsigned long long)process->pid,
                          (unsigned long long)current,
                          (unsigned long long)(current + zero_bytes));
            return -1;
        }
        __atomic_fetch_add(&g_sbrk_zero_bytes_avoided, inc - zero_bytes, __ATOMIC_RELAXED);
    }
    else if (increment < 0)
    {
        /* Negate unsigned so INT64_MIN is rejected without signed overflow. */
        uint64_t dec = 0u - (uint64_t)increment;
        if (dec > (current - base))
        {
            serial_printf("[sbrk] negative clamp pid=0x%016llX dec=0x%016llX cur=0x%016llX base=0x%016llX\n",
                          (unsigned long long)process->pid,
                          (unsigned long long)dec,
                          (unsigned long long)current,
                          (unsigned long long)base);
            return -1;
        }
        new_brk = current - dec;
        uintptr_t new_commit = align_up_uintptr(new_brk, PAGE_SIZE_BYTES_LOCAL);
        if (new_commit < process->user_heap_committed)
        {
            if (!process_heap_release_from(process, new_commit))
            {
                return -1;
            }
            process->user_heap_committed = new_commit;
        }
    }

    process->user_heap_brk = new_brk;
    return (int64_t)current;
}

int64_t process_user_sbrk(process_t *process, int64_t increment)
{
    if (!process)
    {
        return -1;
    }
    uint64_t flags = process_memory_lock(process);
    int64_t result = process_user_sbrk_locked(process, increment);
    process_memory_unlock(process, flags);
    return result;
}

uint64_t thread_current_tid(void)
{
    thread_t *thread = current_thread_local();
    return thread ? thread->tid : 0;
}

int process_thread_set_tls(uintptr_t base)
{
    /* Reject kernel/noncanonical bases before WRMSR, which would otherwise
     * fault in supervisor mode. Mapping/lifetime remains the user's duty. */
    if (base != 0 && !user_ptr_range_valid((const void *)base, 1))
    {
        return -1;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    thread_t *thread = current_thread_local();
    if (!thread || !thread->is_user || !thread->process || !thread->process->is_user)
    {
        cpu_restore_flags(flags);
        return -1;
    }
    /* Save state and update the CPU as one non-preemptible operation. The
     * scheduler already saves/restores this MSR across switches/migration. */
    thread->fs_base = (uint64_t)base;
    wrmsr(MSR_FS_BASE, (uint64_t)base);
    __asm__ volatile ("" ::: "memory");
    cpu_restore_flags(flags);
    return 0;
}

uintptr_t process_thread_get_tls(void)
{
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    thread_t *thread = current_thread_local();
    uintptr_t base = 0;
    if (thread && thread->is_user && thread->process && thread->process->is_user)
    {
        base = (uintptr_t)rdmsr(MSR_FS_BASE);
    }
    cpu_restore_flags(flags);
    return base;
}

int process_thread_set_current_affinity(uint32_t cpu_index)
{
    thread_t *thread = current_thread_local();
    if (!thread || !thread->is_user || !thread->process || !thread->process->is_user)
    {
        return -1;
    }
    bool enabled = cpu_index != UINT32_MAX;
    const smp_cpu_t *cpu = enabled ? smp_cpu_by_index(cpu_index) : NULL;
    if (enabled && (cpu_index >= SMP_MAX_CPUS || !cpu || !cpu->present ||
                    !__atomic_load_n(&cpu->online, __ATOMIC_ACQUIRE)))
    {
        return -1;
    }
    thread_set_affinity(thread, enabled, cpu_index);
    /* Yield outside every lock so the scheduler can transfer stack ownership
     * to the requested CPU before this syscall returns. */
    if (enabled)
    {
        process_yield();
    }
    return 0;
}

uint32_t process_thread_current_cpu(void)
{
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint32_t cpu = current_cpu_index();
    cpu_restore_flags(flags);
    return cpu;
}

static bool user_thread_has_exited(void *context)
{
    thread_t *thread = (thread_t *)context;
    return !thread || thread->state == THREAD_STATE_ZOMBIE;
}

int64_t process_user_thread_create(const char *name,
                                  uintptr_t entry,
                                  uintptr_t arg,
                                  size_t user_stack_size)
{
    process_t *proc = current_process_local();
    if (!proc || !proc->is_user)
    {
        return -1;
    }

    if (entry < USER_ADDRESS_SPACE_BASE ||
        entry > USER_ADDRESS_SPACE_LIMIT)
    {
        return -1;
    }

    size_t stack_bytes = user_stack_size ? user_stack_size : proc->user_stack_size;
    if (stack_bytes > SIZE_MAX - (PAGE_SIZE_BYTES_LOCAL - 1))
    {
        return -1;
    }
    stack_bytes = align_up_size(stack_bytes, PAGE_SIZE_BYTES_LOCAL);
    if (stack_bytes < PAGE_SIZE_BYTES_LOCAL)
    {
        stack_bytes = PAGE_SIZE_BYTES_LOCAL;
    }

    uint64_t memory_flags = process_memory_lock(proc);
    uintptr_t base = 0;
    void *host_stack = NULL;
    if (!process_allocate_aux_user_segment_locked(proc, stack_bytes, &base, &host_stack))
    {
        process_memory_unlock(proc, memory_flags);
        return -1;
    }
    process_memory_unlock(proc, memory_flags);

    uintptr_t ret_addr = USER_STUB_CODE_BASE + USER_THREAD_EXIT_STUB_OFFSET;
    uintptr_t initial_rsp = base + stack_bytes - sizeof(uint64_t);
    memcpy((uint8_t *)host_stack + (stack_bytes - sizeof(uint64_t)), &ret_addr, sizeof(ret_addr));
    if (!process_complete_user_mapping(proc))
    {
        (void)process_unmap_user_segment(proc, base, stack_bytes);
        return -1;
    }

    user_thread_bootstrap_t *bootstrap = (user_thread_bootstrap_t *)malloc(sizeof(*bootstrap));
    if (!bootstrap)
    {
        (void)process_unmap_user_segment(proc, base, stack_bytes);
        return -1;
    }
    bootstrap->entry = entry;
    bootstrap->stack_top = initial_rsp;
    bootstrap->rdi = (uint64_t)arg;
    bootstrap->rsi = 0;
    bootstrap->rdx = 0;

    process_tls_allocation_t tls = {0};
    if (!process_allocate_user_tls(proc, &tls))
    {
        free(bootstrap);
        (void)process_unmap_user_segment(proc, base, stack_bytes);
        return -1;
    }

    if (!name || !name[0])
    {
        name = "uthread";
    }
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
        (void)process_unmap_user_segment(proc, base, stack_bytes);
        if (tls.size)
        {
            (void)process_unmap_user_segment(proc, tls.base, tls.size);
        }
        return -1;
    }

    thread->user_stack_base = base;
    thread->user_stack_size = stack_bytes;
    thread->user_tls_base = tls.base;
    thread->user_tls_size = tls.size;
    thread->fs_base = tls.thread_pointer;

    enqueue_thread(thread);
    return (int64_t)thread->tid;
}

int process_user_thread_join(uint64_t tid, int *status_out)
{
    if (tid == 0)
    {
        return -1;
    }

    thread_t *current = current_thread_local();
    process_t *proc = current ? current->process : NULL;
    if (!current || !proc || !proc->is_user)
    {
        return -1;
    }
    if (current->tid == tid)
    {
        return -1;
    }

    thread_t *target = NULL;
    spinlock_lock(&proc->threads_lock);
    thread_t *cursor = proc->threads;
    while (cursor)
    {
        if (cursor->tid == tid)
        {
            target = cursor;
            break;
        }
        cursor = cursor->process_next;
    }
    if (target)
    {
        if (target->join_claimed != 0 || target->pending_destroy)
        {
            target = NULL;
        }
        else
        {
            target->join_claimed = 1;
        }
    }
    spinlock_unlock(&proc->threads_lock);

    if (!target)
    {
        return -1;
    }

    wait_queue_wait(&target->join_queue, user_thread_has_exited, target);
    int status = target->exit_status;
    if (status_out)
    {
        *status_out = status;
    }
    thread_enqueue_deferred_free(target);
    return status;
}

int process_user_thread_detach(uint64_t tid)
{
    thread_t *current = current_thread_local();
    process_t *proc = current ? current->process : NULL;
    if (!current || !current->is_user || !proc || !proc->is_user || tid == 0)
    {
        return -1;
    }
    uint64_t flags = scheduler_lock_acquire("thread_detach");
    spinlock_lock(&proc->threads_lock);
    thread_t *target = proc->threads;
    while (target && target->tid != tid)
    {
        target = target->process_next;
    }
    int result = -1;
    if (target && target->join_claimed == 0 &&
        !target->pending_destroy && thread_lifetime_active(target))
    {
        target->join_claimed = 1;
        target->detached = true;
        if (target->exited || target->state == THREAD_STATE_ZOMBIE)
        {
            thread_enqueue_deferred_free(target);
        }
        result = 0;
    }
    spinlock_unlock(&proc->threads_lock);
    scheduler_lock_release(flags);
    return result;
}

int process_user_thread_info(uint64_t tid, syscall_thread_info_t *info)
{
    thread_t *current = current_thread_local();
    process_t *proc = current ? current->process : NULL;
    if (!info || !current || !current->is_user || !proc || !proc->is_user)
    {
        return -22;
    }
    if (tid == 0) tid = current->tid;
    uint64_t flags = scheduler_lock_acquire("user_thread_info");
    spinlock_lock(&proc->threads_lock);
    thread_t *target = proc->threads;
    while (target && target->tid != tid) target = target->process_next;
    int result = -3;
    if (target && !target->pending_destroy && thread_lifetime_active(target))
    {
        memset(info, 0, sizeof(*info));
        bool main_thread = target == proc->main_thread;
        info->tid = target->tid;
        info->stack_base = main_thread ? proc->user_stack_top - proc->user_stack_size
                                       : target->user_stack_base;
        info->stack_size = main_thread ? proc->user_stack_size : target->user_stack_size;
        info->guard_size = main_thread ? USER_DEFAULT_STACK_GUARD_SIZE : PAGE_SIZE_BYTES_LOCAL;
        info->flags = (main_thread ? SYSCALL_THREAD_INFO_MAIN : 0) |
                      (target->detached ? SYSCALL_THREAD_INFO_DETACHED : 0);
        info->state = (uint32_t)target->state;
        info->cpu_index = target->running_cpu < SMP_MAX_CPUS ? target->running_cpu : target->last_cpu_index;
        memcpy(info->name, target->name, sizeof(info->name));
        info->name[sizeof(info->name) - 1] = '\0';
        result = 0;
    }
    spinlock_unlock(&proc->threads_lock);
    scheduler_lock_release(flags);
    return result;
}

int process_user_thread_set_name(uint64_t tid, const char *name)
{
    thread_t *current = current_thread_local();
    process_t *proc = current ? current->process : NULL;
    if (!name || !current || !current->is_user || !proc || !proc->is_user)
    {
        return -22;
    }
    size_t length = strlen(name);
    if (length >= PROCESS_NAME_MAX) return -34;
    if (tid == 0) tid = current->tid;
    uint64_t flags = scheduler_lock_acquire("user_thread_set_name");
    spinlock_lock(&proc->threads_lock);
    thread_t *target = proc->threads;
    while (target && target->tid != tid) target = target->process_next;
    int result = -3;
    if (target && !target->pending_destroy && !target->exited && thread_lifetime_active(target))
    {
        memset(target->name, 0, sizeof(target->name));
        memcpy(target->name, name, length);
        result = 0;
    }
    spinlock_unlock(&proc->threads_lock);
    scheduler_lock_release(flags);
    return result;
}

int process_user_thread_priority(uint64_t tid, int priority)
{
    thread_t *current = current_thread_local();
    process_t *proc = current ? current->process : NULL;
    if (!current || !current->is_user || !proc || !proc->is_user ||
        priority < SYSCALL_THREAD_PRIORITY_QUERY || priority > SYSCALL_THREAD_PRIORITY_HIGH)
        return -22;
    if (!tid) tid = current->tid;
    uint64_t flags = scheduler_lock_acquire("user_thread_priority");
    spinlock_lock(&proc->threads_lock);
    thread_t *target = proc->threads;
    while (target && target->tid != tid) target = target->process_next;
    int result = -3;
    if (proc->state != PROCESS_STATE_ZOMBIE &&
        __atomic_load_n(&proc->lifetime_state, __ATOMIC_ACQUIRE) == PROCESS_LIFETIME_ALIVE &&
        target && target->is_user && !target->pending_destroy && !target->exited &&
        target->state != THREAD_STATE_ZOMBIE && thread_lifetime_active(target))
    {
        if (priority == SYSCALL_THREAD_PRIORITY_QUERY)
            result = target->base_priority <= THREAD_PRIORITY_BACKGROUND ? SYSCALL_THREAD_PRIORITY_BACKGROUND :
                     target->base_priority >= THREAD_PRIORITY_HIGH ? SYSCALL_THREAD_PRIORITY_HIGH :
                     SYSCALL_THREAD_PRIORITY_NORMAL;
        else
        {
            thread_priority_t native = priority == SYSCALL_THREAD_PRIORITY_BACKGROUND ? THREAD_PRIORITY_BACKGROUND :
                                       priority == SYSCALL_THREAD_PRIORITY_HIGH ? THREAD_PRIORITY_HIGH : THREAD_PRIORITY_NORMAL;
            thread_set_base_priority_locked(target, native);
            result = 0;
        }
    }
    spinlock_unlock(&proc->threads_lock);
    scheduler_lock_release(flags);
    return result;
}

int process_user_thread_prepare_exit(void)
{
    thread_t *current = current_thread_local();
    process_t *proc = current ? current->process : NULL;
    if (!current || !current->is_user || !proc || !proc->is_user) return -22;
    uint64_t flags = scheduler_lock_acquire("user_thread_prepare_exit");
    spinlock_lock(&proc->threads_lock);
    current->user_cleanup_complete = true;
    bool others = false;
    for (thread_t *thread = proc->threads; thread; thread = thread->process_next)
    {
        if (thread != current && thread->is_user && !thread->exited &&
            thread->state != THREAD_STATE_ZOMBIE && !thread->user_cleanup_complete)
        {
            others = true;
            break;
        }
    }
    int result = 0;
    if (!others && proc->user_exit_owner_tid == 0)
    {
        proc->user_exit_owner_tid = current->tid;
        result = 1;
    }
    spinlock_unlock(&proc->threads_lock);
    scheduler_lock_release(flags);
    return result;
}

void process_user_thread_exit(int status)
{
    process_vm_syscall_leave();
    thread_t *current = current_thread_local();
    if (!current)
    {
        fatal("thread_exit with no current thread");
    }
    process_t *proc = current->process;
    if (!proc || !proc->is_user || !current->is_user)
    {
        fatal("thread_exit without user process");
    }
    uint64_t flags = scheduler_lock_acquire("user_thread_exit");
    spinlock_lock(&proc->threads_lock);
    bool last = true;
    for (thread_t *thread = proc->threads; thread; thread = thread->process_next)
    {
        if (thread != current && !thread->exited && thread->state != THREAD_STATE_ZOMBIE)
        {
            last = false;
            break;
        }
    }
    if (last)
    {
        spinlock_unlock(&proc->threads_lock);
        scheduler_lock_release(flags);
        process_exit(status);
    }
    current->exit_status = status;
    current->exited = true;
    current->state = THREAD_STATE_ZOMBIE;
    current->preempt_pending = false;
    current->time_slice_remaining = 0;
    if (current->detached)
    {
        thread_enqueue_deferred_free(current);
    }
    spinlock_unlock(&proc->threads_lock);
    wait_queue_wake_all_locked(&current->join_queue);
    scheduler_lock_release(flags);
    scheduler_schedule(false);
    fatal("thread_exit returned");
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
        process_snapshot_copy_name(info->name, proc->name[0] ? proc->name : "(anon)");
        info->stdout_fd = proc->stdout_fd;
        spinlock_lock(&proc->threads_lock);
        thread_t *thread = proc->main_thread ? proc->main_thread : proc->threads;
        if (thread)
        {
            info->thread_state = thread->state;
            process_snapshot_copy_name(info->thread_name, thread->name[0] ? thread->name : "");
            info->is_idle = thread->is_idle;
            info->time_slice_remaining = thread->time_slice_remaining;
            info->last_cpu_index = __atomic_load_n(&thread->last_cpu_index, __ATOMIC_RELAXED);
        }
        else
        {
            info->thread_state = THREAD_STATE_ZOMBIE;
            info->thread_name[0] = '\0';
            info->is_idle = false;
            info->time_slice_remaining = 0;
            info->last_cpu_index = RUN_QUEUE_CPU_INVALID;
        }
        spinlock_unlock(&proc->threads_lock);
        info->is_current = false;
        for (uint32_t cpu = 0; cpu < SMP_MAX_CPUS; ++cpu)
        {
            if (g_current_processes[cpu] == proc)
            {
                info->is_current = true;
                break;
            }
        }
        info->runtime_ticks = __atomic_load_n(&proc->runtime_ticks, __ATOMIC_RELAXED);

        uint64_t memory_flags = process_memory_lock(proc);
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
        process_memory_unlock(proc, memory_flags);
    }
    spinlock_unlock(&g_process_lock);

    cpu_restore_flags(flags);
    return count;
}

size_t process_cpu_snapshot(process_cpu_info_t *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }

    uint32_t cpu_count = smp_cpu_count();
    if (cpu_count > SMP_MAX_CPUS)
    {
        cpu_count = SMP_MAX_CPUS;
    }

    uint64_t sched_flags = scheduler_lock_acquire("process_cpu_snapshot");
    size_t count = 0;
    for (uint32_t i = 0; i < cpu_count && count < capacity; ++i)
    {
        process_cpu_info_t *info = &buffer[count++];
        const smp_cpu_t *cpu = smp_cpu_by_index(i);
        info->cpu_index = i;
        info->online = (cpu && __atomic_load_n(&cpu->online, __ATOMIC_ACQUIRE)) ? 1u : 0u;
        info->run_queue_depth = __atomic_load_n(&g_run_queues[i].total, __ATOMIC_RELAXED);
        info->total_ticks = __atomic_load_n(&g_cpu_usage[i].total_ticks, __ATOMIC_RELAXED);
        info->idle_ticks = __atomic_load_n(&g_cpu_usage[i].idle_ticks, __ATOMIC_RELAXED);
        info->switch_count = __atomic_load_n(&g_cpu_switch_counts[i], __ATOMIC_RELAXED);
        info->current_pid = 0;
        info->current_thread_state = THREAD_STATE_ZOMBIE;
        info->current_process_name[0] = '\0';
        info->current_thread_name[0] = '\0';

        thread_t *current = g_current_threads[i];
        if (current)
        {
            info->current_thread_state = current->state;
            info->current_pid = current->process ? current->process->pid : 0;
            process_snapshot_copy_name(info->current_process_name,
                                       (current->process && current->process->name[0]) ? current->process->name : "");
            process_snapshot_copy_name(info->current_thread_name, current->name[0] ? current->name : "");
        }
    }

    scheduler_lock_release(sched_flags);
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
    /* Arming changes global kernel PTEs. Keep the eligibility check and
     * publication atomic with scheduler claims and their stack disarm. */
    uint64_t flags = scheduler_lock_acquire("stack_watch_thread");
    bool result = thread_stack_watch_activate(thread, context, 0);
    scheduler_lock_release(flags);
    return result;
#else
    (void)thread;
    (void)context;
    return false;
#endif
}

bool process_stack_watch_process(process_t *process, const char *context)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!process)
    {
        return false;
    }
    uint64_t flags = scheduler_lock_acquire("stack_watch_process");
    spinlock_lock(&process->threads_lock);
    /* Resolve the main-thread pointer while its lifetime is protected.
     * Do not call the public wrapper and recursively take scheduler_lock. */
    bool result = thread_stack_watch_activate(process->main_thread, context, 0);
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(flags);
    return result;
#else
    (void)process;
    (void)context;
    return false;
#endif
}

static void scheduler_log_process_age_snapshot(uint64_t now_ticks)
{
    if (smp_current_cpu_index() != 0)
    {
        return;
    }

    uint64_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 1000;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_lock(&g_process_lock);
    for (process_t *proc = g_process_list; proc; proc = proc->next)
    {
        thread_t *thread = proc->main_thread;
        if (thread && !thread_pointer_valid(thread))
        {
            serial_printf("[sched] proc_age skip invalid main_thread pid=0x%016llX name=%s ptr=0x%016llX\r\n",
                          (unsigned long long)proc->pid,
                          proc->name[0] ? proc->name : "<unnamed>",
                          (unsigned long long)(uintptr_t)thread);
            thread = NULL;
        }
        uint64_t last_tick = thread ? __atomic_load_n(&thread->last_scheduled_tick, __ATOMIC_RELAXED) : 0;
        uint64_t elapsed_ticks = (last_tick && now_ticks > last_tick) ? (now_ticks - last_tick) : 0;
        uint64_t elapsed_sec = freq ? (elapsed_ticks / freq) : 0;
        const char *pname = proc->name[0] ? proc->name : "<unnamed>";
        const char *pstate = process_state_name(proc->state);
        const char *tstate = thread ? thread_state_name(thread->state) : "none";
        uint64_t pid = proc->pid;
        SCHED_LOG("[sched] proc_age pid=0x%016llX name=%s state=%s thread_state=%s last_s=%llus\r\n",
                  (unsigned long long)pid,
                  pname,
                  pstate,
                  tstate,
                  (unsigned long long)elapsed_sec);
    }
    spinlock_unlock(&g_process_lock);
    cpu_restore_flags(flags);
}

/*
 * Timer/IPI hook used to drive:
 * - sleep queue wakeups
 * - stack watch timeout checks
 * - preemptive scheduling (time slice expiration)
 *
 * When a time slice expires, this function rewrites the interrupted RIP to a
 * preemption trampoline:
 * - user mode → `USER_PREEMPT_STUB_BASE` (mapped per-process)
 * - kernel mode → `process_preempt_trampoline` (arch/x86/process_preempt.S)
 */
static bool g_deferred_wakes;
uint64_t g_deferred_wake_ticks, g_deferred_wake_runs;

void process_poll_deferred_work(void)
{
    process_vm_poll_tlb_completion();
    /* Ordinary value-only syscalls should pay only pending-flag checks when
     * no work was deferred, rather than repeated CPU/guard queries. */
    if (!__atomic_load_n(&g_deferred_wakes, __ATOMIC_ACQUIRE)) return;
    if (spinlock_preempt_disabled() || !(cpu_save_flags() & RFLAGS_IF_BIT)) return;
    if (smp_current_cpu_index() != 0 ||
        !__atomic_exchange_n(&g_deferred_wakes, false, __ATOMIC_ACQ_REL)) return;
    /* A syscall-heavy BSP can be inside a preparation guard on almost every
     * timer interrupt. Time still advances, but sleeping UI/service threads
     * must not wait for a future IRQ to happen to land outside that guard. */
    uint64_t now = timer_ticks();
    sleep_queue_wake_due(now);
    process_alarm_tick(now);
    __atomic_add_fetch(&g_deferred_wake_runs, 1u, __ATOMIC_RELAXED);
}

void process_on_timer_tick(interrupt_frame_t *frame)
{
    if (!frame)
    {
        return;
    }

    thread_t *thread = current_thread_local();
    cpu_account_tick(thread, (frame->cs & 3u) == 3u);

    /* Generic spinlocks raise this depth before attempting the lock.  Do not
     * enter scheduler housekeeping from an interrupt while the interrupted
     * thread owns (or is waiting for) one: housekeeping acquires the scheduler
     * lock and can otherwise invert scheduler -> subsidiary-lock ordering on
     * another CPU.  A later timer/IPI will perform the deferred work. */
    if (spinlock_preempt_disabled())
    {
        if (smp_current_cpu_index() == 0)
        {
            __atomic_store_n(&g_deferred_wakes, true, __ATOMIC_RELEASE);
            __atomic_add_fetch(&g_deferred_wake_ticks, 1u, __ATOMIC_RELAXED);
        }
        return;
    }

    process_vm_poll_tlb_completion();

    /* IRQ0 runs on the BSP and broadcasts schedule IPIs to the APs.  Global
     * housekeeping must run once per tick, not once on every CPU, otherwise
     * every IPI contends on the same scheduler and sleep-queue locks. */
    if (smp_current_cpu_index() == 0)
    {
        static uint64_t last_proc_log = 0;
        uint64_t now_ticks = timer_ticks();
        uint64_t freq = timer_frequency();
        if (freq == 0)
        {
            freq = 1000;
        }
        uint64_t interval = freq * 5ULL;
        if (last_proc_log == 0 || (now_ticks - last_proc_log) >= interval)
        {
            last_proc_log = now_ticks;
            scheduler_log_process_age_snapshot(now_ticks);
        }

        sleep_queue_wake_due(now_ticks);
        process_alarm_tick(now_ticks);
        __atomic_store_n(&g_deferred_wakes, false, __ATOMIC_RELEASE);
        stack_watch_check_timeouts();
    }

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
        /* Wakeup IPIs share this handler with the timer broadcast. They can
         * arrive many times within one tick, so an interrupt is not a unit of
         * CPU time. Charge the slice from its dispatch timestamp instead. */
        uint64_t now = timer_ticks();
        uint64_t started = __atomic_load_n(&thread->last_scheduled_tick, __ATOMIC_RELAXED);
        uint64_t elapsed = now >= started ? now - started : 0;
        uint32_t quantum = scheduler_thread_time_slice_ticks(thread);
        thread->time_slice_remaining = elapsed >= quantum ? 0 : quantum - (uint32_t)elapsed;
    }

    if (thread->time_slice_remaining > 0)
    {
        return;
    }

    bool user_mode = frame && ((frame->cs & 0x3u) == 0x3u);
    if (!frame)
    {
        return;
    }
    /* The user helper already yields. Do not build another helper frame on
     * top of its partially restored registers or replace its destination. */
    if (user_mode && frame->rip >= USER_PREEMPT_STUB_BASE &&
        frame->rip - USER_PREEMPT_STUB_BASE < USER_PREEMPT_STUB_SIZE)
    {
        return;
    }

    thread->preempt_pending = true;
    thread->time_slice_remaining = scheduler_thread_time_slice_ticks(thread);

    __atomic_store_n(&thread->tls.preempt_resume_rip, frame->rip, __ATOMIC_RELEASE);
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
            /* During a context switch we may have already published the incoming thread
             * while still running on the outgoing stack; treat that case as if the
             * outgoing owner is still current to avoid false cross-stack noise. */
            if (writer->in_transition)
            {
                writer = rsp_owner;
            }
            else
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
static process_priority_info_t __attribute__((unused)) process_priority_info(const process_t *process)
{
    process_priority_info_t info;
    info.base_priority = THREAD_PRIORITY_NORMAL;
    info.priority_override = THREAD_PRIORITY_NORMAL;
    info.override_active = false;
    info.effective_priority = THREAD_PRIORITY_NORMAL;

    if (!process_pointer_valid(process) || !thread_pointer_valid(process->main_thread))
    {
        return info;
    }

    thread_t *thread = process->main_thread;
    info.base_priority = thread->base_priority;
    info.priority_override = thread->priority_override;
    info.override_active = thread->priority_override_active;
    info.effective_priority = thread_effective_priority(thread);
    return info;
}
