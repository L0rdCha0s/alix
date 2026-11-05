#include "process_internal.h"

process_t *process_create_user_elf_prepared(const char *name, const uint8_t *image, size_t size,
                                            process_launch_context_t *context,
                                            const char *const *argv, size_t argc,
                                            process_creation_watch_t *watch)
{
    if (!image || !size || !context || !process_cwd_description_valid(context->cwd) || !context->files ||
        !watch || watch->owner || watch->constructed || watch->complete) return NULL;
    process_t *process = allocate_process(name, true);
    if (!process) { __atomic_store_n(&watch->constructed, true, __ATOMIC_RELEASE); return NULL; }
    process->join_waiters = 1;
    __atomic_store_n(&watch->pid, process->pid, __ATOMIC_RELEASE);
    __atomic_store_n(&watch->owner, process, __ATOMIC_RELEASE);
    process->uid = context->uid; process->gid = context->gid;
    process->creation_mask = context->creation_mask;
    if (context->executable_path)
    {
        size_t length = strnlen(context->executable_path, sizeof(process->executable_path));
        if (!length || length == sizeof(process->executable_path) || context->executable_path[0] != '/') goto failed;
        memcpy(process->executable_path, context->executable_path, length + 1);
    }
    for (unsigned number = 1; number < ALIX_SIGNAL_COUNT; ++number)
        if (context->ignored_signals & (1ULL << (number - 1))) process->signal_actions[number].handler = 1;
    process->cwd_owner = context->cwd;
    process->cwd = fd_description_context(context->cwd);
    process->directory_streams = context->files;
    context->cwd = NULL; context->files = NULL;
    process->child_processes = fd_table_create_deferred(FD_TABLE_MAX_ENTRIES, process_fd_retirement_queue());
    if (!process->child_processes || !process_setup_basic_user_memory(process) ||
        !process_store_args(process, argv, argc) ||
        !process_store_environment(process, context->environment, context->environment_count) ||
        !process_prepare_stack_with_args(process)) goto failed;
    uintptr_t entry = 0;
    if (!elf_load_process(process, image, size, &entry) || !entry) goto failed;
    process->user_entry_point = entry;
    user_thread_bootstrap_t *bootstrap = calloc(1, sizeof(*bootstrap));
    if (!bootstrap) goto failed;
    bootstrap->entry = entry;
    bootstrap->stack_top = process->user_initial_stack ? process->user_initial_stack : process->user_stack_top;
    bootstrap->rdi = process->user_argc; bootstrap->rsi = process->user_argv_ptr;
    bootstrap->rdx = process->user_envp_ptr;
    process_tls_allocation_t tls = {0};
    if (!process_allocate_user_tls(process, &tls)) { free(bootstrap); goto failed; }
    thread_t *thread = thread_create(process, name, user_thread_entry, bootstrap,
                                      PROCESS_DEFAULT_STACK_SIZE, false, true);
    if (!thread) { free(bootstrap); goto failed; }
    thread->fs_base = tls.thread_pointer;
    thread->user_tls_base = tls.base;
    thread->user_tls_size = tls.size;
    thread->signal_mask = context->signal_mask;
    process_t *published = process_finalize_launched_process(process, thread, context->parent_pid);
    __atomic_store_n(&watch->constructed, true, __ATOMIC_RELEASE);
    return published;
failed:
    /* This protected constructor has not enqueued a thread. thread_create
     * failures roll back their own unpublished thread/stack; mapped process
     * backing and context references remain owned here. */
    __atomic_store_n(&watch->owner, NULL, __ATOMIC_RELEASE);
    process_clear_args(process);
    process_clear_environment(process);
    process_free_user_regions(process);
    paging_destroy_space(&process->address_space);
    process_release_context(process);
    free(process);
    __atomic_store_n(&watch->constructed, true, __ATOMIC_RELEASE);
    return NULL;
}

void process_discard_image(process_t *image)
{
    if (!image) return;
    process_free_user_regions(image);
    paging_destroy_space(&image->address_space);
    process_release_context(image);
    free(image);
}

extern void process_resume_exception(exception_frame_t *) __attribute__((noreturn));
static void fork_thread_entry(void *argument)
{
    exception_frame_t frame = *(exception_frame_t *)argument;
    current_thread_local()->vm_fault_state = NULL;
    free(argument);
    process_resume_exception(&frame);
}

process_t *process_fork_current(const syscall_frame_t *frame, process_launch_context_t *context,
                                process_creation_watch_t *watch)
{
    process_t *source = current_process_local();
    thread_t *caller = current_thread_local();
    void *signal_state = NULL;
    process_t *child = allocate_process(source->name, true);
    if (!child) { watch->constructed = true; return NULL; }
    child->join_waiters = 1;
    watch->pid = child->pid; watch->owner = child;
    child->uid = context->uid; child->gid = context->gid;
    child->creation_mask = context->creation_mask;
    child->cwd_owner = context->cwd; context->cwd = NULL;
    child->cwd = fd_description_context(child->cwd_owner);
    child->directory_streams = context->files; context->files = NULL;
    child->child_processes = fd_table_create_deferred(FD_TABLE_MAX_ENTRIES, process_fd_retirement_queue());
    memcpy(child->executable_path, source->executable_path, sizeof(child->executable_path));
    uint64_t lock = process_memory_lock(source);
    bool copied = child->child_processes && process_clone_user_memory_locked(child, source);
    process_memory_unlock(source, lock);
    if (!copied || !process_signal_fork_prepare(caller, &signal_state)) goto failed;
    exception_frame_t *saved = calloc(1, sizeof(*saved));
    if (!saved) goto failed;
    memcpy(saved, frame, offsetof(syscall_frame_t, rip));
    memcpy(&saved->cpu, &frame->rip, sizeof(saved->cpu));
    saved->rax = 0;
    thread_t *thread = thread_create(child, child->name, fork_thread_entry, saved,
        PROCESS_DEFAULT_STACK_SIZE, false, true);
    if (!thread) { free(saved); goto failed; }
    process_signal_fork_commit(thread, signal_state); signal_state = NULL;
    thread->vm_fault_state = saved;
    thread->fs_base = rdmsr(MSR_FS_BASE);
    thread->user_tls_base = caller->user_tls_base;
    thread->user_tls_size = caller->user_tls_size;
    thread->user_stack_base = caller->user_stack_base;
    thread->user_stack_size = caller->user_stack_size;
    thread->base_priority = caller->base_priority;
    thread->priority = caller->priority;
    thread->priority_override = caller->priority_override;
    thread->priority_override_active = caller->priority_override_active;
    thread->affinity_enabled = caller->affinity_enabled; thread->affinity_cpu = caller->affinity_cpu;
    fpu_save_state(&thread->fpu_state);
    lock = scheduler_lock_acquire("fork_signals");
    memcpy(child->signal_actions, source->signal_actions, sizeof(child->signal_actions));
    thread->signal_mask = caller->signal_mask;
    thread->signal_altstack = caller->signal_altstack;
    scheduler_lock_release(lock);
    watch->constructed = true;
    return process_finalize_launched_process(child, thread, source->pid);
failed:
    process_signal_fork_discard(signal_state);
    watch->owner = NULL;
    process_discard_image(child);
    watch->constructed = true;
    return NULL;
}

process_t *process_prepare_exec_image(const uint8_t *image, size_t size,
    process_launch_context_t *context, const char *const *argv, size_t argc,
    process_tls_allocation_t *tls)
{
    process_t *stage = allocate_process(argv[0], true);
    if (!stage) return NULL;
    stage->uid = context->uid; stage->gid = context->gid;
    stage->creation_mask = context->creation_mask;
    stage->cwd_owner = context->cwd; context->cwd = NULL;
    stage->cwd = fd_description_context(stage->cwd_owner);
    stage->directory_streams = context->files; context->files = NULL;
    if (context->executable_path)
        memcpy(stage->executable_path, context->executable_path, strlen(context->executable_path) + 1);
    if (!process_setup_basic_user_memory(stage) || !process_store_args(stage, argv, argc) ||
        !process_store_environment(stage, context->environment, context->environment_count) ||
        !process_prepare_stack_with_args(stage) ||
        !elf_load_process(stage, image, size, &stage->user_entry_point) ||
        !process_allocate_user_tls(stage, tls))
    { process_discard_image(stage); return NULL; }
    return stage;
}

int process_exec_commit(syscall_frame_t *frame, process_t *image, const process_tls_allocation_t *tls)
{
    process_t *process = current_process_local();
    thread_t *self = current_thread_local();
    uint64_t lock = scheduler_lock_acquire("exec_claim");
    if (process->exec_owner_tid && process->exec_owner_tid != self->tid)
    { scheduler_lock_release(lock); return -16; }
    process->exec_owner_tid = self->tid;
    spinlock_lock(&process->threads_lock);
    for (thread_t *thread = process->threads; thread; thread = thread->process_next)
    {
        if (thread == self) continue;
        process_io_cancel_thread_locked(thread);
        if (thread_in_run_queue_load(thread)) remove_from_run_queue_locked(thread);
        thread_remove_from_wait_queue(thread);
        if (thread->sleeping) sleep_queue_remove(thread);
        thread->exited = true; thread->state = THREAD_STATE_ZOMBIE;
        thread->preempt_pending = false; thread->wake_pending = false;
        thread->detached = true;
        /* The retired image will reclaim these together, after CPU quiescence.
         * A later thread destructor must not unmap them in the new image. */
        thread->user_tls_base = 0; thread->user_tls_size = 0;
        thread->user_stack_base = 0; thread->user_stack_size = 0;
        thread_enqueue_deferred_free(thread);
        wait_queue_wake_all_locked(&thread->join_queue);
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(lock);
    smp_broadcast_schedule_ipi(false);
    for (;;)
    {
        lock = scheduler_lock_acquire("exec_quiescence");
        spinlock_lock(&process->threads_lock);
        bool alone = process->thread_count == 1 && process->threads == self;
        spinlock_unlock(&process->threads_lock);
        scheduler_lock_release(lock);
        if (alone) break;
        process_yield();
    }
    spinlock_preempt_disable();
    process_signal_thread_cleanup(self);
    lock = scheduler_lock_acquire("exec_replace");
    /* This byte swap moves only image ownership, never scheduler/process locks
     * or kernel stacks. The caller's registered request owns the old image. */
    size_t first = offsetof(process_t, user_regions), end = offsetof(process_t, wait_queue);
    for (size_t i = first; i < end; ++i)
    {
        uint8_t byte = ((uint8_t *)process)[i];
        ((uint8_t *)process)[i] = ((uint8_t *)image)[i];
        ((uint8_t *)image)[i] = byte;
    }
    paging_space_t old_space = process->address_space;
    process->address_space = image->address_space;
    image->address_space = old_space;
    image->address_space.active_cpu_mask = 0;
    process->address_space.active_cpu_mask = 1u << current_cpu_index();
    process->cr3 = process->address_space.cr3;
    image->cr3 = image->address_space.cr3;
    write_cr3(process->cr3);
    /* Preserve the table and its record-lock observer across exec. */
    for (size_t i = 0; i < fd_table_capacity(process->directory_streams); ++i)
    {
        uint32_t flags = 0;
        if (!fd_table_get_flags(process->directory_streams, (int)i, &flags) && (flags & FD_TABLE_CLOEXEC))
            (void)fd_table_close(process->directory_streams, (int)i);
    }
    memcpy(process->executable_path, image->executable_path, sizeof(process->executable_path));
    memcpy(process->name, image->name, sizeof(process->name));
    process->main_thread = process->current_thread = self;
    process->user_exit_owner_tid = 0;
    for (unsigned n = 1; n < ALIX_SIGNAL_COUNT; ++n)
        if (process->signal_actions[n].handler != 1)
            memset(&process->signal_actions[n], 0, sizeof(process->signal_actions[n]));
    memset(&self->signal_altstack, 0, sizeof(self->signal_altstack));
    self->signal_onstack = false; self->user_cleanup_complete = false;
    self->user_tls_base = tls->base; self->user_tls_size = tls->size;
    self->user_stack_base = 0; self->user_stack_size = 0;
    self->fs_base = tls->thread_pointer; self->gs_base = (uintptr_t)self;
    wrmsr(MSR_FS_BASE, self->fs_base); wrmsr(MSR_GS_BASE, self->gs_base);
    memcpy(&self->fpu_state, &g_fpu_initial_state, sizeof(self->fpu_state));
    fpu_restore_state(&self->fpu_state);
    memset(frame, 0, sizeof(*frame));
    frame->rip = process->user_entry_point;
    frame->rsp = process->user_initial_stack;
    frame->cs = GDT_SELECTOR_USER_CODE | 3u; frame->ss = GDT_SELECTOR_USER_DATA | 3u;
    frame->rflags = RFLAGS_DEFAULT;
    frame->rdi = process->user_argc; frame->rsi = process->user_argv_ptr; frame->rdx = process->user_envp_ptr;
    process->exec_owner_tid = 0;
    scheduler_lock_release(lock);
    spinlock_preempt_enable();
    return 0;
}
