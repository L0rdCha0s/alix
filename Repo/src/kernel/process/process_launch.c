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
