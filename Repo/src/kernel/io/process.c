#include "io_process.h"
#include "process_internal.h"
#include "io_event_service.h"
#include "io_vfs.h"
#include "user_copy.h"
#include "errno.h"

#define CHILD_ARGUMENTS 256u
typedef struct child_record child_record_t;
struct child_record
{
    process_launch_context_t launch;
    process_creation_watch_t watch;
    fd_description_t *reservation;
    child_record_t *next;
    uint32_t references;
    bool published, claimed, reaped, kill_sent, closed;
};
typedef struct { fd_table_t *table; } child_table_owner_t;
typedef struct { fd_description_t *record; int slot; bool owns_claim; } child_claim_t;
typedef struct
{
    uint32_t operation, flags, mode, path_offset;
    int32_t fd, destination;
} child_action_t;
typedef struct
{
    uint32_t argc, envc, action_count, search_path_offset;
    uint32_t offsets[CHILD_ARGUMENTS], env_offsets[CHILD_ARGUMENTS];
    child_action_t actions[CHILD_ARGUMENTS];
    char data[];
} child_launch_work_t;
typedef struct { int64_t pid; uint32_t flags, status; } child_wait_work_t;

static io_service_t *g_launch_service;
static io_event_service_t *g_wait_service;
static process_t *g_reaper;
static uint32_t g_start;
static spinlock_t g_orphan_lock;
static child_record_t *g_orphan_head, *g_orphan_tail, *g_reap_batch[64];

static void child_enqueue_orphan(child_record_t *record)
{
    record->next = NULL;
    spinlock_lock(&g_orphan_lock);
    if (g_orphan_tail) g_orphan_tail->next = record;
    else g_orphan_head = record;
    g_orphan_tail = record;
    spinlock_unlock(&g_orphan_lock);
}

static void child_record_put(child_record_t *record)
{
    if (__atomic_fetch_sub(&record->references, 1u, __ATOMIC_ACQ_REL) != 1u) return;
    /* A child-bearing record always has a monitor reference until terminal
     * CPU quiescence. Thus its last owner can safely release the factory ref. */
    process_creation_watch_release(&record->watch);
    free(record);
}

static int child_record_close(void *context)
{
    child_record_t *record = context;
    if (record->reservation)
    {
        (void)fd_table_reservation_cancel(record->reservation);
        fd_description_put(record->reservation);
    }
    fd_description_put(record->launch.cwd);
    fd_table_put(record->launch.files);
    __atomic_store_n(&record->closed, true, __ATOMIC_RELEASE);
    child_record_put(record);
    return 0;
}
static const fd_ops_t child_record_ops = { .close = child_record_close };

static bool child_record_valid(fd_description_t *description)
{
    return description && fd_description_ops(description)->close == child_record_close;
}

static int child_table_close(void *context)
{
    child_table_owner_t *owner = context;
    fd_table_put(owner->table); free(owner); return 0;
}
static const fd_ops_t child_table_ops = { .close = child_table_close };

static void child_claim_release(child_claim_t *claim)
{
    if (__atomic_exchange_n(&claim->owns_claim, false, __ATOMIC_ACQ_REL))
    {
        child_record_t *record = fd_description_context(claim->record);
        __atomic_store_n(&record->claimed, false, __ATOMIC_RELEASE);
    }
}

static int child_claim_close(void *context)
{
    child_claim_t *claim = context;
    child_claim_release(claim);
    fd_description_put(claim->record); free(claim); return 0;
}
static const fd_ops_t child_claim_ops = { .close = child_claim_close };

static fd_table_t *child_current_table(void)
{
    process_t *current = current_process_local();
    return current && current->is_user ? current->child_processes : NULL;
}

static void child_reap_once(void)
{
        size_t count = 0;
        spinlock_lock(&g_orphan_lock);
        while (g_orphan_head && count < 64)
        {
            child_record_t *record = g_orphan_head;
            g_orphan_head = record->next;
            if (!g_orphan_head) g_orphan_tail = NULL;
            record->next = NULL;
            g_reap_batch[count++] = record;
        }
        spinlock_unlock(&g_orphan_lock);
        for (size_t index = 0; index < count; ++index)
        {
            child_record_t *record = g_reap_batch[index];
            process_t *child = __atomic_load_n(&record->watch.owner, __ATOMIC_ACQUIRE);
            if (__atomic_load_n(&record->closed, __ATOMIC_ACQUIRE) && !record->published && !record->kill_sent)
            { record->kill_sent = true; (void)process_kill_signal(child, ALIX_SIGKILL); }
            uint32_t status;
            if (process_wait_status_snapshot(child, &status)) child_enqueue_orphan(record);
            else
            {
                /* Keep PID/status metadata until wait reaps it, but close
                 * files at exit so a parent reading a pipe can observe EOF
                 * before calling waitpid. The context detach is idempotent. */
                process_release_context(child);
                child_record_put(record);
            }
            g_reap_batch[index] = NULL;
        }
}

static void child_reaper_entry(void *unused)
{
    (void)unused;
    for (;;) { child_reap_once(); process_sleep_ms(1); }
}

static int child_apply_actions(child_record_t *record, child_launch_work_t *work)
{
    int error = 0;
    for (uint32_t index = 0; index < work->action_count && !error; ++index)
    {
        child_action_t *action = &work->actions[index];
        if (action->operation == SYSCALL_SPAWN_CLOSE)
        {
            error = fd_table_close(record->launch.files, action->fd);
            if (error == -EBADF) error = 0;
        }
        else if (action->operation == SYSCALL_SPAWN_DUP2)
        {
            if (action->fd == action->destination)
                error = fd_table_set_flags(record->launch.files, action->fd, 0);
            else
            {
                error = fd_table_dup2(record->launch.files, action->fd, action->destination);
                if (error >= 0) error = 0;
            }
        }
        else if (action->operation == SYSCALL_SPAWN_OPEN)
        {
            error = fd_table_close(record->launch.files, action->fd);
            if (error == -EBADF) error = 0;
            fd_description_t *description = NULL;
            if (!error) error = io_vfs_open_owned(fd_description_context(record->launch.cwd), work->data + action->path_offset,
                                                   action->flags & ~SYSCALL_OPEN_CLOEXEC, record->launch.uid, record->launch.gid,
                                                   process_fd_retirement_queue(), &description);
            if (!error)
            {
                error = fd_table_install_at(record->launch.files, action->fd, description,
                                              action->flags & SYSCALL_OPEN_CLOEXEC ? FD_TABLE_CLOEXEC : 0);
                if (error >= 0) error = 0;
            }
            fd_description_put(description);
        }
        else error = -EINVAL;
    }
    if (error) return error;
    spinlock_preempt_disable();
    fd_table_t *filtered = NULL;
    error = fd_table_clone_deferred(record->launch.files, true, &filtered);
    if (!error)
    {
        fd_table_t *old = record->launch.files; record->launch.files = filtered; fd_table_put(old);
    }
    spinlock_preempt_enable();
    return error;
}

static int child_open_program(child_record_t *record, child_launch_work_t *work, vfs_node_t **output)
{
    vfs_node_t *cwd = fd_description_context(record->launch.cwd);
    if (!work->search_path_offset)
        return vfs_open_data_owned(cwd, work->data, false, false, record->launch.uid, record->launch.gid, output);
    char *candidate = malloc(VFS_PATH_MAX);
    if (!candidate) return -ENOMEM;
    const char *path = work->data + work->search_path_offset;
    size_t name = strlen(work->data);
    bool denied = false;
    int result = -ENOENT;
    for (;;)
    {
        const char *separator = strchr(path, ':');
        size_t prefix = separator ? (size_t)(separator - path) : strlen(path);
        if (prefix + (prefix ? 1 : 0) + name + 1 > VFS_PATH_MAX) { result = -ENAMETOOLONG; break; }
        if (prefix) { memcpy(candidate, path, prefix); candidate[prefix++] = '/'; }
        memcpy(candidate + prefix, work->data, name + 1);
        result = vfs_open_data_owned(cwd, candidate, false, false, record->launch.uid, record->launch.gid, output);
        if (result == -EACCES) denied = true;
        else if (result != -ENOENT && result != -ENOTDIR) break;
        if (!separator) { result = denied ? -EACCES : -ENOENT; break; }
        path = separator + 1;
    }
    free(candidate);
    return result;
}

static void child_launch_handler(io_request_t *request, io_service_result_t *result)
{
    result->result = -EINVAL; result->description_owned = NULL;
    fd_description_t *description = io_request_description(request);
    if (!child_record_valid(description) || io_request_buffer_size(request) < sizeof(child_launch_work_t)) return;
    child_record_t *record = fd_description_context(description);
    child_launch_work_t *work = io_request_buffer(request);
    vfs_node_t *file = NULL;
    unsigned char *image = NULL;
    const char **arguments = NULL;
    const char **environment = NULL;
    result->result = child_apply_actions(record, work);
    if (result->result) return;
    result->result = child_open_program(record, work, &file);
    if (result->result) return;
    size_t bytes = 0;
    vfs_node_type_t type;
    if (!vfs_stat(file, &bytes, &type, NULL, NULL, NULL) || type != VFS_NODE_FILE || !bytes)
    { result->result = -ENOEXEC; goto finished; }
    image = malloc(bytes);
    arguments = calloc((size_t)work->argc + 1, sizeof(*arguments));
    environment = calloc((size_t)work->envc + 1, sizeof(*environment));
    if (!image || !arguments || !environment) { result->result = -ENOMEM; goto finished; }
    for (size_t offset = 0; offset < bytes;)
    {
        size_t amount = bytes - offset < 65536 ? bytes - offset : 65536;
        ssize_t copied = vfs_read_data_at(file, offset, image + offset, amount);
        if (copied <= 0 || (size_t)copied > amount) { result->result = -EIO; goto finished; }
        offset += (size_t)copied;
    }
    if (!elf_validate_image(image, bytes, NULL)) { result->result = -ENOEXEC; goto finished; }
    for (uint32_t index = 0; index < work->argc; ++index) arguments[index] = work->data + work->offsets[index];
    for (uint32_t index = 0; index < work->envc; ++index) environment[index] = work->data + work->env_offsets[index];
    record->launch.environment = environment; record->launch.environment_count = work->envc;
    spinlock_preempt_disable();
    bool initialized = process_creation_watch_init(&record->watch);
    spinlock_preempt_enable();
    if (!initialized) { result->result = -EIO; goto finished; }
    process_t *child = process_create_user_elf_prepared(work->data, image, bytes, &record->launch,
                                                        arguments, work->argc, &record->watch);
    record->launch.environment = NULL; record->launch.environment_count = 0;
    process_creation_watch_complete(&record->watch);
    if (!child) result->result = -ENOMEM;
    else
    {
        __atomic_add_fetch(&record->references, 1u, __ATOMIC_ACQ_REL);
        child_enqueue_orphan(record);
        if (!fd_description_get(description)) result->result = -EOVERFLOW;
        else { result->result = (int64_t)record->watch.pid; result->description_owned = description; }
    }
finished:
    record->launch.environment = NULL; record->launch.environment_count = 0;
    free(environment); free(arguments); free(image); vfs_node_release_owned(file);
}

static bool child_wait_handler(io_request_t *request, io_service_result_t *result)
{
    result->result = -EINVAL; result->description_owned = NULL;
    if (io_request_buffer_size(request) != sizeof(child_wait_work_t)) return true;
    fd_description_t *input = io_request_description(request);
    if (!input || fd_description_ops(input)->close != child_table_close) return true;
    child_table_owner_t *owner = fd_description_context(input);
    child_wait_work_t *work = io_request_buffer(request);
    bool exists = false;
    for (size_t index = 0; index < fd_table_capacity(owner->table); ++index)
    {
        fd_description_t *description = NULL;
        if (fd_table_pin(owner->table, (int)index, &description, NULL)) continue;
        child_record_t *record = child_record_valid(description) ? fd_description_context(description) : NULL;
        bool matches = record && !__atomic_load_n(&record->reaped, __ATOMIC_ACQUIRE) &&
                       (work->pid == -1 || (uint64_t)work->pid == record->watch.pid);
        uint32_t status = 0;
        if (!matches) { fd_description_put(description); continue; }
        exists = true;
        if (process_wait_status_snapshot(record->watch.owner, &status) ||
            __atomic_load_n(&record->claimed, __ATOMIC_ACQUIRE))
        { fd_description_put(description); continue; }
        child_claim_t *claim = calloc(1, sizeof(*claim));
        if (!claim) { fd_description_put(description); result->result = -ENOMEM; return true; }
        claim->record = description; claim->slot = (int)index;
        fd_description_t *lease = fd_description_create_deferred(&child_claim_ops, claim, process_fd_retirement_queue());
        if (!lease) { free(claim); fd_description_put(description); result->result = -ENOMEM; return true; }
        bool expected = false;
        if (!__atomic_compare_exchange_n(&record->claimed, &expected, true, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        { fd_description_put(lease); continue; }
        claim->owns_claim = true;
        if (__atomic_load_n(&record->reaped, __ATOMIC_ACQUIRE))
        { child_claim_release(claim); fd_description_put(lease); continue; }
        work->status = status;
        result->result = (int64_t)record->watch.pid;
        result->description_owned = lease;
        return true;
    }
    if (!exists) { result->result = -ECHILD; return true; }
    if (work->flags & SYSCALL_PROCESS_NOHANG) { result->result = 0; return true; }
    return false;
}

bool io_process_services_start(void)
{
    if (spinlock_preempt_disabled() || !process_fd_retirement_queue()) return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&g_start, &expected, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return expected == 2;
    io_service_t *launch = io_service_create(32, 2, child_launch_handler);
    io_event_service_t *wait = launch ? io_event_service_create(64, child_wait_handler) : NULL;
    process_t *reaper = wait ? process_create_kernel_service("child-reaper", child_reaper_entry, NULL, 0) : NULL;
    if (!reaper)
    {
        if (wait && (io_event_service_shutdown(wait) || io_event_service_destroy(wait))) fatal("child wait startup rollback failed");
        if (launch && (io_service_shutdown(launch) || io_service_destroy(launch))) fatal("child launch startup rollback failed");
        __atomic_store_n(&g_start, 0, __ATOMIC_RELEASE);
        return false;
    }
    g_launch_service = launch; g_wait_service = wait; g_reaper = reaper;
    __atomic_store_n(&g_start, 2, __ATOMIC_RELEASE);
    return true;
}

static int child_submit(io_request_t *request, bool launch)
{
    int result = process_io_register_current(request);
    if (result)
    {
        if (launch)
        {
            child_record_t *record = fd_description_context(io_request_description(request));
            if (record->reservation) (void)fd_table_reservation_cancel(record->reservation);
        }
        io_request_waiter_abandon(request); return result;
    }
    result = launch ? io_service_submit(g_launch_service, request) : io_event_service_submit(g_wait_service, request);
    if (result)
    {
        if (launch)
        {
            child_record_t *record = fd_description_context(io_request_description(request));
            if (record->reservation) (void)fd_table_reservation_cancel(record->reservation);
        }
        (void)process_io_finish_current(true);
    }
    return result;
}

static int child_wait_commit(fd_description_t *lease, fd_table_t *table, void *output, uint32_t status)
{
    if (!lease || fd_description_ops(lease)->close != child_claim_close) return -EINVAL;
    child_claim_t *claim = fd_description_context(lease);
    int error = output && !user_copy_to_user(output, &status, sizeof(status)) ? -EFAULT : 0;
    if (!error) error = fd_table_close_if(table, claim->slot, claim->record);
    if (!error)
    {
        child_record_t *record = fd_description_context(claim->record);
        __atomic_store_n(&record->reaped, true, __ATOMIC_RELEASE);
    }
    child_claim_release(claim);
    return error;
}

static int64_t child_finish(bool launching, void *output)
{
    io_request_status_t status;
    int error = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!error) error = process_io_result_current(&request, &status);
    int64_t value = error ? error : status.result;
    if (!error && value > 0)
    {
        fd_description_t *result = NULL;
        error = io_request_take_result(request, &result);
        if (!error && launching)
        {
            child_record_t *record = fd_description_context(result);
            error = fd_table_reservation_commit(record->reservation, result, 0);
            if (error >= 0)
            {
                record->published = true; error = 0;
                fd_description_t *reservation = record->reservation; record->reservation = NULL;
                (void)fd_table_reservation_cancel(reservation); fd_description_put(reservation);
            }
        }
        else if (!error)
        {
            child_wait_work_t *work = io_request_buffer(request);
            error = child_wait_commit(result, child_current_table(), output, work->status);
        }
        fd_description_put(result);
        if (error) value = error;
    }
    if (request && launching)
    {
        child_record_t *record = fd_description_context(io_request_description(request));
        if (record->reservation) (void)fd_table_reservation_cancel(record->reservation);
    }
    (void)process_io_finish_current(error != 0);
    spinlock_preempt_enable();
    return value;
}

static int child_capture_vector(uintptr_t vector, char *data, size_t capacity, size_t *used,
                                 uint32_t *offsets, uint32_t *count, bool nullable)
{
    *count = 0;
    if (!vector && nullable) return 0;
    for (uint32_t index = 0; ; ++index)
    {
        uintptr_t string = 0;
        if (!vector || vector > UINTPTR_MAX - (size_t)index * sizeof(uintptr_t) ||
            !user_copy_from_user(&string, (const void *)(vector + (size_t)index * sizeof(uintptr_t)), sizeof(string))) return -EFAULT;
        if (!string) return 0;
        if (index == CHILD_ARGUMENTS || *used >= capacity) return -E2BIG;
        offsets[index] = (uint32_t)*used;
        size_t length = 0;
        int error = user_copy_cstring_from_user(data + *used, capacity - *used, (const char *)string, &length);
        if (error) return error == -ENAMETOOLONG ? -E2BIG : error;
        *used += length + 1; ++*count;
    }
}

static int child_capture_actions(const syscall_spawn_t *specification, child_launch_work_t *work, size_t available, size_t *used)
{
    for (uint32_t index = 0; index < specification->action_count; ++index)
    {
        syscall_spawn_action_t input;
        size_t offset = (size_t)index * sizeof(input);
        if (!specification->actions || specification->actions > UINTPTR_MAX - offset ||
            !user_copy_from_user(&input, (const void *)(uintptr_t)(specification->actions + offset), sizeof(input))) return -EFAULT;
        if (input.reserved || input.fd < 0 || input.fd >= (int32_t)FD_TABLE_MAX_ENTRIES) return -EBADF;
        child_action_t *action = &work->actions[index];
        action->operation = input.operation; action->fd = input.fd; action->destination = input.destination;
        action->flags = input.flags; action->mode = input.mode;
        if (input.operation == SYSCALL_SPAWN_OPEN)
        {
            if (*used >= available) return -E2BIG;
            action->path_offset = (uint32_t)*used;
            size_t length = 0, capacity = available - *used;
            if (capacity > VFS_PATH_MAX) capacity = VFS_PATH_MAX;
            int error = user_copy_cstring_from_user(work->data + *used, capacity, (const char *)(uintptr_t)input.path, &length);
            if (error) return error;
            *used += length + 1;
        }
        else if (input.flags || input.path || input.mode) return -EINVAL;
        if (input.operation == SYSCALL_SPAWN_DUP2)
        {
            if (input.destination < 0 || input.destination >= (int32_t)FD_TABLE_MAX_ENTRIES) return -EBADF;
        }
        else if (input.operation != SYSCALL_SPAWN_OPEN && input.operation != SYSCALL_SPAWN_CLOSE) return -EINVAL;
        ++work->action_count;
    }
    return 0;
}

static int64_t child_spawn(const char *path, uintptr_t argv, const syscall_spawn_t *specification)
{
    spinlock_preempt_disable();
    fd_table_t *table = child_current_table();
    child_record_t *record = calloc(1, sizeof(*record));
    if (record) record->references = 1;
    fd_description_t *description = record ? fd_description_create_deferred(&child_record_ops, record, process_fd_retirement_queue()) : NULL;
    int error = !table ? -ESRCH : !description ? -ENOMEM : 0;
    if (!description) { free(record); record = NULL; }
    if (!error) error = fd_table_reserve_deferred(table, &record->reservation);
    if (!error)
    {
        record->launch.cwd = process_acquire_cwd_owner(current_process_local(), &record->launch.uid, &record->launch.gid);
        record->launch.parent_pid = current_process_local()->pid;
        error = record->launch.cwd ? fd_table_clone_deferred(process_current_fd_table(), false, &record->launch.files) : -ENOMEM;
        if (!error && specification)
        {
            uint64_t lock = scheduler_lock_acquire("spawn_signal_snapshot");
            thread_t *caller = current_thread_local();
            record->launch.signal_mask = caller->signal_mask;
            for (unsigned number = 1; number < ALIX_SIGNAL_COUNT; ++number)
                if (caller->process->signal_actions[number].handler == 1) record->launch.ignored_signals |= 1ULL << (number - 1);
            scheduler_lock_release(lock);
            if (specification->flags & SYSCALL_SPAWN_SETSIGMASK) record->launch.signal_mask = specification->signal_mask;
            if (specification->flags & SYSCALL_SPAWN_SETSIGDEF) record->launch.ignored_signals &= ~specification->signal_default;
            record->launch.signal_mask &= ALIX_SIGNAL_MASK & ~(1ULL << (ALIX_SIGKILL - 1)) & ~(1ULL << (ALIX_SIGSTOP - 1));
        }
    }
    io_request_t *request = NULL;
    if (!error) error = io_service_request_create(g_launch_service, IO_REQUEST_BUFFER_MAX,
                                                    record->launch.uid, record->launch.gid, &request);
    if (!error) error = io_request_bind(request, description, NULL, NULL);
    if (!error) description = NULL; /* request owns the launch record */
    if (!error)
    {
        child_launch_work_t *work = io_request_buffer(request);
        size_t available = io_request_buffer_size(request) - sizeof(*work), used = 0, length = 0;
        error = user_copy_cstring_from_user(work->data, VFS_PATH_MAX, path, &length);
        if (!error) used = length + 1;
        if (!error) error = child_capture_vector(argv, work->data, available, &used, work->offsets, &work->argc, false);
        if (!error && !work->argc) error = -EINVAL;
        if (!error && specification) error = child_capture_vector((uintptr_t)specification->environment, work->data, available,
                                                                    &used, work->env_offsets, &work->envc, true);
        if (!error && specification) error = child_capture_actions(specification, work, available, &used);
        if (!error && specification && (specification->flags & SYSCALL_SPAWN_SEARCH_PATH))
        {
            if (used >= available) error = -E2BIG;
            else
            {
                work->search_path_offset = (uint32_t)used;
                error = user_copy_cstring_from_user(work->data + used, available - used,
                                                     (const char *)(uintptr_t)specification->search_path, NULL);
            }
        }
    }
    if (error)
    {
        if (record && record->reservation) (void)fd_table_reservation_cancel(record->reservation);
        fd_description_put(description);
        if (request) io_request_waiter_abandon(request);
    }
    else error = child_submit(request, true);
    spinlock_preempt_enable();
    return error ? error : child_finish(true, NULL);
}

static int64_t child_wait(int64_t pid, void *output, uint64_t flags)
{
    if ((pid <= 0 && pid != -1) || pid > INT32_MAX) return -ENOTSUP;
    if (flags & ~((uint64_t)SYSCALL_PROCESS_NOHANG)) return -ENOTSUP;
    if (output && !user_ptr_range_valid(output, sizeof(uint32_t))) return -EFAULT;
    spinlock_preempt_disable();
    fd_table_t *table = child_current_table();
    child_table_owner_t *owner = table ? calloc(1, sizeof(*owner)) : NULL;
    fd_description_t *description = NULL;
    int error = !table ? -ESRCH : !owner ? -ENOMEM : 0;
    if (!error && !fd_table_get(table)) error = -EOVERFLOW;
    else if (!error)
    {
        owner->table = table;
        description = fd_description_create_deferred(&child_table_ops, owner, process_fd_retirement_queue());
        if (!description) { fd_table_put(table); error = -ENOMEM; }
    }
    if (!description) free(owner);
    io_request_t *request = NULL;
    if (!error) error = io_event_service_request_create(g_wait_service, sizeof(child_wait_work_t), 0, 0, &request);
    if (!error) error = io_request_bind(request, description, NULL, NULL);
    if (!error) description = NULL;
    if (!error)
    {
        child_wait_work_t *work = io_request_buffer(request);
        work->pid = pid; work->flags = (uint32_t)flags;
        error = child_submit(request, false);
    }
    else { fd_description_put(description); if (request) io_request_waiter_abandon(request); }
    spinlock_preempt_enable();
    return error ? error : child_finish(false, output);
}

int64_t io_process_dispatch(uint32_t operation, uint64_t first, uint64_t second, uint64_t third)
{
    if (__atomic_load_n(&g_start, __ATOMIC_ACQUIRE) != 2) return -ENOSYS;
    if (operation == SYSCALL_PROCESS_SPAWN) return child_spawn((const char *)first, second, NULL);
    if (operation == SYSCALL_PROCESS_SPAWN_EX)
    {
        syscall_spawn_t specification;
        if (second != sizeof(specification)) return -EINVAL;
        if (!user_copy_from_user(&specification, (const void *)first, sizeof(specification))) return -EFAULT;
        if (specification.version != SYSCALL_SPAWN_VERSION || specification.size != sizeof(specification) ||
            specification.action_count > CHILD_ARGUMENTS) return -EINVAL;
        if (specification.flags & ~(SYSCALL_SPAWN_SETSIGMASK | SYSCALL_SPAWN_SETSIGDEF | SYSCALL_SPAWN_RESETIDS | SYSCALL_SPAWN_SEARCH_PATH)) return -ENOTSUP;
        if (!(specification.flags & SYSCALL_SPAWN_SEARCH_PATH) && specification.search_path) return -EINVAL;
        if ((specification.signal_mask | specification.signal_default) & ~ALIX_SIGNAL_MASK) return -EINVAL;
        return child_spawn((const char *)(uintptr_t)specification.path, (uintptr_t)specification.argv, &specification);
    }
    if (operation == SYSCALL_PROCESS_WAIT) return child_wait((int64_t)first, (void *)second, third);
    return -EINVAL;
}
