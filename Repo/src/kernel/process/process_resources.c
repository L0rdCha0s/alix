#include "process_internal.h"
#include "fd_table.h"
#include "errno.h"
#include "io_stream.h"

/* Kernel-lifetime owner. Admission is bounded; old cwd/FD objects can always
 * enqueue without allocation, including during process teardown. */
static fd_retirement_queue_t *g_process_retirement;
static process_t *g_process_retirement_worker;
static uint32_t g_process_retirement_start;

void process_resource_system_init(void)
{
    if (g_process_retirement) return;
    g_process_retirement = fd_retirement_queue_create(FD_RETIREMENT_MAX_OBJECTS);
    if (!g_process_retirement) fatal("process resource retirement allocation failed");
}

fd_retirement_queue_t *process_fd_retirement_queue(void)
{
    return g_process_retirement;
}

static void process_resource_cleanup_entry(void *unused)
{
    (void)unused;
    for (;;)
    {
        /* A full batch may leave more closed objects queued (including TCP
         * receive buffers). Do not cap reclamation at 64 objects per 10 ms
         * timer tick while producers keep running. Yield between bounded
         * batches so other threads still run; sleep only after catching up. */
        if (fd_retirement_queue_drain(g_process_retirement, 64) == 64)
            process_yield();
        else
            process_sleep_ms(1);
    }
}

bool process_resource_start_cleanup(void)
{
    if (!g_process_retirement || spinlock_preempt_disabled()) return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&g_process_retirement_start, &expected, 1, false,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return expected == 2;
    /* Creation never recursively starts this service. The factory retains
     * its owner before publication; this kernel-lifetime owner is permanent. */
    process_t *worker = process_create_kernel_service("fd-cleanup", process_resource_cleanup_entry, NULL, 0);
    if (!worker)
    {
        __atomic_store_n(&g_process_retirement_start, 0, __ATOMIC_RELEASE);
        return false;
    }
    __atomic_store_n(&g_process_retirement_worker, worker, __ATOMIC_RELEASE);
    __atomic_store_n(&g_process_retirement_start, 2, __ATOMIC_RELEASE);
    return true;
}

static int process_cwd_description_close(void *context)
{
    if (context) vfs_node_release_owned(context);
    return 0;
}

static const fd_ops_t process_cwd_ops = { .close = process_cwd_description_close };

fd_description_t *process_cwd_description_create_owned(vfs_node_t *node)
{
    if (!node || !vfs_is_dir(node) || !g_process_retirement) return NULL;
    return fd_description_create_deferred(&process_cwd_ops, node, g_process_retirement);
}

bool process_cwd_description_valid(fd_description_t *owner)
{
    return owner && fd_description_ops(owner)->close == process_cwd_description_close &&
           fd_description_is_deferred_to(owner, g_process_retirement) &&
           vfs_is_dir(fd_description_context(owner));
}

bool process_prepare_inherited_context(process_t *process, process_t *parent, bool parentless)
{
    if (!process || !g_process_retirement) return false;
    spinlock_preempt_disable();
    process_t *source = parentless ? NULL : parent ? parent : current_process_local();
    fd_description_t *owner = NULL;
    uint32_t uid = VFS_UID_ROOT, gid = VFS_GID_ROOT, creation_mask = 0;
    bool ok = true;
    if (source)
    {
        spinlock_lock(&source->context_lock);
        uid = source->uid;
        gid = source->gid;
        creation_mask = __atomic_load_n(&source->creation_mask, __ATOMIC_ACQUIRE);
        owner = source->cwd_owner;
        if (owner && !fd_description_get(owner)) { owner = NULL; ok = false; }
        spinlock_unlock(&source->context_lock);
    }
    if (ok && !owner)
    {
        /* VFS root is globally owned and cannot disappear after publication.
         * Idle/early processes created before vfs_init intentionally keep NULL. */
        vfs_node_t *node = vfs_root();
        if (node)
        {
            ok = vfs_node_try_retain(node);
            if (ok)
            {
                owner = process_cwd_description_create_owned(node);
                if (!owner)
                {
                    /* This cannot be the final reference: root has a permanent
                     * tree owner. No recursive VFS destructor runs here. */
                    vfs_node_release(node);
                    ok = false;
                }
            }
        }
    }
    fd_table_t *directories = NULL;
    fd_table_t *children = NULL;
    if (ok && process->is_user)
    {
        /* User process creation is spawn, not fork: directory streams are not
         * inherited. All threads of the new process share this owned table. */
        directories = fd_table_create_deferred(FD_TABLE_MAX_ENTRIES, g_process_retirement);
        if (!directories) ok = false;
        if (ok) children = fd_table_create_deferred(FD_TABLE_MAX_ENTRIES, g_process_retirement);
        if (!children) ok = false;
    }
    if (ok)
    {
        process->uid = uid;
        process->gid = gid;
        process->creation_mask = creation_mask;
        process->cwd_owner = owner;
        process->cwd = owner ? fd_description_context(owner) : NULL;
        process->directory_streams = directories;
        process->child_processes = children;
    }
    else
    {
        (void)fd_description_put(owner);
        fd_table_put(directories); fd_table_put(children);
    }
    spinlock_preempt_enable();
    return ok;
}

bool process_prepare_user_fds(process_t *process, process_t *parent, int stdout_fd)
{
    if (!process || !process->is_user || !process->directory_streams) return false;
    spinlock_preempt_disable();
    process_t *source = parent ? parent : current_process_local();
    bool ok = true;
    if (source && source->is_user)
    {
        spinlock_lock(&source->context_lock);
        fd_table_t *inherited = source->directory_streams;
        bool pinned = inherited && fd_table_get(inherited);
        spinlock_unlock(&source->context_lock);
        fd_table_t *copy = NULL;
        ok = pinned && fd_table_clone_deferred(inherited, true, &copy) == 0;
        if (pinned) fd_table_put(inherited);
        if (ok)
        {
            fd_table_t *empty = process->directory_streams;
            process->directory_streams = copy;
            fd_table_put(empty);
        }
        if (ok && stdout_fd >= 0)
        {
            fd_description_t *output = fd_import_owned(stdout_fd);
            ok = output != NULL;
            if (ok)
            {
                (void)fd_table_close(process->directory_streams, 1);
                (void)fd_table_close(process->directory_streams, 2);
                ok = fd_table_install_at(process->directory_streams, 1, output, 0) == 1 &&
                     fd_table_install_at(process->directory_streams, 2, output, 0) == 2;
            }
            fd_description_put(output);
        }
    }
    else
    {
        fd_description_t *input = io_null_input_create(g_process_retirement);
        fd_description_t *output = fd_import_owned(stdout_fd >= 0 ? stdout_fd : g_console_stdout_fd);
        ok = input && output;
        if (ok) ok = fd_table_install_at(process->directory_streams, 0, input, 0) == 0;
        if (ok) ok = fd_table_install_at(process->directory_streams, 1, output, 0) == 1;
        if (ok) ok = fd_table_install_at(process->directory_streams, 2, output, 0) == 2;
        fd_description_put(input);
        fd_description_put(output);
    }
    /* Failed initialization leaves partial entries in this unpublished
     * process-owned table. Constructor rollback releases it asynchronously. */
    spinlock_preempt_enable();
    return ok;
}

fd_table_t *process_current_fd_table(void)
{
    if (!spinlock_preempt_disabled()) return NULL;
    process_t *process = current_process_local();
    if (!process || !process->is_user) return NULL;
    /* This process cannot be destroyed while its current guarded thread is
     * on a CPU. No borrowed table pointer may cross the blocking wait. */
    spinlock_lock(&process->context_lock);
    fd_table_t *table = process->directory_streams;
    spinlock_unlock(&process->context_lock);
    return table;
}

fd_table_t *process_current_directory_table(void)
{
    return process_current_fd_table();
}

fd_description_t *process_acquire_cwd_owner(process_t *process, uint32_t *uid_out, uint32_t *gid_out)
{
    if (!process || !spinlock_preempt_disabled()) return NULL;
    spinlock_lock(&process->context_lock);
    fd_description_t *owner = process->cwd_owner;
    bool ok = !owner || fd_description_get(owner);
    uint32_t uid = process->uid, gid = process->gid;
    spinlock_unlock(&process->context_lock);
    if (!ok) return NULL;
    if (!owner)
    {
        /* A pre-VFS process's NULL owner denotes the permanent global root.
         * Capture that logical cwd from the same snapshot as its credentials. */
        vfs_node_t *node = vfs_root();
        if (!node || !vfs_node_try_retain(node)) return NULL;
        owner = process_cwd_description_create_owned(node);
        if (!owner) vfs_node_release(node); /* Root's tree reference prevents final release. */
    }
    if (owner)
    {
        if (uid_out) *uid_out = uid;
        if (gid_out) *gid_out = gid;
    }
    return owner;
}

int process_set_cwd_description_owned(process_t *process, fd_description_t *owner)
{
    if (!process || !spinlock_preempt_disabled() || !process_cwd_description_valid(owner)) return -EINVAL;
    spinlock_lock(&process->context_lock);
    if (__atomic_load_n(&process->lifetime_state, __ATOMIC_ACQUIRE) != PROCESS_LIFETIME_ALIVE ||
        process->state == PROCESS_STATE_ZOMBIE)
    {
        spinlock_unlock(&process->context_lock);
        return -ESRCH;
    }
    fd_description_t *old = process->cwd_owner;
    process->cwd_owner = owner;
    process->cwd = fd_description_context(owner);
    spinlock_unlock(&process->context_lock);
    (void)fd_description_put(old);
    return 0;
}

void process_release_context(process_t *process)
{
    if (!process) return;
    spinlock_preempt_disable();
    spinlock_lock(&process->context_lock);
    fd_description_t *owner = process->cwd_owner;
    process->cwd_owner = NULL;
    process->cwd = NULL;
    fd_table_t *directories = process->directory_streams;
    process->directory_streams = NULL;
    fd_table_t *children = process->child_processes;
    process->child_processes = NULL;
    spinlock_unlock(&process->context_lock);
    (void)fd_description_put(owner);
    fd_table_put(directories);
    fd_table_put(children);
    spinlock_preempt_enable();
}

uint32_t process_get_uid(const process_t *process)
{
    if (!process) return VFS_UID_ROOT;
    spinlock_lock(&((process_t *)process)->context_lock);
    uint32_t uid = process->uid;
    spinlock_unlock(&((process_t *)process)->context_lock);
    return uid;
}

uint32_t process_get_gid(const process_t *process)
{
    if (!process) return VFS_GID_ROOT;
    spinlock_lock(&((process_t *)process)->context_lock);
    uint32_t gid = process->gid;
    spinlock_unlock(&((process_t *)process)->context_lock);
    return gid;
}

void process_set_identity(process_t *process, uint32_t uid, uint32_t gid)
{
    if (!process) return;
    spinlock_lock(&process->context_lock);
    process->uid = uid;
    process->gid = gid;
    spinlock_unlock(&process->context_lock);
}

vfs_node_t *process_current_cwd(void)
{
    /* Compatibility-only borrowed view. Worker captures use acquire_cwd_owner;
     * legacy shell state/path users still require their own owner lifetime. */
    process_t *process = process_current();
    if (!process) return vfs_root();
    spinlock_lock(&process->context_lock);
    vfs_node_t *node = process->cwd ? process->cwd : vfs_root();
    spinlock_unlock(&process->context_lock);
    return node;
}

void process_set_cwd(process_t *process, vfs_node_t *node)
{
    /* Legacy borrowed-input API: caller must keep node alive across this call.
     * Protected resolve + owned-description handoff is the new worker path. */
    if (!process) return;
    if (!node) node = vfs_root();
    if (!node || !vfs_is_dir(node)) return;
    spinlock_preempt_disable();
    if (vfs_node_try_retain(node))
    {
        fd_description_t *owner = process_cwd_description_create_owned(node);
        if (owner)
        {
            if (process_set_cwd_description_owned(process, owner)) fd_description_put(owner);
        }
        else
        {
            /* The borrowed-input contract requires another owning reference,
             * so undoing our pin cannot be a final VFS release. */
            vfs_node_release(node);
        }
    }
    spinlock_preempt_enable();
}
