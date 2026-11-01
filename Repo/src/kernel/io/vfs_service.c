#include "io_vfs_service.h"
#include "process_internal.h"
#include "user_copy.h"
#include "libc.h"
#include "errno.h"
#include "shell.h"

static io_service_t *g_vfs_service;
static uint32_t g_vfs_service_start;
io_service_t *io_vfs_service_current(void)
{
    return __atomic_load_n(&g_vfs_service, __ATOMIC_ACQUIRE);
}
#if defined(IO_VFS_SELFTEST) && IO_VFS_SELFTEST
static uint32_t g_vfs_selftest_active;
uint32_t io_vfs_selftest_active_handlers(void)
{
    return __atomic_load_n(&g_vfs_selftest_active, __ATOMIC_ACQUIRE);
}
#endif

static void io_vfs_service_handler(io_request_t *request, io_service_result_t *result)
{
#if defined(IO_VFS_SELFTEST) && IO_VFS_SELFTEST
    __atomic_add_fetch(&g_vfs_selftest_active, 1u, __ATOMIC_RELEASE);
#endif
    io_vfs_execute(request, result, process_fd_retirement_queue());
#if defined(IO_VFS_SELFTEST) && IO_VFS_SELFTEST
    __atomic_sub_fetch(&g_vfs_selftest_active, 1u, __ATOMIC_RELEASE);
#endif
}

bool io_vfs_service_start(void)
{
    if (spinlock_preempt_disabled() || !process_fd_retirement_queue()) return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&g_vfs_service_start, &expected, 1, false,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return expected == 2;
    io_service_t *service = io_service_create(128, 2, io_vfs_service_handler);
    if (!service)
    {
        __atomic_store_n(&g_vfs_service_start, 0, __ATOMIC_RELEASE);
        return false;
    }
    __atomic_store_n(&g_vfs_service, service, __ATOMIC_RELEASE);
    __atomic_store_n(&g_vfs_service_start, 2, __ATOMIC_RELEASE);
    return true;
}

int io_vfs_service_snapshot(io_service_status_t *out)
{
    io_service_t *service = __atomic_load_n(&g_vfs_service, __ATOMIC_ACQUIRE);
    return service ? io_service_snapshot(service, out) : -ENOSYS;
}

/* All temporary ownership is either transferred into the registered request
 * or unwound by deferred put/abandon before the preparation guard is dropped. */
static int io_vfs_prepare(const char *path, bool user_path, uint32_t opcode, size_t capacity,
                           fd_description_t *base, fd_description_t *lifetime)
{
    if (!spinlock_preempt_disabled()) return -EINVAL;
    io_service_t *service = __atomic_load_n(&g_vfs_service, __ATOMIC_ACQUIRE);
    if (!service) return -ENOSYS;
    process_t *process = current_process_local();
    if (!process) return -ESRCH;
    uint32_t uid = 0, gid = 0;
    fd_description_t *cwd = NULL;
    if (base)
    {
        if (!process_cwd_description_valid(base) || !fd_description_get(base)) return -EOVERFLOW;
        cwd = base;
        spinlock_lock(&process->context_lock);
        uid = process->uid;
        gid = process->gid;
        spinlock_unlock(&process->context_lock);
    }
    else cwd = process_acquire_cwd_owner(process, &uid, &gid);
    if (!cwd) return -ENOMEM;
    if (lifetime && (!fd_description_is_deferred_to(lifetime, process_fd_retirement_queue()) ||
                     !fd_description_get(lifetime)))
    {
        fd_description_put(cwd);
        return -EOVERFLOW;
    }
    io_request_t *request = NULL;
    int result = io_service_request_create(service, sizeof(io_vfs_operation_t) + VFS_PATH_MAX, uid, gid, &request);
    if (result)
    {
        fd_description_put(cwd);
        fd_description_put(lifetime);
        return result;
    }
    result = io_request_bind_cwd_owner(request, lifetime, cwd);
    if (result)
    {
        fd_description_put(cwd);
        fd_description_put(lifetime);
        io_request_waiter_abandon(request);
        return result;
    }
    result = process_io_register_current(request);
    if (result)
    {
        io_request_waiter_abandon(request);
        return result;
    }
    io_vfs_operation_t *operation = io_request_buffer(request);
    operation->opcode = opcode;
    operation->count = capacity;
    if (user_path)
    {
        result = user_copy_cstring_from_user((char *)operation->data, VFS_PATH_MAX, path, NULL);
    }
    else
    {
        size_t length = 0;
        if (!path) result = -EINVAL;
        else
        {
            while (length < VFS_PATH_MAX && path[length])
            {
                operation->data[length] = (unsigned char)path[length];
                ++length;
            }
            if (length == VFS_PATH_MAX) result = -ENAMETOOLONG;
            else operation->data[length] = 0;
        }
    }
    if (!result) result = io_service_submit(service, request);
    if (result) (void)process_io_finish_current(true);
    return result;
}

static ssize_t io_vfs_readlink_common(const char *path, void *buffer, size_t capacity, bool user)
{
    if (!capacity || capacity > 0x7fffffffffffffffULL) return -EINVAL;
    if (!path || !buffer) return user ? -EFAULT : -EINVAL;
    size_t bounded = capacity < VFS_PATH_MAX ? capacity : VFS_PATH_MAX;
    if (user && !user_ptr_range_valid(buffer, bounded)) return -EFAULT;
    spinlock_preempt_disable();
    int result = io_vfs_prepare(path, user, IO_VFS_READLINK, bounded, NULL, NULL);
    spinlock_preempt_enable();
    if (result) return result;
    io_request_status_t status;
    result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t bytes = result ? result : status.result;
    if (!result && bytes >= 0)
    {
        if ((uint64_t)bytes > bounded) bytes = -EIO;
        else if (bytes)
        {
            io_vfs_operation_t *operation = io_request_buffer(request);
            if (user)
            {
                if (!user_copy_to_user(buffer, operation->data, (size_t)bytes)) bytes = -EFAULT;
            }
            else memcpy(buffer, operation->data, (size_t)bytes);
        }
    }
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    return (ssize_t)bytes;
}

ssize_t io_vfs_readlink_user(const char *path, void *buffer, size_t capacity)
{
    return io_vfs_readlink_common(path, buffer, capacity, true);
}

ssize_t io_vfs_readlink_kernel(const char *path, void *buffer, size_t capacity)
{
    return io_vfs_readlink_common(path, buffer, capacity, false);
}

int io_vfs_change_cwd_kernel(const char *path, uint64_t owner_pid)
{
    spinlock_preempt_disable();
    int result = io_vfs_prepare(path, false, IO_VFS_RESOLVE_CWD, 0, NULL, NULL);
    spinlock_preempt_enable();
    if (result) return result;
    io_request_status_t status;
    result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    if (!result) result = (int)status.result;
    if (!result)
    {
        fd_description_t *owner = NULL;
        result = io_request_take_result(request, &owner);
        if (!result)
        {
            result = process_apply_cwd_to_current_and_pid(owner, owner_pid);
            if (result) fd_description_put(owner);
        }
    }
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    return result;
}

int io_vfs_prepare_cwd(const char *path, fd_description_t *base, fd_description_t *lifetime)
{
    if (!base) return -EINVAL;
    return io_vfs_prepare(path, false, IO_VFS_RESOLVE_CWD, 0, base, lifetime);
}

int io_vfs_apply_shell_cwd_owned(shell_state_t *shell, fd_description_t *owner)
{
    if (!shell || !spinlock_preempt_disabled() || !process_cwd_description_valid(owner)) return -EINVAL;
    /* Reserve the shell's reference before changing either process context. */
    if (!fd_description_get(owner)) return -EOVERFLOW;
    int result = process_apply_cwd_to_current_and_pid(owner, shell->owner_pid);
    if (result) fd_description_put(owner);
    else if (shell_cwd_replace_owned(shell, owner)) fatal("invalid shell cwd result ownership");
    return result;
}

int io_vfs_change_shell_cwd_kernel(const char *path, shell_state_t *shell)
{
    if (!shell) return -EINVAL;
    spinlock_preempt_disable();
    fd_description_t *base = shell_cwd_acquire(shell);
    fd_description_t *lifetime = shell->lifetime_owner;
    bool pinned = !lifetime || fd_description_get(lifetime);
    int result = base && pinned ? io_vfs_prepare_cwd(path, base, lifetime) : -EOVERFLOW;
    fd_description_put(base);
    if (lifetime && pinned) fd_description_put(lifetime);
    spinlock_preempt_enable();
    if (result) return result;
    io_request_status_t status;
    result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    if (!result) result = (int)status.result;
    if (!result)
    {
        fd_description_t *owner = NULL;
        result = io_request_take_result(request, &owner);
        if (!result)
        {
            result = io_vfs_apply_shell_cwd_owned(shell, owner);
            if (result) fd_description_put(owner);
        }
    }
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    return result;
}
