#include "io_vfs_service.h"
#include "process_internal.h"
#include "user_copy.h"
#include "errno.h"

/* Directory handle preparation is bounded and cannot yield. Before any wait,
 * the calling thread's registered I/O record owns every retained input. The
 * protected worker receives heap bytes, retained nodes/descriptions and values
 * only; no user VA, process pointer or caller stack crosses the wait. */
static int io_directory_prepare(uint32_t operation, int handle, const char *path)
{
    io_service_t *service = io_vfs_service_current();
    fd_table_t *table = process_current_directory_table();
    if (!service) return -ENOSYS;
    if (!table) return -ESRCH;
    fd_description_t *description = NULL, *cwd = NULL;
    uint32_t uid = 0, gid = 0;
    int result = 0;
    if (operation == SYSCALL_DIRECTORY_OPEN)
    {
        cwd = process_acquire_cwd_owner(current_process_local(), &uid, &gid);
        if (!cwd) return -ENOMEM;
    }
    else
    {
        result = fd_table_pin(table, handle, &description, NULL);
        if (result) return result;
    }
    size_t payload = operation == SYSCALL_DIRECTORY_OPEN ? VFS_PATH_MAX :
                     operation == SYSCALL_DIRECTORY_NEXT ? sizeof(syscall_directory_entry_t) : 0;
    io_request_t *request = NULL;
    result = io_service_request_create(service, sizeof(io_vfs_operation_t) + payload, uid, gid, &request);
    if (!result)
        result = cwd ? io_request_bind_cwd_owner(request, description, cwd) :
                       io_request_bind(request, description, NULL, NULL);
    if (result)
    {
        fd_description_put(description);
        fd_description_put(cwd);
        if (request) io_request_waiter_abandon(request);
        return result;
    }
    result = process_io_register_current(request);
    if (result) { io_request_waiter_abandon(request); return result; }
    io_vfs_operation_t *work = io_request_buffer(request);
    work->opcode = operation == SYSCALL_DIRECTORY_OPEN ? IO_VFS_OPEN_DIR :
                   operation == SYSCALL_DIRECTORY_NEXT ? IO_VFS_READ_DIR : IO_VFS_REWIND_DIR;
    work->count = operation == SYSCALL_DIRECTORY_NEXT ? sizeof(syscall_directory_entry_t) : 0;
    if (path) result = user_copy_cstring_from_user((char *)work->data, VFS_PATH_MAX, path, NULL);
    if (!result) result = io_service_submit(service, request);
    if (result) (void)process_io_finish_current(true);
    return result;
}

int64_t io_vfs_directory_user(uint32_t operation, int handle, void *argument, size_t bytes)
{
    if (operation > SYSCALL_DIRECTORY_REWIND) return -EINVAL;
    if (operation == SYSCALL_DIRECTORY_OPEN)
    {
        if (handle || bytes) return -EINVAL;
        if (!argument) return -EFAULT;
    }
    else if (operation == SYSCALL_DIRECTORY_NEXT)
    {
        if (bytes != sizeof(syscall_directory_entry_t)) return -EINVAL;
        if (!argument || !user_ptr_range_valid(argument, bytes)) return -EFAULT;
    }
    else if (argument || bytes) return -EINVAL;
    spinlock_preempt_disable();
    if (operation == SYSCALL_DIRECTORY_CLOSE)
    {
        fd_table_t *table = process_current_directory_table();
        int result = table ? fd_table_close(table, handle) : -ESRCH;
        spinlock_preempt_enable();
        return result;
    }
    int result = io_directory_prepare(operation, handle,
                                      operation == SYSCALL_DIRECTORY_OPEN ? argument : NULL);
    spinlock_preempt_enable();
    if (result) return result;
    io_request_status_t status;
    result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t value = result ? result : status.result;
    if (!result && value >= 0 && operation == SYSCALL_DIRECTORY_OPEN)
    {
        fd_description_t *description = NULL;
        value = io_request_take_result(request, &description);
        if (!value)
        {
            fd_table_t *table = process_current_directory_table();
            value = table ? fd_table_install(table, description, 0, FD_TABLE_CLOEXEC) : -ESRCH;
            /* The table retained its own reference, or the deferred queue owns
             * rollback. No local reference remains when the guard is dropped. */
            fd_description_put(description);
        }
    }
    else if (!result && value == 1 && operation == SYSCALL_DIRECTORY_NEXT)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        if (!user_copy_to_user(argument, work->data, bytes)) value = -EFAULT;
    }
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    return value;
}
