#include "io_user_file.h"
#include "io_vfs_service.h"
#include "io_tcp.h"
#include "io_pipe.h"
#include "process_internal.h"
#include "net/dns.h"
#include "net/interface.h"
#include "user_copy.h"
#include "libc.h"
#include "errno.h"
#include <stdint.h>

typedef enum { USER_STORAGE, USER_TCP, USER_DNS, USER_PIPE } user_file_service_t;
typedef struct { char name[256]; } user_dns_operation_t;
static io_event_service_t *g_user_tcp_service;
static io_service_t *g_user_dns_service;
static uint32_t g_user_file_start;

static bool user_tcp_handler(io_request_t *request, io_service_result_t *result)
{
    if (io_pipe_description_valid(io_request_description(request)))
        return io_pipe_execute(request, result);
    return io_tcp_execute(request, result, process_fd_retirement_queue());
}

static void user_dns_handler(io_request_t *request, io_service_result_t *result)
{
    result->description_owned = NULL;
    result->result = -EINVAL;
    if (io_request_buffer_size(request) != sizeof(user_dns_operation_t)) return;
    user_dns_operation_t *operation = io_request_buffer(request);
    uint32_t address = 0;
    if (net_parse_ipv4(operation->name, &address) || net_dns_resolve_ipv4(operation->name, NULL, &address))
        result->result = address ? (int64_t)address : -ENOENT;
    else result->result = -ENOENT;
}

bool io_user_file_services_start(void)
{
    if (spinlock_preempt_disabled() || !io_vfs_service_current() || !process_fd_retirement_queue()) return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&g_user_file_start, &expected, 1, false,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return expected == 2;
    io_event_service_t *tcp = io_event_service_create(128, user_tcp_handler);
    io_service_t *dns = tcp ? io_service_create(64, 2, user_dns_handler) : NULL;
    if (!dns)
    {
        if (tcp && (io_event_service_shutdown(tcp) || io_event_service_destroy(tcp)))
            fatal("user TCP startup rollback failed");
        __atomic_store_n(&g_user_file_start, 0, __ATOMIC_RELEASE);
        return false;
    }
    __atomic_store_n(&g_user_tcp_service, tcp, __ATOMIC_RELEASE);
    __atomic_store_n(&g_user_dns_service, dns, __ATOMIC_RELEASE);
    __atomic_store_n(&g_user_file_start, 2, __ATOMIC_RELEASE);
    return true;
}

/* Guard held. Consume both references on every return. Before the guard drops
 * they belong to a registered request or deferred cleanup. No process/table
 * pointer or local owner crosses the blocking wait. */
static int user_file_create_identity(user_file_service_t kind, size_t bytes, fd_description_t *description,
                                      fd_description_t *cwd, uint32_t uid, uint32_t gid, io_request_t **out)
{
    *out = NULL;
    io_request_t *request = NULL;
    int result;
    if (kind == USER_TCP || kind == USER_PIPE)
    {
        io_event_service_t *service = __atomic_load_n(&g_user_tcp_service, __ATOMIC_ACQUIRE);
        result = service ? io_event_service_request_create(service, bytes, uid, gid, &request) : -ENOSYS;
    }
    else
    {
        io_service_t *service = kind == USER_STORAGE ? io_vfs_service_current() :
                                __atomic_load_n(&g_user_dns_service, __ATOMIC_ACQUIRE);
        result = service ? io_service_request_create(service, bytes, uid, gid, &request) : -ENOSYS;
    }
    if (!result) result = cwd ? io_request_bind_cwd_owner(request, description, cwd) :
                               io_request_bind(request, description, NULL, NULL);
    if (result)
    {
        if (fd_table_reservation_valid(description)) (void)fd_table_reservation_cancel(description);
        fd_description_put(description); fd_description_put(cwd);
        if (request) io_request_waiter_abandon(request);
        return result;
    }
    result = process_io_register_current(request);
    if (result)
    {
        if (fd_table_reservation_valid(io_request_description(request)))
            (void)fd_table_reservation_cancel(io_request_description(request));
        io_request_waiter_abandon(request);
        return result;
    }
    *out = request;
    return 0;
}

static int user_file_create(user_file_service_t kind, size_t bytes, fd_description_t *description,
                             fd_description_t *cwd, io_request_t **out)
{
    process_t *process = current_process_local();
    uint32_t uid = 0, gid = 0;
    if (process)
    {
        spinlock_lock(&process->context_lock);
        uid = process->uid; gid = process->gid;
        spinlock_unlock(&process->context_lock);
    }
    return user_file_create_identity(kind, bytes, description, cwd, uid, gid, out);
}

static void user_file_abort(io_request_t *request)
{
    fd_description_t *description = io_request_description(request);
    if (fd_table_reservation_valid(description)) (void)fd_table_reservation_cancel(description);
    (void)process_io_finish_current(true);
}

static int user_file_submit(user_file_service_t kind, io_request_t *request)
{
    int result = kind == USER_TCP || kind == USER_PIPE ?
        io_event_service_submit(__atomic_load_n(&g_user_tcp_service, __ATOMIC_ACQUIRE), request) :
        io_service_submit(kind == USER_STORAGE ? io_vfs_service_current() :
                            __atomic_load_n(&g_user_dns_service, __ATOMIC_ACQUIRE), request);
    if (result) user_file_abort(request);
    return result;
}

static int user_file_pin(uint64_t fd, fd_description_t **out)
{
    *out = NULL;
    fd_table_t *table = process_current_fd_table();
    if (!table) return -ESRCH;
    if (fd > INT32_MAX) return -EBADF;
    return fd_table_pin(table, (int)fd, out, NULL);
}

static int64_t user_file_finish(user_file_service_t kind, uint32_t operation,
                                 void *output, size_t capacity, uint32_t slot_flags)
{
    io_request_status_t status;
    int result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t value = result ? result : status.result;
    if (!result && value >= 0 && (operation == SYSCALL_FILE_OPEN || operation == SYSCALL_FILE_SOCKET_OPEN))
    {
        fd_description_t *description = NULL;
        value = io_request_take_result(request, &description);
        if (!value)
        {
            value = fd_table_reservation_commit(io_request_description(request), description, slot_flags);
            fd_description_put(description);
        }
    }
    else if (!result && !value && operation == SYSCALL_FILE_CHDIR)
    {
        fd_description_t *description = NULL;
        value = io_request_take_result(request, &description);
        if (!value)
        {
            value = process_set_cwd_description_owned(current_process_local(), description);
            if (value) fd_description_put(description);
        }
    }
    else if (!result && value > 0 && operation == SYSCALL_FILE_GETCWD)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        if ((uint64_t)value >= capacity) value = -EIO;
        else if (!user_copy_to_user(output, work->data, (size_t)value + 1)) value = -EFAULT;
    }
    else if (!result && value > 0 && (operation == SYSCALL_FILE_READ || operation == SYSCALL_FILE_PREAD))
    {
        void *data = kind == USER_TCP ? (void *)((io_tcp_operation_t *)io_request_buffer(request))->data :
                     kind == USER_PIPE ? (void *)((io_pipe_operation_t *)io_request_buffer(request))->data :
                                         (void *)((io_vfs_operation_t *)io_request_buffer(request))->data;
        if ((uint64_t)value > capacity) value = -EIO;
        else if (!user_copy_to_user(output, data, (size_t)value)) value = -EFAULT;
    }
    else if (!result && !value && (operation == SYSCALL_FILE_STAT || operation == SYSCALL_FILE_STAT_PATH))
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        if (!user_copy_to_user(output, &work->stat, sizeof(work->stat))) value = -EFAULT;
    }
    if (request && fd_table_reservation_valid(io_request_description(request)))
        (void)fd_table_reservation_cancel(io_request_description(request));
    bool broken_pipe = request && value == -EPIPE && operation == SYSCALL_FILE_WRITE &&
                       io_pipe_description_valid(io_request_description(request));
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    if (broken_pipe) (void)process_signal_raise(ALIX_SIGPIPE, 0);
    return value;
}

static int64_t user_file_open(const char *path, uint64_t flags)
{
    uint64_t known = SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE |
                     SYSCALL_OPEN_TRUNCATE | SYSCALL_OPEN_EXCLUSIVE | SYSCALL_OPEN_CLOEXEC;
    if (flags & ~known) return -EINVAL;
    spinlock_preempt_disable();
    uint32_t uid = 0, gid = 0;
    fd_description_t *cwd = process_acquire_cwd_owner(current_process_local(), &uid, &gid);
    int result = cwd ? 0 : -ENOMEM;
    fd_description_t *reservation = NULL;
    if (!result) result = fd_table_reserve_deferred(process_current_fd_table(), &reservation);
    io_request_t *request = NULL;
    if (!result) result = user_file_create_identity(USER_STORAGE, sizeof(io_vfs_operation_t) + VFS_PATH_MAX,
                                                    reservation, cwd, uid, gid, &request);
    else fd_description_put(cwd);
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = IO_VFS_OPEN;
        work->flags = (uint32_t)(flags & ~SYSCALL_OPEN_CLOEXEC);
        result = user_copy_cstring_from_user((char *)work->data, VFS_PATH_MAX, path, NULL);
        if (!result) result = user_file_submit(USER_STORAGE, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, SYSCALL_FILE_OPEN, NULL, 0,
                                              flags & SYSCALL_OPEN_CLOEXEC ? FD_TABLE_CLOEXEC : 0);
}

static int64_t user_path_mutation(uint32_t operation, const char *path, const char *new_path, uint64_t flags)
{
    if (flags > 1 || (operation == SYSCALL_FILE_RENAME && flags)) return -EINVAL;
    spinlock_preempt_disable();
    uint32_t uid = 0, gid = 0;
    fd_description_t *cwd = process_acquire_cwd_owner(current_process_local(), &uid, &gid);
    io_request_t *request = NULL;
    size_t paths = operation == SYSCALL_FILE_RENAME ? 2 : 1;
    int result = cwd ? user_file_create_identity(USER_STORAGE,
        sizeof(io_vfs_operation_t) + paths * VFS_PATH_MAX, NULL, cwd, uid, gid, &request) : -ENOMEM;
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = operation == SYSCALL_FILE_RENAME ? IO_VFS_RENAME : IO_VFS_REMOVE;
        work->flags = (uint32_t)flags;
        result = user_copy_cstring_from_user((char *)work->data, VFS_PATH_MAX, path, NULL);
        if (!result && paths == 2)
            result = user_copy_cstring_from_user((char *)work->data + VFS_PATH_MAX, VFS_PATH_MAX, new_path, NULL);
        if (!result) result = user_file_submit(USER_STORAGE, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, operation, NULL, 0, 0);
}

static int64_t user_path_operation(uint32_t operation, const char *path, void *output, uint64_t flags)
{
    if (flags & ~((uint64_t)SYSCALL_STAT_NOFOLLOW)) return -EINVAL;
    if (operation == SYSCALL_FILE_STAT_PATH &&
        (!output || !user_ptr_range_valid(output, sizeof(syscall_stat_t)))) return -EFAULT;
    spinlock_preempt_disable();
    uint32_t uid = 0, gid = 0;
    fd_description_t *cwd = process_acquire_cwd_owner(current_process_local(), &uid, &gid);
    io_request_t *request = NULL;
    int result = cwd ? user_file_create_identity(USER_STORAGE, sizeof(io_vfs_operation_t) + VFS_PATH_MAX,
                                                  NULL, cwd, uid, gid, &request) : -ENOMEM;
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = operation == SYSCALL_FILE_CHDIR ? IO_VFS_RESOLVE_CWD : IO_VFS_STAT_PATH;
        work->flags = (uint32_t)flags;
        result = user_copy_cstring_from_user((char *)work->data, VFS_PATH_MAX, path, NULL);
        if (!result) result = user_file_submit(USER_STORAGE, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, operation, output, 0, 0);
}

static int64_t user_getcwd(void *output, uint64_t capacity)
{
    if (!capacity) return -EINVAL;
    if (capacity > VFS_PATH_MAX) capacity = VFS_PATH_MAX;
    if (!output || !user_ptr_range_valid(output, (size_t)capacity)) return -EFAULT;
    spinlock_preempt_disable();
    uint32_t uid = 0, gid = 0;
    fd_description_t *cwd = process_acquire_cwd_owner(current_process_local(), &uid, &gid);
    io_request_t *request = NULL;
    int result = cwd ? user_file_create_identity(USER_STORAGE, sizeof(io_vfs_operation_t) + (size_t)capacity,
                                                  NULL, cwd, uid, gid, &request) : -ENOMEM;
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = IO_VFS_GETCWD; work->count = capacity;
        result = user_file_submit(USER_STORAGE, request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, SYSCALL_FILE_GETCWD, output, (size_t)capacity, 0);
}

static int64_t user_file_data(uint32_t operation, uint64_t fd, void *buffer, size_t count,
                              int64_t offset, int whence)
{
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    bool tcp = !result && io_tcp_description_valid(description) &&
               (operation == SYSCALL_FILE_READ || operation == SYSCALL_FILE_WRITE || operation == SYSCALL_FILE_SOCKET_AVAILABLE);
    bool pipe = !result && io_pipe_description_valid(description) &&
                (operation == SYSCALL_FILE_READ || operation == SYSCALL_FILE_WRITE);
    user_file_service_t kind = tcp ? USER_TCP : pipe ? USER_PIPE : USER_STORAGE;
    size_t header = tcp ? sizeof(io_tcp_operation_t) : pipe ? sizeof(io_pipe_operation_t) : sizeof(io_vfs_operation_t);
    size_t capacity = IO_REQUEST_BUFFER_MAX - header;
    if (count > capacity) count = capacity;
    size_t bytes = operation == SYSCALL_FILE_READ || operation == SYSCALL_FILE_WRITE || operation == SYSCALL_FILE_PREAD ? count : 0;
    if (!result && operation == SYSCALL_FILE_SOCKET_AVAILABLE && !tcp) result = -ENOTSOCK;
    if (!result && bytes && (!buffer || !user_ptr_range_valid(buffer, bytes))) result = -EFAULT;
    if (!result && operation == SYSCALL_FILE_STAT &&
        (!buffer || !user_ptr_range_valid(buffer, sizeof(syscall_stat_t)))) result = -EFAULT;
    io_request_t *request = NULL;
    if (!result) result = user_file_create(kind, header + bytes, description, NULL, &request);
    else fd_description_put(description);
    if (!result)
    {
        unsigned char *data;
        if (pipe)
        {
            io_pipe_operation_t *work = io_request_buffer(request);
            work->opcode = operation == SYSCALL_FILE_READ ? IO_PIPE_READ : IO_PIPE_WRITE;
            work->count = bytes;
            data = work->data;
        }
        else if (tcp)
        {
            io_tcp_operation_t *work = io_request_buffer(request);
            work->opcode = operation == SYSCALL_FILE_READ ? IO_TCP_READ :
                           operation == SYSCALL_FILE_WRITE ? IO_TCP_WRITE : IO_TCP_AVAILABLE;
            work->count = bytes;
            data = work->data;
        }
        else
        {
            io_vfs_operation_t *work = io_request_buffer(request);
            work->opcode = operation == SYSCALL_FILE_READ ? IO_VFS_READ : operation == SYSCALL_FILE_WRITE ? IO_VFS_WRITE :
                           operation == SYSCALL_FILE_PREAD ? IO_VFS_PREAD : operation == SYSCALL_FILE_STAT ? IO_VFS_STAT : IO_VFS_SEEK;
            work->count = bytes; work->offset = offset; work->whence = whence;
            data = work->data;
        }
        if (operation == SYSCALL_FILE_WRITE && bytes && !user_copy_from_user(data, buffer, bytes)) result = -EFAULT;
        if (!result) result = user_file_submit(kind, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(kind, operation, buffer, count, 0);
}

static int64_t user_socket_open(const char *name)
{
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    fd_description_t *reservation = NULL;
    int result = fd_table_reserve_deferred(process_current_fd_table(), &reservation);
    if (!result) result = user_file_create(USER_TCP, sizeof(io_tcp_operation_t) + NET_IF_NAME_MAX, reservation, NULL, &request);
    if (!result)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        work->opcode = IO_TCP_OPEN;
        if (name) result = user_copy_cstring_from_user((char *)work->data, NET_IF_NAME_MAX, name, NULL);
        bool named = name && work->data[0];
        net_interface_t *selected = !result && named ? net_if_by_name((const char *)work->data) : NULL;
        bool found = false;
        for (size_t index = 0; !result && index < net_if_count(); ++index)
        {
            net_interface_t *interface = net_if_at(index);
            if (interface && interface->present && (selected ? interface == selected : !named))
            { work->interface_index = (uint32_t)index; found = true; break; }
        }
        if (!result && !found) result = -ENODEV;
        if (!result) result = user_file_submit(USER_TCP, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_TCP, SYSCALL_FILE_SOCKET_OPEN, NULL, 0, 0);
}

static int64_t user_socket_connect(uint64_t fd, const char *host, uint64_t port)
{
    if (!port || port > 65535u) return -EINVAL;
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    if (!result && !io_tcp_description_valid(description)) result = -ENOTSOCK;
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_DNS, sizeof(user_dns_operation_t), description, NULL, &request);
    else fd_description_put(description);
    if (!result)
    {
        user_dns_operation_t *work = io_request_buffer(request);
        result = user_copy_cstring_from_user(work->name, sizeof(work->name), host, NULL);
        if (!result) result = user_file_submit(USER_DNS, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    if (result) return result;
    io_request_status_t status;
    result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t address = result ? result : status.result;
    description = NULL;
    if (!result && address > 0)
    {
        description = io_request_description(request);
        if (!fd_description_get(description)) { description = NULL; result = -EOVERFLOW; }
    }
    else if (!result) result = address ? (int)address : -ENOENT;
    (void)process_io_finish_current(result != 0);
    request = NULL;
    if (!result) result = user_file_create(USER_TCP, sizeof(io_tcp_operation_t), description, NULL, &request);
    if (!result)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        work->opcode = IO_TCP_CONNECT; work->ipv4 = (uint32_t)address; work->port = (uint32_t)port;
        result = user_file_submit(USER_TCP, request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_TCP, SYSCALL_FILE_SOCKET_CONNECT, NULL, 0, 0);
}

static int64_t user_pipe_open(void *output, uint64_t flags)
{
    if (flags & ~((uint64_t)SYSCALL_FILE_CLOEXEC)) return -EINVAL;
    if (!output || !user_ptr_range_valid(output, 2 * sizeof(int32_t))) return -EFAULT;
    spinlock_preempt_disable();
    fd_table_t *table = process_current_fd_table();
    fd_description_t *reader = NULL, *writer = NULL;
    int result = table ? io_pipe_create_pair(process_fd_retirement_queue(), &reader, &writer) : -ESRCH;
    int slots[2] = { -1, -1 };
    if (!result) result = fd_table_install_pair(table, reader, writer, (uint32_t)flags, slots);
    if (!result && !user_copy_to_user(output, slots, sizeof(slots)))
    {
        (void)fd_table_close_if(table, slots[0], reader);
        (void)fd_table_close_if(table, slots[1], writer);
        result = -EFAULT;
    }
    fd_description_put(reader); fd_description_put(writer);
    spinlock_preempt_enable();
    return result;
}

int64_t io_user_file_dispatch(uint32_t operation, uint64_t first, uint64_t second,
                               uint64_t third, uint64_t fourth)
{
    switch (operation)
    {
        case SYSCALL_FILE_OPEN: return user_file_open((const char *)first, second);
        case SYSCALL_FILE_READ: case SYSCALL_FILE_WRITE: case SYSCALL_FILE_PREAD:
            return user_file_data(operation, first, (void *)second, third, (int64_t)fourth, 0);
        case SYSCALL_FILE_SEEK: return user_file_data(operation, first, NULL, 0, (int64_t)second, (int)third);
        case SYSCALL_FILE_STAT: return user_file_data(operation, first, (void *)second, 0, 0, 0);
        case SYSCALL_FILE_SOCKET_OPEN: return user_socket_open((const char *)first);
        case SYSCALL_FILE_SOCKET_CONNECT: return user_socket_connect(first, (const char *)second, third);
        case SYSCALL_FILE_SOCKET_AVAILABLE: return user_file_data(operation, first, NULL, 0, 0, 0);
        case SYSCALL_FILE_PIPE: return user_pipe_open((void *)first, second);
        case SYSCALL_FILE_STAT_PATH: return user_path_operation(operation, (const char *)first, (void *)second, third);
        case SYSCALL_FILE_CHDIR: return user_path_operation(operation, (const char *)first, NULL, 0);
        case SYSCALL_FILE_GETCWD: return user_getcwd((void *)first, second);
        case SYSCALL_FILE_REMOVE: case SYSCALL_FILE_RENAME:
            return user_path_mutation(operation, (const char *)first, (const char *)second, third);
        default: break;
    }
    spinlock_preempt_disable();
    fd_table_t *table = process_current_fd_table();
    int64_t result = -EINVAL;
    if (!table) result = -ESRCH;
    else if (first > INT32_MAX) result = -EBADF;
    else switch (operation)
    {
        case SYSCALL_FILE_CLOSE: result = fd_table_close(table, (int)first); break;
        case SYSCALL_FILE_GETFD:
        {
            uint32_t flags = 0;
            result = fd_table_get_flags(table, (int)first, &flags);
            if (!result) result = flags;
            break;
        }
        case SYSCALL_FILE_SETFD:
            result = second <= UINT32_MAX ? fd_table_set_flags(table, (int)first, (uint32_t)second) : -EINVAL;
            break;
        case SYSCALL_FILE_DUP:
            result = second <= INT32_MAX && third <= UINT32_MAX ?
                fd_table_dup(table, (int)first, (int)second, (uint32_t)third) : -EINVAL;
            break;
        case SYSCALL_FILE_DUP2:
            result = second <= INT32_MAX ? fd_table_dup2(table, (int)first, (int)second) : -EBADF;
            break;
        case SYSCALL_FILE_DUP3:
            result = second <= INT32_MAX && third <= UINT32_MAX ?
                fd_table_dup3(table, (int)first, (int)second, (uint32_t)third) : -EINVAL;
            break;
        default: break;
    }
    spinlock_preempt_enable();
    return result;
}
