#include "io_user_file.h"
#include "io_vfs_service.h"
#include "io_tcp.h"
#include "io_pipe.h"
#include "io_audio.h"
#include "io_poll.h"
#include "process_internal.h"
#include "net/dns.h"
#include "net/interface.h"
#include "user_copy.h"
#include "libc.h"
#include "errno.h"
#include <stdint.h>

_Static_assert(FD_STATUS_READ == SYSCALL_OPEN_READ && FD_STATUS_WRITE == SYSCALL_OPEN_WRITE &&
               FD_STATUS_APPEND == SYSCALL_OPEN_APPEND && FD_STATUS_NONBLOCK == SYSCALL_OPEN_NONBLOCK,
               "private descriptor status wire flags");

typedef enum { USER_STORAGE, USER_TCP, USER_DNS, USER_PIPE, USER_AUDIO, USER_POLL } user_file_service_t;
typedef struct
{
    uint32_t reply_mode, server_ip;
    uint16_t server_port;
    char name[SYSCALL_DNS_NAME_MAX + 1u];
    net_dns_result_t resolved;
    syscall_dns_reply_t reply;
} user_dns_operation_t;
_Static_assert(NET_DNS_MAX_ADDRS == SYSCALL_DNS_ADDR_MAX && NET_DNS_NAME_MAX == SYSCALL_DNS_NAME_MAX &&
               NET_DNS_STATUS_OK == SYSCALL_DNS_OK && NET_DNS_STATUS_NOT_FOUND == SYSCALL_DNS_NOT_FOUND &&
               NET_DNS_STATUS_AGAIN == SYSCALL_DNS_AGAIN && NET_DNS_STATUS_FAILURE == SYSCALL_DNS_FAILURE,
               "native DNS result wire limits and status");
static io_event_service_t *g_user_tcp_service;
static io_service_t *g_user_dns_service;
static uint32_t g_user_file_start;

static bool user_tcp_handler(io_request_t *request, io_service_result_t *result)
{
    if (io_poll_description_valid(io_request_description(request)))
        return io_poll_execute(request, result);
    if (io_pipe_description_valid(io_request_description(request)))
        return io_pipe_execute(request, result);
    if (io_audio_description_valid(io_request_description(request)))
        return io_audio_execute(request, result);
    return io_tcp_execute(request, result, process_fd_retirement_queue());
}

static void user_dns_handler(io_request_t *request, io_service_result_t *result)
{
    result->description_owned = NULL;
    result->result = -EINVAL;
    if (io_request_buffer_size(request) != sizeof(user_dns_operation_t)) return;
    user_dns_operation_t *operation = io_request_buffer(request);
    if (operation->reply_mode > 1) return;
    uint32_t address = 0;
    bool success;
    if (net_parse_ipv4(operation->name, &address))
    {
        operation->resolved.status = NET_DNS_STATUS_OK;
        operation->resolved.has_a = true;
        operation->resolved.addr_count = 1;
        operation->resolved.addr = operation->resolved.addrs[0] = address;
        memcpy(operation->resolved.cname, operation->name, strlen(operation->name) + 1);
        success = true;
    }
    else success = net_dns_resolve_at(operation->name, NET_DNS_TYPE_A, NULL,
                                      operation->server_ip, operation->server_port, &operation->resolved);
    if (!operation->reply_mode)
    {
        result->result = success && operation->resolved.has_a && operation->resolved.addr ?
                         (int64_t)operation->resolved.addr : -ENOENT;
        return;
    }
    syscall_dns_reply_t *reply = &operation->reply;
    reply->version = SYSCALL_DNS_VERSION; reply->size = sizeof(*reply);
    reply->status = operation->resolved.status;
    size_t count = success && operation->resolved.has_a ? operation->resolved.addr_count : 0;
    if (count > SYSCALL_DNS_ADDR_MAX) { result->result = -EIO; return; }
    reply->address_count = (uint32_t)count;
    memcpy(reply->addresses, operation->resolved.addrs, count * sizeof(*reply->addresses));
    size_t length = strnlen(operation->resolved.cname, sizeof(operation->resolved.cname));
    if (length > SYSCALL_DNS_NAME_MAX) { result->result = -EIO; return; }
    reply->canonical_length = (uint32_t)length;
    memcpy(reply->canonical, operation->resolved.cname, length + 1);
    result->result = 0;
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
    if (kind == USER_TCP || kind == USER_PIPE || kind == USER_AUDIO || kind == USER_POLL)
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
    int result = kind == USER_TCP || kind == USER_PIPE || kind == USER_AUDIO || kind == USER_POLL ?
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
    int result = kind == USER_POLL ? process_io_wait_current_interruptible(&status) :
                                     process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t value = result ? result : status.result;
    if (!result && value >= 0 && operation == SYSCALL_FILE_POLL)
    {
        syscall_pollfd_t *entries = io_poll_entries(io_request_description(request));
        if (!entries) value = -EIO;
        else if (capacity && !user_copy_to_user(output, entries, capacity)) value = -EFAULT;
    }
    else if (!result && value >= 0 && (operation == SYSCALL_FILE_OPEN || operation == SYSCALL_FILE_SOCKET_OPEN))
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
    else if (!result && value > 0 && (operation == SYSCALL_FILE_GETCWD || operation == SYSCALL_FILE_REALPATH))
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        if ((uint64_t)value >= capacity) value = -EIO;
        else if (!user_copy_to_user(output, work->data, (size_t)value + 1)) value = -EFAULT;
    }
    else if (!result && value > 0 && (operation == SYSCALL_FILE_READ || operation == SYSCALL_FILE_PREAD ||
                                     operation == SYSCALL_FILE_NET_RECV))
    {
        void *data = kind == USER_TCP ? (void *)((io_tcp_operation_t *)io_request_buffer(request))->data :
                     kind == USER_PIPE ? (void *)((io_pipe_operation_t *)io_request_buffer(request))->data :
                     kind == USER_AUDIO ? (void *)((io_audio_operation_t *)io_request_buffer(request))->data :
                                         (void *)((io_vfs_operation_t *)io_request_buffer(request))->data;
        if ((uint64_t)value > capacity) value = -EIO;
        else if (!user_copy_to_user(output, data, (size_t)value)) value = -EFAULT;
    }
    else if (!result && !value && (operation == SYSCALL_FILE_STAT || operation == SYSCALL_FILE_STAT_PATH))
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        if (!user_copy_to_user(output, &work->stat, sizeof(work->stat))) value = -EFAULT;
    }
    else if (!result && !value && operation == SYSCALL_FILE_DNS_RESOLVE)
    {
        user_dns_operation_t *work = io_request_buffer(request);
        if (capacity != sizeof(work->reply) || !user_copy_to_user(output, &work->reply, sizeof(work->reply))) value = -EFAULT;
    }
    else if (!result && !value && operation == SYSCALL_FILE_AUDIO_STATUS)
    {
        io_audio_operation_t *work = io_request_buffer(request);
        if (!user_copy_to_user(output, work->data, sizeof(syscall_audio_status_t))) value = -EFAULT;
    }
    if (request && fd_table_reservation_valid(io_request_description(request)))
        (void)fd_table_reservation_cancel(io_request_description(request));
    bool broken_pipe = request && value == -EPIPE && operation == SYSCALL_FILE_WRITE &&
                       io_pipe_description_valid(io_request_description(request));
    if (request && value == -EPIPE && operation == SYSCALL_FILE_NET_SEND &&
        !(slot_flags & SYSCALL_MSG_NOSIGNAL)) broken_pipe = true;
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    if (broken_pipe) (void)process_signal_raise(ALIX_SIGPIPE, 0);
    return value;
}

static int64_t user_file_open(const char *path, uint64_t flags)
{
    uint64_t known = SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE |
                     SYSCALL_OPEN_TRUNCATE | SYSCALL_OPEN_EXCLUSIVE | SYSCALL_OPEN_APPEND | SYSCALL_OPEN_CLOEXEC | SYSCALL_OPEN_NONBLOCK;
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
    if (flags > SYSCALL_REMOVE_DIRECTORY_ONLY || (operation == SYSCALL_FILE_RENAME && flags)) return -EINVAL;
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
        work->opcode = operation == SYSCALL_FILE_RENAME ? IO_VFS_RENAME :
                       operation == SYSCALL_FILE_MKDIR ? IO_VFS_MKDIR : IO_VFS_REMOVE;
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

static int64_t user_realpath(const char *path, void *output, uint64_t capacity)
{
    if (!capacity || capacity > VFS_PATH_MAX) return -EINVAL;
    if (!output || !user_ptr_range_valid(output, (size_t)capacity)) return -EFAULT;
    spinlock_preempt_disable();
    uint32_t uid = 0, gid = 0;
    fd_description_t *cwd = process_acquire_cwd_owner(current_process_local(), &uid, &gid);
    io_request_t *request = NULL;
    int result = cwd ? user_file_create_identity(USER_STORAGE, sizeof(io_vfs_operation_t) + VFS_PATH_MAX,
                                                  NULL, cwd, uid, gid, &request) : -ENOMEM;
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = IO_VFS_REALPATH; work->count = capacity;
        result = user_copy_cstring_from_user((char *)work->data, VFS_PATH_MAX, path, NULL);
        if (!result) result = user_file_submit(USER_STORAGE, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, SYSCALL_FILE_REALPATH, output, (size_t)capacity, 0);
}

static int64_t user_file_data(uint32_t operation, uint64_t fd, void *buffer, size_t count,
                              int64_t offset, int whence, uint32_t message_flags)
{
    bool socket_operation = operation == SYSCALL_FILE_NET_RECV || operation == SYSCALL_FILE_NET_SEND;
    bool reading = operation == SYSCALL_FILE_READ || operation == SYSCALL_FILE_NET_RECV;
    bool writing = operation == SYSCALL_FILE_WRITE || operation == SYSCALL_FILE_NET_SEND;
    uint32_t known = reading ? SYSCALL_MSG_PEEK | SYSCALL_MSG_DONTWAIT : SYSCALL_MSG_DONTWAIT | SYSCALL_MSG_NOSIGNAL;
    if (message_flags & ~known) return -EOPNOTSUPP;
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    bool tcp = !result && io_tcp_description_valid(description) &&
               (reading || writing || operation == SYSCALL_FILE_SOCKET_AVAILABLE);
    if (!result && socket_operation && !tcp) result = -ENOTSOCK;
    bool pipe = !result && io_pipe_description_valid(description) &&
                (operation == SYSCALL_FILE_READ || operation == SYSCALL_FILE_WRITE);
    bool audio_operation = operation == SYSCALL_FILE_AUDIO_WRITE || operation == SYSCALL_FILE_AUDIO_STATUS ||
                           operation == SYSCALL_FILE_AUDIO_DRAIN;
    bool audio = !result && io_audio_description_valid(description) &&
                 (operation == SYSCALL_FILE_READ || operation == SYSCALL_FILE_WRITE || audio_operation);
    if (!result && audio_operation && !audio) result = -ENOTTY;
    if (!result && audio && (operation == SYSCALL_FILE_WRITE || operation == SYSCALL_FILE_AUDIO_WRITE) && count % 4)
        result = -EINVAL;
    user_file_service_t kind = tcp ? USER_TCP : pipe ? USER_PIPE : audio ? USER_AUDIO : USER_STORAGE;
    size_t header = tcp ? sizeof(io_tcp_operation_t) : pipe ? sizeof(io_pipe_operation_t) :
                    audio ? sizeof(io_audio_operation_t) : sizeof(io_vfs_operation_t);
    size_t capacity = IO_REQUEST_BUFFER_MAX - header;
    if (count > capacity) count = capacity;
    size_t bytes = reading || writing || operation == SYSCALL_FILE_PREAD ||
                   operation == SYSCALL_FILE_AUDIO_WRITE || operation == SYSCALL_FILE_AUDIO_STATUS ? count : 0;
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
        if (audio)
        {
            io_audio_operation_t *work = io_request_buffer(request);
            work->opcode = operation == SYSCALL_FILE_READ ? IO_AUDIO_READ :
                           operation == SYSCALL_FILE_AUDIO_STATUS ? IO_AUDIO_STATUS :
                           operation == SYSCALL_FILE_AUDIO_DRAIN ? IO_AUDIO_DRAIN : IO_AUDIO_WRITE;
            work->count = bytes;
            data = work->data;
        }
        else if (pipe)
        {
            io_pipe_operation_t *work = io_request_buffer(request);
            work->opcode = operation == SYSCALL_FILE_READ ? IO_PIPE_READ : IO_PIPE_WRITE;
            work->count = bytes;
            data = work->data;
        }
        else if (tcp)
        {
            io_tcp_operation_t *work = io_request_buffer(request);
            work->opcode = reading ? IO_TCP_READ : writing ? IO_TCP_WRITE : IO_TCP_AVAILABLE;
            work->count = bytes;
            work->flags = message_flags;
            data = work->data;
        }
        else
        {
            io_vfs_operation_t *work = io_request_buffer(request);
            work->opcode = operation == SYSCALL_FILE_READ ? IO_VFS_READ : operation == SYSCALL_FILE_WRITE ? IO_VFS_WRITE :
                           operation == SYSCALL_FILE_PREAD ? IO_VFS_PREAD : operation == SYSCALL_FILE_STAT ? IO_VFS_STAT :
                           operation == SYSCALL_FILE_SYNC ? IO_VFS_SYNC :
                           operation == SYSCALL_FILE_TRUNCATE ? IO_VFS_TRUNCATE : IO_VFS_SEEK;
            work->count = bytes; work->offset = offset; work->whence = whence;
            data = work->data;
        }
        if ((writing || operation == SYSCALL_FILE_AUDIO_WRITE) &&
            bytes && !user_copy_from_user(data, buffer, bytes)) result = -EFAULT;
        if (!result) result = user_file_submit(kind, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(kind, operation, buffer, count, message_flags);
}

static int64_t user_socket_open(const char *name, uint32_t status_flags, uint32_t slot_flags)
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
        work->flags = status_flags;
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
    return result ? result : user_file_finish(USER_TCP, SYSCALL_FILE_SOCKET_OPEN, NULL, 0, slot_flags);
}

static int64_t user_socket_connect_address(uint64_t fd, const void *address, uint64_t length)
{
    if (length < sizeof(syscall_sockaddr_in_t)) return -EINVAL;
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    if (!result && !io_tcp_description_valid(description)) result = -ENOTSOCK;
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_TCP, sizeof(io_tcp_operation_t) + sizeof(syscall_sockaddr_in_t),
                                           description, NULL, &request);
    else fd_description_put(description);
    if (!result)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        syscall_sockaddr_in_t *endpoint = (void *)work->data;
        if (!user_copy_from_user(endpoint, address, sizeof(*endpoint))) result = -EFAULT;
        else if (endpoint->family != SYSCALL_AF_INET) result = -EAFNOSUPPORT;
        else
        {
            work->opcode = IO_TCP_CONNECT;
            work->ipv4 = __builtin_bswap32(endpoint->address_be);
            work->port = __builtin_bswap16(endpoint->port_be);
            if (!work->ipv4 || !work->port) result = -EINVAL;
        }
        if (!result) result = user_file_submit(USER_TCP, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_TCP, SYSCALL_FILE_NET_CONNECT, NULL, 0, 0);
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

static int64_t user_dns_resolve(const char *hostname, void *output, uint64_t bytes, uint64_t server)
{
    if (bytes != sizeof(syscall_dns_reply_t)) return -EINVAL;
    uint32_t address = (uint32_t)(server >> 32);
    uint16_t port = (uint16_t)server;
    if ((server & UINT64_C(0xffff0000)) || ((!address) != (!port))) return -EINVAL;
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    int result = user_file_create(USER_DNS, sizeof(user_dns_operation_t), NULL, NULL, &request);
    if (!result)
    {
        user_dns_operation_t *work = io_request_buffer(request);
        work->reply_mode = 1; work->server_ip = address; work->server_port = port;
        result = user_copy_cstring_from_user(work->name, sizeof(work->name), hostname, NULL);
        if (!result && !work->name[0]) result = -EINVAL;
        if (!result) result = user_file_submit(USER_DNS, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_DNS, SYSCALL_FILE_DNS_RESOLVE, output, sizeof(syscall_dns_reply_t), 0);
}

static int64_t user_socket_query_finish(uint32_t operation, void *output, void *length_output, uint32_t capacity)
{
    io_request_status_t status;
    int result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t value = result ? result : status.result;
    if (!value)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        io_tcp_query_reply_t *reply = (void *)work->data;
        bool name = operation == SYSCALL_FILE_NET_GETNAME;
        uint32_t expected = name ? sizeof(reply->address) : sizeof(reply->value);
        uint32_t copied = capacity < expected ? capacity : expected;
        const void *data = name ? (const void *)&reply->address : (const void *)&reply->value;
        uint32_t returned = name ? expected : copied;
        if (reply->length != expected) value = -EIO;
        else if ((copied && !user_copy_to_user(output, data, copied)) ||
                 !user_copy_to_user(length_output, &returned, sizeof(returned))) value = -EFAULT;
        else value = io_tcp_query_commit(io_request_description(request));
    }
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    return value;
}

static int64_t user_socket_query(uint32_t operation, uint64_t fd, void *data, uint64_t length, uint64_t option)
{
    bool name = operation == SYSCALL_FILE_NET_GETNAME;
    bool setting = operation == SYSCALL_FILE_NET_SETOPT;
    if (name && option > 1) return -EINVAL;
    if (setting && length < sizeof(int32_t)) return -EINVAL;
    spinlock_preempt_disable();
    fd_description_t *description = NULL, *query = NULL;
    int result = user_file_pin(fd, &description);
    if (!result) result = io_tcp_query_create(description, process_fd_retirement_queue(), &query);
    else fd_description_put(description);
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_TCP, sizeof(io_tcp_operation_t) + sizeof(io_tcp_query_reply_t),
                                           query, NULL, &request);
    uint32_t capacity = 0;
    if (!result)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        io_tcp_query_reply_t *reply = (void *)work->data;
        work->opcode = name ? IO_TCP_GETNAME : setting ? IO_TCP_SETOPT : IO_TCP_GETOPT;
        if (name) work->interface_index = (uint32_t)option;
        else { work->ipv4 = (uint32_t)(option >> 32); work->port = (uint32_t)option; }
        if (setting)
        {
            if (!user_copy_from_user(&reply->value, data, sizeof(reply->value))) result = -EFAULT;
        }
        else if (!user_copy_from_user(&capacity, (const void *)(uintptr_t)length, sizeof(capacity))) result = -EFAULT;
        if (!result) result = user_file_submit(USER_TCP, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    if (result) return result;
    if (setting) return user_file_finish(USER_TCP, operation, NULL, 0, 0);
    return user_socket_query_finish(operation, data, (void *)(uintptr_t)length, capacity);
}

static int64_t user_pipe_open(void *output, uint64_t flags)
{
    if (flags & ~((uint64_t)SYSCALL_FILE_CLOEXEC | SYSCALL_OPEN_NONBLOCK)) return -EINVAL;
    if (!output || !user_ptr_range_valid(output, 2 * sizeof(int32_t))) return -EFAULT;
    spinlock_preempt_disable();
    fd_table_t *table = process_current_fd_table();
    fd_description_t *reader = NULL, *writer = NULL;
    int result = table ? io_pipe_create_pair(process_fd_retirement_queue(), &reader, &writer) : -ESRCH;
    if (!result && (flags & SYSCALL_OPEN_NONBLOCK))
    {
        (void)fd_description_set_status_flags(reader, SYSCALL_OPEN_NONBLOCK);
        (void)fd_description_set_status_flags(writer, SYSCALL_OPEN_NONBLOCK);
    }
    int slots[2] = { -1, -1 };
    if (!result) result = fd_table_install_pair(table, reader, writer, (uint32_t)flags & SYSCALL_FILE_CLOEXEC, slots);
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

static int64_t user_audio_open(uint64_t flags)
{
    if (flags & ~((uint64_t)SYSCALL_FILE_CLOEXEC)) return -EINVAL;
    spinlock_preempt_disable();
    fd_table_t *table = process_current_fd_table();
    fd_description_t *description = NULL;
    int result = table ? io_audio_create(process_fd_retirement_queue(), process_current_pid(), &description) : -ESRCH;
    if (!result) result = fd_table_install(table, description, 0, (uint32_t)flags);
    fd_description_put(description);
    spinlock_preempt_enable();
    return result;
}

static int64_t user_file_poll(void *entries, uint64_t count, int64_t timeout)
{
    if (count > FD_TABLE_MAX_ENTRIES || timeout < INT32_MIN || timeout > INT32_MAX) return -EINVAL;
    size_t bytes = (size_t)count * sizeof(syscall_pollfd_t);
    if (bytes && (!entries || !user_ptr_range_valid(entries, bytes))) return -EFAULT;
    spinlock_preempt_disable();
    fd_table_t *table = process_current_fd_table();
    fd_description_t *description = NULL;
    int result = table ? io_poll_create(process_fd_retirement_queue(), (size_t)count, (int)timeout,
                                          &description) : -ESRCH;
    if (!result && bytes && !user_copy_from_user(io_poll_entries(description), entries, bytes)) result = -EFAULT;
    if (!result) result = io_poll_pin(description, table);
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_POLL, 0, description, NULL, &request);
    else fd_description_put(description);
    if (!result) result = user_file_submit(USER_POLL, request);
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_POLL, SYSCALL_FILE_POLL, entries, bytes, 0);
}

typedef struct
{
    syscall_fd_set_t read, write, except;
} user_select_sets_t;
typedef struct
{
    syscall_select_t query;
    user_select_sets_t sets;
    struct { int64_t seconds, microseconds; } timeout;
} user_select_prepare_t;

_Static_assert(SYSCALL_SELECT_FD_MAX == FD_TABLE_MAX_ENTRIES, "select descriptor table ABI");
_Static_assert(sizeof(syscall_fd_set_t) == 32 && sizeof(syscall_select_t) == 48, "select wire ABI");

static bool user_select_isset(const syscall_fd_set_t *set, unsigned fd)
{
    return (set->bits[fd / 64u] & (UINT64_C(1) << (fd % 64u))) != 0;
}

static int64_t user_select_finish(int nfds, void *readfds, void *writefds, void *exceptfds)
{
    /* These output addresses belong only to this live caller. The protected
     * event worker receives owned masks/descriptions, never these addresses
     * or any pointer to the caller's kernel stack. */
    io_request_status_t status;
    int result = process_io_wait_current_interruptible(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t value = result ? result : status.result;
    syscall_pollfd_t *entries = !result ? io_poll_entries(io_request_description(request)) : NULL;
    if (!result && value >= 0 && (!entries || value > nfds ||
        io_request_buffer_size(request) != sizeof(user_select_sets_t))) value = -EIO;
    if (!result && value >= 0)
    {
        /* Invalid descriptors are an error, not exceptional readiness. Reject
         * the entire result before changing any caller descriptor set. */
        for (int fd = 0; fd < nfds; ++fd)
            if (entries[fd].revents & SYSCALL_POLL_NVAL) { value = -EBADF; break; }
    }
    if (!result && value >= 0)
    {
        user_select_sets_t *sets = io_request_buffer(request);
        memset(sets, 0, sizeof(*sets));
        value = 0;
        for (int fd = 0; fd < nfds; ++fd)
        {
            uint64_t bit = UINT64_C(1) << ((unsigned)fd % 64u);
            unsigned word = (unsigned)fd / 64u;
            if (entries[fd].revents & SYSCALL_POLL_IN) { sets->read.bits[word] |= bit; ++value; }
            if (entries[fd].revents & SYSCALL_POLL_OUT) { sets->write.bits[word] |= bit; ++value; }
            if (entries[fd].revents & SYSCALL_POLL_PRI) { sets->except.bits[word] |= bit; ++value; }
        }
        if ((readfds && !user_copy_to_user(readfds, &sets->read, sizeof(sets->read))) ||
            (writefds && !user_copy_to_user(writefds, &sets->write, sizeof(sets->write))) ||
            (exceptfds && !user_copy_to_user(exceptfds, &sets->except, sizeof(sets->except)))) value = -EFAULT;
    }
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    return value;
}

static int64_t user_file_select(const void *input, uint64_t bytes)
{
    if (bytes != sizeof(syscall_select_t)) return -EINVAL;
    spinlock_preempt_disable();
    user_select_prepare_t *prepared = calloc(1, sizeof(*prepared));
    int result = prepared ? 0 : -ENOMEM;
    if (!result && !user_copy_from_user(&prepared->query, input, sizeof(prepared->query))) result = -EFAULT;
    if (!result && prepared->query.version != SYSCALL_SELECT_VERSION) result = -ENOTSUP;
    if (!result && (prepared->query.size != sizeof(prepared->query) || prepared->query.flags ||
        prepared->query.nfds < 0 || prepared->query.nfds > (int)SYSCALL_SELECT_FD_MAX)) result = -EINVAL;
    void *readfds = !result ? (void *)(uintptr_t)prepared->query.readfds : NULL;
    void *writefds = !result ? (void *)(uintptr_t)prepared->query.writefds : NULL;
    void *exceptfds = !result ? (void *)(uintptr_t)prepared->query.exceptfds : NULL;
    int nfds = !result ? prepared->query.nfds : 0;
    int64_t timeout = -1;
    if (!result && prepared->query.timeout)
    {
        if (!user_copy_from_user(&prepared->timeout, (const void *)(uintptr_t)prepared->query.timeout,
                                    sizeof(prepared->timeout))) result = -EFAULT;
        else if (prepared->timeout.seconds < 0 || prepared->timeout.microseconds < 0 || prepared->timeout.microseconds >= 1000000)
            result = -EINVAL;
        else
        {
            uint64_t rounded = ((uint64_t)prepared->timeout.microseconds + 999u) / 1000u;
            if ((uint64_t)prepared->timeout.seconds > ((uint64_t)INT64_MAX - rounded) / 1000u) result = -EINVAL;
            else timeout = prepared->timeout.seconds * 1000 + (int64_t)rounded;
        }
    }
    if (!result && ((readfds && !user_copy_from_user(&prepared->sets.read, readfds, sizeof(prepared->sets.read))) ||
        (writefds && !user_copy_from_user(&prepared->sets.write, writefds, sizeof(prepared->sets.write))) ||
        (exceptfds && !user_copy_from_user(&prepared->sets.except, exceptfds, sizeof(prepared->sets.except))))) result = -EFAULT;
    fd_description_t *description = NULL;
    fd_table_t *table = process_current_fd_table();
    if (!result) result = table ? io_select_create(process_fd_retirement_queue(), (size_t)nfds,
                                                    timeout, &description) : -ESRCH;
    if (!result)
    {
        syscall_pollfd_t *entries = io_poll_entries(description);
        for (int fd = 0; fd < nfds; ++fd)
        {
            uint32_t events = user_select_isset(&prepared->sets.read, (unsigned)fd) ? SYSCALL_POLL_IN : 0;
            if (user_select_isset(&prepared->sets.write, (unsigned)fd)) events |= SYSCALL_POLL_OUT;
            if (user_select_isset(&prepared->sets.except, (unsigned)fd)) events |= SYSCALL_POLL_PRI;
            entries[fd] = (syscall_pollfd_t){ .fd = events ? fd : -1, .events = (int16_t)events };
        }
        result = io_poll_pin(description, table);
    }
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_POLL, sizeof(user_select_sets_t), description, NULL, &request);
    else fd_description_put(description);
    /* Captured input metadata contains user addresses. Destroy it before any
     * asynchronous worker is submitted or the syscall caller can block. */
    free(prepared);
    if (!result) result = user_file_submit(USER_POLL, request);
    spinlock_preempt_enable();
    return result ? result : user_select_finish(nfds, readfds, writefds, exceptfds);
}

int64_t io_user_file_dispatch(uint32_t operation, uint64_t first, uint64_t second,
                               uint64_t third, uint64_t fourth)
{
    switch (operation)
    {
        case SYSCALL_FILE_OPEN: return user_file_open((const char *)first, second);
        case SYSCALL_FILE_READ: case SYSCALL_FILE_WRITE: case SYSCALL_FILE_PREAD:
            return user_file_data(operation, first, (void *)second, third, (int64_t)fourth, 0, 0);
        case SYSCALL_FILE_SEEK: return user_file_data(operation, first, NULL, 0, (int64_t)second, (int)third, 0);
        case SYSCALL_FILE_STAT: return user_file_data(operation, first, (void *)second, 0, 0, 0, 0);
        case SYSCALL_FILE_SYNC:
            if (second || third || fourth) return -EINVAL;
            return user_file_data(operation, first, NULL, 0, 0, 0, 0);
        case SYSCALL_FILE_TRUNCATE:
            if (third || fourth || second > INT64_MAX) return -EINVAL;
            return user_file_data(operation, first, NULL, 0, (int64_t)second, 0, 0);
        case SYSCALL_FILE_REALPATH:
            if (fourth) return -EINVAL;
            return user_realpath((const char *)first, (void *)second, third);
        case SYSCALL_FILE_MKDIR:
            if (second || third || fourth) return -EINVAL;
            return user_path_mutation(operation, (const char *)first, NULL, 0);
        case SYSCALL_FILE_SOCKET_OPEN: return user_socket_open((const char *)first, 0, 0);
        case SYSCALL_FILE_NET_OPEN:
            if (fourth) return -EINVAL;
            if (first != SYSCALL_AF_INET) return -EAFNOSUPPORT;
            if (second & ~(UINT64_C(15) | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_CLOEXEC)) return -EINVAL;
            if ((second & 15u) != SYSCALL_SOCK_STREAM || (third && third != SYSCALL_IPPROTO_TCP)) return -EPROTONOSUPPORT;
            return user_socket_open(NULL, (uint32_t)second & SYSCALL_OPEN_NONBLOCK,
                                      second & SYSCALL_OPEN_CLOEXEC ? FD_TABLE_CLOEXEC : 0);
        case SYSCALL_FILE_NET_CONNECT:
            if (fourth) return -EINVAL;
            return user_socket_connect_address(first, (const void *)second, third);
        case SYSCALL_FILE_NET_RECV: case SYSCALL_FILE_NET_SEND:
            if (fourth > UINT32_MAX) return -EINVAL;
            return user_file_data(operation, first, (void *)second, third, 0, 0, (uint32_t)fourth);
        case SYSCALL_FILE_NET_GETOPT: case SYSCALL_FILE_NET_SETOPT: case SYSCALL_FILE_NET_GETNAME:
            return user_socket_query(operation, first, (void *)second, third, fourth);
        case SYSCALL_FILE_DNS_RESOLVE:
            return user_dns_resolve((const char *)first, (void *)second, third, fourth);
        case SYSCALL_FILE_SOCKET_CONNECT: return user_socket_connect(first, (const char *)second, third);
        case SYSCALL_FILE_SOCKET_AVAILABLE: return user_file_data(operation, first, NULL, 0, 0, 0, 0);
        case SYSCALL_FILE_PIPE: return user_pipe_open((void *)first, second);
        case SYSCALL_FILE_AUDIO_OPEN: return user_audio_open(first);
        case SYSCALL_FILE_AUDIO_WRITE:
            return user_file_data(operation, first, (void *)second, third, 0, 0, 0);
        case SYSCALL_FILE_AUDIO_STATUS:
            if (third != sizeof(syscall_audio_status_t)) return -EINVAL;
            if (fourth != SYSCALL_AUDIO_STATUS_VERSION) return -ENOTSUP;
            return user_file_data(operation, first, (void *)second, sizeof(syscall_audio_status_t), 0, 0, 0);
        case SYSCALL_FILE_AUDIO_DRAIN: return user_file_data(operation, first, NULL, 0, 0, 0, 0);
        case SYSCALL_FILE_POLL: return user_file_poll((void *)first, second, (int64_t)third);
        case SYSCALL_FILE_SELECT:
            if (third || fourth) return -EINVAL;
            return user_file_select((const void *)first, second);
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
        case SYSCALL_FILE_GETFL: case SYSCALL_FILE_SETFL:
        {
            fd_description_t *description = NULL;
            result = fd_table_pin(table, (int)first, &description, NULL);
            if (!result)
            {
                if (operation == SYSCALL_FILE_GETFL) result = (int64_t)fd_description_status_flags(description);
                else result = second <= UINT32_MAX ? fd_description_set_status_flags(description, (uint32_t)second) : -EINVAL;
            }
            fd_description_put(description);
            break;
        }
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
