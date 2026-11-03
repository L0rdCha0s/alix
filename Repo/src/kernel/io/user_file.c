#include "io_user_file.h"
#include <stddef.h>
#include "io_vfs_service.h"
#include "io_tcp.h"
#include "io_udp.h"
#include "io_pipe.h"
#include "io_audio.h"
#include "io_poll.h"
#include "io_record_lock.h"
#include "process_internal.h"
#include "net/dns.h"
#include "net/interface.h"
#include "user_copy.h"
#include "libc.h"
#include "errno.h"
#include <stdint.h>

_Static_assert(FD_STATUS_READ == SYSCALL_OPEN_READ && FD_STATUS_WRITE == SYSCALL_OPEN_WRITE &&
               FD_STATUS_APPEND == SYSCALL_OPEN_APPEND && FD_STATUS_NONBLOCK == SYSCALL_OPEN_NONBLOCK &&
               FD_STATUS_SYNC == SYSCALL_OPEN_SYNC,
               "private descriptor status wire flags");

typedef enum { USER_STORAGE, USER_TCP, USER_DNS, USER_PIPE, USER_AUDIO, USER_POLL, USER_FLOCK } user_file_service_t;
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
    if (io_record_lock_description_valid(io_request_description(request)))
        return io_record_lock_execute(request, result);
    if (io_flock_description_valid(io_request_description(request)))
        return io_flock_execute(request, result);
    if (io_poll_description_valid(io_request_description(request)))
        return io_poll_execute(request, result);
    if (io_pipe_description_valid(io_request_description(request)))
        return io_pipe_execute(request, result);
    if (io_audio_description_valid(io_request_description(request)))
        return io_audio_execute(request, result);
    if (io_udp_request_valid(request)) return io_udp_execute(request, result, process_fd_retirement_queue());
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
    if (kind == USER_TCP || kind == USER_PIPE || kind == USER_AUDIO || kind == USER_POLL || kind == USER_FLOCK)
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
    int result = kind == USER_TCP || kind == USER_PIPE || kind == USER_AUDIO || kind == USER_POLL || kind == USER_FLOCK ?
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
    int result = kind == USER_POLL || kind == USER_FLOCK ? process_io_wait_current_interruptible(&status) :
                                     process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t value = result ? result : status.result;
    if (!result && !value && (operation == SYSCALL_FILE_SYSTEM_INFO || operation == SYSCALL_FILE_HOSTNAME))
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        syscall_utsname_t *info = (void *)work->data;
        if (operation == SYSCALL_FILE_SYSTEM_INFO)
            value = capacity == sizeof(*info) && user_copy_to_user(output, info, sizeof(*info)) ? 0 : -EFAULT;
        else
        {
            size_t length = strnlen(info->nodename, sizeof(info->nodename));
            if (length == sizeof(info->nodename)) value = -EIO;
            else if (capacity <= length) value = -ENAMETOOLONG;
            else if (!user_copy_to_user(output, info->nodename, length + 1)) value = -EFAULT;
        }
    }
    else if (!result && value >= 0 && operation == SYSCALL_FILE_IOCTL)
    {
        void *data = kind == USER_TCP ? (void *)((io_tcp_operation_t *)io_request_buffer(request))->data :
                     kind == USER_PIPE ? (void *)((io_pipe_operation_t *)io_request_buffer(request))->data :
                                         (void *)((io_vfs_operation_t *)io_request_buffer(request))->data;
        int32_t *reply = data;
        *reply = value > INT32_MAX ? INT32_MAX : (int32_t)value;
        value = capacity == sizeof(*reply) && user_copy_to_user(output, reply, sizeof(*reply)) ? 0 : -EFAULT;
    }
    else if (!result && !value && operation == SYSCALL_FILE_FLOCK)
    {
        fd_description_t *lease = NULL;
        result = io_request_take_result(request, &lease);
        value = result ? result : io_flock_commit(lease);
        fd_description_put(lease);
    }
    else if (!result && !value && operation == SYSCALL_FILE_RECORD_LOCK)
    {
        fd_description_t *lease = NULL;
        result = io_request_take_result(request, &lease);
        value = result ? result : io_record_lock_commit(lease);
        if (!value && io_record_lock_is_query(lease) &&
            !user_copy_to_user(output, io_record_lock_query(lease), sizeof(syscall_record_lock_t))) value = -EFAULT;
        fd_description_put(lease);
    }
    else if (!result && value >= 0 && operation == SYSCALL_FILE_POLL)
    {
        syscall_pollfd_t *entries = io_poll_entries(io_request_description(request));
        if (!entries) value = -EIO;
        else if (capacity && !user_copy_to_user(output, entries, capacity)) value = -EFAULT;
    }
    else if (!result && value >= 0 && (operation == SYSCALL_FILE_OPEN || operation == SYSCALL_FILE_SOCKET_OPEN ||
                                      operation == SYSCALL_FILE_SHM_OPEN))
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
    else if (!result && !value && (operation == SYSCALL_FILE_STAT_INFO || operation == SYSCALL_FILE_PATH_INFO))
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        if (!user_copy_to_user(output, work->data, sizeof(syscall_stat_info_t))) value = -EFAULT;
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
    if (request && value >= 0 && (operation == SYSCALL_FILE_NET_RECV || operation == SYSCALL_FILE_READ) &&
        io_udp_description_valid(io_request_description(request)) && (slot_flags & 0x20u))
        value = io_udp_state(request)->packet.length;
    if (request && operation == SYSCALL_FILE_FLOCK && value < 0)
        io_flock_abort(io_request_description(request));
    if (request && operation == SYSCALL_FILE_RECORD_LOCK && value < 0)
        io_record_lock_abort(io_request_description(request));
    if (request && fd_table_reservation_valid(io_request_description(request)))
        (void)fd_table_reservation_cancel(io_request_description(request));
    bool broken_pipe = request && value == -EPIPE &&
                       (operation == SYSCALL_FILE_WRITE || operation == SYSCALL_FILE_WRITEV) &&
                       io_pipe_description_valid(io_request_description(request));
    if (request && value == -EPIPE && operation == SYSCALL_FILE_NET_SEND &&
        !(slot_flags & SYSCALL_MSG_NOSIGNAL)) broken_pipe = true;
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    if (broken_pipe) (void)process_signal_raise(ALIX_SIGPIPE, 0);
    return value;
}

static int64_t user_file_open(const char *path, uint64_t flags, bool shared_memory, uint64_t mode)
{
    uint64_t known = SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE |
                     SYSCALL_OPEN_TRUNCATE | SYSCALL_OPEN_EXCLUSIVE | SYSCALL_OPEN_APPEND | SYSCALL_OPEN_CLOEXEC | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_SYNC;
    if (flags & ~known) return -EINVAL;
    if ((flags & SYSCALL_OPEN_CREATE) && mode > UINT32_MAX) return -EINVAL;
    if ((flags & SYSCALL_OPEN_CREATE) && (mode & 07000u)) return -EOPNOTSUPP;
    if (shared_memory)
    {
        if (!(flags & SYSCALL_OPEN_READ) || (flags & (SYSCALL_OPEN_APPEND | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_SYNC)) ||
            ((flags & SYSCALL_OPEN_CREATE) && mode > UINT32_MAX)) return -EINVAL;
        flags |= SYSCALL_OPEN_CLOEXEC;
    }
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
        work->opcode = shared_memory ? IO_VFS_SHM_OPEN : IO_VFS_OPEN_MODE;
        work->flags = (uint32_t)(flags & ~SYSCALL_OPEN_CLOEXEC);
        uint32_t mask = __atomic_load_n(&current_process_local()->creation_mask, __ATOMIC_ACQUIRE);
        work->whence = (int32_t)((mode & 0777u) & ~mask);
        result = user_copy_cstring_from_user((char *)work->data, VFS_PATH_MAX, path, NULL);
        if (!result) result = user_file_submit(USER_STORAGE, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE,
                                              shared_memory ? SYSCALL_FILE_SHM_OPEN : SYSCALL_FILE_OPEN, NULL, 0,
                                              flags & SYSCALL_OPEN_CLOEXEC ? FD_TABLE_CLOEXEC : 0);
}

static int64_t user_file_shm_unlink(const char *name)
{
    spinlock_preempt_disable();
    uint32_t uid = 0, gid = 0;
    fd_description_t *cwd = process_acquire_cwd_owner(current_process_local(), &uid, &gid);
    io_request_t *request = NULL;
    int result = cwd ? user_file_create_identity(USER_STORAGE, sizeof(io_vfs_operation_t) + VFS_PATH_MAX,
                                                NULL, cwd, uid, gid, &request) : -ENOMEM;
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = IO_VFS_SHM_UNLINK;
        result = user_copy_cstring_from_user((char *)work->data, VFS_PATH_MAX, name, NULL);
        if (!result) result = user_file_submit(USER_STORAGE, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, SYSCALL_FILE_SHM_UNLINK, NULL, 0, 0);
}

static int64_t user_file_flock(uint64_t fd, uint32_t flags)
{
    if (!io_flock_flags_valid(flags)) return -EINVAL;
    spinlock_preempt_disable();
    fd_description_t *target = NULL;
    int result = user_file_pin(fd, &target);
    io_flock_state_t *state = !result ? io_vfs_flock_state(target) : NULL;
    if (!result && !state) result = -EOPNOTSUPP;
    if (!result && (flags & ~SYSCALL_FLOCK_NONBLOCK) == SYSCALL_FLOCK_UNLOCK)
    {
        result = io_flock_unlock(state);
        fd_description_put(target);
        spinlock_preempt_enable();
        return result;
    }
    fd_description_t *lease = NULL;
    if (!result) result = io_flock_create(process_fd_retirement_queue(), target, state, flags, &lease);
    else fd_description_put(target);
    io_request_t *request = NULL;
    if (!result)
    {
        /* Retain one local lease owner only inside this bounded guard. The
         * generic request helper consumes the other reference on every path;
         * preparation failure must release the target pin before returning. */
        if (!fd_description_get(lease)) result = -EOVERFLOW;
        else
        {
            result = user_file_create(USER_FLOCK, 0, lease, NULL, &request);
            if (!result) result = user_file_submit(USER_FLOCK, request);
        }
        if (result) io_flock_abort(lease);
        fd_description_put(lease);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_FLOCK, SYSCALL_FILE_FLOCK, NULL, 0, 0);
}

static bool user_record_event_capacity(void *context)
{
    io_event_service_status_t status;
    return io_event_service_snapshot(context,&status) || status.queue.closed ||
        status.queue.live<status.queue.capacity || !status.queue.cleanup;
}
static bool user_record_storage_capacity(void *context)
{
    io_service_status_t status;
    return io_service_snapshot(context,&status) || status.queue.closed ||
        status.queue.live<status.queue.capacity || !status.queue.cleanup;
}
static int user_record_wait_admission(user_file_service_t kind)
{
    io_queue_status_t queue;
    void *service;
    int result;
    if(kind==USER_FLOCK)
    {
        service=__atomic_load_n(&g_user_tcp_service,__ATOMIC_ACQUIRE);
        io_event_service_status_t status;
        result=service?io_event_service_snapshot(service,&status):-ENOSYS;
        if(result)return result;
        queue=status.queue;
    }
    else
    {
        service=io_vfs_service_current();
        io_service_status_t status;
        result=service?io_service_snapshot(service,&status):-ENOSYS;
        if(result)return result;
        queue=status.queue;
    }
    if(queue.closed)return -ECANCELED;
    if(queue.live<queue.capacity)return 0;
    /* Wait only for reclaimable garbage. Active-resource exhaustion is an
     * explicit lock resource error, rather than a dependency-cycle wait. */
    if(!queue.cleanup)return -ENOLCK;
    (void)process_io_wait_cleanup(kind==USER_FLOCK?user_record_event_capacity:user_record_storage_capacity,service,1);
    return 0;
}
static int user_record_request(user_file_service_t kind,uint32_t uid,uint32_t gid,io_request_t **request)
{
    if(kind==USER_FLOCK)
    {
        io_event_service_t *service=__atomic_load_n(&g_user_tcp_service,__ATOMIC_ACQUIRE);
        return service?io_event_service_request_create(service,0,uid,gid,request):-ENOSYS;
    }
    io_service_t *service=io_vfs_service_current();
    return service?io_service_request_create(service,sizeof(io_vfs_operation_t),uid,gid,request):-ENOSYS;
}
static int64_t user_file_record_lock(uint64_t fd, uint32_t command, const void *query)
{
    if(command!=SYSCALL_F_GETLK&&command!=SYSCALL_F_SETLK&&command!=SYSCALL_F_SETLKW)return -EINVAL;
    /* A small scalar snapshot is the only state before admission. It stays
     * on this caller's own stack and is never passed to a worker. Waiting for
     * capacity therefore holds no unregistered heap object or descriptor. */
    syscall_record_lock_t captured;
    spinlock_preempt_disable();
    bool copied=user_copy_from_user(&captured,query,sizeof(captured));
    spinlock_preempt_enable();
    if(!copied)return -EFAULT;
    user_file_service_t kind=captured.whence==SYSCALL_SEEK_SET?USER_FLOCK:USER_STORAGE;
    int result;
    io_request_t *request=NULL;
    for(;;)
    {
        spinlock_preempt_disable();
        process_t *process=current_process_local();
        uint32_t uid=0,gid=0;
        if(process){spinlock_lock(&process->context_lock);uid=process->uid;gid=process->gid;spinlock_unlock(&process->context_lock);}
        result=user_record_request(kind,uid,gid,&request);
        if(result==-EAGAIN)
        {
            spinlock_preempt_enable();
            result=user_record_wait_admission(kind);
            if(result)return result;
            continue;
        }
        if(result){spinlock_preempt_enable();return result;}
        fd_description_t *target=NULL,*lease=NULL;
        result=user_file_pin(fd,&target);
        if(!result)result=io_record_lock_create(process_fd_retirement_queue(),process_current_fd_table(),
            target,process_current_pid(),command,&lease);
        if(!result){*io_record_lock_query(lease)=captured;result=io_record_lock_validate(lease);}
        if(!result)
        {
            result=io_request_bind(request,lease,NULL,NULL);
            if(!result)lease=NULL; /* request now owns it */
        }
        if(!result)result=process_io_register_current(request);
        if(result)
        {
            io_record_lock_abort(lease);fd_description_put(lease);
            io_record_lock_abort(io_request_description(request));
            (void)io_request_waiter_abandon(request);
        }
        else
        {
            if(kind==USER_STORAGE)((io_vfs_operation_t *)io_request_buffer(request))->opcode=IO_VFS_LOCK_RESOLVE;
            result=user_file_submit(kind,request);
        }
        spinlock_preempt_enable();
        if(result){process_io_notify_cleanup();return result;}
        break;
    }
    if(kind==USER_STORAGE)
    {
        io_request_status_t status;
        result=process_io_wait_current(&status);
        if(result)
        {
            spinlock_preempt_disable();(void)process_io_finish_current(true);spinlock_preempt_enable();return result;
        }
        for(;;)
        {
            spinlock_preempt_disable();
            io_request_t *previous=NULL,*next=NULL;
            result=process_io_result_current(&previous,&status);
            if(!result)result=(int)status.result;
            if(!result)result=user_record_request(USER_FLOCK,io_request_uid(previous),io_request_gid(previous),&next);
            if(result==-EAGAIN)
            {
                /* The completed storage request remains registered while
                 * waiting; it owns the original file/lease through cancellation. */
                spinlock_preempt_enable();
                result=user_record_wait_admission(USER_FLOCK);
                if(!result)continue;
                spinlock_preempt_disable();(void)process_io_finish_current(true);spinlock_preempt_enable();return result;
            }
            if(!result)
            {
                fd_description_t *lease=io_request_description(previous);
                if(!fd_description_get(lease))result=-EOVERFLOW;
                else
                {
                    result=io_request_bind(next,lease,NULL,NULL);
                    if(result)fd_description_put(lease);
                }
            }
            if(!result)result=process_io_finish_current(false);
            if(!result)result=process_io_register_current(next);
            if(result)
            {
                if(next)(void)io_request_waiter_abandon(next);
                (void)process_io_finish_current(true);
            }
            else result=user_file_submit(USER_FLOCK,next);
            spinlock_preempt_enable();
            if(result){process_io_notify_cleanup();return result;}
            break;
        }
    }
    return user_file_finish(USER_FLOCK,SYSCALL_FILE_RECORD_LOCK,(void *)query,sizeof(syscall_record_lock_t),0);
}

static int64_t user_file_ioctl(uint64_t fd, uint64_t command, void *argument, uint64_t bytes)
{
    if (command == SYSCALL_IOCTL_FIOCLEX || command == SYSCALL_IOCTL_FIONCLEX)
    {
        if (argument || bytes) return -EINVAL;
        spinlock_preempt_disable();
        fd_table_t *table = process_current_fd_table();
        int result = !table ? -ESRCH : fd > INT32_MAX ? -EBADF :
            fd_table_set_flags(table, (int)fd, command == SYSCALL_IOCTL_FIOCLEX ? FD_TABLE_CLOEXEC : 0);
        spinlock_preempt_enable();
        return result;
    }
    bool reading = command == SYSCALL_IOCTL_FIONREAD;
    bool nonblock = command == SYSCALL_IOCTL_FIONBIO;
    if ((reading || nonblock) && bytes != sizeof(int32_t)) return -EINVAL;
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    if (!result && nonblock)
    {
        int32_t enabled = 0;
        if (!user_copy_from_user(&enabled, argument, sizeof(enabled))) result = -EFAULT;
        else result = fd_description_update_status_flags(description, FD_STATUS_NONBLOCK,
                                                           enabled ? FD_STATUS_NONBLOCK : 0);
        fd_description_put(description);
        spinlock_preempt_enable();
        return result;
    }
    if (!reading)
    {
        fd_description_put(description);
        spinlock_preempt_enable();
        return result ? result : -ENOTTY;
    }
    if (!result && (!argument || !user_ptr_range_valid(argument, sizeof(int32_t)))) result = -EFAULT;
    bool udp = !result && io_udp_description_valid(description);
    bool tcp = !result && (io_tcp_description_valid(description) || udp);
    bool pipe = !result && io_pipe_description_valid(description);
    if (!result && !tcp && !pipe && !io_vfs_description_valid(description)) result = -ENOTTY;
    user_file_service_t kind = tcp ? USER_TCP : pipe ? USER_PIPE : USER_STORAGE;
    size_t header = tcp ? sizeof(io_tcp_operation_t) : pipe ? sizeof(io_pipe_operation_t) : sizeof(io_vfs_operation_t);
    io_request_t *request = NULL;
    if (!result) result = user_file_create(kind, header + (udp ? 8 + sizeof(io_udp_state_t) : sizeof(int32_t)), description, NULL, &request);
    else fd_description_put(description);
    if (!result)
    {
        if (tcp) ((io_tcp_operation_t *)io_request_buffer(request))->opcode = IO_TCP_AVAILABLE;
        else if (pipe) ((io_pipe_operation_t *)io_request_buffer(request))->opcode = IO_PIPE_AVAILABLE;
        else ((io_vfs_operation_t *)io_request_buffer(request))->opcode = IO_VFS_AVAILABLE;
        result = user_file_submit(kind, request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(kind, SYSCALL_FILE_IOCTL, argument, sizeof(int32_t), 0);
}

static int64_t user_resource_limit(bool setting, uint64_t resource, void *data, uint64_t bytes)
{
    if (bytes != sizeof(syscall_rlimit_t) ||
        (resource != SYSCALL_RESOURCE_NOFILE && resource != SYSCALL_RESOURCE_AS)) return -EINVAL;
    if (setting && resource == SYSCALL_RESOURCE_AS) return -ENOTSUP;
    if (!data || !user_ptr_range_valid(data, sizeof(syscall_rlimit_t))) return -EFAULT;
    spinlock_preempt_disable();
    process_t *process = current_process_local();
    fd_table_t *table = process_current_fd_table();
    syscall_rlimit_t limit = { UINT64_MAX, UINT64_MAX };
    int result = !process || !process->is_user || !table ? -ESRCH : 0;
    if (!result && setting)
    {
        if (!user_copy_from_user(&limit, data, sizeof(limit))) result = -EFAULT;
        else result = fd_table_set_limits(table, limit.current, limit.maximum, process_get_uid(process) == 0);
    }
    else if (!result)
    {
        /* No aggregate address-space quota is currently imposed. */
        if (resource == SYSCALL_RESOURCE_NOFILE) result = fd_table_get_limits(table, &limit.current, &limit.maximum);
        if (!result && !user_copy_to_user(data, &limit, sizeof(limit))) result = -EFAULT;
    }
    spinlock_preempt_enable();
    return result;
}

static int64_t user_system_info(uint32_t operation, void *output, uint64_t capacity)
{
    if (operation == SYSCALL_FILE_SYSTEM_INFO && capacity != sizeof(syscall_utsname_t)) return -EINVAL;
    if (operation == SYSCALL_FILE_HOSTNAME && !capacity) return -ENAMETOOLONG;
    size_t shape = operation == SYSCALL_FILE_SYSTEM_INFO ? sizeof(syscall_utsname_t) : 1;
    if (!output || !user_ptr_range_valid(output, shape)) return -EFAULT;
    spinlock_preempt_disable();
    uint32_t uid = 0, gid = 0;
    fd_description_t *cwd = process_acquire_cwd_owner(current_process_local(), &uid, &gid);
    io_request_t *request = NULL;
    int result = cwd ? user_file_create_identity(USER_STORAGE, sizeof(io_vfs_operation_t) + sizeof(syscall_utsname_t),
                                                  NULL, cwd, uid, gid, &request) : -ENOMEM;
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = IO_VFS_SYSTEM_INFO; work->count = sizeof(syscall_utsname_t);
        result = user_file_submit(USER_STORAGE, request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, operation, output, (size_t)capacity, 0);
}

static int64_t user_path_mutation(uint32_t operation, const char *path, const char *new_path, uint64_t flags,
                                  uint64_t mode)
{
    if (operation == SYSCALL_FILE_MKDIR_MODE && mode > UINT32_MAX) return -EINVAL;
    if (operation == SYSCALL_FILE_MKDIR_MODE && (mode & 07000u)) return -EOPNOTSUPP;
    if (operation == SYSCALL_FILE_CHMOD_PATH && mode > 0177777u) return -EINVAL;
    if (operation == SYSCALL_FILE_CHMOD_PATH && (mode & 07000u)) return -EOPNOTSUPP;
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
                       operation == SYSCALL_FILE_CHMOD_PATH ? IO_VFS_CHMOD_PATH :
                       (operation == SYSCALL_FILE_MKDIR || operation == SYSCALL_FILE_MKDIR_MODE) ?
                           IO_VFS_MKDIR_MODE : IO_VFS_REMOVE;
        work->flags = (uint32_t)flags;
        if (operation == SYSCALL_FILE_MKDIR || operation == SYSCALL_FILE_MKDIR_MODE)
            work->whence = (int32_t)((mode & 0777u) & ~__atomic_load_n(&current_process_local()->creation_mask, __ATOMIC_ACQUIRE));
        if (operation == SYSCALL_FILE_CHMOD_PATH) work->whence = (int32_t)mode;
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
    size_t reply_size = operation == SYSCALL_FILE_PATH_INFO ? sizeof(syscall_stat_info_t) : sizeof(syscall_stat_t);
    if (operation != SYSCALL_FILE_CHDIR &&
        (!output || !user_ptr_range_valid(output, reply_size))) return -EFAULT;
    spinlock_preempt_disable();
    uint32_t uid = 0, gid = 0;
    fd_description_t *cwd = process_acquire_cwd_owner(current_process_local(), &uid, &gid);
    io_request_t *request = NULL;
    int result = cwd ? user_file_create_identity(USER_STORAGE, sizeof(io_vfs_operation_t) + VFS_PATH_MAX,
                                                  NULL, cwd, uid, gid, &request) : -ENOMEM;
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = operation == SYSCALL_FILE_CHDIR ? IO_VFS_RESOLVE_CWD :
                       operation == SYSCALL_FILE_PATH_INFO ? IO_VFS_PATH_INFO : IO_VFS_STAT_PATH;
        work->flags = (uint32_t)flags;
        result = user_copy_cstring_from_user((char *)work->data, VFS_PATH_MAX, path, NULL);
        if (!result) result = user_file_submit(USER_STORAGE, request);
        else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, operation, output, 0, 0);
}

static int64_t user_file_stat_info(uint64_t fd, void *output)
{
    if (!output || !user_ptr_range_valid(output, sizeof(syscall_stat_info_t))) return -EFAULT;
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_STORAGE,
        sizeof(io_vfs_operation_t) + sizeof(syscall_stat_info_t), description, NULL, &request);
    else fd_description_put(description);
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = IO_VFS_STAT_INFO;
        result = user_file_submit(USER_STORAGE, request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, SYSCALL_FILE_STAT_INFO, output, 0, 0);
}

static int64_t user_file_metadata(uint32_t operation, uint64_t fd, uint32_t first, uint32_t second)
{
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    if (!result && !io_vfs_description_valid(description)) result = -EOPNOTSUPP;
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_STORAGE, sizeof(io_vfs_operation_t), description, NULL, &request);
    else fd_description_put(description);
    if (!result)
    {
        io_vfs_operation_t *work = io_request_buffer(request);
        work->opcode = operation == SYSCALL_FILE_CHMOD ? IO_VFS_CHMOD : IO_VFS_CHOWN;
        work->flags = first; work->whence = (int32_t)second;
        result = user_file_submit(USER_STORAGE, request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_STORAGE, operation, NULL, 0, 0);
}

static int64_t user_file_set_times(const char *path, const void *times)
{
    spinlock_preempt_disable();
    uint32_t uid=0,gid=0;
    fd_description_t *cwd=process_acquire_cwd_owner(current_process_local(),&uid,&gid);
    io_request_t *request=NULL;
    int result=cwd?user_file_create_identity(USER_STORAGE,sizeof(io_vfs_operation_t)+VFS_PATH_MAX+
        sizeof(syscall_file_times_t),NULL,cwd,uid,gid,&request):-ENOMEM;
    if (!result)
    {
        io_vfs_operation_t *work=io_request_buffer(request);
        work->opcode=IO_VFS_SET_TIMES;work->flags=times?1:0;
        result=user_copy_cstring_from_user((char *)work->data,VFS_PATH_MAX,path,NULL);
        syscall_file_times_t *captured=(void *)(work->data+VFS_PATH_MAX);
        if (!result&&times&&!user_copy_from_user(captured,times,sizeof(*captured)))result=-EFAULT;
        if (!result&&(captured->access_seconds<0||captured->modify_seconds<0))result=-EOVERFLOW;
        if (!result&&(captured->access_microseconds<0||captured->access_microseconds>999999||
            captured->modify_microseconds<0||captured->modify_microseconds>999999))result=-EINVAL;
        if (!result)result=user_file_submit(USER_STORAGE,request);else user_file_abort(request);
    }
    spinlock_preempt_enable();
    return result?result:user_file_finish(USER_STORAGE,SYSCALL_FILE_SET_TIMES,NULL,0,0);
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

/* Capture the vector headers and bounded payload before submitting a single
 * ordinary write. Workers see only owned bytes, preserving pipe atomicity and
 * a single append/offset gate. Larger vectors may return a short prefix. */
static int64_t user_file_writev(uint64_t fd,const void *input,uint64_t count)
{
    if(count>SYSCALL_IOV_MAX)return -EINVAL;
    spinlock_preempt_disable();
    fd_description_t *description=NULL;
    int result=user_file_pin(fd,&description);
    syscall_iovec_t *vectors=NULL;
    if(!result && count) {
        vectors=malloc((size_t)count*sizeof(*vectors));
        if(!vectors)result=-ENOMEM;
        else if(!user_copy_from_user(vectors,input,(size_t)count*sizeof(*vectors)))result=-EFAULT;
    }
    uint64_t total=0;
    for(size_t i=0;!result && i<count;++i) {
        if(vectors[i].length>(uint64_t)INT64_MAX-total)result=-EINVAL;
        else total+=vectors[i].length;
    }
    bool udp=!result && io_udp_description_valid(description);
    if(!result && udp && total>NET_UDP_MAX_PAYLOAD)result=-EMSGSIZE;
    bool tcp=!result && (io_tcp_description_valid(description) || udp);
    bool pipe=!result && io_pipe_description_valid(description);
    bool audio=!result && io_audio_description_valid(description);
    user_file_service_t kind=tcp?USER_TCP:pipe?USER_PIPE:audio?USER_AUDIO:USER_STORAGE;
    size_t header=tcp?sizeof(io_tcp_operation_t):pipe?sizeof(io_pipe_operation_t):
                  audio?sizeof(io_audio_operation_t):sizeof(io_vfs_operation_t);
    size_t bytes=total<IO_REQUEST_BUFFER_MAX-header?(size_t)total:IO_REQUEST_BUFFER_MAX-header;
    if(!result && audio && total%4)result=-EINVAL;
    io_request_t *request=NULL;
    if(!result)result=user_file_create(kind,header+(udp?((bytes+7)&~(size_t)7)+sizeof(io_udp_state_t):bytes),description,NULL,&request);
    else fd_description_put(description);
    if(!result) {
        unsigned char *data;
        if(tcp) {
            io_tcp_operation_t *work=io_request_buffer(request);
            work->opcode=IO_TCP_WRITE;work->count=bytes;data=work->data;
        } else if(pipe) {
            io_pipe_operation_t *work=io_request_buffer(request);
            work->opcode=IO_PIPE_WRITE;work->count=bytes;data=work->data;
        } else if(audio) {
            io_audio_operation_t *work=io_request_buffer(request);
            work->opcode=IO_AUDIO_WRITE;work->count=bytes;data=work->data;
        } else {
            io_vfs_operation_t *work=io_request_buffer(request);
            work->opcode=IO_VFS_WRITE;work->count=bytes;data=work->data;
        }
        size_t copied=0;
        for(size_t i=0;i<count && copied<bytes;++i) {
            size_t n=vectors[i].length<bytes-copied?(size_t)vectors[i].length:bytes-copied;
            if(n && !user_copy_from_user(data+copied,(const void *)(uintptr_t)vectors[i].base,n)) {
                result=-EFAULT;break;
            }
            copied+=n;
        }
        free(vectors);vectors=NULL;
        if(!result)result=user_file_submit(kind,request);
        else user_file_abort(request);
    }
    free(vectors);
    spinlock_preempt_enable();
    return result?result:user_file_finish(kind,SYSCALL_FILE_WRITEV,NULL,0,0);
}

/* Vector metadata is part of the registered request, after its bounded TCP
 * payload. The event worker uses only work->count payload bytes. User virtual
 * addresses in the trailer are dereferenced solely by the resumed caller. */
typedef struct
{
    uintptr_t header;
    syscall_msghdr_t message;
    syscall_iovec_t vectors[];
} user_message_metadata_t;
typedef struct
{
    syscall_msghdr_t message;
    syscall_iovec_t vectors[SYSCALL_IOV_MAX];
} user_message_prepare_t;

static int64_t user_file_message_finish(uint32_t operation, size_t metadata_offset, uint32_t flags)
{
    io_request_status_t status;
    int result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t value = result ? result : status.result;
    if (!result && value >= 0 && operation == SYSCALL_FILE_NET_RECVMSG)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        size_t size = io_request_buffer_size(request);
        if (metadata_offset > size || sizeof(user_message_metadata_t) > size - metadata_offset ||
            (uint64_t)value > work->count) value = -EIO;
        else
        {
            user_message_metadata_t *metadata = (void *)((unsigned char *)work + metadata_offset);
            uint64_t count = metadata->message.vector_count;
            if (count > SYSCALL_IOV_MAX || count >
                (size - metadata_offset - sizeof(*metadata)) / sizeof(syscall_iovec_t)) value = -EIO;
            size_t copied = 0, length = value < 0 ? 0 : (size_t)value;
            for (size_t i = 0; value >= 0 && i < count && copied < length; ++i)
            {
                size_t bytes = metadata->vectors[i].length < length - copied ?
                               (size_t)metadata->vectors[i].length : length - copied;
                if (bytes && !user_copy_to_user((void *)(uintptr_t)metadata->vectors[i].base,
                                                work->data + copied, bytes)) value = -EFAULT;
                copied += bytes;
            }
            if (value >= 0 && copied != length) value = -EIO;
            if (value >= 0)
            {
                metadata->message.name_length = 0;
                metadata->message.control_length = 0;
                metadata->message.flags = io_udp_description_valid(io_request_description(request)) &&
                    io_udp_state(request)->packet.length > (uint64_t)value ? 0x20 : 0;
                if (!user_copy_to_user((void *)(metadata->header + offsetof(syscall_msghdr_t, name_length)),
                                        &metadata->message.name_length, sizeof(metadata->message.name_length)) ||
                    !user_copy_to_user((void *)(metadata->header + offsetof(syscall_msghdr_t, control_length)),
                                        &metadata->message.control_length, sizeof(metadata->message.control_length)) ||
                    !user_copy_to_user((void *)(metadata->header + offsetof(syscall_msghdr_t, flags)),
                                        &metadata->message.flags, sizeof(metadata->message.flags))) value = -EFAULT;
            }
        }
    }
    bool broken = request && value == -EPIPE && operation == SYSCALL_FILE_NET_SENDMSG &&
                  !(flags & SYSCALL_MSG_NOSIGNAL);
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    if (broken) (void)process_signal_raise(ALIX_SIGPIPE, 0);
    return value;
}

static int64_t user_file_message(uint32_t operation, uint64_t fd, const void *header, uint32_t flags)
{
    _Static_assert(sizeof(syscall_msghdr_t) == 56, "native message header");
    bool reading = operation == SYSCALL_FILE_NET_RECVMSG;
    uint32_t known = reading ? SYSCALL_MSG_PEEK | SYSCALL_MSG_DONTWAIT :
                              SYSCALL_MSG_DONTWAIT | SYSCALL_MSG_NOSIGNAL;
    if (flags & ~known) return -EOPNOTSUPP;
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    bool udp = !result && io_udp_description_valid(description);
    if (!result && !io_tcp_description_valid(description) && !udp) result = -ENOTSOCK;
    user_message_prepare_t *prepare = NULL;
    if (!result)
    {
        prepare = calloc(1, sizeof(*prepare));
        if (!prepare) result = -ENOMEM;
        else if (!user_copy_from_user(&prepare->message, header, sizeof(prepare->message))) result = -EFAULT;
    }
    uint64_t count = prepare ? prepare->message.vector_count : 0;
    if (!result && count > SYSCALL_IOV_MAX) result = -EINVAL;
    if (!result && (prepare->message.name || (!reading && prepare->message.name_length) ||
                    (!reading && prepare->message.control_length))) result = -EOPNOTSUPP;
    if (!result && count && !user_copy_from_user(prepare->vectors,
        (const void *)(uintptr_t)prepare->message.vectors, (size_t)count * sizeof(syscall_iovec_t))) result = -EFAULT;
    uint64_t total = 0;
    for (size_t i = 0; !result && i < count; ++i)
    {
        if (prepare->vectors[i].length > (uint64_t)INT64_MAX - total) result = -EINVAL;
        else total += prepare->vectors[i].length;
    }
    size_t metadata_bytes = sizeof(user_message_metadata_t) + (size_t)(count <= SYSCALL_IOV_MAX ? count : 0) * sizeof(syscall_iovec_t);
    if (!result && udp && !reading && total > NET_UDP_MAX_PAYLOAD) result = -EMSGSIZE;
    size_t capacity = (IO_REQUEST_BUFFER_MAX - sizeof(io_tcp_operation_t) - metadata_bytes - (udp ? sizeof(io_udp_state_t) : 0)) & ~(size_t)7;
    if (udp && capacity > NET_UDP_MAX_PAYLOAD) capacity = NET_UDP_MAX_PAYLOAD;
    size_t bytes = total < capacity ? (size_t)total : capacity;
    size_t metadata_offset = sizeof(io_tcp_operation_t) + ((bytes + 7) & ~(size_t)7);
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_TCP, metadata_offset + metadata_bytes + (udp ? sizeof(io_udp_state_t) : 0), description, NULL, &request);
    else fd_description_put(description);
    if (!result)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        work->opcode = reading ? IO_TCP_READ : IO_TCP_WRITE;
        work->count = bytes; work->flags = flags;
        user_message_metadata_t *metadata = (void *)((unsigned char *)work + metadata_offset);
        metadata->header = (uintptr_t)header;
        metadata->message = prepare->message;
        if (count) memcpy(metadata->vectors, prepare->vectors, (size_t)count * sizeof(syscall_iovec_t));
        size_t copied = 0;
        for (size_t i = 0; !reading && i < count && copied < bytes; ++i)
        {
            size_t length = prepare->vectors[i].length < bytes - copied ?
                            (size_t)prepare->vectors[i].length : bytes - copied;
            if (length && !user_copy_from_user(work->data + copied,
                (const void *)(uintptr_t)prepare->vectors[i].base, length)) { result = -EFAULT; break; }
            copied += length;
        }
        free(prepare); prepare = NULL;
        if (!result) result = user_file_submit(USER_TCP, request);
        else user_file_abort(request);
    }
    free(prepare);
    spinlock_preempt_enable();
    return result ? result : user_file_message_finish(operation, metadata_offset, flags);
}

static int64_t user_file_data(uint32_t operation, uint64_t fd, void *buffer, size_t count,
                              int64_t offset, int whence, uint32_t message_flags)
{
    bool socket_operation = operation == SYSCALL_FILE_NET_RECV || operation == SYSCALL_FILE_NET_SEND;
    bool reading = operation == SYSCALL_FILE_READ || operation == SYSCALL_FILE_NET_RECV;
    bool writing = operation == SYSCALL_FILE_WRITE || operation == SYSCALL_FILE_NET_SEND;
    uint32_t known = reading ? SYSCALL_MSG_PEEK | SYSCALL_MSG_DONTWAIT | 0x20u : SYSCALL_MSG_DONTWAIT | SYSCALL_MSG_NOSIGNAL;
    if (message_flags & ~known) return -EOPNOTSUPP;
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    bool udp = !result && io_udp_description_valid(description) && (reading || writing || operation == SYSCALL_FILE_SOCKET_AVAILABLE);
    if (!result && !udp && (message_flags & 0x20u)) result = -EOPNOTSUPP;
    if (!result && udp && writing && count > NET_UDP_MAX_PAYLOAD) result = -EMSGSIZE;
    bool tcp = !result && (io_tcp_description_valid(description) || udp) &&
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
    if (udp) capacity = NET_UDP_MAX_PAYLOAD;
    if (count > capacity) count = capacity;
    size_t bytes = reading || writing || operation == SYSCALL_FILE_PREAD ||
                   operation == SYSCALL_FILE_AUDIO_WRITE || operation == SYSCALL_FILE_AUDIO_STATUS ? count : 0;
    if (!result && operation == SYSCALL_FILE_SOCKET_AVAILABLE && !tcp) result = -ENOTSOCK;
    if (!result && bytes && (!buffer || !user_ptr_range_valid(buffer, bytes))) result = -EFAULT;
    if (!result && operation == SYSCALL_FILE_STAT &&
        (!buffer || !user_ptr_range_valid(buffer, sizeof(syscall_stat_t)))) result = -EFAULT;
    io_request_t *request = NULL;
    if (!result) result = user_file_create(kind, header + (udp ? ((bytes + 7) & ~(size_t)7) + sizeof(io_udp_state_t) : bytes), description, NULL, &request);
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

static int64_t user_udp_open(uint32_t status_flags, uint32_t slot_flags)
{
    spinlock_preempt_disable();
    fd_description_t *reservation = NULL;
    int result = fd_table_reserve_deferred(process_current_fd_table(), &reservation);
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_TCP, sizeof(io_tcp_operation_t) + sizeof(io_udp_state_t), reservation, NULL, &request);
    if (!result)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        work->opcode = IO_UDP_OPEN; work->flags = status_flags;
        result = user_file_submit(USER_TCP, request);
    }
    spinlock_preempt_enable();
    return result ? result : user_file_finish(USER_TCP, SYSCALL_FILE_SOCKET_OPEN, NULL, 0, slot_flags);
}

typedef struct
{
    syscall_udp_request_t arguments;
    syscall_sockaddr_in_t endpoint;
    uint32_t address_capacity, reserved;
} user_udp_metadata_t;

static int64_t user_udp_datagram_finish(bool reading)
{
    io_request_status_t status;
    int result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t value = result ? result : status.result;
    if (!result && value >= 0 && reading)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        io_udp_state_t *state = io_udp_state(request);
        size_t size = io_request_buffer_size(request);
        if (!state || size < sizeof(*work) + sizeof(*state) + sizeof(user_udp_metadata_t) || (uint64_t)value > work->count)
            value = -EIO;
        else
        {
            user_udp_metadata_t *metadata = (void *)((unsigned char *)state - sizeof(*metadata));
            syscall_udp_request_t *args = &metadata->arguments;
            if (value && !user_copy_to_user((void *)(uintptr_t)args->data, work->data, (size_t)value)) value = -EFAULT;
            if (value >= 0 && args->address)
            {
                metadata->endpoint = (syscall_sockaddr_in_t){ .family = SYSCALL_AF_INET,
                    .address_be = __builtin_bswap32(state->packet.source_ip),
                    .port_be = __builtin_bswap16(state->packet.source_port) };
                uint32_t copied = metadata->address_capacity < sizeof(metadata->endpoint) ? metadata->address_capacity : sizeof(metadata->endpoint);
                metadata->address_capacity = sizeof(metadata->endpoint);
                if ((copied && !user_copy_to_user((void *)(uintptr_t)args->address, &metadata->endpoint, copied)) ||
                    !user_copy_to_user((void *)(uintptr_t)args->address_length_pointer, &metadata->address_capacity, sizeof(uint32_t))) value = -EFAULT;
            }
            if (value >= 0 && args->packet_info)
            {
                state->packet_wire = (alix_udp_packet_info_t){ .version = 1, .source_ipv4 = state->packet.source_ip,
                    .destination_ipv4 = state->packet.destination_ip, .source_port = state->packet.source_port,
                    .length = state->packet.length, .interface_index = state->packet.interface_index,
                    .tos = state->packet.tos, .ttl = state->packet.ttl };
                if (!user_copy_to_user((void *)(uintptr_t)args->packet_info, &state->packet_wire, sizeof(state->packet_wire))) value = -EFAULT;
            }
            if (value >= 0 && (args->flags & 0x20u)) value = state->packet.length;
        }
    }
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    return value;
}

static int64_t user_udp_datagram(uint64_t fd, bool reading, const void *input)
{
    _Static_assert(sizeof(syscall_udp_request_t) == 64 && sizeof(alix_udp_packet_info_t) == 24, "native datagram ABI");
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    if (!result && !io_udp_description_valid(description)) result = io_tcp_description_valid(description) ? -EOPNOTSUPP : -ENOTSOCK;
    user_udp_metadata_t *prepare = NULL;
    if (!result)
    {
        prepare = calloc(1, sizeof(*prepare));
        if (!prepare) result = -ENOMEM;
        else if (!user_copy_from_user(&prepare->arguments, input, sizeof(prepare->arguments))) result = -EFAULT;
    }
    uint32_t known = reading ? SYSCALL_MSG_PEEK | SYSCALL_MSG_DONTWAIT | 0x20u : SYSCALL_MSG_DONTWAIT | SYSCALL_MSG_NOSIGNAL;
    if (!result && (prepare->arguments.reserved || prepare->arguments.flags & ~known)) result = -EOPNOTSUPP;
    if (!result && (prepare->arguments.tos < -1 || prepare->arguments.tos > 255)) result = -EINVAL;
    if (!result && !reading && prepare->arguments.length > NET_UDP_MAX_PAYLOAD) result = -EMSGSIZE;
    size_t count = prepare && prepare->arguments.length < NET_UDP_MAX_PAYLOAD ? (size_t)prepare->arguments.length : NET_UDP_MAX_PAYLOAD;
    if (!result && count && (!prepare->arguments.data || !user_ptr_range_valid((void *)(uintptr_t)prepare->arguments.data, count))) result = -EFAULT;
    if (!result && !reading && prepare->arguments.address)
    {
        if (prepare->arguments.address_length < sizeof(prepare->endpoint)) result = -EINVAL;
        else if (!user_copy_from_user(&prepare->endpoint, (const void *)(uintptr_t)prepare->arguments.address, sizeof(prepare->endpoint))) result = -EFAULT;
        else if (prepare->endpoint.family != SYSCALL_AF_INET) result = -EAFNOSUPPORT;
    }
    if (!result && reading && prepare->arguments.address &&
        !user_copy_from_user(&prepare->address_capacity, (const void *)(uintptr_t)prepare->arguments.address_length_pointer, sizeof(uint32_t))) result = -EFAULT;
    if (!result && reading && prepare->arguments.packet_info &&
        !user_ptr_range_valid((const void *)(uintptr_t)prepare->arguments.packet_info, sizeof(alix_udp_packet_info_t))) result = -EFAULT;
    size_t payload = (count + 7) & ~(size_t)7;
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_TCP, sizeof(io_tcp_operation_t) + payload + sizeof(*prepare) + sizeof(io_udp_state_t), description, NULL, &request);
    else fd_description_put(description);
    if (!result)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        user_udp_metadata_t *metadata = (void *)(work->data + payload);
        *metadata = *prepare;
        work->opcode = reading ? IO_TCP_READ : IO_TCP_WRITE;
        work->count = count; work->flags = prepare->arguments.flags;
        if (!reading)
        {
            work->ipv4 = __builtin_bswap32(prepare->endpoint.address_be);
            work->port = __builtin_bswap16(prepare->endpoint.port_be);
            work->interface_index = prepare->arguments.source_ipv4;
            work->padding = (uint32_t)(prepare->arguments.tos + 1);
            if (count && !user_copy_from_user(work->data, (const void *)(uintptr_t)prepare->arguments.data, count)) result = -EFAULT;
        }
        free(prepare); prepare = NULL;
        if (!result) result = user_file_submit(USER_TCP, request);
        else user_file_abort(request);
    }
    free(prepare);
    spinlock_preempt_enable();
    return result ? result : user_udp_datagram_finish(reading);
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

static int64_t user_socket_connect_address(uint64_t fd, const void *address, uint64_t length, bool binding)
{
    if (!binding && length < sizeof(syscall_sockaddr_in_t)) return -EINVAL;
    spinlock_preempt_disable();
    fd_description_t *description = NULL;
    int result = user_file_pin(fd, &description);
    bool udp = !result && io_udp_description_valid(description);
    if (!result && !io_tcp_description_valid(description) && !udp) result = -ENOTSOCK;
    if (!result && binding && !udp) result = -EOPNOTSUPP;
    if (!result && length < sizeof(syscall_sockaddr_in_t)) result = -EINVAL;
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_TCP, sizeof(io_tcp_operation_t) + sizeof(syscall_sockaddr_in_t) + (udp ? sizeof(io_udp_state_t) : 0),
                                           description, NULL, &request);
    else fd_description_put(description);
    if (!result)
    {
        io_tcp_operation_t *work = io_request_buffer(request);
        syscall_sockaddr_in_t *endpoint = (void *)work->data;
        if (!user_copy_from_user(endpoint, address, sizeof(*endpoint))) result = -EFAULT;
        else if (udp && !binding && endpoint->family == 0) work->opcode = IO_TCP_CONNECT;
        else if (endpoint->family != SYSCALL_AF_INET) result = -EAFNOSUPPORT;
        else
        {
            work->opcode = binding ? IO_UDP_BIND : IO_TCP_CONNECT;
            work->ipv4 = __builtin_bswap32(endpoint->address_be);
            work->port = __builtin_bswap16(endpoint->port_be);
            if (!binding && (!work->ipv4 || !work->port)) result = -EINVAL;
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
        else value = io_udp_description_valid(io_request_description(request)) ? 0 : io_tcp_query_commit(io_request_description(request));
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
    bool udp = !result && io_udp_description_valid(description);
    if (!result && udp) query = description;
    else if (!result) result = io_tcp_query_create(description, process_fd_retirement_queue(), &query);
    else fd_description_put(description);
    io_request_t *request = NULL;
    if (!result) result = user_file_create(USER_TCP, sizeof(io_tcp_operation_t) + sizeof(io_tcp_query_reply_t) + (udp ? sizeof(io_udp_state_t) : 0),
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

int64_t io_user_file_map(uintptr_t address, size_t length, uint32_t protection,
                         uint32_t flags, int fd, int64_t offset)
{
    size_t rounded=0;
    int result=process_vm_file_check(address,length,protection,flags,offset,&rounded);
    if (result) return result;
    spinlock_preempt_disable();
    thread_t *thread=current_thread_local();
    fd_description_t *description=NULL;
    if (!thread || thread->vm_file_prepare) result=-EBUSY;
    else result=user_file_pin((uint64_t)(int64_t)fd,&description);
    if (!result && !io_vfs_description_valid(description)) result=-ENODEV;
    io_request_t *request=NULL;
    if (!result) result=user_file_create(USER_STORAGE,sizeof(io_vfs_operation_t),description,NULL,&request);
    else fd_description_put(description);
    if (!result) {
        io_vfs_operation_t *work=io_request_buffer(request);
        work->opcode=IO_VFS_MAP;work->flags=flags;work->whence=(int32_t)protection;
        work->count=rounded;work->offset=offset;
        result=user_file_submit(USER_STORAGE,request);
    }
    spinlock_preempt_enable();
    if (result) return result;
    io_request_status_t status;
    result=process_io_wait_current(&status);
    spinlock_preempt_disable();
    request=NULL;
    if (!result) result=process_io_result_current(&request,&status);
    if (!result) result=(int)status.result;
    if (!result) result=io_request_take_result(request,&thread->vm_file_prepare);
    (void)process_io_finish_current(result!=0);
    spinlock_preempt_enable();
    if (result) return result;
    /* This reference is in heap-owned thread cleanup before any VM/TLB wait. */
    int64_t value=process_vm_map_file(current_process_local(),address,length,protection,flags,thread->vm_file_prepare);
    spinlock_preempt_disable();
    description=thread->vm_file_prepare;thread->vm_file_prepare=NULL;
    fd_description_put(description);
    spinlock_preempt_enable();
    return value;
}

int io_user_file_msync(uintptr_t address,size_t length,uint32_t flags)
{
    spinlock_preempt_disable();
    fd_description_t *bundle=NULL;
    int result=process_vm_sync_prepare(current_process_local(),address,length,flags,&bundle);
    io_request_t *request=NULL;
    if (!result) result=user_file_create(USER_STORAGE,sizeof(io_vfs_operation_t),bundle,NULL,&request);
    if (!result) {
        ((io_vfs_operation_t *)io_request_buffer(request))->opcode=IO_VFS_SYNC_MAPPINGS;
        result=user_file_submit(USER_STORAGE,request);
    }
    spinlock_preempt_enable();
    return result?result:(int)user_file_finish(USER_STORAGE,SYSCALL_FILE_SYNC,NULL,0,0);
}

int64_t io_user_file_dispatch(uint32_t operation, uint64_t first, uint64_t second,
                               uint64_t third, uint64_t fourth)
{
    switch (operation)
    {
        case SYSCALL_FILE_WRITEV:
            if(fourth)return -EINVAL;
            return user_file_writev(first,(const void *)second,third);
        case SYSCALL_FILE_OPEN: return user_file_open((const char *)first, second, false, 0666u);
        case SYSCALL_FILE_OPEN_MODE:
            if (fourth) return -EINVAL;
            return user_file_open((const char *)first, second, false, third);
        case SYSCALL_FILE_SHM_OPEN:
            if (fourth) return -EINVAL;
            return user_file_open((const char *)first, second, true, third);
        case SYSCALL_FILE_SHM_UNLINK:
            if (second || third || fourth) return -EINVAL;
            return user_file_shm_unlink((const char *)first);
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
            return user_path_mutation(operation, (const char *)first, NULL, 0, 0777u);
        case SYSCALL_FILE_MKDIR_MODE:
            if (third || fourth) return -EINVAL;
            return user_path_mutation(operation, (const char *)first, NULL, 0, second);
        case SYSCALL_FILE_CHMOD_PATH:
            if (third || fourth) return -EINVAL;
            return user_path_mutation(operation, (const char *)first, NULL, 0, second);
        case SYSCALL_FILE_SOCKET_OPEN: return user_socket_open((const char *)first, 0, 0);
        case SYSCALL_FILE_NET_OPEN:
            if (fourth) return -EINVAL;
            if (first != SYSCALL_AF_INET) return -EAFNOSUPPORT;
            if (second & ~(UINT64_C(15) | SYSCALL_OPEN_NONBLOCK | SYSCALL_OPEN_CLOEXEC)) return -EINVAL;
            if ((second & 15u) == 2 && (!third || third == 17))
                return user_udp_open((uint32_t)second & SYSCALL_OPEN_NONBLOCK,
                                     second & SYSCALL_OPEN_CLOEXEC ? FD_TABLE_CLOEXEC : 0);
            if ((second & 15u) != SYSCALL_SOCK_STREAM || (third && third != SYSCALL_IPPROTO_TCP)) return -EPROTONOSUPPORT;
            return user_socket_open(NULL, (uint32_t)second & SYSCALL_OPEN_NONBLOCK,
                                      second & SYSCALL_OPEN_CLOEXEC ? FD_TABLE_CLOEXEC : 0);
        case SYSCALL_FILE_NET_BIND:
            if (fourth) return -EINVAL;
            return user_socket_connect_address(first, (const void *)second, third, true);
        case SYSCALL_FILE_DATAGRAM:
            if (fourth || second > 1) return -EINVAL;
            return user_udp_datagram(first, second != 0, (const void *)third);
        case SYSCALL_FILE_NET_CONNECT:
            if (fourth) return -EINVAL;
            return user_socket_connect_address(first, (const void *)second, third, false);
        case SYSCALL_FILE_NET_SENDMSG: case SYSCALL_FILE_NET_RECVMSG:
            if (fourth || third > UINT32_MAX) return -EINVAL;
            return user_file_message(operation, first, (const void *)second, (uint32_t)third);
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
        case SYSCALL_FILE_STAT_INFO:
            if (third || fourth) return -EINVAL;
            return user_file_stat_info(first, (void *)second);
        case SYSCALL_FILE_CHOWN:
            if (second > UINT32_MAX || third > UINT32_MAX || fourth) return -EINVAL;
            return user_file_metadata(operation, first, (uint32_t)second, (uint32_t)third);
        case SYSCALL_FILE_CHMOD:
            if (second > UINT32_MAX || third || fourth) return -EINVAL;
            return user_file_metadata(operation, first, (uint32_t)second, 0);
        case SYSCALL_FILE_PATH_INFO:
            if (fourth) return -EINVAL;
            return user_path_operation(operation, (const char *)first, (void *)second, third);
        case SYSCALL_FILE_STAT_PATH: return user_path_operation(operation, (const char *)first, (void *)second, third);
        case SYSCALL_FILE_CHDIR: return user_path_operation(operation, (const char *)first, NULL, 0);
        case SYSCALL_FILE_GETCWD: return user_getcwd((void *)first, second);
        case SYSCALL_FILE_FLOCK:
            if (second > UINT32_MAX || third || fourth) return -EINVAL;
            return user_file_flock(first, (uint32_t)second);
        case SYSCALL_FILE_RECORD_LOCK:
            if (second > UINT32_MAX || fourth) return -EINVAL;
            return user_file_record_lock(first, (uint32_t)second, (const void *)third);
        case SYSCALL_FILE_SET_TIMES:
            if (third || fourth) return -EINVAL;
            return user_file_set_times((const char *)first, (const void *)second);
        case SYSCALL_FILE_IOCTL:
            return user_file_ioctl(first, second, (void *)third, fourth);
        case SYSCALL_FILE_SYSTEM_INFO: case SYSCALL_FILE_HOSTNAME:
            if (third || fourth) return -EINVAL;
            return user_system_info(operation, (void *)first, second);
        case SYSCALL_FILE_GET_LIMIT: case SYSCALL_FILE_SET_LIMIT:
            if (fourth) return -EINVAL;
            return user_resource_limit(operation == SYSCALL_FILE_SET_LIMIT, first, (void *)second, third);
        case SYSCALL_FILE_REMOVE: case SYSCALL_FILE_RENAME:
            return user_path_mutation(operation, (const char *)first, (const char *)second, third, 0);
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
            result = second <= INT32_MAX && third <= UINT32_MAX && fourth <= SYSCALL_DUP_CHECK_MINIMUM ?
                (fourth ? fd_table_dup_minimum(table, (int)first, (int)second, (uint32_t)third) :
                          fd_table_dup(table, (int)first, (int)second, (uint32_t)third)) : -EINVAL;
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
