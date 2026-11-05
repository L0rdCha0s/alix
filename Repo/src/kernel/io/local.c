#include "io_local.h"
#include "io_event_service.h"
#include "spinlock.h"
#include "heap.h"
#include "libc.h"
#include "errno.h"

#define LOCAL_CAPACITY 65536u
#define LOCAL_RECORDS 128u
#define LOCAL_PEEK SYSCALL_MSG_PEEK
#define LOCAL_CTRUNC 8u
#define LOCAL_DONTWAIT SYSCALL_MSG_DONTWAIT

typedef struct local_rights
{
    struct local_rights *next;
    uint64_t position;
    size_t count;
    fd_description_t *descriptions[IO_LOCAL_RIGHTS_MAX];
} local_rights_t;
typedef struct
{
    size_t head, used, records;
    uint64_t received, sent;
    local_rights_t *first, *last;
    unsigned char data[LOCAL_CAPACITY];
} local_lane_t;
typedef struct
{
    spinlock_t lock;
    bool active[2], read_closed[2], write_closed[2];
    local_lane_t lanes[2];
} local_pair_t;
typedef struct { local_pair_t *pair; unsigned side; } local_endpoint_t;
struct io_local_control
{
    local_rights_t *rights;
    fd_table_t *table;
    size_t installed, output_bytes;
    int slots[IO_LOCAL_RIGHTS_MAX];
    uint32_t output_flags;
    unsigned char output[IO_LOCAL_CONTROL_BYTES];
};
typedef struct { uint64_t length; int32_t level, type; } local_cmsg_t;

static void local_rights_release(local_rights_t *rights)
{
    while (rights)
    {
        local_rights_t *next = rights->next;
        for (size_t i = 0; i < rights->count; ++i) fd_description_put(rights->descriptions[i]);
        free(rights);
        rights = next;
    }
}
static local_rights_t *local_discard_lane(local_lane_t *lane)
{
    local_rights_t *rights = lane->first;
    lane->head = lane->used = lane->records = 0;
    lane->first = lane->last = NULL;
    lane->received = lane->sent;
    return rights;
}
static int local_close(void *context)
{
    local_endpoint_t *endpoint = context;
    local_pair_t *pair = endpoint->pair;
    unsigned side = endpoint->side;
    spinlock_lock(&pair->lock);
    pair->active[side] = false;
    pair->read_closed[side] = pair->write_closed[side] = true;
    local_rights_t *discard = local_discard_lane(&pair->lanes[side]);
    bool last = !pair->active[side ^ 1];
    spinlock_unlock(&pair->lock);
    io_event_service_notify();
    local_rights_release(discard);
    free(endpoint);
    if (last) free(pair);
    return 0;
}
static uint32_t local_poll(void *context)
{
    local_endpoint_t *endpoint = context;
    local_pair_t *pair = endpoint->pair;
    unsigned side = endpoint->side, peer = side ^ 1;
    spinlock_lock(&pair->lock);
    uint32_t flags = 0;
    if (pair->lanes[side].used || pair->read_closed[side] || pair->write_closed[peer]) flags |= SYSCALL_POLL_IN;
    if (pair->write_closed[side] || pair->read_closed[peer]) flags |= SYSCALL_POLL_OUT | SYSCALL_POLL_ERR;
    else if (pair->lanes[peer].used < LOCAL_CAPACITY) flags |= SYSCALL_POLL_OUT;
    if (!pair->active[peer] || (pair->write_closed[peer] && pair->write_closed[side])) flags |= SYSCALL_POLL_HUP;
    spinlock_unlock(&pair->lock);
    return flags;
}
static const fd_ops_t local_ops = {.close = local_close, .poll = local_poll};
bool io_local_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == local_close;
}
int io_local_create_pair(fd_retirement_queue_t *retirement, uint32_t flags,
                          fd_description_t **first, fd_description_t **second)
{
    *first = *second = NULL;
    local_pair_t *pair = calloc(1, sizeof(*pair));
    local_endpoint_t *a = pair ? malloc(sizeof(*a)) : NULL;
    local_endpoint_t *b = a ? malloc(sizeof(*b)) : NULL;
    if (!b) { free(a); free(pair); return -ENOMEM; }
    spinlock_init(&pair->lock);
    pair->active[0] = pair->active[1] = true;
    *a = (local_endpoint_t){pair, 0}; *b = (local_endpoint_t){pair, 1};
    fd_description_t *left = fd_description_create_deferred(&local_ops, a, retirement);
    if (!left) { free(a); free(b); free(pair); return -ENOMEM; }
    fd_description_t *right = fd_description_create_deferred(&local_ops, b, retirement);
    if (!right) { pair->active[1] = false; free(b); fd_description_put(left); return -ENOMEM; }
    (void)fd_description_initialize_status(left, FD_STATUS_READ | FD_STATUS_WRITE | flags);
    (void)fd_description_initialize_status(right, FD_STATUS_READ | FD_STATUS_WRITE | flags);
    *first = left; *second = right;
    return 0;
}
int io_local_shutdown(fd_description_t *description, unsigned direction)
{
    if (!io_local_description_valid(description)) return -ENOTSOCK;
    if (direction > 2) return -EINVAL;
    local_endpoint_t *endpoint = fd_description_context(description);
    local_pair_t *pair = endpoint->pair;
    local_rights_t *discard = NULL;
    spinlock_lock(&pair->lock);
    if (direction != 1)
    {
        pair->read_closed[endpoint->side] = true;
        discard = local_discard_lane(&pair->lanes[endpoint->side]);
    }
    if (direction != 0) pair->write_closed[endpoint->side] = true;
    spinlock_unlock(&pair->lock);
    io_event_service_notify();
    local_rights_release(discard);
    return 0;
}
static int local_control_close(void *context)
{
    io_local_control_t *control = context;
    for (size_t i = 0; i < control->installed; ++i)
        (void)fd_table_close_if(control->table, control->slots[i], control->rights->descriptions[i]);
    fd_table_put(control->table);
    local_rights_release(control->rights);
    free(control);
    return 0;
}
static const fd_ops_t local_control_ops = {.close = local_control_close};
int io_local_control_create(fd_retirement_queue_t *retirement, fd_description_t **owner)
{
    *owner = NULL;
    io_local_control_t *control = calloc(1, sizeof(*control));
    local_rights_t *rights = control ? calloc(1, sizeof(*rights)) : NULL;
    if (!rights) { free(control); return -ENOMEM; }
    control->rights = rights;
    *owner = fd_description_create_deferred(&local_control_ops, control, retirement);
    if (!*owner) { free(rights); free(control); return -ENOMEM; }
    return 0;
}
int io_local_control_capture(io_local_control_t *control, fd_table_t *table, const void *data, size_t bytes)
{
    if (!control || !control->rights || control->rights->count) return -EINVAL;
    size_t position = 0;
    while (position < bytes)
    {
        if (bytes - position < sizeof(local_cmsg_t)) return -EINVAL;
        local_cmsg_t header;
        memcpy(&header, (const char *)data + position, sizeof(header));
        if (header.length < sizeof(header) || header.length > bytes - position ||
            header.level != SYSCALL_SOL_SOCKET || header.type != 1 ||
            (header.length - sizeof(header)) % sizeof(int32_t)) return -EINVAL;
        size_t count = (header.length - sizeof(header)) / sizeof(int32_t);
        local_rights_t *rights = control->rights;
        if (count > IO_LOCAL_RIGHTS_MAX - rights->count) return -EMSGSIZE;
        for (size_t i = 0; i < count; ++i)
        {
            int32_t fd;
            memcpy(&fd, (const char *)data + position + sizeof(header) + i * sizeof(fd), sizeof(fd));
            int error = fd_table_pin(table, fd, &rights->descriptions[rights->count], NULL);
            if (error) return error;
            ++rights->count;
        }
        size_t step = (header.length + 7) & ~(size_t)7;
        if (step > bytes - position) break;
        position += step;
    }
    return 0;
}
int io_local_control_install(io_local_control_t *control, fd_table_t *table, size_t capacity, bool cloexec)
{
    if (!control || control->table) return -EINVAL;
    local_rights_t *rights = control->rights;
    if (!rights || !rights->count) return 0;
    if (!fd_table_get(table)) return -EOVERFLOW;
    control->table = table;
    size_t count = capacity >= sizeof(local_cmsg_t) ? (capacity - sizeof(local_cmsg_t)) / sizeof(int32_t) : 0;
    if (count > rights->count) count = rights->count;
    for (size_t i = 0; i < count; ++i)
    {
        int fd = fd_table_install(table, rights->descriptions[i], 0, cloexec ? FD_TABLE_CLOEXEC : 0);
        if (fd < 0) break;
        control->slots[control->installed++] = fd;
    }
    if (control->installed < rights->count) control->output_flags |= LOCAL_CTRUNC;
    if (control->installed)
    {
        local_cmsg_t header = {sizeof(header) + control->installed * sizeof(int32_t), SYSCALL_SOL_SOCKET, 1};
        memcpy(control->output, &header, sizeof(header));
        memcpy(control->output + sizeof(header), control->slots, control->installed * sizeof(int32_t));
        control->output_bytes = (header.length + 7) & ~(size_t)7;
        if (control->output_bytes > capacity) control->output_bytes = header.length;
    }
    return 0;
}
const void *io_local_control_output(io_local_control_t *control, size_t *bytes, uint32_t *flags)
{
    *bytes = control->output_bytes; *flags = control->output_flags;
    return control->output;
}
void io_local_control_commit(io_local_control_t *control) { control->installed = 0; }

static bool local_query(local_endpoint_t *endpoint, io_tcp_operation_t *operation, io_service_result_t *result)
{
    io_tcp_query_reply_t *reply = (void *)operation->data;
    result->result = 0;
    if (operation->opcode == IO_TCP_GETNAME)
    {
        memset(&reply->address, 0, sizeof(reply->address));
        reply->address.family = 1; reply->length = sizeof(uint16_t);
        return true;
    }
    if (operation->ipv4 != SYSCALL_SOL_SOCKET) { result->result = -ENOPROTOOPT; return true; }
    bool setting = operation->opcode == IO_TCP_SETOPT;
    int value = 0;
    switch (operation->port)
    {
        case SYSCALL_SO_TYPE: value = SYSCALL_SOCK_STREAM; break;
        case SYSCALL_SO_DOMAIN: value = 1; break;
        case SYSCALL_SO_PROTOCOL: case SYSCALL_SO_ERROR: case SYSCALL_SO_ACCEPTCONN: value = 0; break;
        case SYSCALL_SO_SNDBUF: case SYSCALL_SO_RCVBUF:
            if (setting && reply->value <= 0) result->result = -EINVAL;
            reply->length = sizeof(reply->value); reply->value = LOCAL_CAPACITY;
            return true;
        case SYSCALL_SO_KEEPALIVE: case SYSCALL_SO_REUSEADDR:
            if (setting && reply->value) result->result = -EOPNOTSUPP;
            reply->length = sizeof(reply->value); reply->value = 0;
            return true;
        default: result->result = -ENOPROTOOPT; return true;
    }
    if (setting) result->result = -ENOPROTOOPT;
    reply->length = sizeof(reply->value); reply->value = value;
    (void)endpoint;
    return true;
}
bool io_local_execute(io_request_t *request, io_service_result_t *result)
{
    result->result = -EINVAL; result->description_owned = NULL;
    if (io_request_buffer_size(request) < sizeof(io_tcp_operation_t)) return true;
    fd_description_t *description = io_request_description(request);
    if (!io_local_description_valid(description)) { result->result = -ENOTSOCK; return true; }
    io_tcp_operation_t *operation = io_request_buffer(request);
    local_endpoint_t *endpoint = fd_description_context(description);
    if (operation->opcode == IO_TCP_GETOPT || operation->opcode == IO_TCP_SETOPT || operation->opcode == IO_TCP_GETNAME)
    {
        if (io_request_buffer_size(request) < sizeof(*operation) + sizeof(io_tcp_query_reply_t)) return true;
        return local_query(endpoint, operation, result);
    }
    local_pair_t *pair = endpoint->pair;
    unsigned side = endpoint->side, peer = side ^ 1;
    bool writing = operation->opcode == IO_TCP_WRITE;
    if (operation->opcode != IO_TCP_READ && !writing && operation->opcode != IO_TCP_AVAILABLE) return true;
    if (operation->count > io_request_buffer_size(request) - sizeof(*operation)) return true;
    io_local_control_t *control = io_request_cwd(request);
    local_rights_t *discard = NULL;
    bool complete = true;
    bool readiness_changed = false;
    spinlock_lock(&pair->lock);
    local_lane_t *lane = &pair->lanes[writing ? peer : side];
    size_t bytes = operation->count;
    if (operation->opcode == IO_TCP_AVAILABLE) result->result = (int64_t)lane->used;
    else if (!bytes) result->result = 0;
    else if (writing)
    {
        bool rights = control && control->rights && control->rights->count;
        if (pair->write_closed[side] || pair->read_closed[peer]) result->result = -EPIPE;
        else if (lane->used == LOCAL_CAPACITY || (rights && lane->records == LOCAL_RECORDS)) complete = false;
        else if (bytes > UINT64_MAX - lane->sent) result->result = -EOVERFLOW;
        else
        {
            if (bytes > LOCAL_CAPACITY - lane->used) bytes = LOCAL_CAPACITY - lane->used;
            if (rights)
            {
                local_rights_t *record = control->rights;
                record->position = lane->sent;
                if (lane->last) lane->last->next = record; else lane->first = record;
                lane->last = record; ++lane->records;
                control->rights = NULL;
            }
            size_t tail = (lane->head + lane->used) % LOCAL_CAPACITY;
            size_t first = bytes < LOCAL_CAPACITY - tail ? bytes : LOCAL_CAPACITY - tail;
            readiness_changed = lane->used == 0;
            memcpy(lane->data + tail, operation->data, first);
            memcpy(lane->data, operation->data + first, bytes - first);
            lane->used += bytes; lane->sent += bytes;
            result->result = (int64_t)bytes;
        }
    }
    else if (pair->read_closed[side]) result->result = 0;
    else if (!lane->used)
    {
        if (pair->write_closed[peer]) result->result = 0;
        else complete = false;
    }
    else
    {
        if (bytes > lane->used) bytes = lane->used;
        local_rights_t *record = lane->first;
        if (record && record->position > lane->received && record->position - lane->received < bytes)
            bytes = (size_t)(record->position - lane->received);
        else if (record && record->position == lane->received && record->next &&
                 record->next->position - lane->received < bytes)
            bytes = (size_t)(record->next->position - lane->received);
        size_t first = bytes < LOCAL_CAPACITY - lane->head ? bytes : LOCAL_CAPACITY - lane->head;
        memcpy(operation->data, lane->data + lane->head, first);
        memcpy(operation->data + first, lane->data, bytes - first);
        if (record && record->position == lane->received && control)
        {
            if (operation->flags & LOCAL_PEEK)
            {
                for (size_t i = 0; i < record->count; ++i)
                {
                    if (!fd_description_get(record->descriptions[i])) { result->result = -EOVERFLOW; goto unlocked; }
                    control->rights->descriptions[control->rights->count++] = record->descriptions[i];
                }
            }
            else
            {
                discard = control->rights; control->rights = record;
            }
        }
        if (!(operation->flags & LOCAL_PEEK))
        {
            readiness_changed = lane->used == LOCAL_CAPACITY || lane->records == LOCAL_RECORDS;
            if (record && record->position == lane->received)
            {
                lane->first = record->next; if (!lane->first) lane->last = NULL;
                record->next = NULL; --lane->records;
                if (!control) discard = record;
            }
            lane->head = (lane->head + bytes) % LOCAL_CAPACITY;
            lane->used -= bytes; lane->received += bytes;
            if (!lane->used && !lane->first) lane->sent = lane->received = 0;
        }
        result->result = (int64_t)bytes;
    }
unlocked:
    spinlock_unlock(&pair->lock);
    if (readiness_changed) io_event_service_notify();
    local_rights_release(discard);
    if (!complete && ((fd_description_status_flags(description) & FD_STATUS_NONBLOCK) || (operation->flags & LOCAL_DONTWAIT)))
    { result->result = -EAGAIN; complete = true; }
    return complete;
}
