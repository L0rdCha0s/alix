#include "io_record_lock.h"
#include "io_vfs.h"
#include "heap.h"
#include "spinlock.h"
#include "errno.h"
#include <stdint.h>

#define RECORD_MAX 4096u
typedef struct record {
    struct record *next;
    fd_description_t *target;
    const void *key;
    fd_table_t *owner; /* weak: shutdown observer removes records before free */
    int64_t start, end;
    int32_t pid;
    int16_t type;
} record_t;
typedef struct record_lease {
    struct record_lease *next;
    fd_description_t *target;
    fd_table_t *owner; /* strong while preparing/waiting, never held by records */
    const void *key;
    syscall_record_lock_t query, reply;
    record_t *fresh, *split;
    int64_t start, end, base;
    int32_t pid;
    uint32_t command;
    int16_t type;
    bool linked, revoked, resolved, granted, reserved;
} record_lease_t;
static spinlock_t record_gate;
static record_t *held_records, *retired_records;
static record_lease_t *record_leases;
static size_t record_allocated;

static void record_retire_locked(record_t *record)
{
    record->next = retired_records; retired_records = record;
}
static void record_free(record_t *record)
{
    if (!record) return;
    fd_description_put(record->target);
    free(record);
    spinlock_lock(&record_gate); --record_allocated; spinlock_unlock(&record_gate);
}
size_t io_record_lock_drain(size_t budget)
{
    size_t count = 0;
    while (count < budget)
    {
        spinlock_lock(&record_gate);
        record_t *record = retired_records;
        if (record) retired_records = record->next;
        spinlock_unlock(&record_gate);
        if (!record) break;
        record_free(record); ++count;
    }
    return count;
}
static record_t *record_new(record_lease_t *lease)
{
    spinlock_lock(&record_gate);
    bool admitted = record_allocated < RECORD_MAX;
    if (admitted) ++record_allocated;
    spinlock_unlock(&record_gate);
    if (!admitted) return NULL;
    record_t *record = calloc(1, sizeof(*record));
    if (!record)
    {
        spinlock_lock(&record_gate); --record_allocated; spinlock_unlock(&record_gate);
        return NULL;
    }
    if (!fd_description_get(lease->target)) { record_free(record); return NULL; }
    record->target = lease->target; record->owner = lease->owner;
    record->key = lease->key; record->pid = lease->pid;
    return record;
}
static void record_unlink_lease_locked(record_lease_t *lease)
{
    if (!lease->linked) return;
    record_lease_t **link = &record_leases;
    while (*link && *link != lease) link = &(*link)->next;
    if (*link) *link = lease->next;
    lease->next = NULL; lease->linked = false;
}
static void record_closed(void *context, fd_description_t *description)
{
    const void *key = description ? io_vfs_record_key(description) : NULL;
    if (description && !key) return;
    spinlock_lock(&record_gate);
    for (record_lease_t *lease = record_leases; lease; lease = lease->next)
        if (lease->owner == context && (!description || lease->key == key))
        { lease->revoked = true; lease->reserved = false; }
    record_t **link = &held_records;
    while (*link)
    {
        record_t *record = *link;
        if (record->owner == context && (!description || record->key == key))
        { *link = record->next; record_retire_locked(record); }
        else link = &record->next;
    }
    spinlock_unlock(&record_gate);
}
static void record_abort(record_lease_t *lease)
{
    spinlock_lock(&record_gate);
    record_unlink_lease_locked(lease);
    lease->revoked = true; lease->reserved = false;
    if (lease->fresh) { record_retire_locked(lease->fresh); lease->fresh = NULL; }
    if (lease->split) { record_retire_locked(lease->split); lease->split = NULL; }
    spinlock_unlock(&record_gate);
}
static int record_close(void *context)
{
    record_lease_t *lease = context;
    record_abort(lease);
    record_free(lease->fresh); record_free(lease->split);
    fd_description_put(lease->target);
    fd_table_put(lease->owner);
    free(lease);
    return 0;
}
static const fd_ops_t record_ops = { .close = record_close };
bool io_record_lock_description_valid(const fd_description_t *description)
{ return description && fd_description_ops(description)->close == record_close; }
syscall_record_lock_t *io_record_lock_query(fd_description_t *description)
{ return io_record_lock_description_valid(description) ? &((record_lease_t *)fd_description_context(description))->query : NULL; }
bool io_record_lock_is_query(fd_description_t *description)
{ return io_record_lock_description_valid(description) && ((record_lease_t *)fd_description_context(description))->command == SYSCALL_F_GETLK; }
bool io_record_lock_resolved(fd_description_t *description)
{ return io_record_lock_description_valid(description) && ((record_lease_t *)fd_description_context(description))->resolved; }
void io_record_lock_abort(fd_description_t *description)
{ if (io_record_lock_description_valid(description)) record_abort(fd_description_context(description)); }

int io_record_lock_create(fd_retirement_queue_t *retirement, fd_table_t *table,
    fd_description_t *target, uint64_t pid, uint32_t command, fd_description_t **output)
{
    int result = -EINVAL;
    if (output) *output = NULL;
    if (!output || !table || !retirement || !io_vfs_record_key(target) ||
        !fd_description_is_deferred_to(target, retirement) || !pid || pid > INT32_MAX ||
        (command != SYSCALL_F_GETLK && command != SYSCALL_F_SETLK && command != SYSCALL_F_SETLKW)) goto failed;
    if (!fd_table_get(table)) { result = -EBADF; goto failed; }
    result = fd_table_observe_closes(table, record_closed, table);
    if (result) { fd_table_put(table); goto failed; }
    record_lease_t *lease = calloc(1, sizeof(*lease));
    if (!lease) { fd_table_put(table); result = -ENOMEM; goto failed; }
    lease->target = target; lease->owner = table; lease->key = io_vfs_record_key(target);
    lease->pid = (int32_t)pid; lease->command = command;
    if (command != SYSCALL_F_GETLK)
    {
        lease->fresh = record_new(lease); lease->split = record_new(lease);
        if (!lease->fresh || !lease->split) { record_close(lease); return -ENOLCK; }
    }
    fd_description_t *description = fd_description_create_deferred(&record_ops, lease, retirement);
    if (!description) { record_close(lease); return -ENOMEM; }
    spinlock_lock(&record_gate);
    lease->next = record_leases; record_leases = lease; lease->linked = true;
    spinlock_unlock(&record_gate);
    *output = description;
    return 0;
failed:
    fd_description_put(target);
    return result;
}
static int record_normalize(record_lease_t *lease)
{
    int64_t start;
    if (__builtin_add_overflow(lease->base, lease->query.start, &start)) return -EOVERFLOW;
    if (start < 0) return -EINVAL;
    int64_t end = INT64_MAX;
    if (lease->query.length < 0)
    {
        end = start - 1;
        if (__builtin_add_overflow(start, lease->query.length, &start) || start < 0) return -EINVAL;
    }
    else if (lease->query.length && __builtin_add_overflow(start, lease->query.length - 1, &end)) return -EOVERFLOW;
    lease->start = start; lease->end = end; lease->resolved = true;
    return 0;
}
int io_record_lock_validate(fd_description_t *description)
{
    if (!io_record_lock_description_valid(description)) return -EINVAL;
    record_lease_t *lease = fd_description_context(description);
    if (lease->query.type != SYSCALL_F_RDLCK && lease->query.type != SYSCALL_F_WRLCK &&
        lease->query.type != SYSCALL_F_UNLCK) return -EINVAL;
    if (lease->query.whence < SYSCALL_SEEK_SET || lease->query.whence > SYSCALL_SEEK_END ||
        (lease->command == SYSCALL_F_GETLK && lease->query.type == SYSCALL_F_UNLCK)) return -EINVAL;
    lease->type = lease->query.type;
    uint32_t access = fd_description_status_flags(lease->target);
    if (lease->command != SYSCALL_F_GETLK &&
        ((lease->type == SYSCALL_F_RDLCK && !(access & FD_STATUS_READ)) ||
         (lease->type == SYSCALL_F_WRLCK && !(access & FD_STATUS_WRITE)))) return -EBADF;
    return lease->query.whence == SYSCALL_SEEK_SET ? record_normalize(lease) : 0;
}
int io_record_lock_resolve(fd_description_t *description)
{
    if (!io_record_lock_description_valid(description)) return -EINVAL;
    record_lease_t *lease = fd_description_context(description);
    if (lease->resolved) return 0;
    int result = io_vfs_record_base(lease->target, lease->query.whence, &lease->base);
    return result ? result : record_normalize(lease);
}
static bool record_conflicts(const record_lease_t *lease, const void *owner, const void *key,
                            int64_t start, int64_t end, int16_t type)
{
    return owner != lease->owner && key == lease->key && start <= lease->end && end >= lease->start &&
           type != SYSCALL_F_UNLCK && lease->type != SYSCALL_F_UNLCK &&
           (type == SYSCALL_F_WRLCK || lease->type == SYSCALL_F_WRLCK);
}
static void record_answer(record_lease_t *lease, int64_t start, int64_t end, int16_t type, int32_t pid)
{
    if (lease->reply.type != SYSCALL_F_UNLCK && lease->reply.start <= start) return;
    lease->reply = (syscall_record_lock_t){ .start = start, .length = end == INT64_MAX ? 0 : end - start + 1,
        .pid = pid, .type = type, .whence = SYSCALL_SEEK_SET };
}
bool io_record_lock_execute(io_request_t *request, io_service_result_t *result)
{
    result->result = -EINVAL; result->description_owned = NULL;
    fd_description_t *description = io_request_description(request);
    if (!io_record_lock_description_valid(description)) return true;
    record_lease_t *lease = fd_description_context(description);
    spinlock_lock(&record_gate);
    if (lease->revoked || fd_table_closed(lease->owner)) { result->result = -ECANCELED; goto done; }
    if (!lease->resolved) goto done;
    bool conflict = false;
    lease->reply = lease->query; lease->reply.type = SYSCALL_F_UNLCK;
    for (record_t *record = held_records; record; record = record->next)
        if (record_conflicts(lease, record->owner, record->key, record->start, record->end, record->type))
        { conflict = true; record_answer(lease, record->start, record->end, record->type, record->pid); }
    for (record_lease_t *other = record_leases; other; other = other->next)
        if (other->reserved && !other->revoked && record_conflicts(lease, other->owner, other->key, other->start, other->end, other->type))
        { conflict = true; record_answer(lease, other->start, other->end, other->type, other->pid); }
    if (conflict && lease->command != SYSCALL_F_GETLK)
    {
        if (lease->command == SYSCALL_F_SETLKW) { spinlock_unlock(&record_gate); return false; }
        result->result = -EAGAIN; goto done;
    }
    if (!fd_description_get(description)) { result->result = -EOVERFLOW; goto done; }
    if (lease->command == SYSCALL_F_GETLK) lease->query = lease->reply;
    else lease->reserved = true;
    lease->granted = true; result->description_owned = description; result->result = 0;
done:
    spinlock_unlock(&record_gate);
    return true;
}
static void record_apply_locked(record_lease_t *lease)
{
    record_t **link = &held_records;
    while (*link)
    {
        record_t *record = *link;
        if (record->owner != lease->owner || record->key != lease->key ||
            record->end < lease->start || record->start > lease->end) { link = &record->next; continue; }
        if (record->start < lease->start && record->end > lease->end)
        {
            record_t *right = lease->split; lease->split = NULL;
            right->start = lease->end + 1; right->end = record->end; right->type = record->type;
            right->next = record->next; record->next = right; record->end = lease->start - 1;
            link = &right->next;
        }
        else if (record->start < lease->start) { record->end = lease->start - 1; link = &record->next; }
        else if (record->end > lease->end) { record->start = lease->end + 1; link = &record->next; }
        else { *link = record->next; record_retire_locked(record); }
    }
    if (lease->type == SYSCALL_F_UNLCK) return;
    record_t *fresh = lease->fresh; lease->fresh = NULL;
    fresh->start = lease->start; fresh->end = lease->end; fresh->type = lease->type;
    /* Merge equal adjacent ranges for the same owner; reservations never
     * mutate old locks until this live-caller commit. */
    bool merged;
    do {
        merged = false; link = &held_records;
        while (*link)
        {
            record_t *record = *link;
            if (record->owner == fresh->owner && record->key == fresh->key && record->type == fresh->type &&
                (record->end == INT64_MAX || record->end + 1 >= fresh->start) &&
                (fresh->end == INT64_MAX || fresh->end + 1 >= record->start))
            {
                if (record->start < fresh->start) fresh->start = record->start;
                if (record->end > fresh->end) fresh->end = record->end;
                *link = record->next; record_retire_locked(record); merged = true;
            }
            else link = &record->next;
        }
    } while (merged);
    fresh->next = held_records; held_records = fresh;
}
int io_record_lock_commit(fd_description_t *description)
{
    if (!io_record_lock_description_valid(description)) return -EINVAL;
    record_lease_t *lease = fd_description_context(description);
    spinlock_lock(&record_gate);
    int result = lease->revoked || !lease->granted || fd_table_closed(lease->owner) ? -ECANCELED : 0;
    if (!result)
    {
        if (lease->command != SYSCALL_F_GETLK) record_apply_locked(lease);
        record_unlink_lease_locked(lease); lease->reserved = false; lease->granted = false;
        if (lease->fresh) { record_retire_locked(lease->fresh); lease->fresh = NULL; }
        if (lease->split) { record_retire_locked(lease->split); lease->split = NULL; }
    }
    spinlock_unlock(&record_gate);
    return result;
}
