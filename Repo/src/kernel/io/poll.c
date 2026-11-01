#include "io_poll.h"
#include "heap.h"
#include "timer.h"
#include "errno.h"
#include <stdint.h>

_Static_assert(sizeof(syscall_pollfd_t) == 8, "poll wire layout");
typedef struct
{
    fd_description_t *description;
} io_poll_pin_t;
typedef struct
{
    size_t count;
    bool infinite, pinned, select_mode;
    uint64_t deadline;
    io_poll_pin_t *pins;
    syscall_pollfd_t entries[];
} io_poll_set_t;

static int io_poll_close(void *context)
{
    io_poll_set_t *set = context;
    for (size_t index = 0; index < set->count; ++index)
        fd_description_put(set->pins[index].description);
    free(set->pins);
    free(set);
    return 0;
}
static const fd_ops_t io_poll_ops = { .close = io_poll_close };

bool io_poll_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_poll_close;
}

static int io_poll_create_mode(fd_retirement_queue_t *retirement, size_t count, int64_t timeout,
                                  bool select_mode, fd_description_t **output)
{
    if (!output) return -EINVAL;
    *output = NULL;
    if (!retirement || count > FD_TABLE_MAX_ENTRIES || (select_mode && timeout < -1)) return -EINVAL;
    io_poll_set_t *set = calloc(1, sizeof(*set) + count * sizeof(syscall_pollfd_t));
    if (!set) return -ENOMEM;
    set->pins = calloc(count ? count : 1, sizeof(*set->pins));
    if (!set->pins) { free(set); return -ENOMEM; }
    set->count = count; set->infinite = timeout < 0; set->select_mode = select_mode;
    uint64_t now = timer_monotonic_millis();
    set->deadline = timeout > 0 && now > UINT64_MAX - (uint64_t)timeout ? UINT64_MAX :
                       now + (timeout > 0 ? (uint64_t)timeout : 0);
    *output = fd_description_create_deferred(&io_poll_ops, set, retirement);
    if (!*output) { free(set->pins); free(set); return -ENOMEM; }
    return 0;
}

int io_poll_create(fd_retirement_queue_t *retirement, size_t count, int timeout,
                     fd_description_t **output)
{
    return io_poll_create_mode(retirement, count, timeout, false, output);
}

int io_select_create(fd_retirement_queue_t *retirement, size_t count, int64_t timeout,
                       fd_description_t **output)
{
    return io_poll_create_mode(retirement, count, timeout, true, output);
}

syscall_pollfd_t *io_poll_entries(fd_description_t *description)
{
    return io_poll_description_valid(description) ?
        ((io_poll_set_t *)fd_description_context(description))->entries : NULL;
}

int io_poll_pin(fd_description_t *description, fd_table_t *table)
{
    if (!io_poll_description_valid(description) || !table) return -EINVAL;
    io_poll_set_t *set = fd_description_context(description);
    if (set->pinned) return -EINVAL;
    set->pinned = true;
    for (size_t index = 0; index < set->count; ++index)
    {
        syscall_pollfd_t *entry = &set->entries[index];
        entry->revents = 0;
        if (set->select_mode && (entry->events & ~(SYSCALL_POLL_IN | SYSCALL_POLL_OUT | SYSCALL_POLL_PRI)))
            return -EINVAL;
        if (entry->fd < 0) continue;
        int result = fd_table_pin(table, entry->fd, &set->pins[index].description, NULL);
        if (result == -EBADF) entry->revents = SYSCALL_POLL_NVAL;
        else if (result) return result;
    }
    return 0;
}

bool io_poll_execute(io_request_t *request, io_service_result_t *result)
{
    if (!result) return true;
    result->result = -EINVAL; result->description_owned = NULL;
    fd_description_t *description = request ? io_request_description(request) : NULL;
    if (!io_poll_description_valid(description)) return true;
    io_poll_set_t *set = fd_description_context(description);
    if (!set->pinned) return true;
    int ready = 0;
    for (size_t index = 0; index < set->count; ++index)
    {
        syscall_pollfd_t *entry = &set->entries[index];
        if (entry->fd < 0) { entry->revents = 0; continue; }
        fd_description_t *target = set->pins[index].description;
        if (!target) entry->revents = SYSCALL_POLL_NVAL;
        else
        {
            const fd_ops_t *ops = fd_description_ops(target);
            uint32_t flags = ops->poll ? ops->poll(fd_description_context(target)) : SYSCALL_POLL_ERR;
            if (set->select_mode)
            {
                uint32_t selected = flags & SYSCALL_POLL_PRI;
                if (flags & (SYSCALL_POLL_IN | SYSCALL_POLL_ERR | SYSCALL_POLL_HUP)) selected |= SYSCALL_POLL_IN;
                if (flags & (SYSCALL_POLL_OUT | SYSCALL_POLL_ERR)) selected |= SYSCALL_POLL_OUT;
                entry->revents = (int16_t)(selected & (uint16_t)entry->events);
            }
            else entry->revents = (int16_t)(flags & ((uint16_t)entry->events |
                                            SYSCALL_POLL_ERR | SYSCALL_POLL_HUP | SYSCALL_POLL_NVAL));
        }
        if (entry->revents) ++ready;
    }
    if (!ready && (set->infinite || timer_monotonic_millis() < set->deadline)) return false;
    result->result = ready;
    return true;
}
