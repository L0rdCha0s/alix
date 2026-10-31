#include "process_internal.h"
#include "io_vfs_service.h"
#include "errno.h"

int process_apply_cwd_to_current_and_pid(fd_description_t *owner, uint64_t owner_pid)
{
    if (!spinlock_preempt_disabled() || !process_cwd_description_valid(owner)) return -EINVAL;
    uint64_t flags = scheduler_lock_acquire("cwd_apply");
    process_t *current = current_process_local();
    if (!current || current->state == PROCESS_STATE_ZOMBIE)
    {
        scheduler_lock_release(flags);
        return -ESRCH;
    }
    spinlock_lock(&g_process_lock);
    process_t *target = current;
    if (owner_pid && owner_pid != current->pid)
    {
        target = g_process_list;
        while (target && target->pid != owner_pid) target = target->next;
    }
    if (!target || target->state == PROCESS_STATE_ZOMBIE ||
        __atomic_load_n(&target->lifetime_state, __ATOMIC_ACQUIRE) != PROCESS_LIFETIME_ALIVE)
    {
        spinlock_unlock(&g_process_lock);
        scheduler_lock_release(flags);
        return -ESRCH;
    }
    /* Each destination receives its own reference. Acquire before mutating
     * either context; no target process pointer survived the worker wait. */
    if (target != current && !fd_description_get(owner))
    {
        spinlock_unlock(&g_process_lock);
        scheduler_lock_release(flags);
        return -EOVERFLOW;
    }
    process_t *first = current->pid < target->pid ? current : target;
    process_t *second = first == current ? target : current;
    spinlock_lock(&first->context_lock);
    if (second != first) spinlock_lock(&second->context_lock);
    fd_description_t *old_current = current->cwd_owner;
    fd_description_t *old_target = target != current ? target->cwd_owner : NULL;
    current->cwd_owner = owner;
    current->cwd = fd_description_context(owner);
    if (target != current)
    {
        target->cwd_owner = owner;
        target->cwd = fd_description_context(owner);
    }
    if (second != first) spinlock_unlock(&second->context_lock);
    spinlock_unlock(&first->context_lock);
    spinlock_unlock(&g_process_lock);
    scheduler_lock_release(flags);
    fd_description_put(old_current);
    fd_description_put(old_target);
    return 0;
}
