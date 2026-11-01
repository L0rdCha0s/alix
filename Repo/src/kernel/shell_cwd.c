#include "shell.h"
#include "fd_table.h"
#include "errno.h"

bool shell_cwd_init(shell_state_t *shell)
{
    if (!shell || !spinlock_preempt_disabled()) return false;
    spinlock_init(&shell->cwd_lock);
    shell_actors_init(shell);
    shell->cwd_owner = process_acquire_cwd_owner(process_current(), NULL, NULL);
    shell->cwd = shell->cwd_owner ? fd_description_context(shell->cwd_owner) : NULL;
    shell->lifetime_owner = NULL;
    return shell->cwd_owner != NULL;
}

fd_description_t *shell_cwd_acquire(shell_state_t *shell)
{
    if (!shell || !spinlock_preempt_disabled()) return NULL;
    spinlock_lock(&shell->cwd_lock);
    fd_description_t *owner = shell->cwd_owner;
    if (owner && !fd_description_get(owner)) owner = NULL;
    spinlock_unlock(&shell->cwd_lock);
    return owner;
}

int shell_cwd_replace_owned(shell_state_t *shell, fd_description_t *owner)
{
    if (!shell || !spinlock_preempt_disabled() || !process_cwd_description_valid(owner)) return -EINVAL;
    spinlock_lock(&shell->cwd_lock);
    fd_description_t *previous = shell->cwd_owner;
    shell->cwd_owner = owner;
    shell->cwd = fd_description_context(owner);
    spinlock_unlock(&shell->cwd_lock);
    fd_description_put(previous);
    return 0;
}

void shell_cwd_destroy(shell_state_t *shell)
{
    if (!shell) return;
    spinlock_preempt_disable();
    spinlock_lock(&shell->cwd_lock);
    fd_description_t *owner = shell->cwd_owner;
    shell->cwd_owner = NULL;
    shell->cwd = NULL;
    spinlock_unlock(&shell->cwd_lock);
    fd_description_put(owner);
    spinlock_preempt_enable();
}

bool shell_cwd_apply_current(shell_state_t *shell)
{
    spinlock_preempt_disable();
    fd_description_t *owner = shell_cwd_acquire(shell);
    int result = owner ? process_set_cwd_description_owned(process_current(), owner) : -EINVAL;
    if (result) fd_description_put(owner);
    spinlock_preempt_enable();
    return result == 0;
}
