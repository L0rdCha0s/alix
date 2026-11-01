#include "shell.h"
#include "process_internal.h"
#include "heap.h"
#include "fd_table.h"

#define SHELL_ACTOR_LIMIT 128u

struct shell_actor
{
    process_creation_watch_t watch;
    shell_state_t *shell;
    fd_description_t *owner, *session_owner;
    struct shell_actor *next;
    void (*retired)(void *, struct shell_actor *);
    void *retired_context;
    bool counted;
};

static int shell_actor_close(void *context)
{
    shell_actor_t *actor = context;
    if (process_creation_watch_stop(&actor->watch)) fatal("shell actor could not quiesce");
    /* A runner slot is protected by the session lock. Clear it before releasing
     * the retained process, so metadata readers cannot observe a freed process. */
    if (actor->retired) actor->retired(actor->retired_context, actor);
    process_creation_watch_release(&actor->watch);
    if (actor->counted)
    {
        spinlock_lock(&actor->shell->actors_lock);
        if (actor->shell->actor_live) --actor->shell->actor_live;
        if (!actor->shell->actor_live && !actor->shell->actors_closing) actor->shell->actors_paused = false;
        spinlock_unlock(&actor->shell->actors_lock);
    }
    fd_description_t *session_owner = actor->session_owner;
    free(actor);
    fd_description_put(session_owner);
    return 0;
}

static const fd_ops_t shell_actor_ops = { .close = shell_actor_close };

void shell_actors_init(shell_state_t *shell)
{
    spinlock_init(&shell->actors_lock);
    shell->actors = NULL;
    shell->actor_live = 0;
    shell->actors_closing = shell->actors_paused = false;
}

void shell_actors_reap(shell_state_t *shell)
{
    if (!shell || !shell->lifetime_owner) return;
    spinlock_preempt_disable();
    shell_actor_t *retired = NULL;
    spinlock_lock(&shell->actors_lock);
    shell_actor_t **cursor = &shell->actors;
    /* Bounded live admission also bounds this metadata-only scan. */
    while (*cursor)
    {
        shell_actor_t *actor = *cursor;
        if (process_creation_watch_quiescent(&actor->watch))
        {
            *cursor = actor->next;
            actor->next = retired;
            retired = actor;
        }
        else cursor = &actor->next;
    }
    spinlock_unlock(&shell->actors_lock);
    while (retired)
    {
        shell_actor_t *next = retired->next;
        fd_description_put(retired->owner);
        retired = next;
    }
    spinlock_preempt_enable();
}

bool shell_actor_begin(shell_state_t *shell, shell_actor_t **out,
                        void (*retired)(void *, shell_actor_t *), void *context)
{
    if (!out) return false;
    *out = NULL;
    if (!shell || !shell->lifetime_owner) return true; /* CLI/startup coordinator owns its state. */
    spinlock_preempt_disable();
    shell_actors_reap(shell);
    fd_description_t *session_owner = shell->lifetime_owner;
    if (!fd_description_get(session_owner)) { spinlock_preempt_enable(); return false; }
    shell_actor_t *actor = calloc(1, sizeof(*actor));
    if (!actor || !process_creation_watch_init(&actor->watch))
    {
        free(actor); fd_description_put(session_owner); spinlock_preempt_enable(); return false;
    }
    actor->shell = shell;
    actor->session_owner = session_owner;
    actor->retired = retired;
    actor->retired_context = context;
    actor->owner = fd_description_create_deferred(&shell_actor_ops, actor, process_fd_retirement_queue());
    if (!actor->owner)
    {
        free(actor); fd_description_put(session_owner); spinlock_preempt_enable(); return false;
    }
    spinlock_lock(&shell->actors_lock);
    bool admitted = !shell->actors_closing && !shell->actors_paused && shell->actor_live < SHELL_ACTOR_LIMIT;
    if (admitted)
    {
        actor->counted = true;
        ++shell->actor_live;
        actor->next = shell->actors;
        shell->actors = actor;
        *out = actor;
    }
    spinlock_unlock(&shell->actors_lock);
    if (!admitted)
    {
        process_creation_watch_complete(&actor->watch);
        fd_description_put(actor->owner);
    }
    spinlock_preempt_enable();
    return admitted;
}

process_t *shell_actor_create(shell_actor_t *actor, const char *name, thread_entry_t entry,
                               void *argument, size_t stack_size, int stdout_fd)
{
    return actor ? process_create_kernel_observed(name, entry, argument, stack_size, stdout_fd, &actor->watch) :
                   process_create_kernel(name, entry, argument, stack_size, stdout_fd);
}

void shell_actor_complete(shell_actor_t *actor)
{
    if (actor) process_creation_watch_complete(&actor->watch); /* Last creator access. */
}

bool shell_actor_quiescent(shell_actor_t *actor)
{
    return !actor || process_creation_watch_quiescent(&actor->watch);
}

uint64_t shell_actor_pid(const shell_actor_t *actor)
{
    return actor ? __atomic_load_n(&actor->watch.pid, __ATOMIC_ACQUIRE) : 0;
}

void shell_actors_mark_closing(shell_state_t *shell)
{
    spinlock_lock(&shell->actors_lock);
    shell->actors_closing = shell->actors_paused = true;
    spinlock_unlock(&shell->actors_lock);
}

bool shell_actors_retire_all(shell_state_t *shell)
{
    spinlock_preempt_disable();
    spinlock_lock(&shell->actors_lock);
    shell_actor_t *list = shell->actors;
    shell->actors = NULL;
    bool pending = shell->actor_live != 0;
    if (pending) shell->actors_paused = true;
    spinlock_unlock(&shell->actors_lock);
    while (list)
    {
        shell_actor_t *next = list->next;
        fd_description_put(list->owner);
        list = next;
    }
    spinlock_preempt_enable();
    return pending;
}
