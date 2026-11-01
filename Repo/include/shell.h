#ifndef SHELL_H
#define SHELL_H

#include "types.h"
#include "vfs.h"
#include "process.h"

typedef struct shell_output shell_output_t;
typedef struct shell_state shell_state_t;
typedef struct shell_actor shell_actor_t;
typedef void (*shell_console_tap_fn)(void *context, const char *data, size_t len);

struct shell_output
{
    bool to_file;
    vfs_node_t *file;
    size_t file_offset;
    bool to_buffer;
    char *buffer;
    size_t length;
    size_t capacity;
};

struct shell_state
{
    vfs_node_t *cwd; /* Compatibility view owned by cwd_owner. */
    spinlock_t cwd_lock;
    fd_description_t *cwd_owner;
    fd_description_t *lifetime_owner; /* Optional session pin; immutable. */
    spinlock_t actors_lock;
    shell_actor_t *actors;
    size_t actor_live;
    bool actors_closing, actors_paused;
    void (*stream_fn)(void *context, const char *data, size_t len);
    void *stream_context;
    int stdout_fd;
    process_t *foreground_process;
    process_wait_hook_t wait_hook;
    void *wait_context;
    process_t *owner_process;
    uint64_t owner_pid; /* Stable identity for protected cwd resolution. */
    void (*cwd_changed_fn)(void *context, vfs_node_t *cwd);
    void *cwd_changed_context;
};

/* Caller owns shell-state lifetime. Acquire/replace/init require a bounded
 * preparation/result guard; destruction only enqueues deferred references. */
bool shell_cwd_init(shell_state_t *shell);
fd_description_t *shell_cwd_acquire(shell_state_t *shell);
int shell_cwd_replace_owned(shell_state_t *shell, fd_description_t *owner);
void shell_cwd_destroy(shell_state_t *shell);
bool shell_cwd_apply_current(shell_state_t *shell);
void shell_actors_init(shell_state_t *shell);
bool shell_actor_begin(shell_state_t *shell, shell_actor_t **out, void (*retired)(void *, shell_actor_t *), void *context);
process_t *shell_actor_create(shell_actor_t *actor, const char *name, thread_entry_t entry, void *argument, size_t stack_size, int stdout_fd);
void shell_actor_complete(shell_actor_t *actor);
bool shell_actor_quiescent(shell_actor_t *actor);
uint64_t shell_actor_pid(const shell_actor_t *actor);
void shell_actors_reap(shell_state_t *shell);
void shell_actors_mark_closing(shell_state_t *shell);
bool shell_actors_retire_all(shell_state_t *shell);

/* Foreground tracking is shared across threads (shell workers + interruptors). */
static inline process_t *shell_foreground_load(shell_state_t *shell)
{
    if (!shell)
    {
        return NULL;
    }
    return __atomic_load_n(&shell->foreground_process, __ATOMIC_ACQUIRE);
}

static inline void shell_foreground_store(shell_state_t *shell, process_t *proc)
{
    if (shell)
    {
        __atomic_store_n(&shell->foreground_process, proc, __ATOMIC_RELEASE);
    }
}

void shell_main(void);

void shell_output_init_console(shell_output_t *out);
void shell_output_init_buffer(shell_output_t *out);
bool shell_output_prepare_file(shell_output_t *out, vfs_node_t *file);
bool shell_output_write(shell_output_t *out, const char *text);
bool shell_output_write_len(shell_output_t *out, const char *text, size_t len);
void shell_print_error(const char *msg);
char *shell_output_take_buffer(shell_output_t *out);
void shell_output_reset(shell_output_t *out);

char *shell_execute_line(shell_state_t *shell, const char *line, bool *success);
bool shell_output_error(shell_output_t *out, const char *msg);
bool shell_request_interrupt(shell_state_t *shell);
bool shell_execute_binary(shell_state_t *shell,
                          shell_output_t *out,
                          const char *path,
                          const char *args,
                          const char *label);
void shell_set_console_tap(shell_console_tap_fn fn, void *context);
void shell_get_console_tap(shell_console_tap_fn *fn_out, void **ctx_out);
void shell_emit_console_tap(const char *data, size_t len);
void shell_clear_active_shell(shell_state_t *shell);
void shell_clear_console_tap_if_matches(shell_console_tap_fn fn, void *context);

#endif
