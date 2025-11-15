#ifndef PROCESS_H
#define PROCESS_H

#include "types.h"
#include "interrupts.h"
#include "vfs.h"

#define PROCESS_NAME_MAX 32
#define PROCESS_DEFAULT_STACK_SIZE (128UL * 1024UL)

typedef struct process process_t;
typedef struct thread thread_t;
typedef struct trap_frame trap_frame_t;

typedef void (*thread_entry_t)(void *arg);
typedef void (*process_wait_hook_t)(void *context);

typedef enum
{
    THREAD_PRIORITY_IDLE = 0,
    THREAD_PRIORITY_BACKGROUND,
    THREAD_PRIORITY_NORMAL,
    THREAD_PRIORITY_HIGH,
    THREAD_PRIORITY_UI,
    THREAD_PRIORITY_COUNT
} thread_priority_t;

typedef struct wait_queue
{
    thread_t *head;
    thread_t *tail;
} wait_queue_t;

typedef bool (*wait_queue_predicate_t)(void *context);

typedef enum
{
    THREAD_STATE_READY,
    THREAD_STATE_RUNNING,
    THREAD_STATE_BLOCKED,
    THREAD_STATE_ZOMBIE
} thread_state_t;

typedef enum
{
    PROCESS_STATE_READY,
    PROCESS_STATE_RUNNING,
    PROCESS_STATE_ZOMBIE
} process_state_t;

typedef struct process_info
{
    uint64_t pid;
    process_state_t state;
    thread_state_t thread_state;
    const char *name;
    const char *thread_name;
    bool is_current;
    bool is_idle;
    uint32_t time_slice_remaining;
    int stdout_fd;
    uint64_t heap_used_bytes;
    uint64_t heap_committed_bytes;
} process_info_t;

typedef struct process_user_layout
{
    bool is_user;
    uintptr_t cr3;
    uintptr_t entry_point;
    uintptr_t stack_top;
    size_t stack_size;
} process_user_layout_t;

void process_system_init(void);
void process_start_scheduler(void);
void process_run_secondary_cpu(uint32_t cpu_index);
void process_scheduler_set_ready(void);

process_t *process_create_kernel(const char *name,
                                 thread_entry_t entry,
                                 void *arg,
                                 size_t stack_size,
                                 int stdout_fd);
process_t *process_create_kernel_with_parent(const char *name,
                                             thread_entry_t entry,
                                             void *arg,
                                             size_t stack_size,
                                             int stdout_fd,
                                             process_t *parent);
process_t *process_create_user_dummy(const char *name,
                                     int stdout_fd);
process_t *process_create_user_dummy_with_parent(const char *name,
                                                 int stdout_fd,
                                                 process_t *parent);

void process_yield(void);
void process_sleep_ticks(uint64_t ticks);
void process_sleep_ms(uint32_t ms);
void process_exit(int status) __attribute__((noreturn));

int process_join(process_t *process, int *status_out);
int process_join_with_hook(process_t *process,
                          int *status_out,
                          process_wait_hook_t hook,
                          void *context);
bool process_kill(process_t *process, int status);
void process_kill_tree(process_t *process);

process_t *process_current(void);
thread_t *thread_current(void);
bool process_thread_stack_bounds(const thread_t *thread,
                                 uintptr_t *base_out,
                                 uintptr_t *top_out);
const char *process_thread_name_const(const thread_t *thread);
process_t *process_thread_owner(const thread_t *thread);
bool process_stack_watch_thread(thread_t *thread, const char *context);
bool process_stack_watch_process(process_t *process, const char *context);
bool process_handle_stack_watch_fault(uintptr_t fault_addr,
                                      interrupt_frame_t *frame,
                                      uint64_t error_code);
uint64_t process_current_pid(void);
vfs_node_t *process_current_cwd(void);
void process_set_cwd(process_t *process, vfs_node_t *dir);
int process_current_stdout_fd(void);
ssize_t process_stdout_write(const char *data, size_t len);

void process_on_timer_tick(interrupt_frame_t *frame);
void process_preempt_hook(void);
void process_destroy(process_t *process);
size_t process_snapshot(process_info_t *buffer, size_t capacity);
const char *process_state_name(process_state_t state);
const char *thread_state_name(thread_state_t state);
uint64_t process_get_pid(const process_t *process);
void process_dump_current_thread(void);
bool process_handle_exception(interrupt_frame_t *frame,
                              const char *reason,
                              uint64_t error_code,
                              bool has_address,
                              uint64_t address);
bool process_query_user_layout(const process_t *process,
                               process_user_layout_t *layout);
int64_t process_user_sbrk(process_t *process, int64_t increment);
uint64_t process_take_preempt_resume_rip(void);
bool process_map_user_segment(process_t *process,
                              uintptr_t user_base,
                              size_t bytes,
                              bool writable,
                              bool executable,
                              void **host_ptr_out);
void process_dump_user_stack(process_t *process,
                             uintptr_t rsp,
                             size_t max_entries_above,
                             size_t max_entries_below);
void process_debug_scan_current_kernel_stack(const char *context,
                                             uintptr_t rsp_hint,
                                             bool full_stack);
void thread_disable_context_guard(thread_t *thread);
process_t *process_create_user_elf(const char *name,
                                   const uint8_t *image,
                                   size_t size,
                                   int stdout_fd,
                                   const char *const *argv,
                                   size_t argc);
process_t *process_create_user_elf_with_parent(const char *name,
                                               const uint8_t *image,
                                               size_t size,
                                               int stdout_fd,
                                               process_t *parent,
                                               const char *const *argv,
                                               size_t argc);

void process_set_priority(process_t *process, thread_priority_t priority);
void process_set_priority_override(process_t *process, thread_priority_t priority);
void process_clear_priority_override(process_t *process);

void wait_queue_init(wait_queue_t *queue);
void wait_queue_wait(wait_queue_t *queue, wait_queue_predicate_t predicate, void *context);
void wait_queue_wake_one(wait_queue_t *queue);
void wait_queue_wake_all(wait_queue_t *queue);

thread_t *process_find_stack_owner(const void *ptr, size_t len);
bool process_pointer_on_stack(const void *ptr, size_t len);
void process_debug_log_stack_write(const char *label,
                                   const void *caller,
                                   void *dest,
                                   size_t len);

#endif
