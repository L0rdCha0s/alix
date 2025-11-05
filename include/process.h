#ifndef PROCESS_H
#define PROCESS_H

#include "types.h"
#include "interrupts.h"

#define PROCESS_NAME_MAX 32
#define PROCESS_DEFAULT_STACK_SIZE (32UL * 1024UL)

typedef struct process process_t;
typedef struct thread thread_t;
typedef struct trap_frame trap_frame_t;

typedef void (*thread_entry_t)(void *arg);

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

void process_system_init(void);
void process_start_scheduler(void);

process_t *process_create_kernel(const char *name,
                                 thread_entry_t entry,
                                 void *arg,
                                 size_t stack_size);

void process_yield(void);
void process_exit(int status) __attribute__((noreturn));

int process_join(process_t *process, int *status_out);

process_t *process_current(void);
thread_t *thread_current(void);
uint64_t process_current_pid(void);

void process_on_timer_tick(interrupt_frame_t *frame);
void process_destroy(process_t *process);

#endif
