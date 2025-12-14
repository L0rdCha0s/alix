# Processes, Threads, and Scheduling

This kernel uses kernel threads as its primary unit of execution, with optional user-mode threads/processes sharing the same scheduler.

## Key Types and Globals

Defined primarily in `include/process.h` and `include/process_internal.h`:

- `process_t` — owns an address space (`paging_space_t`), a thread list, parent/child links, and basic accounting.
- `thread_t` — owns a kernel stack, saved CPU context, wait/sleep state, priority/affinity, and (for user threads) user-mode entry + TLS state.
- `run_queue_t` — per-CPU run queue with per-priority linked lists.

Per-CPU current pointers (arrays indexed by CPU):

- `g_current_threads[SMP_MAX_CPUS]`
- `g_current_processes[SMP_MAX_CPUS]`
- `g_idle_threads[SMP_MAX_CPUS]`

## Translation Unit Layout

`src/kernel/process.c` `#include`s multiple files under `src/kernel/process/` into one translation unit. This keeps internal helpers visible without exporting them in headers.

## Thread Creation and Stack Layout (`process_thread.c`)

Thread creation allocates:

- A `thread_t` object on the kernel heap.
- A kernel stack allocation that includes:
  - A guard region filled with `STACK_GUARD_PATTERN`
  - An aligned usable stack area
  - A “redzone” reserved below the top of stack (`THREAD_CONTEXT_REDZONE_BYTES`) so the context frame and preempt/save logic don’t collide with normal stack usage.

The initial CPU context is built so that the first `context_switch(...)` into the thread returns into `thread_trampoline`, which calls the thread’s `entry(arg)` and then `process_exit(...)`.

## Context Switching (`process_common.c`)

`context_switch(prev_ctx_ptr, next_ctx, transition_flag, running_cpu_ptr)` is a naked assembly routine that:

- Saves callee-saved registers + RFLAGS on the current stack.
- Stores the resulting stack pointer into `*prev_ctx_ptr`.
- Loads `next_ctx` as the new stack pointer and restores registers/RFLAGS.
- Returns to the return address stored in the new context frame.

This means the *saved context pointer is effectively a stack pointer*.

## Scheduler Model (`process_scheduler.c`)

Important characteristics:

- **Per-CPU run queues**: threads are enqueued onto a CPU run queue, possibly migrated if affinity requires.
- **Priority buckets**: each run queue maintains lists per `thread_priority_t`.
- **Idle threads**: there is an idle thread per CPU that halts (`hlt`) when no runnable work exists.
- **Affinity**: `thread_set_affinity` and process-level affinity can force a thread onto a specific CPU run queue to avoid stranding.

The scheduler’s main loop (`scheduler_main_loop` in `process_init.c`) repeatedly calls `scheduler_schedule(false)` then halts.

## Preemption Path (Timer IRQ + IPI)

Preemption is driven by the timer interrupt and a “schedule IPI” broadcast:

- Timer IRQ handler: `src/arch/x86/interrupts.c:irq0_handler`
  - Calls `timer_on_tick()`
  - Calls `process_on_timer_tick(frame)`
  - Broadcasts `SMP_SCHEDULE_IPI_VECTOR` so other CPUs get a chance to preempt too.
- Schedule IPI handler: `src/kernel/smp.c:smp_handle_schedule_ipi`
  - Also calls `process_on_timer_tick(frame)`

`process_on_timer_tick` (in `process_api.c`) decrements the current thread’s time slice and, when it expires, forces the interrupted context to route through a preemption trampoline:

- **Kernel-mode threads**: rewrite `frame->rip` to `process_preempt_trampoline` (`src/arch/x86/process_preempt.S`)
- **User-mode threads**: rewrite `frame->rip` to a user-mapped preemption stub at `USER_PREEMPT_STUB_BASE` (bytes live in `g_user_preempt_stub` in `process_common.c` and are mapped into each user process)

Both paths ultimately call `process_preempt_hook()`, which clears `preempt_pending` and calls `process_yield()`.

## Waiting and Sleeping

- `wait_queue_t` is a simple spinlock-protected FIFO used for joins and blocking.
- Sleeping uses a global sleep list and a periodic wake check: `sleep_queue_wake_due(timer_ticks())`.

## SMP Safety Notes

Thread stacks are per-thread and must never be shared across CPUs/threads. This repo includes explicit stack-owner diagnostics to catch cases where data from one thread’s stack is used for DMA or async work on another CPU.

