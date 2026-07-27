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

The files under `src/kernel/process/` are compiled as separate translation units. Shared implementation contracts are declared in `include/process_internal.h`; `src/kernel/process.c` remains only as a historical compatibility stub and is excluded by the build.

## Thread Creation and Stack Layout (`process_thread.c`)

Thread creation allocates:

- A `thread_t` object on the kernel heap.
- A kernel stack allocation that includes:
  - A guard region filled with `STACK_GUARD_PATTERN`
  - An aligned usable stack area
  - A “redzone” reserved below the top of stack (`THREAD_CONTEXT_REDZONE_BYTES`) so the context frame and preempt/save logic don’t collide with normal stack usage.

The initial CPU context is built so that the first `context_switch(...)` into the thread returns into `thread_trampoline`, which calls the thread’s `entry(arg)` and then `process_exit(...)`.

## Context Switching (`process_common.c`)

`context_switch(prev_ctx_ptr, next_ctx, transition_flag, running_cpu_ptr, saved_rflags, scheduler_lock, restore_rflags_ptr)` is a naked assembly routine that:

- Saves callee-saved registers + RFLAGS on the current stack.
- Stores the resulting stack pointer into `*prev_ctx_ptr`.
- Loads `next_ctx` as the new stack pointer.
- Clears the outgoing thread's transition/CPU ownership only after changing stacks.
- Releases the scheduler lock from the incoming stack.
- Keeps interrupts masked until `scheduler_finish_switch()` has completed ownership, process-state, wakeup, and deferred-free bookkeeping; it then restores the incoming thread's original RFLAGS.
- Returns to the return address stored in the new context frame.

This means the *saved context pointer is effectively a stack pointer*.

## Scheduler Model (`process_scheduler.c`)

Important characteristics:

- **Per-CPU run queues**: threads are enqueued onto a CPU run queue, possibly migrated if affinity requires.
- **Priority buckets**: each run queue maintains lists per `thread_priority_t`.
- **Process policies**: priority, priority overrides, and affinity apply to every existing thread and are retained as defaults for threads created later.
- **Idle threads**: there is an idle thread per CPU that halts (`hlt`) when no runnable work exists.
- **Affinity**: `thread_set_affinity` and process-level affinity can force a thread onto a specific CPU run queue to avoid stranding.
- **Preemption migration**: when an affinity- or UI-bound current thread is requeued, it is placed directly on its required CPU's queue; the old CPU retains stack ownership until the assembly handoff clears it.
- **Spinlock ownership**: generic kernel spinlocks maintain a per-thread nesting depth (with a per-CPU fallback before scheduler threads exist). Timer callbacks, timer/IPI scheduler housekeeping, and voluntary yields defer lock-taking or preemption while that depth is non-zero, ensuring an interrupted lock owner cannot invert the scheduler-to-subsidiary-lock order. Locks shared with an IRQ handler use the IRQ-save helpers; release publishes the unlocked word and restores the saved interrupt state while the nesting guard is still raised. The scheduler's cross-stack lock uses raw lock operations because assembly releases it only after moving to the incoming stack.

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

The timer tick counter advances even when the interrupted context has a generic spinlock outstanding, but periodic timer callbacks are left due until a later safe tick. `process_on_timer_tick()` likewise accounts the local CPU tick and then returns before acquiring any scheduler, sleep-queue, or stack-watch lock while the nesting depth is non-zero. Global process-age, sleep-wakeup, and stack-watch housekeeping runs only on CPU 0; schedule IPIs on the other CPUs perform only local accounting and preemption work.

## Waiting and Sleeping

- `wait_queue_t` is a spinlock-protected FIFO used for joins and blocking. Wake-all drains the complete queue; it has no fixed waiter limit.
- Process joins block on the process wait queue and complete only after every thread is a zombie and is absent from CPUs, transition slots, sleep/wait lists, and run queues.
- Process teardown uses the lock order scheduler → process thread list → subsidiary queues. Thread resources are deferred until no CPU or queue references them. During a context switch, `g_switch_out_threads[cpu]` remains published as a hazard pointer until outgoing-thread bookkeeping, join wakeups, and scheduler-locked deferred reclamation have completed. Final process teardown severs every `thread->process` link under the same scheduler lock before freeing the address space.
- Sleeping uses a global sleep list and a periodic wake check: `sleep_queue_wake_due(timer_ticks())`.

## SMP Safety Notes

Thread stacks are per-thread and must never be shared across CPUs/threads. This repo includes explicit stack-owner diagnostics to catch cases where data from one thread’s stack is used for DMA or async work on another CPU.

Process child links and the global process list are protected by `g_process_lock`. Per-process memory metadata is protected separately by `memory_lock`; user mappings reject overflow, out-of-range addresses, reserved-area collisions, and overlaps with existing regions. Secondary user-thread stacks are unmapped when their owning thread is finally reclaimed.
