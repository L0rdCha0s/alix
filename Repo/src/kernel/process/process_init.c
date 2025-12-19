#include "process_internal.h"

/*
 * src/kernel/process/process_init.c
 *
 * Scheduler bring-up:
 * - Initializes global scheduler/process state.
 * - Creates the idle process and per-CPU idle threads.
 * - Provides the entry path for starting scheduling on the BSP and APs.
 *
 * See docs/kernel/process.md for the full scheduling/preemption model.
 */

/*
 * Initialise the process subsystem.
 *
 * Must be called on the BSP before starting APs or enabling timer-driven
 * scheduling. Sets up:
 * - run queues and global registries
 * - the idle process and per-CPU idle threads
 * - time slice configuration derived from the timer frequency
 */
void process_system_init(void)
{
    fpu_prepare_initial_state();

    if (g_console_stdout_fd < 0)
    {
        g_console_stdout_fd = fd_install(1, &console_stdout_ops, NULL);
        if (g_console_stdout_fd < 0)
        {
            g_console_stdout_fd = fd_allocate(&console_stdout_ops, NULL);
        }
        if (g_console_stdout_fd < 0)
        {
            fatal("unable to allocate console stdout fd");
        }
    }
    if (fd_install(2, &console_stdout_ops, NULL) < 0)
    {
        /* Best effort: stderr may already be reserved. */
    }

    g_process_list = NULL;
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        g_current_processes[i] = NULL;
        g_current_threads[i] = NULL;
        g_idle_threads[i] = NULL;
    }
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        run_queue_t *queue = &g_run_queues[i];
        spinlock_init(&queue->lock);
        queue->total = 0;
        queue->lock_owner = NULL;
        queue->lock_owner_label = NULL;
        queue->lock_owner_caller = NULL;
        queue->lock_acquired_ticks = 0;
        queue->cpu_index = i;
        for (int pr = 0; pr < THREAD_PRIORITY_COUNT; ++pr)
        {
            queue->heads[pr] = NULL;
            queue->tails[pr] = NULL;
            queue->counts[pr] = 0;
        }
    }
#if ENABLE_STACK_WRITE_DEBUG
    for (uint32_t i = 0; i < STACK_OWNER_BUCKET_COUNT; ++i)
    {
        g_stack_owner_buckets[i] = NULL;
        spinlock_init(&g_stack_owner_locks[i]);
    }
#endif
    spinlock_init(&g_scheduler_lock);
    spinlock_init(&g_sleep_queue_lock);
    spinlock_init(&g_process_lock);
    spinlock_init(&g_thread_registry_lock);
    g_thread_registry_head = NULL;
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        spinlock_init(&g_deferred_free_locks[i]);
        g_deferred_thread_frees[i] = NULL;
    }
    g_sleep_queue_head = NULL;
    g_next_pid = 1;
    g_next_tid = 1;

    uint32_t freq = timer_frequency();
    if (freq)
    {
        const uint32_t desired_slice_ms = 10;
        uint64_t ticks = ((uint64_t)freq * desired_slice_ms + 999ULL) / 1000ULL;
        if (ticks == 0)
        {
            ticks = 1;
        }
        if (ticks > UINT32_MAX)
        {
            ticks = UINT32_MAX;
        }
        g_time_slice_ticks = (uint32_t)ticks;
    }
    else
    {
        g_time_slice_ticks = PROCESS_TIME_SLICE_DEFAULT_TICKS;
    }

    process_t *idle_process = allocate_process("idle", false);
    if (!idle_process)
    {
        fatal("unable to allocate idle process");
    }
    idle_process->pid = 0;
    idle_process->state = PROCESS_STATE_READY;
    idle_process->is_user = false;
    idle_process->cr3 = read_cr3();
    spinlock_lock(&g_process_lock);
    idle_process->next = g_process_list;
    g_process_list = idle_process;
    spinlock_unlock(&g_process_lock);
    g_idle_process = idle_process;

    uint32_t cpu_count = smp_cpu_count();
    if (cpu_count == 0)
    {
        cpu_count = 1;
    }
    for (uint32_t cpu = 0; cpu < cpu_count; ++cpu)
    {
        char name[PROCESS_NAME_MAX];
        const char prefix[] = "idle";
        size_t pos = 0;
        while (prefix[pos] && pos < PROCESS_NAME_MAX - 1)
        {
            name[pos] = prefix[pos];
            pos++;
        }
        uint32_t value = cpu;
        char digits[10];
        size_t dpos = 0;
        do
        {
            digits[dpos++] = (char)('0' + (value % 10));
            value /= 10;
        } while (value > 0 && dpos < sizeof(digits));
        while (dpos > 0 && pos < PROCESS_NAME_MAX - 1)
        {
            name[pos++] = digits[--dpos];
        }
        name[pos] = '\0';

        thread_t *idle_thread = thread_create(idle_process,
                                              name,
                                              idle_thread_entry,
                                              NULL,
                                              PROCESS_DEFAULT_STACK_SIZE,
                                              true,
                                              false);
        if (!idle_thread)
        {
            fatal("unable to allocate idle thread");
        }
        idle_thread->state = THREAD_STATE_READY;
        idle_thread->is_idle = true;
        g_idle_threads[cpu] = idle_thread;
        if (cpu == 0)
        {
            idle_process->main_thread = idle_thread;
            idle_process->current_thread = idle_thread;
        }
    }
#if ENABLE_STACK_WRITE_DEBUG
    g_stack_write_debug_enabled = true;
    g_stack_owner_ready = true;
#endif
}

/*
 * Main scheduler loop for a CPU.
 *
 * Each CPU runs its idle thread; the idle thread calls `scheduler_schedule()`
 * when woken by an interrupt or when there is runnable work.
 */
static void scheduler_main_loop(void)
{
    lapic_set_tpr(0);
    scheduler_wait_for_boot_ready();
    while (1)
    {
        scheduler_schedule(false);
        __asm__ volatile ("hlt");
    }
}

/*
 * Start scheduling on the BSP.
 *
 * This switches the CPU onto the BSP idle thread's kernel stack and jumps into
 * `scheduler_main_loop`. It does not return.
 */
void process_start_scheduler(void)
{
    uint32_t cpu = current_cpu_index();
    thread_t *idle = g_idle_threads[cpu];
    if (!idle)
    {
        fatal("no idle thread for BSP scheduler start");
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    /* Make sure the BSP actually runs on the idle thread's stack before scheduling. */
    arch_cpu_set_kernel_stack(cpu, idle->kernel_stack_top);
    wrmsr(MSR_GS_BASE, idle->gs_base);
    wrmsr(MSR_FS_BASE, idle->fs_base);

    uint64_t new_rsp = idle->kernel_stack_top;
    void (*target)(void) = scheduler_main_loop;
    if (flags & RFLAGS_IF_BIT)
    {
        __asm__ volatile (
            "mov %0, %%rsp\n\t"
            "sti\n\t"
            "jmp *%1\n\t"
            :
            : "r"(new_rsp), "r"(target)
            : "memory");
    }
    else
    {
        __asm__ volatile (
            "mov %0, %%rsp\n\t"
            "jmp *%1\n\t"
            :
            : "r"(new_rsp), "r"(target)
            : "memory");
    }
    fatal("process_start_scheduler unreachable");
}

/*
 * Bind the BSP to its idle thread (thread-local pointers, MSRs, stack).
 *
 * This is used during the transition from single-threaded bring-up into the
 * scheduler, before enabling interrupts and calling `process_start_scheduler`.
 */
void process_bind_idle_to_bsp(void)
{
    thread_t *idle = g_idle_threads[0];
    if (!idle)
    {
        fatal("no idle thread for BSP");
    }
    set_current_thread_local(idle);
    set_current_process_local(idle->process);
    idle->state = THREAD_STATE_RUNNING;
    idle->context_valid = true;
    idle->preempt_pending = false;
    idle->time_slice_remaining = scheduler_time_slice_ticks();
    __atomic_store_n(&idle->running_cpu, 0, __ATOMIC_RELEASE);
    arch_cpu_set_kernel_stack(0, idle->kernel_stack_top);
    wrmsr(MSR_GS_BASE, idle->gs_base);
    wrmsr(MSR_FS_BASE, idle->fs_base);
}

/*
 * Entry point for secondary CPUs once SMP bring-up completes.
 *
 * APs are started by `src/kernel/smp.c` and arrive here after minimal CPU/IDT
 * init. This function binds the CPU to its idle thread and enters the per-CPU
 * scheduler loop.
 */
void process_run_secondary_cpu(uint32_t cpu_index)
{
    if (cpu_index >= SMP_MAX_CPUS)
    {
        fatal("process_run_secondary_cpu: cpu index out of range");
    }
    uint32_t cpu = cpu_index;
    thread_t *idle = g_idle_threads[cpu];
    if (!idle)
    {
        fatal("no idle thread for secondary CPU");
    }

    __asm__ volatile ("cli" ::: "memory");

    set_current_thread_local(idle);
    set_current_process_local(idle->process);
    idle->state = THREAD_STATE_RUNNING;
    idle->context_valid = true;
    idle->preempt_pending = false;
    idle->time_slice_remaining = scheduler_time_slice_ticks();
    __atomic_store_n(&idle->running_cpu, cpu, __ATOMIC_RELEASE);

    arch_cpu_set_kernel_stack(cpu, idle->kernel_stack_top);
    wrmsr(MSR_GS_BASE, idle->gs_base);
    wrmsr(MSR_FS_BASE, idle->fs_base);
    lapic_set_tpr(0xFF); /* Mask external IRQs until ready. */

    uint64_t new_rsp = idle->kernel_stack_top;
    uint64_t target = (uint64_t)scheduler_main_loop;

    lapic_set_tpr(0x00); /* Unmask now that stack and GS are valid. */

    __asm__ volatile (
        "mov %0, %%rsp\n\t"
        "sti\n\t"
        "jmp *%1\n\t"
        :
        : "r"(new_rsp), "r"(target)
        : "memory");
}

void process_scheduler_set_ready(void)
{
    __atomic_store_n(&g_scheduler_boot_ready, true, __ATOMIC_RELEASE);
}

bool process_scheduler_ready(void)
{
    return __atomic_load_n(&g_scheduler_boot_ready, __ATOMIC_ACQUIRE);
}
