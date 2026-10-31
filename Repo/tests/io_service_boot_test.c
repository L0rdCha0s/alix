#include "process_internal.h"
#include "io_service.h"
#include "errno.h"
#include <stdint.h>

#define IO_BOOT_MAGIC UINT64_C(0x494f424f4f545245)
#define IO_BOOT_PAYLOAD 32u

typedef struct
{
    wait_queue_t caller_start, storage_gate, result_gate;
    bool release_storage, release_result;
    uint32_t handled, blocked, busy, late_outputs;
    uint32_t input_closed, output_closed, cwd_closed;
    vfs_node_t *cwd;
} io_boot_shared_t;

typedef struct
{
    io_boot_shared_t *shared;
    uint32_t kind;
    bool busy;
    io_request_status_t status;
    uint8_t payload[IO_BOOT_PAYLOAD];
} io_boot_job_t;

typedef struct
{
    io_boot_shared_t *shared;
    uint64_t magic;
    bool output;
} io_boot_asset_t;

typedef struct
{
    io_boot_shared_t *shared;
    io_service_t *service;
    process_t *process;
    io_request_t *request, *borrow;
    io_request_status_t status;
    uint32_t kind;
    bool start, submitted, hold_result, result_held, returned, saw_cancel;
    uint8_t copied[IO_BOOT_PAYLOAD];
} io_boot_caller_t;

typedef struct
{
    io_service_t *service;
    bool started, done;
    int result;
} io_boot_stopper_t;

typedef struct
{
    wait_queue_t gate;
    bool entered, release, self_kill_refused;
} io_boot_probe_t;

typedef struct
{
    io_boot_shared_t *shared;
    io_service_t *service;
    io_boot_caller_t callers[5];
    io_boot_stopper_t stopper;
    io_service_status_t snapshot;
} io_boot_control_t;

static io_boot_shared_t *g_io_boot_shared;

static uint32_t io_boot_count(uint32_t *counter)
{
    return __atomic_load_n(counter, __ATOMIC_ACQUIRE);
}

static void io_boot_require(bool condition, const char *label)
{
    if (condition) return;
    serial_printf("IO_SERVICE_TEST: FAIL %s", label);
    fatal("protected I/O executor boot self-test failed");
}

static bool io_boot_flag(void *context)
{
    return __atomic_load_n((bool *)context, __ATOMIC_ACQUIRE);
}

static uint64_t io_boot_deadline(void)
{
    uint64_t frequency = timer_frequency();
    io_boot_require(frequency != 0, "timer available");
    return timer_ticks() + frequency * 10;
}

static void io_boot_poll(uint64_t deadline, const char *label)
{
    io_boot_require(timer_ticks() < deadline, label);
    process_sleep_ms(1);
}

static void io_boot_wait_flag(bool *flag, const char *label)
{
    uint64_t deadline = io_boot_deadline();
    while (!__atomic_load_n(flag, __ATOMIC_ACQUIRE)) io_boot_poll(deadline, label);
}

static void io_boot_wait_count(uint32_t *counter, uint32_t target, const char *label)
{
    uint64_t deadline = io_boot_deadline();
    while (__atomic_load_n(counter, __ATOMIC_ACQUIRE) < target) io_boot_poll(deadline, label);
}

static bool io_boot_quiescent(process_t *process)
{
    uint64_t flags = scheduler_lock_acquire("io_boot_quiescent");
    bool ready = process->state == PROCESS_STATE_ZOMBIE && process_threads_quiescent_locked(process);
    scheduler_lock_release(flags);
    return ready;
}

static void io_boot_wait_quiescent(process_t *process, const char *label)
{
    uint64_t deadline = io_boot_deadline();
    while (!io_boot_quiescent(process)) io_boot_poll(deadline, label);
}

static bool io_boot_waiting(io_boot_caller_t *caller, wait_queue_t *expected)
{
    uint64_t flags = scheduler_lock_acquire("io_boot_waiting");
    spinlock_lock(&caller->process->threads_lock);
    thread_t *thread = caller->process->main_thread;
    bool ready = thread && thread->io_request && thread->state == THREAD_STATE_BLOCKED &&
                 thread->waiting_queue && (!expected || thread->waiting_queue == expected) &&
                 !thread->in_transition &&
                 __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE) == RUN_QUEUE_CPU_INVALID;
    for (uint32_t cpu = 0; ready && cpu < SMP_MAX_CPUS; ++cpu)
        if (__atomic_load_n(&g_current_threads[cpu], __ATOMIC_ACQUIRE) == thread ||
            __atomic_load_n(&g_switch_out_threads[cpu], __ATOMIC_ACQUIRE) == thread) ready = false;
    spinlock_unlock(&caller->process->threads_lock);
    scheduler_lock_release(flags);
    return ready;
}

static void io_boot_wait_caller(io_boot_caller_t *caller, wait_queue_t *expected, const char *label)
{
    uint64_t deadline = io_boot_deadline();
    while (!io_boot_waiting(caller, expected)) io_boot_poll(deadline, label);
}

static io_boot_shared_t *io_boot_cleanup_context(void)
{
    io_boot_shared_t *shared = __atomic_load_n(&g_io_boot_shared, __ATOMIC_ACQUIRE);
    process_t *process = process_current();
    thread_t *thread = thread_current();
    const char *name = thread ? process_thread_name_const(thread) : NULL;
    io_boot_require(shared && process && process->kernel_service && name &&
                    strcmp(name, "io-cleanup") == 0,
                    "cleanup worker owns finalization");
    io_boot_require(!spinlock_preempt_disabled() && (cpu_save_flags() & RFLAGS_IF_BIT),
                    "destructors outside scheduler/spinlocks");
    return shared;
}

static int io_boot_close_asset(void *context)
{
    io_boot_asset_t *asset = context;
    io_boot_shared_t *shared = io_boot_cleanup_context();
    io_boot_require(asset && asset->magic == IO_BOOT_MAGIC && asset->shared == shared, "live finalization asset");
    bool output = asset->output;
    asset->magic = 0;
    free(asset);
    __atomic_add_fetch(output ? &shared->output_closed : &shared->input_closed, 1u, __ATOMIC_RELEASE);
    return 0;
}

static void io_boot_release_cwd(void *context)
{
    io_boot_shared_t *shared = io_boot_cleanup_context();
    io_boot_require(context == shared->cwd, "captured cwd reference");
    vfs_node_release(context);
    __atomic_add_fetch(&shared->cwd_closed, 1u, __ATOMIC_RELEASE);
}

static const fd_ops_t g_io_boot_ops = {.close = io_boot_close_asset};

static fd_description_t *io_boot_description(io_boot_shared_t *shared, bool output)
{
    io_boot_asset_t *asset = calloc(1, sizeof(*asset));
    io_boot_require(asset != NULL, "asset allocation");
    asset->shared = shared;
    asset->magic = IO_BOOT_MAGIC;
    asset->output = output;
    fd_description_t *description = fd_description_create(&g_io_boot_ops, asset);
    io_boot_require(description != NULL, "description allocation");
    return description;
}

static void io_boot_handler(io_request_t *request, io_service_result_t *result)
{
    io_boot_job_t *job = io_request_buffer(request);
    io_boot_shared_t *shared = job->shared;
    io_boot_asset_t *input = fd_description_context(io_request_description(request));
    io_boot_require(!process_pointer_on_stack(job, sizeof(*job)) &&
                    !process_pointer_on_stack(result, sizeof(*result)), "heap operation and result records");
    io_boot_require(io_request_uid(request) == 37 && io_request_gid(request) == 41 &&
                    io_request_cwd(request) == shared->cwd, "explicit captured caller authority");
    io_boot_require(process_current()->kernel_service && process_get_uid(process_current()) == 0 &&
                    !spinlock_preempt_disabled(), "persistent worker context");
    io_boot_require(input && input->magic == IO_BOOT_MAGIC, "input reference before I/O");
    __atomic_add_fetch(&shared->handled, 1u, __ATOMIC_RELEASE);
    if (job->kind == 1)
    {
        job->busy = true; /* Represents storage-owned state across a blocking continuation. */
        __atomic_add_fetch(&shared->busy, 1u, __ATOMIC_RELEASE);
        __atomic_add_fetch(&shared->blocked, 1u, __ATOMIC_RELEASE);
        wait_queue_wait(&shared->storage_gate, io_boot_flag, &shared->release_storage);
        io_boot_require(job->busy && input->magic == IO_BOOT_MAGIC && io_request_cwd(request) == shared->cwd,
                        "running I/O survives killed caller");
        io_boot_require(io_request_status(request, &job->status) == 0 && job->status.cancelled,
                        "running request cancelled");
        __atomic_add_fetch(&shared->late_outputs, 1u, __ATOMIC_RELEASE);
        job->busy = false;
        __atomic_sub_fetch(&shared->busy, 1u, __ATOMIC_RELEASE);
    }
    memset(job->payload, 0x5a, sizeof(job->payload));
    result->description_owned = io_boot_description(shared, true);
    result->result = sizeof(job->payload);
}

static void io_boot_caller_entry(void *context)
{
    io_boot_caller_t *caller = context;
    wait_queue_wait(&caller->shared->caller_start, io_boot_flag, &caller->start);
    spinlock_preempt_disable();
    process_t *process = process_current();
    io_boot_require(io_service_request_create(caller->service, sizeof(io_boot_job_t), process->uid,
                                               process->gid, &caller->request) == 0, "caller prepare");
    io_boot_job_t *job = io_request_buffer(caller->request);
    job->shared = caller->shared;
    job->kind = caller->kind;
    vfs_node_t *cwd = process_current_cwd();
    vfs_node_retain(cwd);
    io_boot_require(io_request_bind(caller->request, io_boot_description(caller->shared, false),
                                     cwd, io_boot_release_cwd) == 0, "caller bind");
    io_boot_require(process_io_register_current(caller->request) == 0, "caller register");
    io_boot_require(io_service_submit(caller->service, caller->request) == 0, "caller submit");
    __atomic_store_n(&caller->submitted, true, __ATOMIC_RELEASE);
    spinlock_preempt_enable();

    int waited = process_io_wait_current(&caller->status);
    io_boot_require(waited == 0, "live caller completion");
    if (caller->hold_result)
    {
        __atomic_store_n(&caller->result_held, true, __ATOMIC_RELEASE);
        wait_queue_wait(&caller->shared->result_gate, io_boot_flag, &caller->shared->release_result);
    }
    spinlock_preempt_disable();
    int result = process_io_result_current(&caller->borrow, &caller->status);
    if (caller->hold_result)
        io_boot_require(result == -ECANCELED && caller->borrow == NULL, "shutdown cancellation observed");
    else
    {
        io_boot_require(result == 0 && caller->borrow && caller->status.result == IO_BOOT_PAYLOAD, "live result");
        io_boot_job_t *completed = io_request_buffer(caller->borrow);
        memcpy(caller->copied, completed->payload, sizeof(caller->copied));
        for (size_t index = 0; index < sizeof(caller->copied); ++index)
            io_boot_require(caller->copied[index] == 0x5a, "guarded result copy");
    }
    caller->borrow = NULL;
    caller->request = NULL;
    io_boot_require(process_io_finish_current(result != 0) == 0, "caller finish");
    __atomic_store_n(&caller->saw_cancel, result == -ECANCELED, __ATOMIC_RELEASE);
    __atomic_store_n(&caller->returned, true, __ATOMIC_RELEASE);
    spinlock_preempt_enable();
}

static void io_boot_start_caller(io_boot_control_t *control, unsigned index, uint32_t kind, bool hold_result)
{
    io_boot_caller_t *caller = &control->callers[index];
    caller->shared = control->shared;
    caller->service = control->service;
    caller->kind = kind;
    caller->hold_result = hold_result;
    caller->process = process_create_kernel_with_parent("io-test-caller", io_boot_caller_entry,
                                                         caller, 0, -1, process_current());
    io_boot_require(caller->process != NULL, "caller process allocation");
    process_set_identity(caller->process, 37, 41);
    process_set_cwd(caller->process, control->shared->cwd);
    __atomic_store_n(&caller->start, true, __ATOMIC_RELEASE);
    wait_queue_wake_all(&control->shared->caller_start);
    io_boot_wait_flag(&caller->submitted, "caller submission deadline");
}

static void io_boot_collect_caller(io_boot_caller_t *caller, bool kill)
{
    if (kill) io_boot_require(process_kill(caller->process, -7), "ordinary caller can be killed");
    io_boot_wait_quiescent(caller->process, "caller quiescence deadline");
    (void)process_join(caller->process, NULL);
    if (kill) io_boot_require(!__atomic_load_n(&caller->returned, __ATOMIC_ACQUIRE), "killed waiter never resumed");
    process_destroy(caller->process);
    caller->process = NULL;
    caller->request = NULL; /* Any obsolete observer pointer is no longer used. */
}

static void io_boot_probe_entry(void *context)
{
    io_boot_probe_t *probe = context;
    process_t *process = process_current();
    io_boot_require(process->kernel_service && process->parent == NULL, "probe protected and parentless");
    __atomic_store_n(&probe->self_kill_refused, !process_kill(process, -1), __ATOMIC_RELEASE);
    __atomic_store_n(&probe->entered, true, __ATOMIC_RELEASE);
    wait_queue_wait(&probe->gate, io_boot_flag, &probe->release);
}

static void io_boot_service_probes(void)
{
    io_boot_probe_t *probe = calloc(1, sizeof(*probe));
    io_boot_require(probe != NULL, "probe record");
    wait_queue_init(&probe->gate);
    probe->release = true;
    process_t *process = process_create_kernel_service("io-test-fast", io_boot_probe_entry, probe, 0);
    io_boot_require(process != NULL, "fast service creation");
    io_boot_wait_flag(&probe->entered, "fast service startup deadline");
    io_boot_wait_quiescent(process, "fast service exit deadline");
    process_sleep_ms(2); /* Give orphan reaping a chance while the factory owner remains. */
    io_boot_require(process->magic == PROCESS_MAGIC && __atomic_load_n(&process->join_waiters, __ATOMIC_ACQUIRE) == 1 &&
                    __atomic_load_n(&probe->self_kill_refused, __ATOMIC_ACQUIRE),
                    "exited service retained before owner join");
    io_boot_require(process_join_kernel_service(process, NULL) == 0, "fast service retained join");

    probe->release = probe->entered = probe->self_kill_refused = false;
    process = process_create_kernel_service("io-test-held", io_boot_probe_entry, probe, 0);
    io_boot_require(process != NULL, "held service creation");
    io_boot_wait_flag(&probe->entered, "held service startup deadline");
    io_boot_require(!process_kill(process, -1), "remote service kill refused");
    process_kill_tree(process);
    io_boot_require(!process_is_zombie(process) && __atomic_load_n(&probe->self_kill_refused, __ATOMIC_ACQUIRE),
                    "service tree kill refused");
    __atomic_store_n(&probe->release, true, __ATOMIC_RELEASE);
    wait_queue_wake_all(&probe->gate);
    io_boot_wait_quiescent(process, "held service exit deadline");
    io_boot_require(process_join_kernel_service(process, NULL) == 0, "held service retained join");
    free(probe);
    serial_printf("IO_SERVICE_TEST: retained factory probes PASS");
}

static void io_boot_stop_entry(void *context)
{
    io_boot_stopper_t *stopper = context;
    __atomic_store_n(&stopper->started, true, __ATOMIC_RELEASE);
    stopper->result = io_service_shutdown(stopper->service);
    __atomic_store_n(&stopper->done, true, __ATOMIC_RELEASE);
}

static process_t *io_boot_start_stopper(io_boot_control_t *control)
{
    control->stopper = (io_boot_stopper_t){.service = control->service};
    process_t *process = process_create_kernel_service("io-test-stop", io_boot_stop_entry, &control->stopper, 0);
    io_boot_require(process != NULL, "shutdown controller allocation");
    io_boot_wait_flag(&control->stopper.started, "shutdown controller startup deadline");
    uint64_t deadline = io_boot_deadline();
    do
    {
        io_boot_require(io_service_snapshot(control->service, &control->snapshot) == 0, "shutdown snapshot");
        if (!control->snapshot.stopping) io_boot_poll(deadline, "shutdown publication deadline");
    } while (!control->snapshot.stopping);
    return process;
}

static void io_boot_finish_stopper(io_boot_control_t *control, process_t *process)
{
    io_boot_wait_flag(&control->stopper.done, "shutdown completion deadline");
    io_boot_wait_quiescent(process, "shutdown controller quiescence deadline");
    io_boot_require(process_join_kernel_service(process, NULL) == 0 && control->stopper.result == 0,
                    "shutdown retained controller join");
    io_boot_require(io_service_destroy(control->service) == 0, "stopped service destruction");
    control->service = NULL;
}

bool io_service_boot_test(void)
{
    serial_printf("IO_SERVICE_TEST: start");
    io_boot_require(process_scheduler_ready() && !spinlock_preempt_disabled(), "boot controller can block");
    io_boot_service_probes();
    io_boot_control_t *control = calloc(1, sizeof(*control));
    io_boot_shared_t *shared = calloc(1, sizeof(*shared));
    io_boot_require(control && shared, "controller records");
    control->shared = shared;
    shared->cwd = vfs_root();
    vfs_node_retain(shared->cwd);
    wait_queue_init(&shared->caller_start);
    wait_queue_init(&shared->storage_gate);
    wait_queue_init(&shared->result_gate);
    __atomic_store_n(&g_io_boot_shared, shared, __ATOMIC_RELEASE);
    control->service = io_service_create(8, 2, io_boot_handler);
    io_boot_require(control->service != NULL, "executor creation");
    spinlock_preempt_disable();
    io_boot_require(io_service_shutdown(control->service) == -EINVAL && io_service_destroy(control->service) == -EINVAL,
                    "guarded control calls rejected");
    spinlock_preempt_enable();

    io_boot_start_caller(control, 0, 0, false);
    io_boot_wait_flag(&control->callers[0].returned, "normal caller result deadline");
    io_boot_collect_caller(&control->callers[0], false);
    io_boot_wait_count(&shared->input_closed, 1, "normal input cleanup deadline");
    io_boot_wait_count(&shared->output_closed, 1, "normal output cleanup deadline");
    io_boot_wait_count(&shared->cwd_closed, 1, "normal cwd cleanup deadline");

    for (unsigned index = 1; index <= 2; ++index)
    {
        io_boot_start_caller(control, index, 1, false);
        io_boot_wait_count(&shared->blocked, index, "running storage deadline");
        io_boot_wait_caller(&control->callers[index], NULL, "I/O waiter off-CPU deadline");
        io_boot_collect_caller(&control->callers[index], true);
    }
    io_boot_require(io_boot_count(&shared->input_closed) == 1 && io_boot_count(&shared->cwd_closed) == 1 &&
                    io_boot_count(&shared->busy) == 2,
                    "running ownership retained after caller deaths");
    io_boot_start_caller(control, 3, 0, false);
    io_boot_wait_caller(&control->callers[3], NULL, "queued waiter off-CPU deadline");
    io_boot_collect_caller(&control->callers[3], true);
    io_boot_wait_count(&shared->input_closed, 2, "independent queued cleanup deadline");
    io_boot_wait_count(&shared->cwd_closed, 2, "independent queued cwd deadline");
    io_boot_require(io_boot_count(&shared->handled) == 3 && io_boot_count(&shared->busy) == 2 &&
                    io_boot_count(&shared->output_closed) == 1,
                    "cleanup progresses while storage pool blocked");
    serial_printf("IO_SERVICE_TEST: independent cleanup PASS");

    process_t *stopper = io_boot_start_stopper(control);
    io_boot_require(!__atomic_load_n(&control->stopper.done, __ATOMIC_ACQUIRE) &&
                    control->snapshot.active_workers == 2 && io_service_shutdown(control->service) == -EBUSY,
                    "shutdown waits for active continuations");
    __atomic_store_n(&shared->release_storage, true, __ATOMIC_RELEASE);
    wait_queue_wake_all(&shared->storage_gate);
    io_boot_finish_stopper(control, stopper);
    io_boot_require(io_boot_count(&shared->input_closed) == 4 && io_boot_count(&shared->output_closed) == 3 &&
                    io_boot_count(&shared->cwd_closed) == 4 && io_boot_count(&shared->late_outputs) == 2 &&
                    io_boot_count(&shared->busy) == 0, "late results cleaned exactly once");

    control->service = io_service_create(2, 1, io_boot_handler);
    io_boot_require(control->service != NULL, "retained waiter executor");
    io_boot_start_caller(control, 4, 0, true);
    io_boot_wait_flag(&control->callers[4].result_held, "completed waiter retained deadline");
    io_boot_wait_caller(&control->callers[4], &shared->result_gate, "retained waiter off-CPU deadline");
    stopper = io_boot_start_stopper(control);
    uint64_t deadline = io_boot_deadline();
    do
    {
        io_boot_require(io_service_snapshot(control->service, &control->snapshot) == 0, "retained waiter snapshot");
        if (control->snapshot.active_workers) io_boot_poll(deadline, "storage stop deadline");
    } while (control->snapshot.active_workers);
    io_boot_require(control->snapshot.queue.live == 1 && !__atomic_load_n(&control->stopper.done, __ATOMIC_ACQUIRE) &&
                    io_boot_count(&shared->input_closed) == 4 && io_boot_count(&shared->output_closed) == 3,
                    "shutdown retains live waiter reference");
    __atomic_store_n(&shared->release_result, true, __ATOMIC_RELEASE);
    wait_queue_wake_all(&shared->result_gate);
    io_boot_wait_flag(&control->callers[4].returned, "cancelled retained waiter return deadline");
    io_boot_require(__atomic_load_n(&control->callers[4].saw_cancel, __ATOMIC_ACQUIRE),
                    "retained waiter observes shutdown cancellation");
    io_boot_collect_caller(&control->callers[4], false);
    io_boot_finish_stopper(control, stopper);
    io_boot_require(io_boot_count(&shared->input_closed) == 5 && io_boot_count(&shared->output_closed) == 4 &&
                    io_boot_count(&shared->cwd_closed) == 5,
                    "all request assets released");
    __atomic_store_n(&g_io_boot_shared, NULL, __ATOMIC_RELEASE);
    vfs_node_release(shared->cwd);
    free(shared);
    free(control);
    serial_printf("IO_SERVICE_TEST: PASS workers=2 cleanup=independent killed_callers=3 late_outputs=2 retained_join=1 waiter_shutdown=1");
    return true;
}
