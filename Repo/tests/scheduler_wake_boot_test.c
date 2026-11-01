#include "process_internal.h"
#include "heap.h"

typedef struct
{
    process_t *peer, *controller;
    thread_t *self;
    uint32_t cpu, peer_runs;
    bool start, release;
    bool saved_process_affinity, saved_thread_affinity;
    uint32_t saved_process_cpu, saved_thread_cpu;
    const char *failure;
} scheduler_wake_state_t;

static void scheduler_wake_peer(void *argument)
{
    scheduler_wake_state_t *state = argument;
    while (!__atomic_load_n(&state->start, __ATOMIC_ACQUIRE)) process_sleep_ms(1);
    while (!__atomic_load_n(&state->release, __ATOMIC_ACQUIRE))
    {
        __atomic_add_fetch(&state->peer_runs, 1u, __ATOMIC_RELEASE);
        process_yield();
    }
}

static bool scheduler_wake_peer_ready(scheduler_wake_state_t *state)
{
    uint64_t flags = scheduler_lock_acquire("wake_park_probe");
    spinlock_lock(&state->peer->threads_lock);
    thread_t *peer = state->peer->main_thread;
    bool ready = peer && peer->state == THREAD_STATE_READY && thread_in_run_queue_load(peer) &&
                 !peer->in_transition &&
                 __atomic_load_n(&peer->running_cpu, __ATOMIC_ACQUIRE) == RUN_QUEUE_CPU_INVALID;
    spinlock_unlock(&state->peer->threads_lock);
    scheduler_lock_release(flags);
    return ready;
}

bool scheduler_wake_boot_test(void)
{
    scheduler_wake_state_t *state = calloc(1, sizeof(*state));
    if (!state) { serial_printf("SCHEDULER_WAKE_TEST: FAIL controller allocation"); return false; }
    state->controller = process_current();
    state->self = thread_current();
    state->cpu = smp_current_cpu_index();
    uint64_t flags = scheduler_lock_acquire("wake_park_save");
    spinlock_lock(&state->controller->threads_lock);
    state->saved_process_affinity = state->controller->default_affinity_enabled;
    state->saved_process_cpu = state->controller->default_affinity_cpu;
    state->saved_thread_affinity = state->self->affinity_enabled;
    state->saved_thread_cpu = state->self->affinity_cpu;
    spinlock_unlock(&state->controller->threads_lock);
    scheduler_lock_release(flags);
#define REQUIRE(test,label) do { if (!(test)) { state->failure=(label); goto failed; } } while (0)
    serial_printf("SCHEDULER_WAKE_TEST: start runnable waiter park intent");
    process_set_affinity(state->controller, state->cpu);
    state->peer = process_create_kernel_service("wake-park-peer", scheduler_wake_peer, state, 0);
    REQUIRE(state->peer, "create retained peer");
    process_set_affinity(state->peer, state->cpu);
    __atomic_store_n(&state->start, true, __ATOMIC_RELEASE);
    uint64_t deadline = timer_ticks() + (uint64_t)timer_frequency() * 5u;
    while (!scheduler_wake_peer_ready(state) && timer_ticks() < deadline) process_yield();
    REQUIRE(scheduler_wake_peer_ready(state), "same-CPU runnable peer");
    for (unsigned count = 0; count < 32; ++count)
    {
        /* This is exactly the state after an early wake/nested preemption:
         * the old wait call still asks to park, while current is RUNNING and
         * another thread is ready. Old code discards the caller here. */
        scheduler_schedule(false);
        REQUIRE(smp_current_cpu_index() == state->cpu && thread_current() == state->self,
                "caller ownership after stale park");
    }
    REQUIRE(__atomic_load_n(&state->peer_runs, __ATOMIC_ACQUIRE) != 0, "peer ran");
    __atomic_store_n(&state->release, true, __ATOMIC_RELEASE);
    REQUIRE(process_join_kernel_service(state->peer, NULL) == 0, "peer quiescent join"); state->peer = NULL;
    flags = scheduler_lock_acquire("wake_park_restore");
    spinlock_lock(&state->controller->threads_lock);
    state->controller->default_affinity_enabled = state->saved_process_affinity;
    state->controller->default_affinity_cpu = state->saved_process_cpu;
    state->self->affinity_enabled = state->saved_thread_affinity;
    state->self->affinity_cpu = state->saved_thread_cpu;
    spinlock_unlock(&state->controller->threads_lock);
    scheduler_lock_release(flags);
    free(state);
    serial_printf("SCHEDULER_WAKE_TEST: PASS stale_park=32 runnable_preserved=1 peer_progress=1 retained_join=1");
    return true;
failed:
    __atomic_store_n(&state->release, true, __ATOMIC_RELEASE);
    serial_printf("SCHEDULER_WAKE_TEST: FAIL %s", state->failure ? state->failure : "unknown");
    return false; /* Keep heap state/registered owners for debugger evidence. */
#undef REQUIRE
}
