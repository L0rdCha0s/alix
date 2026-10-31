#include "userlib.h"
#include "stdlib.h"
#include "serial.h"

extern int __cxa_thread_atexit_impl(void (*function)(void *), void *argument, void *dso);

typedef struct
{
    alix_thread_t main_thread;
    alix_thread_t first;
    alix_thread_t last;
    syscall_thread_info_t main_info;
    syscall_thread_info_t worker_info;
    volatile uint32_t gate;
    volatile uint32_t main_tls_done;
    volatile uint32_t main_joined;
    volatile uint32_t last_ready;
    volatile uint32_t failures;
    int main_status;
    int worker_status;
} state_t;

static state_t *state;

static void main_tls_cleanup(void *argument)
{
    state_t *shared = argument;
    __atomic_add_fetch(&shared->main_tls_done, 1u, __ATOMIC_RELEASE);
}

static void final_check(void)
{
    bool okay = state && state->failures == 0 && state->main_status == 0 &&
                state->worker_status == 0 && state->main_tls_done == 1 &&
                state->main_joined == 1 && state->last_ready == 1;
    serial_printf("MAIN_THREAD_EXIT_TEST: %s main_joined=%u tls=%u last=%u\n",
                  okay ? "PASS" : "FAIL", state->main_joined, state->main_tls_done, state->last_ready);
    free(state);
    if (!okay) _Exit(1);
}

static void first_worker(void *argument)
{
    state_t *shared = argument;
    while (!__atomic_load_n(&shared->gate, __ATOMIC_ACQUIRE)) sys_yield();
    if (sys_thread_info(0, &shared->worker_info) != 0 ||
        shared->worker_info.tid != sys_thread_self() ||
        (shared->worker_info.flags & SYSCALL_THREAD_INFO_MAIN) ||
        shared->worker_info.guard_size != 4096 || shared->worker_info.stack_size < 16384 ||
        alix_thread_join(shared->main_thread, &shared->main_status) != 0 ||
        __atomic_load_n(&shared->main_tls_done, __ATOMIC_ACQUIRE) != 1)
    {
        __atomic_add_fetch(&shared->failures, 1u, __ATOMIC_RELAXED);
    }
    __atomic_store_n(&shared->main_joined, 1u, __ATOMIC_RELEASE);
}

static void last_worker(void *argument)
{
    state_t *shared = argument;
    while (!__atomic_load_n(&shared->gate, __ATOMIC_ACQUIRE)) sys_yield();
    if (alix_thread_join(shared->first, &shared->worker_status) != 0 ||
        __atomic_load_n(&shared->main_joined, __ATOMIC_ACQUIRE) != 1)
    {
        __atomic_add_fetch(&shared->failures, 1u, __ATOMIC_RELAXED);
    }
    __atomic_store_n(&shared->last_ready, 1u, __ATOMIC_RELEASE);
    /* Returning through alix_thread_exit must run process finalizers once. */
}

int main(void)
{
    state = calloc(1, sizeof(*state));
    if (!state) return 1;
    state->main_thread = alix_thread_self();
    if (sys_thread_set_name(0, "main-exit-check") != 0 ||
        sys_thread_set_name(0, "012345678901234567890123456789012") != -34 ||
        sys_thread_info(0, &state->main_info) != 0 ||
        !(state->main_info.flags & SYSCALL_THREAD_INFO_MAIN) ||
        strcmp(state->main_info.name, "main-exit-check") != 0 ||
        sys_thread_info(0, NULL) != -14 ||
        atexit(final_check) != 0 ||
        __cxa_thread_atexit_impl(main_tls_cleanup, state, NULL) != 0 ||
        alix_thread_create(&state->first, "join_main", first_worker, state) != 0 ||
        alix_thread_create(&state->last, "last_exit", last_worker, state) != 0)
    {
        serial_printf("MAIN_THREAD_EXIT_TEST: FAIL setup\n");
        _Exit(1);
    }
    __atomic_store_n(&state->gate, 1u, __ATOMIC_RELEASE);
    alix_thread_exit(0);
}
