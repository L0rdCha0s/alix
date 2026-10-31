#!/usr/bin/env python3
"""Execute native futex and condition code at the wake-before-sleep boundary."""

from pathlib import Path
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run, function_definition

ROOT = Path(__file__).resolve().parents[1]


def kernel_test():
    source = (ROOT / "src/kernel/process/process_futex.c").read_text()
    source = source.replace('#include "process_internal.h"', '')
    program = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
#define SYSCALL_FUTEX_WAIT_FOREVER UINT32_MAX
#define SYSCALL_FUTEX_OK 0
#define SYSCALL_FUTEX_AGAIN (-11)
#define SYSCALL_FUTEX_INTERRUPTED (-4)
#define EINTR 4
#define SYSCALL_FUTEX_FAULT (-14)
#define SYSCALL_FUTEX_INVALID (-22)
#define SYSCALL_FUTEX_TIMED_OUT (-110)
#define ADDRESS ((uintptr_t)0x100001000ULL)
typedef unsigned spinlock_t;
typedef struct { unsigned wakes; } wait_queue_t;
typedef struct process process_t;
typedef struct thread {
    process_t *process;
    struct thread *process_next;
    bool is_user, pending_destroy, exited, live;
    wait_queue_t futex_queue;
    uintptr_t futex_address;
    bool futex_waiting, futex_notified, futex_interrupted, signal_pending;
} thread_t;
struct process { bool is_user; spinlock_t threads_lock; thread_t *threads; };
static process_t process, other;
static thread_t threads[5], outsider;
static thread_t *current;
static bool scheduler_locked, inject_wake, inject_interrupt;
static bool process_signal_pending_locked(thread_t *thread) { CHECK(scheduler_locked);return thread->signal_pending; }
static unsigned waits;
static uint32_t word;
static uint64_t waited_ticks;
static thread_t *current_thread_local(void) { return current; }
static bool user_ptr_range_valid(const void *p, size_t bytes)
{ return (uintptr_t)p >= ADDRESS && (uintptr_t)p + bytes <= ADDRESS + 8192; }
static uint64_t scheduler_lock_acquire(const char *where)
{ (void)where; CHECK(!scheduler_locked); scheduler_locked = true; return 512; }
static void scheduler_lock_release(uint64_t flags)
{ CHECK(scheduler_locked && flags == 512); scheduler_locked = false; }
static void spinlock_lock(spinlock_t *lock) { CHECK(scheduler_locked && !*lock); *lock = 1; }
static void spinlock_unlock(spinlock_t *lock) { CHECK(scheduler_locked && *lock); *lock = 0; }
static bool process_memory_read_user_u32(process_t *p, uintptr_t address, uint32_t *value)
{ CHECK(scheduler_locked && p == current->process); if (address != ADDRESS) return false; *value = word; return true; }
static void wait_queue_init(wait_queue_t *queue) { queue->wakes = 0; }
static bool thread_lifetime_active(thread_t *thread) { return thread->live; }
static uint32_t timer_frequency(void) { return 100; }
static void wait_queue_wake_all_locked(wait_queue_t *queue)
{ CHECK(scheduler_locked); ++queue->wakes; }
int process_futex_wake(uintptr_t, uint32_t);
static bool injected_wait(wait_queue_t *queue, bool (*predicate)(void *), void *context)
{
    CHECK(!scheduler_locked && queue == &current->futex_queue && context == current);
    ++waits;
    if (inject_interrupt) { current->futex_interrupted = true; current->futex_notified = true; }
    if (inject_wake) {
        thread_t *waiter = current;
        current = &threads[0];
        CHECK(process_futex_wake(ADDRESS, 1) == 1);
        current = waiter;
        CHECK(predicate(context));
    }
    return predicate(context);
}
static void wait_queue_wait(wait_queue_t *queue, bool (*predicate)(void *), void *context)
{ CHECK(injected_wait(queue, predicate, context)); }
static bool wait_queue_wait_timeout(wait_queue_t *queue, bool (*predicate)(void *), void *context, uint64_t ticks)
{ waited_ticks = ticks; return injected_wait(queue, predicate, context); }
'''
    program += source
    program += r'''
static void reset(void)
{
    memset(&process, 0, sizeof(process)); memset(&other, 0, sizeof(other));
    memset(threads, 0, sizeof(threads)); memset(&outsider, 0, sizeof(outsider));
    process.is_user = other.is_user = true; process.threads = threads;
    for (unsigned i = 0; i < 5; ++i) {
        threads[i].process = &process; threads[i].is_user = threads[i].live = true;
        threads[i].process_next = i < 4 ? &threads[i + 1] : NULL;
    }
    outsider.process = &other; outsider.is_user = outsider.live = true; other.threads = &outsider;
    current = &threads[1]; scheduler_locked = inject_wake = inject_interrupt = false; waits = 0; word = 7; waited_ticks = 0;
}
int main(void)
{
    reset();
    CHECK(process_futex_wait(0, 7, UINT32_MAX) == SYSCALL_FUTEX_INVALID);
    CHECK(process_futex_wait(ADDRESS + 1, 7, UINT32_MAX) == SYSCALL_FUTEX_INVALID);
    CHECK(process_futex_wait(ADDRESS + 4096, 7, UINT32_MAX) == SYSCALL_FUTEX_FAULT);
    CHECK(process_futex_wait(ADDRESS, 6, UINT32_MAX) == SYSCALL_FUTEX_AGAIN);
    CHECK(process_futex_wait(ADDRESS, 7, 0) == SYSCALL_FUTEX_TIMED_OUT);
    CHECK(waits == 0 && !current->futex_waiting);

    inject_wake = true;
    CHECK(process_futex_wait(ADDRESS, 7, UINT32_MAX) == 0);
    CHECK(waits == 1 && !current->futex_waiting && current->futex_address == 0);
    CHECK(current->futex_queue.wakes == 1);
    CHECK(process_futex_wake(ADDRESS, 1) == 0);

    inject_wake = false;
    CHECK(process_futex_wait(ADDRESS, 7, 11) == SYSCALL_FUTEX_TIMED_OUT);
    CHECK(waited_ticks == 2 && !current->futex_waiting);
    CHECK(process_futex_wait(ADDRESS, 7, 1) == SYSCALL_FUTEX_TIMED_OUT && waited_ticks == 1);

    current->signal_pending = true;
    CHECK(process_futex_wait(ADDRESS, 7, UINT32_MAX) == SYSCALL_FUTEX_INTERRUPTED);
    current->signal_pending = false; inject_interrupt = true;
    CHECK(process_futex_wait(ADDRESS, 7, UINT32_MAX) == SYSCALL_FUTEX_INTERRUPTED);
    CHECK(!current->futex_waiting && !current->futex_interrupted);
    reset(); current = &threads[0];
    for (unsigned i = 1; i < 5; ++i) { threads[i].futex_waiting = true; threads[i].futex_address = ADDRESS; }
    threads[3].exited = true; threads[4].pending_destroy = true;
    CHECK(process_futex_wake(ADDRESS, 0) == 0);
    CHECK(process_futex_wake(ADDRESS, 1) == 1);
    CHECK(threads[1].futex_notified && !threads[2].futex_notified);
    CHECK(process_futex_wake(ADDRESS, UINT32_MAX) == 1);
    CHECK(process_futex_wake(ADDRESS, UINT32_MAX) == 0);
    threads[2].futex_notified = false;
    current = &outsider;
    CHECK(process_futex_wake(ADDRESS, UINT32_MAX) == 0 && !threads[2].futex_notified);
    CHECK(process_futex_wake(ADDRESS + 1, 1) == SYSCALL_FUTEX_INVALID);
    CHECK(!scheduler_locked);
    puts("futex registration/wake/timeout/isolation tests passed");
}
'''
    compile_and_run("futex-contract", program)


def condition_test():
    libc = (ROOT / "user/lib/libc.c").read_text()
    program = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
#define SYSCALL_FUTEX_OK 0
#define SYSCALL_FUTEX_AGAIN (-11)
#define SYSCALL_FUTEX_INTERRUPTED (-4)
#define EINTR 4
#define SYSCALL_FUTEX_INVALID (-22)
#define SYSCALL_FUTEX_TIMED_OUT (-110)
#define ALIX_WAIT_FOREVER UINT32_MAX
typedef struct { uint32_t state; } alix_mutex_t;
typedef struct { volatile uint32_t sequence; } alix_cond_t;
static alix_mutex_t *expected_mutex;
static int wait_result;
static bool signal_before_wait;
static uint32_t wake_count, wait_timeout, interrupted_waits;
static uint64_t milliseconds;
static uint64_t sys_monotonic_millis(void) { return milliseconds; }
static void alix_mutex_unlock(alix_mutex_t *m) { CHECK(m == expected_mutex && m->state == 1); m->state = 0; }
static void alix_mutex_lock(alix_mutex_t *m) { CHECK(m == expected_mutex && m->state == 0); m->state = 1; }
static int sys_futex_wait(volatile uint32_t *word, uint32_t expected, uint32_t timeout)
{
    CHECK(expected_mutex->state == 0); wait_timeout = timeout;
    if (interrupted_waits) { --interrupted_waits; milliseconds += 7; return -EINTR; }
    if (signal_before_wait) __atomic_add_fetch(word, 1u, __ATOMIC_RELEASE);
    return *word != expected ? SYSCALL_FUTEX_AGAIN : wait_result;
}
static int sys_futex_wake(volatile uint32_t *word, uint32_t count) { (void)word; wake_count = count; return 0; }
'''
    for function in ("void alix_cond_init", "int alix_cond_timedwait", "int alix_cond_wait",
                     "int alix_cond_signal", "int alix_cond_broadcast"):
        program += function_definition(libc, function) + "\n"
    program += r'''
int main(void)
{
    alix_cond_t *condition = calloc(1, sizeof(*condition));
    expected_mutex = calloc(1, sizeof(*expected_mutex)); CHECK(condition && expected_mutex);
    alix_cond_init(condition); expected_mutex->state = 1;
    signal_before_wait = true;
    CHECK(alix_cond_wait(condition, expected_mutex) == 0);
    CHECK(expected_mutex->state == 1 && wait_timeout == UINT32_MAX);
    signal_before_wait = false; wait_result = SYSCALL_FUTEX_TIMED_OUT;
    CHECK(alix_cond_timedwait(condition, expected_mutex, 20) == SYSCALL_FUTEX_TIMED_OUT);
    CHECK(expected_mutex->state == 1 && wait_timeout == 20);
    interrupted_waits = 2; milliseconds = 100;
    CHECK(alix_cond_timedwait(condition, expected_mutex, 20) == SYSCALL_FUTEX_TIMED_OUT);
    CHECK(wait_timeout == 6 && expected_mutex->state == 1);
    interrupted_waits = 3;
    CHECK(alix_cond_timedwait(condition, expected_mutex, 20) == SYSCALL_FUTEX_TIMED_OUT);
    CHECK(milliseconds == 135 && expected_mutex->state == 1);
    wait_result = -14;
    CHECK(alix_cond_wait(condition, expected_mutex) == -14 && expected_mutex->state == 1);
    uint32_t sequence = condition->sequence;
    CHECK(alix_cond_signal(condition) == 0 && wake_count == 1 && condition->sequence == sequence + 1);
    CHECK(alix_cond_broadcast(condition) == 0 && wake_count == UINT32_MAX && condition->sequence == sequence + 2);
    CHECK(alix_cond_wait(NULL, expected_mutex) == SYSCALL_FUTEX_INVALID && expected_mutex->state == 1);
    CHECK(alix_cond_signal(NULL) == SYSCALL_FUTEX_INVALID);
    free(condition); free(expected_mutex);
    puts("condition unlock/register/relock tests passed");
}
'''
    compile_and_run("condition-contract", program)


def mutex_test():
    libc = (ROOT / "user/lib/libc.c").read_text()
    program = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #c); abort(); } } while (0)
#define SYSCALL_FUTEX_WAIT_FOREVER UINT32_MAX
#define SYSCALL_FUTEX_OK 0
#define SYSCALL_FUTEX_AGAIN (-11)
#define SYSCALL_FUTEX_INTERRUPTED (-4)
#define EINTR 4
#define ENOSYS 38
typedef struct { volatile uint32_t state; } alix_mutex_t;
static alix_mutex_t mutex;
static unsigned calls, wakes, yields, mode;
static int fatal_status;
static jmp_buf failure;
static void mutex_exit(int status) { fatal_status = status; longjmp(failure, 1); }
static void serial_printf(const char *format, ...) { (void)format; }
static int sys_futex_wait(volatile uint32_t *word, uint32_t expected, uint32_t timeout)
{
    CHECK(word == &mutex.state && *word == 2 && expected == 2 && timeout == UINT32_MAX);
    ++calls;
    if (mode == 2) return -ENOSYS;
    if (mode == 3 && calls == 1) return 0; /* A spurious return never grants ownership. */
    if (mode == 4) return -14;
    if (mode == 5 && calls == 1) return -EINTR;
    __atomic_store_n(word, 0, __ATOMIC_RELEASE);
    return mode == 0 ? SYSCALL_FUTEX_AGAIN : 0;
}
static int sys_yield(void) { ++yields; __atomic_store_n(&mutex.state, 0, __ATOMIC_RELEASE); return 0; }
static int sys_futex_wake(volatile uint32_t *word, uint32_t count)
{ CHECK(word == &mutex.state && *word == 0 && count == 1); ++wakes; return 1; }
#define exit mutex_exit
'''
    for function in ("void alix_mutex_init", "void alix_mutex_lock", "void alix_mutex_unlock"):
        program += function_definition(libc, function) + "\n"
    program += r'''
int main(void)
{
    alix_mutex_init(&mutex);
    alix_mutex_lock(&mutex);
    CHECK(mutex.state == 1 && calls == 0);
    alix_mutex_unlock(&mutex); CHECK(mutex.state == 0 && wakes == 0);
    for (mode = 0; mode < 4; ++mode) {
        calls = wakes = yields = 0; mutex.state = 1;
        alix_mutex_lock(&mutex);
        CHECK(mutex.state == 2 && calls == (mode == 3 ? 2u : 1u));
        CHECK(yields == (mode == 2 ? 1u : 0u));
        alix_mutex_unlock(&mutex); CHECK(mutex.state == 0 && wakes == 1);
    }
    mode = 5; mutex.state = 1; calls = 0;
    alix_mutex_lock(&mutex); CHECK(calls == 2 && mutex.state == 2); alix_mutex_unlock(&mutex);
    mode = 4; mutex.state = 1;
    if (setjmp(failure) == 0) { alix_mutex_lock(&mutex); CHECK(false); }
    CHECK(fatal_status == 1 && mutex.state == 2);
    puts("mutex contention/wake-before-wait/unsupported-host tests passed");
}
'''
    compile_and_run("mutex-contract", program)


if __name__ == "__main__":
    kernel_test()
    condition_test()
    mutex_test()
    print("futex and condition contract tests passed")
