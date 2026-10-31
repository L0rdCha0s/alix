#!/usr/bin/env python3
"""Execute scheduler selection with an interrupt injected at unsafe unlocks."""

from pathlib import Path
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run, function_definition

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    scheduler = (ROOT / "src/kernel/process/process_scheduler.c").read_text()
    handoff = function_definition(scheduler, "static bool switch_to_thread")
    locked_argument = "uint64_t sched_lock_enter" in handoff[:handoff.index("{")]
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(c, m) do { if (!(c)) { fprintf(stderr, "%s\n", m); exit(1); } } while (0)
#define RUN_QUEUE_CPU_INVALID UINT32_MAX
#define THREAD_STATE_READY 0
#define THREAD_STATE_RUNNING 1
#define THREAD_STATE_BLOCKED 2
#define THREAD_STATE_ZOMBIE 3
#define THREAD_PRIORITY_NORMAL 1
#define THREAD_PRIORITY_UI 2
typedef struct { bool locked; } spinlock_t;
typedef struct thread {
    unsigned state; bool is_idle, wake_pending, preempt_pending, in_transition, context_valid, in_run_queue;
    uint32_t running_cpu, time_slice_remaining; uint64_t last_scheduled_tick; spinlock_t context_lock;
    bool affinity_enabled; uint32_t affinity_cpu, priority;
} thread_t;
typedef struct { uint32_t total; } run_queue_t;
static thread_t current, selected[2], idle;
static thread_t *g_idle_threads[2] = {&idle, &idle};
static run_queue_t run_queue;
static uint64_t g_scheduler_switch_count, g_cpu_switch_counts[2];
static bool scheduler_locked, claimed, reject_first;
static uint64_t irq_flags, last_saved_flags;
static unsigned current_cpu, selections, switches, unsafe_unlocks;
static bool empty_local, switched_to_idle, cpu_online[2] = {true, true};
static uint32_t g_ui_cpu_index = RUN_QUEUE_CPU_INVALID;
static unsigned enqueues, empty_dequeues;
static uint32_t expected_enqueue_cpu, enqueued_cpu;
static uint32_t __attribute__((unused)) scheduler_cpu_limit(void) { return 2; }
static bool __attribute__((unused)) scheduler_cpu_online(uint32_t cpu) { return cpu < 2 && cpu_online[cpu]; }
static uint64_t timer_ticks(void) { return 20; }
static uint32_t current_cpu_index(void) { return current_cpu; }
static thread_t *current_thread_local(void) { return &current; }
static bool thread_assert_stack_current(thread_t *t, const char *where) { (void)t; (void)where; return true; }
static void process_exit(int code) { (void)code; abort(); }
static void fatal(const char *message) { fprintf(stderr, "%s\n", message); abort(); }
static uint32_t scheduler_time_slice_ticks(void) { return 10; }
static void scheduler_log_if_stalled(const char *where, uint64_t start) { (void)where; (void)start; }
static void scheduler_log_running_cpu_change(thread_t *t, uint32_t cpu, const char *why) { (void)t; (void)cpu; (void)why; }
static void spinlock_lock(spinlock_t *lock) { CHECK(!lock->locked, "nested context lock"); lock->locked = true; }
static void spinlock_unlock(spinlock_t *lock) { CHECK(lock->locked, "unowned context lock"); lock->locked = false; }
static const char *scheduler_thread_name(thread_t *t) { (void)t; return "test"; }
static uint64_t scheduler_thread_pid(thread_t *t) { (void)t; return 1; }
static const char *thread_state_name(unsigned state) { (void)state; return "test"; }
static bool thread_in_run_queue_load(thread_t *t) { return t->in_run_queue; }
static void log_discard(const char *format, ...) { (void)format; }
#define SCHED_LOG(...) log_discard(__VA_ARGS__)
static uint64_t scheduler_lock_acquire(const char *where)
{
    (void)where; CHECK(!scheduler_locked, "scheduler lock acquired recursively");
    uint64_t previous = irq_flags; irq_flags &= ~512ULL; scheduler_locked = true; return previous;
}
static void scheduler_lock_release(uint64_t flags)
{
    CHECK(scheduler_locked, "unowned scheduler lock release"); scheduler_locked = false; irq_flags = flags;
    /* Another CPU may terminate the unprotected claim even with local IF=0.
     * With IF=1, local timer preemption can also interleave in this window. */
    if (claimed) unsafe_unlocks++;
}
static run_queue_t *scheduler_run_queue(uint32_t cpu) { (void)cpu; return &run_queue; }
static uint64_t run_queue_lock_acquire(run_queue_t *queue, const char *where)
{ (void)queue; (void)where; CHECK(scheduler_locked, "queue selected without scheduler lock"); return irq_flags; }
static void run_queue_lock_release(run_queue_t *queue, uint64_t flags) { (void)queue; (void)flags; }
static void enqueue_current_thread_local(thread_t *t)
{
    CHECK(scheduler_locked && !(irq_flags & 512), "unprotected current enqueue");
    t->in_run_queue = true; enqueues++; enqueued_cpu = expected_enqueue_cpu;
}
static thread_t *dequeue_thread_for_cpu(uint32_t cpu, thread_t *skip)
{
    (void)skip; CHECK(scheduler_locked && !(irq_flags & 512), "unprotected dequeue");
    if (empty_local) { empty_dequeues++; return NULL; }
    CHECK(cpu == current_cpu, "retry used pre-migration CPU index"); CHECK(selections < 2, "selection retry loop");
    thread_t *next = &selected[selections++];
    next->state = THREAD_STATE_READY; next->running_cpu = cpu; next->in_transition = true;
    claimed = true; return next;
}
static void scheduler_log_pick(thread_t *cur, thread_t *next, uint32_t cpu, const char *why)
{ (void)cur; (void)next; (void)cpu; (void)why; }
static void scheduler_trace(const char *why, thread_t *t) { (void)why; (void)t; }
static void process_reap_orphans(void) { CHECK(!scheduler_locked && !claimed, "handoff left scheduler locked or thread claimed"); }
static void process_reap_retired_memory(void) { CHECK(!scheduler_locked, "memory reaper called under scheduler lock"); }
'''
    program += "static bool switch_to_thread(thread_t *next" + (", uint64_t flags" if locked_argument else "") + ")\n{\n"
    if not locked_argument:
        program += 'uint64_t flags = scheduler_lock_acquire("old-switch");\n'
    program += r'''
    CHECK(unsafe_unlocks == 0, "dequeued thread claim exposed before context handoff");
    CHECK(scheduler_locked && !(irq_flags & 512), "handoff did not own scheduler lock with interrupts masked");
    switches++; last_saved_flags = flags;
    switched_to_idle = next->is_idle;
    if (reject_first && switches == 1)
    {
        next->state = THREAD_STATE_ZOMBIE; next->in_transition = false; next->running_cpu = RUN_QUEUE_CPU_INVALID;
        claimed = false; scheduler_lock_release(flags); current_cpu = 1; return false;
    }
    next->state = THREAD_STATE_RUNNING; next->in_transition = false;
    claimed = false; scheduler_lock_release(flags); return true;
}
'''
    if "static uint32_t scheduler_required_cpu" in scheduler:
        program += function_definition(scheduler, "static uint32_t scheduler_required_cpu") + "\n"
    program += function_definition(scheduler, "void scheduler_schedule") + "\n"
    program += r'''
static void reset(bool irq_enabled, bool retry)
{
    current = (thread_t){.state = THREAD_STATE_BLOCKED};
    selected[0] = selected[1] = (thread_t){0}; idle = (thread_t){.is_idle = true};
    scheduler_locked = claimed = false; reject_first = retry;
    irq_flags = 2 | (irq_enabled ? 512 : 0); last_saved_flags = 0;
    current_cpu = selections = switches = unsafe_unlocks = 0; run_queue.total = 0;
    empty_local = switched_to_idle = false; enqueues = empty_dequeues = 0;
    enqueued_cpu = expected_enqueue_cpu = RUN_QUEUE_CPU_INVALID;
    g_ui_cpu_index = RUN_QUEUE_CPU_INVALID; cpu_online[0] = cpu_online[1] = true;
}
int main(void)
{
    for (unsigned enabled = 0; enabled < 2; enabled++)
        for (unsigned retry = 0; retry < 2; retry++)
        {
            reset(enabled, retry); uint64_t initial_flags = irq_flags;
            scheduler_schedule(false);
            CHECK(selections == 1u + retry && switches == selections, "handoff did not retry rejected context");
            CHECK(last_saved_flags == initial_flags && irq_flags == initial_flags, "handoff lost original interrupt flags");
            CHECK(!scheduler_locked && !claimed && unsafe_unlocks == 0, "incomplete scheduler handoff");
        }
    reset(true, false); current.state = THREAD_STATE_RUNNING;
    scheduler_schedule(true);
    CHECK(selections == 0 && switches == 0 && !scheduler_locked && (irq_flags & 512), "run-current fast path changed");

    /* A current thread pinned elsewhere must yield its stack even when the
     * local run queue is empty. Unbound/same-CPU threads retain the fast path. */
    for (unsigned enabled = 0; enabled < 2; ++enabled)
        for (unsigned scenario = 0; scenario < 8; ++scenario)
        {
            reset(enabled, false); current.state = THREAD_STATE_RUNNING;
            current.priority = THREAD_PRIORITY_NORMAL; empty_local = true;
            bool migrate = false;
            if (scenario == 1) { current.affinity_enabled = true; current.affinity_cpu = 0; }
            if (scenario == 2) { current.affinity_enabled = true; current.affinity_cpu = 1; migrate = true; }
            if (scenario == 3) { current.priority = THREAD_PRIORITY_UI; g_ui_cpu_index = 1; migrate = true; }
            if (scenario == 4) { current.priority = THREAD_PRIORITY_UI; g_ui_cpu_index = 0; }
            if (scenario == 5) {
                current.priority = THREAD_PRIORITY_UI; g_ui_cpu_index = 1;
                current.affinity_enabled = true; current.affinity_cpu = 0;
            }
            if (scenario == 6) { current.affinity_enabled = true; current.affinity_cpu = 2; }
            if (scenario == 7) {
                current.affinity_enabled = true; current.affinity_cpu = 1; cpu_online[1] = false;
            }
            uint64_t initial_flags = irq_flags; expected_enqueue_cpu = 1;
            scheduler_schedule(true);
            CHECK(irq_flags == initial_flags && !scheduler_locked && !claimed,
                  "affinity handoff changed interrupt state or retained scheduler ownership");
            if (migrate) {
                CHECK(enqueues == 1 && enqueued_cpu == 1 && current.in_run_queue,
                      "lone thread pinned to another CPU was not enqueued for migration");
                CHECK(switches == 1 && switched_to_idle && empty_dequeues == 2,
                      "lone migrating thread did not hand its stack to idle");
                CHECK(last_saved_flags == initial_flags, "migration lost original interrupt flags");
            } else {
                CHECK(enqueues == 0 && switches == 0 && empty_dequeues == 0,
                      "unbound/same-CPU fast path changed");
            }
        }
    puts("scheduler handoff test passed"); return 0;
}
'''
    compile_and_run("scheduler-handoff", program)
    print("scheduler handoff test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"scheduler handoff test failed: {error}", file=sys.stderr)
        raise SystemExit(1)
