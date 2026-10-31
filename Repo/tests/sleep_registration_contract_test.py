#!/usr/bin/env python3
"""Check scheduler-serialized sleep registration against termination and wake."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run, function_definition

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/kernel/process/process_api.c").read_text()
program = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define THREAD_STATE_RUNNING 1
#define THREAD_STATE_BLOCKED 2
#define THREAD_STATE_ZOMBIE 3
#define PROCESS_STATE_ZOMBIE 3
#define SCHED_SLEEP_LOG(...) ((void)0)
typedef struct { int state; } process_t;
typedef struct {
    process_t *process; int state;
    bool is_idle, alive, exited, pending_destroy, wake_pending, sleeping;
    uint64_t sleep_until_tick;
} thread_t;
static process_t process;
static thread_t thread;
static bool locked, guard, absent, kill_before_lock, kill_after_registration, wake_after_registration;
static uint64_t flags, ticks;
static unsigned schedules, yields, inserted;
static void terminate(void) {
    thread.state = THREAD_STATE_ZOMBIE; thread.exited = true; thread.sleeping = false;
    thread.wake_pending = false; process.state = PROCESS_STATE_ZOMBIE;
}
static uint64_t scheduler_lock_acquire(const char *why) {
    (void)why; assert(!locked);
    if (kill_before_lock) { kill_before_lock = false; terminate(); }
    uint64_t saved = flags; flags &= ~512ULL; locked = true; return saved;
}
static void scheduler_lock_release(uint64_t saved) {
    assert(locked); locked = false; flags = saved;
    if (kill_after_registration && inserted) { kill_after_registration = false; terminate(); }
    if (wake_after_registration && inserted) {
        wake_after_registration = false; thread.sleeping = false; thread.wake_pending = true;
    }
}
static bool spinlock_preempt_disabled(void) { return guard; }
static thread_t *current_thread_local(void) { assert(locked); return absent ? NULL : &thread; }
static bool thread_lifetime_active(thread_t *value) { return value->alive; }
static uint64_t timer_ticks(void) { assert(locked); return ticks; }
static void sleep_queue_insert(thread_t *value) {
    assert(locked && !(flags & 512) && value == &thread && value->state == THREAD_STATE_BLOCKED);
    assert(!value->exited && !value->sleeping && !value->wake_pending);
    value->sleeping = true; ++inserted;
}
static void process_yield(void) { assert(!locked); ++yields; }
static void scheduler_schedule(bool requeue) { assert(!locked && !requeue); ++schedules; }
'''
program += function_definition(source, "void process_sleep_ticks(")
program += r'''
static void reset(unsigned enabled) {
    process = (process_t){0};
    thread = (thread_t){.process = &process, .state = THREAD_STATE_RUNNING, .alive = true};
    locked = guard = absent = kill_before_lock = kill_after_registration = wake_after_registration = false;
    flags = 2 | (enabled ? 512 : 0); ticks = 100; schedules = yields = inserted = 0;
}
int main(void) {
    for (unsigned enabled = 0; enabled < 2; ++enabled) {
        reset(enabled); uint64_t saved = flags;
        process_sleep_ticks(5);
        assert(inserted == 1 && schedules == 1 && thread.sleeping && thread.sleep_until_tick == 105 && flags == saved);
        reset(enabled); kill_before_lock = true;
        process_sleep_ticks(5);
        assert(!inserted && schedules == 1 && thread.state == THREAD_STATE_ZOMBIE && !thread.sleeping && flags == saved);
        reset(enabled); kill_after_registration = true;
        process_sleep_ticks(5);
        assert(inserted == 1 && schedules == 1 && thread.state == THREAD_STATE_ZOMBIE && !thread.sleeping && flags == saved);
        reset(enabled); wake_after_registration = true;
        process_sleep_ticks(5);
        assert(inserted == 1 && schedules == 1 && thread.wake_pending && !thread.sleeping && flags == saved);
        reset(enabled); guard = true;
        process_sleep_ticks(5); assert(!inserted && !schedules && !yields && flags == saved);
        reset(enabled); process_sleep_ticks(0); assert(!inserted && !schedules && yields == 1);
        reset(enabled); absent = true; process_sleep_ticks(5); assert(!inserted && yields == 1 && flags == saved);
        reset(enabled); thread.is_idle = true; process_sleep_ticks(5); assert(!inserted && yields == 1 && flags == saved);
        reset(enabled); ticks = UINT64_MAX - 2; process_sleep_ticks(5);
        assert(thread.sleep_until_tick == UINT64_MAX && inserted == 1 && flags == saved);
    }
    puts("Sleep registration: termination/wake serialization, IRQ restoration and saturation PASS");
}
'''
compile_and_run("sleep-registration", program)
