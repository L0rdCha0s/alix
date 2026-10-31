#!/usr/bin/env python3
"""Inject a remote scheduler claim during production stack-watch arming."""
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from audio_stream_contract_test import function_definition

ROOT = Path(__file__).resolve().parents[1]
common = (ROOT / "src/kernel/process/process_common.c").read_text()
api = (ROOT / "src/kernel/process/process_api.c").read_text()
code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ENABLE_STACK_WRITE_DEBUG 1
#define ENABLE_STACK_WRITE_DEBUG_LOGS 0
#define RUN_QUEUE_CPU_INVALID UINT32_MAX
#define THREAD_STATE_RUNNING 1
#define SMP_MAX_CPUS 2
#define PAGE_SIZE_BYTES_LOCAL 4096
#define CTX_RFLAGS 6
#define CTX_RET 7
#define CONTEXT_SWITCH_SAVED_WORDS CTX_RET
#define RFLAGS_RESERVED_BIT 2
#define __kernel_text_start ((char *)0x100000)
#define __kernel_data_end ((char *)0x200000)
static void test_log(const char *format, ...) { (void)format; }
#define SCHED_LOG(...) test_log(__VA_ARGS__)
typedef struct { bool held; } spinlock_t;
typedef struct process process_t;
typedef struct thread {
    bool alive, stack_watch_active, in_transition, context_valid, stack_watch_enabled;
    bool stack_watch_timeout_logged;
    void *stack_base, *stack_allocation_raw, *context;
    size_t stack_size, stack_allocation_size, stack_watch_len;
    uintptr_t kernel_stack_top, stack_watch_base, stack_watch_suspect;
    const char *stack_watch_context;
    uint32_t running_cpu;
    unsigned state;
    spinlock_t context_lock;
    char name[8];
    process_t *process;
} thread_t;
struct process { thread_t *main_thread; spinlock_t threads_lock; uint64_t pid; };
static thread_t target, *g_current_threads[SMP_MAX_CPUS];
static void *stack_allocation;
static uintptr_t stack_base;
static bool g_scheduler_boot_ready = true, scheduler_locked, writable;
static bool claim_pending, inject_claim;
static uint64_t irq_flags;
static unsigned quarantines, permission_calls;
static void remote_claim(void) {
    if (scheduler_locked) { claim_pending = true; return; }
    target.running_cpu = 1; target.state = THREAD_STATE_RUNNING;
    g_current_threads[1] = &target;
    writable = true; target.stack_watch_active = false;
}
static uint64_t scheduler_lock_acquire(const char *where) {
    (void)where; assert(!scheduler_locked);
    uint64_t saved = irq_flags; irq_flags &= ~512ULL; scheduler_locked = true;
    return saved;
}
static void scheduler_lock_release(uint64_t saved) {
    assert(scheduler_locked); scheduler_locked = false; irq_flags = saved;
    if (claim_pending) { claim_pending = false; remote_claim(); }
}
static void spinlock_lock(spinlock_t *lock) {
    assert((scheduler_locked || lock == &target.context_lock) && !lock->held); lock->held = true;
}
static void spinlock_unlock(spinlock_t *lock) { assert(lock->held); lock->held = false; }
static bool thread_lifetime_active(const thread_t *thread) { return thread && thread->alive; }
static thread_t *current_thread_local(void) { return NULL; }
static bool pointer_is_canonical(uintptr_t address) { return address != 0; }
static void __attribute__((unused)) thread_quarantine_corrupt(thread_t *thread, const char *label) {
    (void)thread; (void)label;
    /* The real callback takes the scheduler/process locks through remove/kill. */
    assert(!scheduler_locked); ++quarantines;
}
static uintptr_t align_down_uintptr(uintptr_t value, size_t size) { return value & ~(size-1); }
static uintptr_t align_up_uintptr(uintptr_t value, size_t size) { return (value+size-1) & ~(size-1); }
static bool paging_set_kernel_range_writable(uintptr_t base, size_t len, bool enabled) {
    assert(base == stack_base && len == 0x2000); ++permission_calls;
    if (inject_claim) { inject_claim = false; remote_claim(); }
    writable = enabled; return true;
}
static void thread_stack_watch_capture_snapshot(thread_t *thread) { (void)thread; }
static uintptr_t thread_stack_watch_default_suspect(thread_t *thread) { return (uintptr_t)thread->context; }
static void thread_stack_watch_deactivate(thread_t *thread) { writable = true; thread->stack_watch_active = false; }
'''
for name in ("static bool thread_saved_frame_valid(",
             "static bool thread_stack_watch_can_arm_now(",
             "static bool thread_stack_watch_arm_now(",
             "bool thread_stack_watch_activate("):
    code += function_definition(common, name) + "\n"
for name in ("bool process_stack_watch_thread(", "bool process_stack_watch_process("):
    code += function_definition(api, name) + "\n"
code += r'''
static void reset(bool interrupts) {
    memset((void *)stack_base, 0, 0x2000);
    target = (thread_t){.alive=true, .context_valid=true, .stack_base=(void *)stack_base,
        .stack_allocation_raw=(void *)stack_base, .context=(void *)(stack_base+0x1fc0),
        .stack_size=0x2000, .stack_allocation_size=0x2000, .kernel_stack_top=stack_base+0x2000,
        .running_cpu=RUN_QUEUE_CPU_INVALID};
    ((uint64_t *)target.context)[CTX_RFLAGS] = RFLAGS_RESERVED_BIT;
    ((uint64_t *)target.context)[CTX_RET] = 0x100100;
    memset(g_current_threads, 0, sizeof(g_current_threads));
    scheduler_locked = claim_pending = false; writable = inject_claim = true;
    irq_flags = 2 | (interrupts ? 512 : 0);
    permission_calls = quarantines = 0;
}
int main(void) {
    stack_allocation = calloc(1, 0x3000); assert(stack_allocation);
    stack_base = align_up_uintptr((uintptr_t)stack_allocation, 0x1000);
    /* Reproduce the old sequence: check idle, remote claim/disarm, publish RO.
     * A subsequent TLB IPI makes the live stack fault on its own next push. */
    reset(true);
    assert(thread_stack_watch_activate(&target, "old_unlocked", 0));
    assert(target.running_cpu == 1 && !writable);
    for (unsigned interrupts=0; interrupts<2; ++interrupts) {
        for (unsigned by_process=0; by_process<2; ++by_process) {
            reset(interrupts);
            uint64_t flags = irq_flags;
            process_t process = {.main_thread=&target};
            bool ok = by_process ? process_stack_watch_process(&process, "test")
                                 : process_stack_watch_thread(&target, "test");
            assert(ok && target.running_cpu == 1 && writable && !target.stack_watch_active);
            assert(irq_flags == flags && !scheduler_locked && !process.threads_lock.held);
            reset(interrupts); remote_claim(); inject_claim = false;
            assert(process_stack_watch_thread(&target, "already_running"));
            assert(writable && !target.stack_watch_active);
            process.main_thread = NULL;
            assert(!process_stack_watch_process(&process, "exited"));
            assert(!scheduler_locked && !process.threads_lock.held && irq_flags == flags);
        }
    }
    /* Execute real saved-frame validation while both public locks are held.
     * Bad metadata must neither arm pages, repair frames nor quarantine/kill. */
    for (unsigned by_process=0; by_process<2; ++by_process) {
        for (unsigned malformed=0; malformed<6; ++malformed) {
            reset(true); inject_claim = false;
            uint64_t *saved = target.context;
            if (malformed == 0) target.context = (void *)(stack_base - 8);
            if (malformed == 1) target.context = (void *)(target.kernel_stack_top - 8);
            if (malformed == 2) target.context = (void *)((uintptr_t)target.context + 1);
            if (malformed == 3) saved[CTX_RET] = 0;
            if (malformed == 4) saved[CTX_RET] = 0x200000;
            if (malformed == 5) saved[CTX_RFLAGS] = 0;
            uint64_t before_flags = saved[CTX_RFLAGS], before_rip = saved[CTX_RET];
            process_t process = {.main_thread=&target};
            bool ok = by_process ? process_stack_watch_process(&process, "malformed")
                                 : process_stack_watch_thread(&target, "malformed");
            assert(!ok && writable && !target.stack_watch_active && !target.stack_watch_enabled);
            assert(permission_calls == 0 && quarantines == 0);
            assert(saved[CTX_RFLAGS] == before_flags && saved[CTX_RET] == before_rip);
            assert(!scheduler_locked && !process.threads_lock.held && !target.context_lock.held);
            assert(irq_flags == 514);
        }
    }
    assert(!process_stack_watch_process(NULL, "null"));
    free(stack_allocation);
    puts("Stack-watch race: scheduler-serialized arming and non-mutating malformed-frame rejection PASS");
}
'''
with tempfile.TemporaryDirectory(prefix="alix-stack-watch-") as directory:
    path = Path(directory) / "test.c"
    binary = Path(directory) / "test"
    path.write_text(code)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
