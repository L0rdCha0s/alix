#!/usr/bin/env python3
"""Execute the real deferred reaper and off-CPU I/O abandonment on the host."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    active = (ROOT / "src/kernel/process/process_common.c").read_text()
    tree = ROOT
    if "void process_reap_deferred_threads(void)" not in active:
        tree = ROOT / "build/ports/zen/idle-deferred-reaper"
    if len(sys.argv) > 1:
        tree = Path(sys.argv[1]).resolve()
    common = (tree / "src/kernel/process/process_common.c").read_text()
    for path, signature in (("src/kernel/process/process_init.c", "static void scheduler_main_loop("),
                            ("src/kernel/process/process_scheduler.c", "void idle_thread_entry(")):
        idle = function_definition((tree / path).read_text(), signature)
        assert idle.index("process_reap_deferred_threads();") < idle.index("cpu_cli();")
    # Bound the executable source, not just the model's configured budget.
    assert "#define DEFERRED_THREAD_FREE_BUDGET 32u" in common
    code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"idle reaper line %d: %s\n",__LINE__,#x); abort(); } } while (0)
#define SMP_MAX_CPUS 8
#define RUN_QUEUE_CPU_INVALID UINT32_MAX
#define RFLAGS_IF_BIT 512ULL
#define DEFERRED_THREAD_FREE_BUDGET 32u
enum { THREAD_STATE_RUNNING, THREAD_STATE_ZOMBIE };
typedef enum { THREAD_LIFETIME_ACTIVE, THREAD_LIFETIME_DEFERRED, THREAD_LIFETIME_FREED } thread_lifetime_state_t;
typedef struct io_request { bool waiter, cleanup; struct io_request *next; } io_request_t;
typedef struct thread {
    struct thread *deferred_next;
    io_request_t *io_request;
    uint32_t last_cpu_index, running_cpu;
    thread_lifetime_state_t lifetime_state;
    bool pending_destroy, sleeping, in_run_queue, in_transition, stack_watch_blocked, stack_watch_active, actual_queue;
    void *waiting_queue;
    int state;
} thread_t;
typedef struct { uint32_t cpu_index; uint64_t grabbed, freed, requeued, duration_ticks; } deferred_free_stats_t;
typedef struct { pthread_mutex_t mutex; } spinlock_t;
static spinlock_t g_deferred_free_locks[SMP_MAX_CPUS];
static pthread_mutex_t scheduler_mutex = PTHREAD_MUTEX_INITIALIZER;
static thread_t *g_deferred_thread_frees[SMP_MAX_CPUS], *g_deferred_thread_free_tails[SMP_MAX_CPUS];
static thread_t *g_current_threads[SMP_MAX_CPUS], *g_switch_out_threads[SMP_MAX_CPUS];
static bool g_scheduler_boot_ready;
static _Thread_local bool scheduler_held, prep_guard;
static _Thread_local unsigned queue_depth;
static _Thread_local uint64_t irq_flags = 514;
static uint64_t freed_threads, abandoned_waiters, cleanup_callbacks, live_requests;
static io_request_t *cleanup_head;
static thread_t *inject_arrival;
static const uint64_t DEFERRED_FREE_WARN_MS = 250;
static void spinlock_lock(spinlock_t *lock) { CHECK(!pthread_mutex_lock(&lock->mutex)); ++queue_depth; }
static void spinlock_unlock(spinlock_t *lock) { CHECK(queue_depth); --queue_depth; CHECK(!pthread_mutex_unlock(&lock->mutex)); }
static uint64_t cpu_save_flags(void) { return irq_flags; }
static void cpu_cli(void) { irq_flags &= ~RFLAGS_IF_BIT; }
static void cpu_restore_flags(uint64_t flags) { irq_flags = flags; }
static bool spinlock_preempt_disabled(void) { return prep_guard || queue_depth; }
static uint64_t scheduler_lock_acquire(const char *label) {
    (void)label; CHECK(!scheduler_held && !queue_depth && !prep_guard);
    uint64_t flags=irq_flags; cpu_cli(); CHECK(!pthread_mutex_lock(&scheduler_mutex)); scheduler_held=true; return flags;
}
static void scheduler_lock_release(uint64_t flags) {
    CHECK(scheduler_held && !queue_depth); scheduler_held=false; CHECK(!pthread_mutex_unlock(&scheduler_mutex)); cpu_restore_flags(flags);
}
static uint64_t timer_ticks(void) { return 0; }
static uint64_t scheduler_ticks_to_ms(uint64_t ticks) { return ticks; }
static bool scheduler_thread_in_any_queue(thread_t *thread) { CHECK(scheduler_held); return thread->actual_queue; }
static bool thread_in_run_queue_load(thread_t *thread) { return thread->in_run_queue; }
static void fatal(const char *message) { fprintf(stderr,"fatal: %s\n", message); abort(); }
static int io_request_waiter_abandon(io_request_t *request) {
    CHECK(scheduler_held && !queue_depth && request->waiter && !request->cleanup);
    request->waiter=false; request->cleanup=true; request->next=cleanup_head; cleanup_head=request; ++abandoned_waiters; return 0;
}
static void drain_cleanup(void) {
    CHECK(!scheduler_held && !queue_depth);
    while (cleanup_head) { io_request_t *r=cleanup_head; cleanup_head=r->next;
        CHECK(r->cleanup && !r->waiter && live_requests); --live_requests; ++cleanup_callbacks; free(r); }
}
static void thread_enqueue_deferred_free(thread_t *thread);
static void thread_free_resources(thread_t *thread) {
    CHECK(scheduler_held && !(irq_flags&RFLAGS_IF_BIT) && !queue_depth);
    CHECK(!thread->io_request && thread->state==THREAD_STATE_ZOMBIE);
    ++freed_threads; free(thread);
    /* Deterministically insert a new queue node between detach and retry. */
    if (inject_arrival) { thread_t *arrival=inject_arrival; inject_arrival=NULL; thread_enqueue_deferred_free(arrival); }
}
'''
    code += function_definition((ROOT / "src/kernel/process/process_io.c").read_text(),
                                "bool process_io_abandon_thread_locked(") + "\n"
    for signature in ("void thread_enqueue_deferred_free(", "bool thread_process_deferred_frees_locked(",
                      "void process_reap_deferred_threads("):
        code += function_definition(common, signature) + "\n"
    code += r'''
static thread_t *new_thread(uint32_t cpu, bool io) {
    thread_t *t=calloc(1,sizeof(*t)); CHECK(t); t->last_cpu_index=cpu;
    t->running_cpu=RUN_QUEUE_CPU_INVALID; t->state=THREAD_STATE_ZOMBIE;
    if (io) { t->io_request=calloc(1,sizeof(*t->io_request)); CHECK(t->io_request);
        t->io_request->waiter=true; ++live_requests; }
    return t;
}
static deferred_free_stats_t reap(uint32_t cpu) {
    deferred_free_stats_t stats; uint64_t flags=scheduler_lock_acquire("test");
    thread_process_deferred_frees_locked(cpu,&stats); scheduler_lock_release(flags);
    CHECK(stats.grabbed <= DEFERRED_THREAD_FREE_BUDGET); return stats;
}
static void all_empty(void) {
    for (unsigned cpu=0;cpu<SMP_MAX_CPUS;++cpu) {
        CHECK(!g_deferred_thread_frees[cpu] && !g_deferred_thread_free_tails[cpu]);
    }
}
static void remote_idle_regression(void) {
    thread_t *t=new_thread(7,true); thread_enqueue_deferred_free(t);
    /* Original behavior: CPU0 may switch repeatedly, CPU7 never does again. */
    for (unsigned i=0;i<64;++i) CHECK(!reap(0).grabbed);
    CHECK(live_requests==1 && abandoned_waiters==0 && cleanup_callbacks==0);
    g_scheduler_boot_ready=false;
    process_reap_deferred_threads(); CHECK(!freed_threads);
    g_scheduler_boot_ready=true; prep_guard=true;
    process_reap_deferred_threads(); CHECK(!freed_threads); prep_guard=false;
    irq_flags=2; process_reap_deferred_threads(); CHECK(!freed_threads && irq_flags==2); irq_flags=514;
    /* No scheduler_finish_switch call is needed to reclaim the remote queue. */
    for (unsigned i=0;i<SMP_MAX_CPUS;++i) process_reap_deferred_threads();
    CHECK(freed_threads==1 && abandoned_waiters==1 && cleanup_callbacks==0 && live_requests==1);
    CHECK(irq_flags==514); drain_cleanup(); CHECK(live_requests==0 && cleanup_callbacks==1); all_empty();
}
static void hazards(void) {
    enum { COUNT=11 }; thread_t **held=calloc(COUNT,sizeof(*held)); CHECK(held);
    for (unsigned i=0;i<COUNT;++i) { held[i]=new_thread(2,true); thread_enqueue_deferred_free(held[i]); }
    held[0]->running_cpu=7; g_current_threads[6]=held[1]; g_switch_out_threads[7]=held[2];
    held[3]->actual_queue=true; held[4]->in_run_queue=true; held[5]->sleeping=true;
    held[6]->waiting_queue=held; held[7]->in_transition=true; held[8]->stack_watch_blocked=true;
    held[9]->stack_watch_active=true; held[10]->state=THREAD_STATE_RUNNING;
    uint64_t before=freed_threads, abandoned=abandoned_waiters;
    deferred_free_stats_t stats=reap(2); CHECK(stats.grabbed==COUNT && stats.requeued==COUNT && !stats.freed);
    CHECK(freed_threads==before && abandoned_waiters==abandoned);
    held[0]->running_cpu=RUN_QUEUE_CPU_INVALID; g_current_threads[6]=NULL; g_switch_out_threads[7]=NULL;
    held[3]->actual_queue=false; held[4]->in_run_queue=false; held[5]->sleeping=false;
    held[6]->waiting_queue=NULL; held[7]->in_transition=false; held[8]->stack_watch_blocked=false;
    held[9]->stack_watch_active=false; held[10]->state=THREAD_STATE_ZOMBIE;
    stats=reap(2); CHECK(stats.freed==COUNT && !stats.requeued); CHECK(freed_threads==before+COUNT);
    free(held); drain_cleanup(); all_empty();
}
static void budget_and_rotation(void) {
    enum { BLOCKED=100, SAFE=3 }; thread_t **held=calloc(BLOCKED,sizeof(*held)); CHECK(held);
    for (unsigned i=0;i<SAFE;++i) thread_enqueue_deferred_free(new_thread(3,false));
    for (unsigned i=0;i<BLOCKED;++i) { held[i]=new_thread(3,false); held[i]->in_transition=true; thread_enqueue_deferred_free(held[i]); }
    uint64_t before=freed_threads;
    for (unsigned i=0;i<4;++i) reap(3);
    CHECK(freed_threads==before+SAFE);
    for (unsigned i=0;i<BLOCKED;++i) held[i]->in_transition=false;
    for (unsigned i=0;i<4;++i) reap(3);
    CHECK(freed_threads==before+SAFE+BLOCKED); free(held); all_empty();
    /* An arrival after detach must survive retry append; tail stays exact. */
    thread_t *unsafe=new_thread(1,false); unsafe->in_transition=true;
    thread_enqueue_deferred_free(unsafe); thread_enqueue_deferred_free(new_thread(1,false));
    inject_arrival=new_thread(1,false); thread_t *arrival=inject_arrival;
    deferred_free_stats_t stats=reap(1); CHECK(stats.freed==1 && stats.requeued==1 && !inject_arrival);
    CHECK(g_deferred_thread_frees[1]==arrival && arrival->deferred_next==unsafe && g_deferred_thread_free_tails[1]==unsafe);
    unsafe->in_transition=false; CHECK(reap(1).freed==2); all_empty();
    /* Invalid owner uses the same fallback queue/tail pair. */
    thread_enqueue_deferred_free(new_thread(UINT32_MAX,false)); CHECK(reap(UINT32_MAX).freed==1); all_empty();
}
typedef struct { unsigned id, iterations; } worker_arg_t;
static void *producer(void *opaque) {
    worker_arg_t *arg=opaque;
    for (unsigned i=0;i<arg->iterations;++i) {
        thread_t *t=new_thread((i+arg->id)%SMP_MAX_CPUS,false);
        uint64_t flags=scheduler_lock_acquire("producer"); thread_enqueue_deferred_free(t); scheduler_lock_release(flags);
        if (!(i%17)) sched_yield();
    }
    return NULL;
}
static void *idle_worker(void *opaque) {
    worker_arg_t *arg=opaque;
    for (unsigned i=0;i<arg->iterations;++i) { process_reap_deferred_threads(); if (!(i%17)) sched_yield(); }
    return NULL;
}
static void concurrent_sweeps(void) {
    enum { WORKERS=8, ITERATIONS=4000 };
    pthread_t *workers=calloc(WORKERS,sizeof(*workers)); worker_arg_t *args=calloc(WORKERS,sizeof(*args)); CHECK(workers && args);
    uint64_t before=freed_threads;
    for (unsigned i=0;i<WORKERS;++i) { args[i].id=i; args[i].iterations=ITERATIONS;
        CHECK(!pthread_create(&workers[i],NULL,i<WORKERS/2?producer:idle_worker,&args[i])); }
    for (unsigned i=0;i<WORKERS;++i) CHECK(!pthread_join(workers[i],NULL));
    for (unsigned i=0;i<ITERATIONS;++i) process_reap_deferred_threads();
    CHECK(freed_threads==before+(WORKERS/2)*ITERATIONS); all_empty(); free(args); free(workers);
}
int main(void) {
    for (unsigned i=0;i<SMP_MAX_CPUS;++i) CHECK(!pthread_mutex_init(&g_deferred_free_locks[i].mutex,NULL));
    remote_idle_regression(); hazards(); budget_and_rotation(); concurrent_sweeps();
    CHECK(!live_requests && cleanup_callbacks==abandoned_waiters);
    puts("idle deferred reaper: PASS remote waiter, all CPU hazards, budget, retry fairness, 16000 concurrent lifetimes");
    return 0;
}
'''
    # Source has external linkage, matching its production declaration.
    code = code.replace("static void thread_enqueue_deferred_free(thread_t *thread);",
                        "void thread_enqueue_deferred_free(thread_t *thread);")
    compile_and_run("idle-deferred-reaper", code)
    print("idle deferred reaper production contracts: PASS")


if __name__ == "__main__":
    main()
