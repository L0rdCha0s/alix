#!/usr/bin/env python3
"""Run active process I/O glue with scheduler claim/cancel interleavings."""
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def without_includes(path):
    return "\n".join(line for line in (ROOT / path).read_text().splitlines()
                     if not line.startswith("#include "))


def main():
    api = (ROOT / "src/kernel/process/process_api.c").read_text()
    scheduler = (ROOT / "src/kernel/process/process_scheduler.c").read_text()
    glue = ROOT / "src/kernel/process/process_io.c"
    termination = function_definition(api, "static void process_mark_terminated(")
    code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"process I/O line %d: %s\n",__LINE__,#c); abort(); } } while(0)
typedef struct syscall_stat syscall_stat_t;
typedef struct { bool held; } spinlock_t;
static void spinlock_init(spinlock_t *lock) { lock->held=false; }
static void spinlock_lock(spinlock_t *lock);
static void spinlock_unlock(spinlock_t *lock);
'''
    for path in ("include/fd.h", "include/fd_table.h", "include/io_request.h"):
        code += without_includes(path) + "\n"
    code += r'''
#define SMP_MAX_CPUS 2
#define RUN_QUEUE_CPU_INVALID UINT32_MAX
enum { THREAD_STATE_RUNNING, THREAD_STATE_READY, THREAD_STATE_BLOCKED, THREAD_STATE_ZOMBIE };
enum { PROCESS_STATE_RUNNING, PROCESS_STATE_ZOMBIE };
typedef struct thread thread_t;
typedef struct process process_t;
typedef struct wait_queue { spinlock_t lock; thread_t *head,*tail; } wait_queue_t;
struct thread {
    process_t *process; thread_t *process_next, *wait_queue_next;
    io_request_t *io_request; wait_queue_t *waiting_queue; wait_queue_t join_queue;
    bool io_interruptible, caught_pending;
    bool io_admission_pending;
    uint64_t io_admission_sequence, sleep_until_tick;
    bool alive, pending_destroy, exited, in_transition, sleeping, in_run_queue, wake_pending, preempt_pending;
    uint32_t running_cpu, time_slice_remaining; int state, exit_status;
};
struct process { thread_t *threads; spinlock_t threads_lock; wait_queue_t wait_queue; int state, exit_status; uint32_t wait_status; };
static thread_t *g_current_threads[SMP_MAX_CPUS], *g_switch_out_threads[SMP_MAX_CPUS], *model_thread;
static wait_queue_t g_io_completion_queue;
static bool scheduler_locked, prep_guard, cleanup_worker, publish_gap, deferred_notify;
static unsigned lock_depth, schedules, closes;
static unsigned preempt_depth;
static void spinlock_preempt_disable(void) { ++preempt_depth; }
static void spinlock_preempt_enable(void) { CHECK(preempt_depth); --preempt_depth; }
static bool spinlock_preempt_disabled(void) { return prep_guard || preempt_depth; }
static uint64_t irq_flags = 514;
static io_request_t *executor_request;
static void (*schedule_action)(void);
static void model_publish_gap(void);
static void finish_deferred_notifications(void);
static void spinlock_lock(spinlock_t *lock) {
    if (publish_gap && lock == &g_io_completion_queue.lock) { publish_gap=false; model_publish_gap(); }
    CHECK(!lock->held); lock->held=true; ++lock_depth;
}
static void spinlock_unlock(spinlock_t *lock) { CHECK(lock->held && lock_depth); lock->held=false; --lock_depth; }
static uint64_t cpu_save_flags(void) { return irq_flags; }
static void cpu_cli(void) { irq_flags &= ~512ULL; }
static void cpu_restore_flags(uint64_t flags) { irq_flags=flags; }
static uint64_t scheduler_lock_acquire(const char *where) {
    (void)where; CHECK(!scheduler_locked); uint64_t flags=irq_flags; irq_flags &= ~512ULL; scheduler_locked=true; return flags;
}
static void scheduler_lock_release(uint64_t flags) {
    CHECK(scheduler_locked && lock_depth==0); scheduler_locked=false; irq_flags=flags;
    finish_deferred_notifications();
}
static thread_t *current_thread_local(void) { CHECK(prep_guard || scheduler_locked); return model_thread; }
static bool thread_lifetime_active(const thread_t *thread) { return thread && thread->alive; }
static void process_alarm_cancel_locked(process_t *process) { (void)process; CHECK(scheduler_locked); }
static bool process_signal_pending_locked(thread_t *thread) { CHECK(scheduler_locked); return thread->caught_pending; }
static bool thread_in_run_queue_load(const thread_t *thread) { return thread->in_run_queue; }
static void remove_from_run_queue_locked(thread_t *thread) { CHECK(scheduler_locked); thread->in_run_queue=false; }
static void sleep_queue_remove(thread_t *thread) { CHECK(scheduler_locked); thread->sleeping=false; }
static void sleep_queue_insert(thread_t *thread) { CHECK(scheduler_locked); thread->sleeping=true; }
static uint64_t timer_ticks(void) { return 20; }
static uint32_t scheduler_select_target_cpu(thread_t *thread) { (void)thread; return 0; }
static void enqueue_thread_on_cpu_locked(thread_t *thread,uint32_t cpu) {
    (void)cpu; CHECK(scheduler_locked && !thread->exited && thread->state!=THREAD_STATE_ZOMBIE); thread->in_run_queue=true;
}
static void scheduler_schedule(bool requeue);
static void *checked_calloc(size_t n,size_t bytes) { CHECK(!lock_depth && !scheduler_locked); return calloc(n,bytes); }
static void checked_free(void *ptr) { CHECK(!lock_depth && !scheduler_locked); free(ptr); }
#define calloc checked_calloc
#define free checked_free
'''
    code += without_includes("src/kernel/fd/table.c") + "\n"
    code += without_includes("src/kernel/io/request.c") + "\n"
    for signature in ("static thread_t *wait_queue_dequeue_locked(",
                      "void wait_queue_wake_all_locked(", "void wait_queue_wake_all("):
        code += function_definition(api, signature) + "\n"
    code += function_definition(scheduler, "void thread_remove_from_wait_queue(") + "\n"
    code += 'static bool wait_queue_wait_timeout(wait_queue_t*q,bool(*predicate)(void*),void*context,uint64_t ticks){(void)q;(void)predicate;(void)context;(void)ticks;CHECK(false);return false;}\n'
    code += "\n".join(line for line in glue.read_text().splitlines() if not line.startswith("#include "))
    code += "\n" + termination + r'''
static bool model_quiescent;
static bool process_threads_quiescent_locked(process_t *process) {
    CHECK(scheduler_locked&&process==model_thread->process);return model_quiescent;
}
'''
    code += function_definition(api, "int process_wait_status_snapshot(") + r'''

static void model_publish_gap(void) {
    CHECK(scheduler_locked && executor_request);
    CHECK(io_request_publish_complete(executor_request, 37, NULL)==0);
    deferred_notify=true; /* Worker must wait for scheduler_lock before broadcast. */
}
static void finish_deferred_notifications(void) {
    if (!deferred_notify) return;
    deferred_notify=false;
    process_io_notify_completion();
    CHECK(io_request_worker_release(executor_request)==0); executor_request=NULL;
}
static void complete_action(void) {
    CHECK(executor_request && !scheduler_locked && !lock_depth);
    CHECK(process_io_complete_request(executor_request, 37, NULL)==0); executor_request=NULL;
}
static void kill_action(void) { process_mark_terminated(model_thread->process, -1, 255u << 8); }
static void signal_action(void) {
    uint64_t flags=scheduler_lock_acquire("model_signal");
    CHECK(model_thread->io_interruptible); model_thread->caught_pending=true;
    process_io_cancel_thread_locked(model_thread); scheduler_lock_release(flags);
    complete_action();
}
static void scheduler_schedule(bool requeue) {
    CHECK(!requeue && !scheduler_locked && !lock_depth && !prep_guard); ++schedules;
    if (schedule_action) { void (*action)(void)=schedule_action; schedule_action=NULL; action(); }
    if (model_thread->state==THREAD_STATE_ZOMBIE) return; /* Deliberate hostile return tests the terminal guard. */
    CHECK(model_thread->wake_pending || model_thread->in_run_queue);
    model_thread->wake_pending=model_thread->in_run_queue=false;
    model_thread->state=THREAD_STATE_RUNNING;
}
static int resource_close(void *context) {
    CHECK(cleanup_worker && !scheduler_locked && !lock_depth && context); ++closes; free(context); return 0;
}
static const fd_ops_t ops={.close=resource_close};
static io_queue_t *new_fixture(void) {
    CHECK(!model_thread && !scheduler_locked && !lock_depth);
    model_thread=calloc(1,sizeof(*model_thread)); CHECK(model_thread);
    model_thread->process=calloc(1,sizeof(*model_thread->process)); CHECK(model_thread->process);
    model_thread->process->threads=model_thread; model_thread->process->state=PROCESS_STATE_RUNNING;
    model_thread->alive=true; model_thread->state=THREAD_STATE_RUNNING; model_thread->running_cpu=0;
    g_current_threads[0]=model_thread;
    memset(&g_io_completion_queue,0,sizeof(g_io_completion_queue));
    prep_guard=false; publish_gap=deferred_notify=false; executor_request=NULL; schedule_action=NULL;
    schedules=closes=0; irq_flags=514;
    io_queue_t *queue=io_queue_create(4); CHECK(queue); return queue;
}
static io_request_t *prepare(io_queue_t *queue) {
    prep_guard=true;
    io_request_t *request=NULL; CHECK(io_request_create(queue,32,123,456,&request)==0);
    void *context=calloc(1,1); CHECK(context);
    fd_description_t *description=fd_description_create(&ops,context); CHECK(description);
    CHECK(io_request_bind(request,description,NULL,NULL)==0);
    return request;
}
static void drain_fixture(io_queue_t *queue) {
    CHECK(!prep_guard && !scheduler_locked && !lock_depth);
    io_queue_shutdown(queue); cleanup_worker=true; io_queue_drain(queue,SIZE_MAX); cleanup_worker=false;
    CHECK(io_queue_destroy(queue)==0);
    if (model_thread) {
        CHECK(!model_thread->io_request && !model_thread->waiting_queue);
        free(model_thread->process); free(model_thread); model_thread=NULL;
    }
    memset(g_current_threads,0,sizeof(g_current_threads)); memset(g_switch_out_threads,0,sizeof(g_switch_out_threads));
}
static void completed_and_gap(void) {
    for (unsigned mode=0;mode<3;++mode) {
        io_queue_t *queue=new_fixture(); io_request_t *request=prepare(queue);
        CHECK(process_io_register_current(request)==0);
        CHECK(io_request_submit(request)==0); executor_request=io_queue_take(queue); CHECK(executor_request==request);
        prep_guard=false;
        thread_t *unrelated=NULL;
        io_request_t *other=NULL;
        if (mode==2) {
            unrelated=calloc(1,sizeof(*unrelated)); CHECK(unrelated);
            CHECK(io_request_create(queue,0,123,456,&other)==0);
            unrelated->alive=true; unrelated->state=THREAD_STATE_BLOCKED;
            unrelated->running_cpu=RUN_QUEUE_CPU_INVALID; unrelated->io_request=other;
            unrelated->waiting_queue=&g_io_completion_queue;
            g_io_completion_queue.head=g_io_completion_queue.tail=unrelated;
        }
        if (mode==0) complete_action();
        if (mode==1) publish_gap=true;
        if (mode==2) schedule_action=complete_action;
        io_request_status_t status;
        CHECK(process_io_wait_current(&status)==0 && status.result==37);
        if (unrelated) {
            CHECK(unrelated->state==THREAD_STATE_BLOCKED && !unrelated->in_run_queue && !unrelated->wake_pending);
            CHECK(g_io_completion_queue.head==unrelated && g_io_completion_queue.tail==unrelated);
            uint64_t flags=scheduler_lock_acquire("unrelated_waiter");
            thread_remove_from_wait_queue(unrelated); scheduler_lock_release(flags);
            CHECK(io_request_waiter_abandon(other)==0); free(unrelated);
        }
        CHECK(!model_thread->waiting_queue && !g_io_completion_queue.head && !g_io_completion_queue.tail);
        CHECK(schedules==(mode==0 ? 0u : 1u) && !closes && irq_flags==514);
        io_request_t *borrow=NULL;
        CHECK(process_io_result_current(&borrow,&status)==-EINVAL && !borrow);
        prep_guard=true; CHECK(process_io_result_current(&borrow,&status)==0 && borrow==request);
        memset(io_request_buffer(borrow),0xa5,32);
        CHECK(process_io_finish_current(false)==0 && !model_thread->io_request && !closes);
        prep_guard=false; drain_fixture(queue); CHECK(closes==1);
    }
}
static void kill_before_submit(void) {
    io_queue_t *queue=new_fixture(); io_request_t *request=prepare(queue);
    CHECK(process_io_register_current(request)==0);
    process_mark_terminated(model_thread->process,-1,255u << 8);
    CHECK(model_thread->io_request==request && !closes);
    CHECK(io_request_submit(request)==-ECANCELED && !io_queue_take(queue));
    CHECK(process_io_finish_current(false)==0 && model_thread->state==THREAD_STATE_ZOMBIE);
    prep_guard=false; drain_fixture(queue); CHECK(closes==1);

    queue=new_fixture(); request=prepare(queue);
    process_mark_terminated(model_thread->process,-1,255u << 8);
    CHECK(process_io_register_current(request)==-ECANCELED && !model_thread->io_request);
    CHECK(io_request_waiter_abandon(request)==0 && !closes); /* Failed registration leaves caller ownership. */
    prep_guard=false; drain_fixture(queue); CHECK(closes==1);
}
static void kill_wait_and_reap(void) {
    io_queue_t *queue=new_fixture(); io_request_t *request=prepare(queue);
    CHECK(process_io_register_current(request)==0 && io_request_submit(request)==0);
    executor_request=io_queue_take(queue); prep_guard=false;
    schedule_action=kill_action;
    io_request_status_t status; CHECK(process_io_wait_current(&status)==-ECANCELED);
    CHECK(model_thread->state==THREAD_STATE_ZOMBIE && !model_thread->waiting_queue && !model_thread->in_run_queue);
    CHECK(!g_io_completion_queue.head && model_thread->io_request==request && !closes);
    uint64_t flags=scheduler_lock_acquire("test_reap");
    CHECK(!process_io_abandon_thread_locked(model_thread));
    model_thread->running_cpu=RUN_QUEUE_CPU_INVALID;
    CHECK(!process_io_abandon_thread_locked(model_thread)); /* Still current on CPU. */
    g_current_threads[0]=NULL; g_switch_out_threads[0]=model_thread;
    CHECK(!process_io_abandon_thread_locked(model_thread));
    g_switch_out_threads[0]=NULL; model_thread->in_transition=true;
    CHECK(!process_io_abandon_thread_locked(model_thread)); model_thread->in_transition=false;
    CHECK(process_io_abandon_thread_locked(model_thread) && !model_thread->io_request);
    scheduler_lock_release(flags);
    free(model_thread->process); free(model_thread); model_thread=NULL;
    CHECK(!closes);
    /* Late completion has no borrowed process/thread/completion-queue pointer. */
    complete_action(); drain_fixture(queue); CHECK(closes==1);
}
static void kill_during_result_copy(void) {
    io_queue_t *queue=new_fixture(); io_request_t *request=prepare(queue);
    CHECK(process_io_register_current(request)==0 && io_request_submit(request)==0);
    executor_request=io_queue_take(queue); prep_guard=false; complete_action();
    prep_guard=true; io_request_t *borrow=NULL; io_request_status_t status;
    CHECK(process_io_result_current(&borrow,&status)==0 && borrow==request);
    process_mark_terminated(model_thread->process,-1,255u << 8);
    uint64_t flags=scheduler_lock_acquire("test_copy_reap");
    CHECK(!process_io_abandon_thread_locked(model_thread)); scheduler_lock_release(flags);
    memset(io_request_buffer(borrow),0x7b,32); CHECK(!closes);
    CHECK(process_io_finish_current(false)==0 && model_thread->state==THREAD_STATE_ZOMBIE);
    prep_guard=false; drain_fixture(queue); CHECK(closes==1);
}
static void preparation_failure(void) {
    io_queue_t *queue=new_fixture(); io_request_t *request=prepare(queue);
    prep_guard=false; CHECK(process_io_register_current(request)==-EINVAL && !model_thread->io_request);
    prep_guard=true; CHECK(process_io_register_current(request)==0);
    io_request_t *second=NULL; CHECK(io_request_create(queue,0,1,2,&second)==0);
    CHECK(process_io_register_current(second)==-EBUSY && model_thread->io_request==request);
    CHECK(io_request_waiter_abandon(second)==0);
    io_request_status_t status; CHECK(process_io_wait_current(&status)==-EINVAL);
    CHECK(process_io_finish_current(false)==-EAGAIN);
    CHECK(process_io_finish_current(true)==0 && !closes);
    prep_guard=false; drain_fixture(queue); CHECK(closes==1);
}
static void termination_status(void) {
    io_queue_t *queue=new_fixture();uint32_t output=12345;
    model_quiescent=false;
    CHECK(process_wait_status_snapshot(model_thread->process,&output)==-EAGAIN&&output==12345);
    process_mark_terminated(model_thread->process,141,141u<<8);
    CHECK(process_wait_status_snapshot(model_thread->process,&output)==-EAGAIN&&output==12345);
    model_quiescent=true;
    CHECK(!process_wait_status_snapshot(model_thread->process,&output)&&output==(141u<<8));
    process_mark_terminated(model_thread->process,143,15);
    CHECK(model_thread->process->exit_status==141&&!process_wait_status_snapshot(model_thread->process,&output)&&output==(141u<<8));
    drain_fixture(queue);
    queue=new_fixture();process_mark_terminated(model_thread->process,141,13);
    CHECK(!process_wait_status_snapshot(model_thread->process,&output)&&output==13);
    CHECK(process_wait_status_snapshot(NULL,&output)==-EINVAL&&process_wait_status_snapshot(model_thread->process,NULL)==-EINVAL);
    drain_fixture(queue);
}
static void interrupted_poll(void) {
    for(unsigned mode=0;mode<3;++mode) {
        io_queue_t *queue=new_fixture(); io_request_t *request=prepare(queue);
        CHECK(!process_io_register_current(request) && !io_request_submit(request));
        executor_request=io_queue_take(queue); CHECK(executor_request==request); prep_guard=false;
        if(mode!=1)model_thread->caught_pending=true;
        else schedule_action=signal_action;
        io_request_status_t status;
        if(mode==2) {
            schedule_action=complete_action;
            CHECK(!process_io_wait_current(&status)&&status.result==37);
        } else CHECK(process_io_wait_current_interruptible(&status)==-EINTR);
        CHECK(!model_thread->io_interruptible&&!model_thread->waiting_queue&&!g_io_completion_queue.head);
        prep_guard=true;CHECK(!process_io_finish_current(mode!=2)&&!model_thread->io_request);prep_guard=false;
        if(executor_request)complete_action();
        drain_fixture(queue);CHECK(closes==1);
    }
}
int main(void) {
    preparation_failure(); completed_and_gap(); kill_before_submit(); kill_wait_and_reap(); kill_during_result_copy();
    termination_status();
    interrupted_poll();
    puts("process I/O registration, completion gap, terminal waiter and off-CPU cleanup contracts passed");
    return 0;
}
'''
    compile_and_run("process-io", code)
    print("process I/O lifecycle contracts passed")


if __name__ == "__main__":
    main()
