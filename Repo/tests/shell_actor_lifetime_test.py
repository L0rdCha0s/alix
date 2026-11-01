#!/usr/bin/env python3
"""Production actor ownership: owner teardown cannot free zombie/on-CPU state."""
import os,shlex,sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run,function_definition

def main():
    stage=ROOT/os.environ.get('ALIX_SHELL_SOURCE','.')
    def stripped(path):return '\n'.join(line for line in path.read_text().splitlines() if not line.startswith('#include '))
    code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <time.h>
#include <sys/types.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"shell actor line %d: %s\n",__LINE__,#x);abort(); } } while(0)
typedef struct syscall_stat syscall_stat_t;
typedef struct { uint32_t value; } spinlock_t;
static _Thread_local unsigned held,preempt;
static _Thread_local bool cleanup_worker,scheduler_held;
static uint64_t allocations,closed_fds,freed_sessions,destroyed_processes,join_waits,sleep_waits;
static bool late_writer,drain_done,fail_thread,abort_constructor;
static jmp_buf *constructor_environment;
static void spinlock_init(spinlock_t *l) { l->value=0; }
static void spinlock_lock(spinlock_t *l) { while(__atomic_exchange_n(&l->value,1,__ATOMIC_ACQUIRE)) sched_yield();++held; }
static void spinlock_unlock(spinlock_t *l) { CHECK(held);--held;__atomic_store_n(&l->value,0,__ATOMIC_RELEASE); }
static void spinlock_preempt_disable(void) { ++preempt; }
static void spinlock_preempt_enable(void) { CHECK(preempt);--preempt; }
static bool spinlock_preempt_disabled(void) { return held||preempt; }
static void *tracked_calloc(size_t n,size_t s) { void *p=calloc(n,s);if(p)__atomic_fetch_add(&allocations,1,__ATOMIC_RELAXED);return p; }
static void tracked_free(void *p) { if(p){CHECK(__atomic_fetch_sub(&allocations,1,__ATOMIC_RELAXED));free(p);} }
#define calloc tracked_calloc
#define free tracked_free
'''
    for path in (ROOT/'include/fd.h',ROOT/'include/fd_table.h',ROOT/'src/kernel/fd/table.c'):
        code+=stripped(path)+'\n'
    code+=r'''
#define SMP_MAX_CPUS 4
#define RUN_QUEUE_CPU_INVALID UINT32_MAX
enum { PROCESS_STATE_READY,PROCESS_STATE_ZOMBIE };
enum { THREAD_STATE_READY,THREAD_STATE_ZOMBIE };
typedef struct wait_queue { unsigned unused; } wait_queue_t;
typedef struct thread {
    uint64_t owner_pid,tid; int state; uint32_t running_cpu;
    bool in_transition,in_run_queue,sleeping; void *waiting_queue;
    struct thread *registry_next,*process_next;
} thread_t;
typedef struct process {
    uint64_t pid; int state,exit_status; bool kernel_service,is_user;
    uint32_t join_waiters,running_thread_count; int address_space;
    spinlock_t threads_lock; thread_t *threads; wait_queue_t wait_queue;
    struct process *parent,*first_child,*sibling_next,*sibling_prev;
} process_t;
typedef void (*thread_entry_t)(void *);
typedef struct { uint64_t creator_pid,creator_tid,pid;process_t *owner;bool constructed,complete; } process_creation_watch_t;
static thread_t *g_thread_registry_head,*g_current_threads[SMP_MAX_CPUS],*g_switch_out_threads[SMP_MAX_CPUS];
static spinlock_t g_thread_registry_lock;
static pthread_mutex_t scheduler_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local process_t *model_current;
static _Thread_local thread_t *model_thread;
static _Thread_local process_creation_watch_t *probe_watch;
static process_t *cleanup_process;
static uint64_t next_pid=100;
static uint64_t scheduler_lock_acquire(const char *label) { (void)label;CHECK(!scheduler_held);CHECK(!pthread_mutex_lock(&scheduler_mutex));scheduler_held=true;return 0; }
static void scheduler_lock_release(uint64_t flags) { (void)flags;CHECK(scheduler_held);scheduler_held=false;CHECK(!pthread_mutex_unlock(&scheduler_mutex)); }
static bool thread_in_run_queue_load(const thread_t *t) { return t->in_run_queue; }
static process_t *current_process_local(void) { return model_current; }
static thread_t *current_thread_local(void) { return model_thread; }
static process_t *process_current(void) { return model_current; }
static void fatal(const char *s) { fprintf(stderr,"fatal: %s\n",s);abort(); }
static void serial_printf(const char *format,...) { (void)format; }
static void process_create_log(const char *name,const char *label) { (void)name;(void)label; }
static bool string_name_equals(const char *a,const char *b) { return a&&b&&!strcmp(a,b); }
static void process_sleep_ms(uint32_t ms) { (void)ms;CHECK(cleanup_worker&&!held&&!preempt&&!scheduler_held);__atomic_fetch_add(&sleep_waits,1,__ATOMIC_RELAXED);sched_yield(); }
static void wait_queue_wait(wait_queue_t *q,bool (*predicate)(void *),void *context) {
    (void)q;CHECK(cleanup_worker&&!held&&!preempt);
    for(;;){uint64_t f=scheduler_lock_acquire("host_wait");bool ready=predicate(context);scheduler_lock_release(f);if(ready)return;__atomic_fetch_add(&join_waits,1,__ATOMIC_RELAXED);sched_yield();}
}
static process_t *new_process(void) { process_t *p=calloc(1,sizeof(*p));CHECK(p);p->pid=next_pid++;spinlock_init(&p->threads_lock);return p; }
static void add_thread(process_t *p,thread_t *t) {
    t->owner_pid=p->pid;t->tid=p->pid;t->running_cpu=RUN_QUEUE_CPU_INVALID;p->threads=t;
    spinlock_lock(&g_thread_registry_lock);t->registry_next=g_thread_registry_head;g_thread_registry_head=t;spinlock_unlock(&g_thread_registry_lock);
}
static process_t *allocate_process(const char *name,bool user) { (void)name;CHECK(preempt && !user);return new_process(); }
static bool process_prepare_inherited_context(process_t *p,process_t *parent,bool service) { (void)p;(void)parent;(void)service;return true; }
static void paging_destroy_space(int *space) { (void)space; }
static void process_release_context(process_t *p) { (void)p; }
static thread_t *thread_create(process_t *p,const char *name,thread_entry_t entry,void *arg,size_t size,bool idle,bool user) {
    (void)name;(void)entry;(void)arg;(void)size;CHECK(!idle&&!user && p->join_waiters==1 && probe_watch && __atomic_load_n(&probe_watch->owner,__ATOMIC_ACQUIRE)==p && probe_watch->pid==p->pid);
    if(abort_constructor) longjmp(*constructor_environment,1);
    if(fail_thread)return NULL;
    thread_t *t=calloc(1,sizeof(*t));CHECK(t);add_thread(p,t);return t;
}
static process_t *process_finalize_new_process(process_t *p,thread_t *t,int fd,process_t *parent) {
    (void)t;(void)fd;CHECK(!parent && p->join_waiters==1);p->parent=model_current;
    p->sibling_next=model_current->first_child;if(p->sibling_next)p->sibling_next->sibling_prev=p;model_current->first_child=p;return p;
}
static void process_detach_child(process_t *p) {
    if(p->parent && p->parent->first_child==p)p->parent->first_child=p->sibling_next;
    if(p->sibling_prev)p->sibling_prev->sibling_next=p->sibling_next;
    if(p->sibling_next)p->sibling_next->sibling_prev=p->sibling_prev;
    p->parent=p->sibling_next=p->sibling_prev=NULL;
}
static process_t *process_retain_first_child(process_t *p) { process_t *c=p->first_child;if(c)++c->join_waiters;return c; }
static bool process_is_zombie(const process_t *p) { return p->state==PROCESS_STATE_ZOMBIE; }
static bool process_kill(process_t *p,int status) { uint64_t f=scheduler_lock_acquire("kill");p->state=PROCESS_STATE_ZOMBIE;p->exit_status=status;for(thread_t *t=p->threads;t;t=t->process_next)t->state=THREAD_STATE_ZOMBIE;scheduler_lock_release(f);return true; }
'''
    api=(stage/'src/kernel/process/process_api.c').read_text()
    code+=function_definition((ROOT/'src/kernel/process/process_scheduler.c').read_text(),'bool process_threads_quiescent_locked(')+'\n'
    code+=function_definition(api,'static bool process_join_ready(')+r'''
static int process_join(process_t *p,int *status) { wait_queue_wait(&p->wait_queue,process_join_ready,p);if(status)*status=p->exit_status;return p->exit_status; }
static void process_destroy_retained(process_t *p) {
    CHECK(cleanup_worker&&!held&&!preempt && p->join_waiters);if(--p->join_waiters)return;
    uint64_t f=scheduler_lock_acquire("destroy");CHECK(p->state==PROCESS_STATE_ZOMBIE && process_threads_quiescent_locked(p));process_detach_child(p);
    thread_t *t=p->threads;
    if(t){spinlock_lock(&g_thread_registry_lock);thread_t **cursor=&g_thread_registry_head;while(*cursor&&*cursor!=t)cursor=&(*cursor)->registry_next;CHECK(*cursor==t);*cursor=t->registry_next;spinlock_unlock(&g_thread_registry_lock);}
    scheduler_lock_release(f);free(t);free(p);__atomic_fetch_add(&destroyed_processes,1,__ATOMIC_RELAXED);
}
'''
    code+=function_definition(api,'void process_kill_tree(')+'\n'
    code+=function_definition(api,'static process_t *process_create_kernel_internal(')+'\n'
    code+=function_definition(api,'process_t *process_create_kernel(')+'\n'
    code+=stripped(stage/'src/kernel/process/process_creation_watch.c')+'\n'
    for sig in ('process_t *process_create_kernel_observed(', 'int process_creation_watch_stop(', 'void process_creation_watch_release('):code+=function_definition(api,sig)+'\n'
    code+=r'''
typedef struct shell_actor shell_actor_t;
typedef void (*shell_stream_fn)(void *,const char *,size_t);
typedef struct shell_state {
    spinlock_t actors_lock; shell_actor_t *actors;size_t actor_live;bool actors_closing,actors_paused;
    fd_description_t *lifetime_owner,*cwd_owner;shell_stream_fn stream_fn;void *stream_context;
} shell_state_t;
static fd_retirement_queue_t *retirement;
static fd_retirement_queue_t *process_fd_retirement_queue(void) { return retirement; }
'''
    code+=stripped(stage/'src/kernel/shell_actors.c')+r'''
typedef struct shell_session {
    shell_state_t state;process_t *owner,*runner;uint32_t handle;int stdout_fd;
    fd_description_t *lifetime,*shutdown;char *pending_home,*capture;
    struct shell_session *next;spinlock_t lock;bool closed,running,completed;int last_status;
    shell_actor_t *runner_actor;size_t capture_len;
} shell_session_t;
static shell_session_t *g_shell_sessions;
static spinlock_t list_lock;
static void shell_list_lock(void) { spinlock_lock(&list_lock); }
static void shell_list_unlock(void) { spinlock_unlock(&list_lock); }
static void shell_session_lock(shell_session_t *s) { spinlock_lock(&s->lock); }
static void shell_session_unlock(shell_session_t *s) { spinlock_unlock(&s->lock); }
static void shell_clear_active_shell(shell_state_t *s) { (void)s;CHECK(cleanup_worker&&!held&&!preempt); }
static void shell_clear_console_tap_if_matches(shell_stream_fn f,void *ctx) { (void)f;(void)ctx;CHECK(cleanup_worker&&!held&&!preempt); }
static void shell_cwd_destroy(shell_state_t *s) { CHECK(!s->actor_live&&!s->actors);fd_description_put(s->cwd_owner); }
int fd_close(int fd) { CHECK(fd==7 && cleanup_worker&&!held&&!preempt && !__atomic_load_n(&late_writer,__ATOMIC_ACQUIRE));__atomic_fetch_add(&closed_fds,1,__ATOMIC_RELAXED);return 0; }
'''
    session=(stage/'src/kernel/shell_service.c').read_text()
    for sig in ('static int shell_session_lifetime_close(', 'static int shell_session_shutdown_close(', 'static void shell_session_runner_retired('):
        body=function_definition(session,sig)
        if 'lifetime_close' in sig:body=body.replace('    free(session);','    free(session);\n    __atomic_fetch_add(&freed_sessions,1,__ATOMIC_RELAXED);')
        code+=body+'\n'
    for name in ('shell_session_lifetime_ops','shell_session_shutdown_ops'):
        code+=next(line for line in session.splitlines() if line.startswith('static const fd_ops_t '+name))+'\n'
    code+=function_definition(session,'void shell_service_cleanup_process(')+'\n'
    code+=function_definition(session,'static process_t *shell_session_cleanup_runner_locked(')+'\n'
    code+=function_definition(session,'bool shell_service_close_session(')+r'''
static shell_session_t *make_session(process_t *owner) {
    shell_session_t *s=calloc(1,sizeof(*s));CHECK(s);s->owner=owner;s->handle=1;s->stdout_fd=7;spinlock_init(&s->lock);shell_actors_init(&s->state);
    s->lifetime=fd_description_create_deferred(&shell_session_lifetime_ops,s,retirement);CHECK(s->lifetime);s->state.lifetime_owner=s->lifetime;
    s->shutdown=fd_description_create_deferred(&shell_session_shutdown_ops,s,retirement);CHECK(s->shutdown);s->next=g_shell_sessions;g_shell_sessions=s;return s;
}
static void dummy_entry(void *arg) { (void)arg; }
static void *drainer(void *unused) {
    (void)unused;cleanup_worker=true;model_current=cleanup_process;model_thread=NULL;
    while(fd_retirement_queue_drain(retirement,128)) {}
    __atomic_store_n(&drain_done,true,__ATOMIC_RELEASE);return NULL;
}
static void wait_counter(uint64_t *counter,uint64_t before) {
    struct timespec begin,now;clock_gettime(CLOCK_MONOTONIC,&begin);
    while(__atomic_load_n(counter,__ATOMIC_ACQUIRE)<=before){sched_yield();clock_gettime(CLOCK_MONOTONIC,&now);CHECK(now.tv_sec-begin.tv_sec<5);}
}
static void set_offcpu(process_t *p,thread_t *t,unsigned cpu,bool switching) {
    uint64_t f=scheduler_lock_acquire("offcpu");p->running_thread_count=0;t->running_cpu=RUN_QUEUE_CPU_INVALID;t->in_transition=switching;g_current_threads[cpu]=NULL;g_switch_out_threads[cpu]=switching?t:NULL;scheduler_lock_release(f);
}
static void case_zombie_oncpu(process_t *owner,process_t *creator) {
    shell_session_t *s=make_session(owner);shell_actor_t *actor=NULL;
    shell_session_lock(s);CHECK(shell_actor_begin(&s->state,&actor,shell_session_runner_retired,s));s->runner_actor=actor;shell_session_unlock(s);
    CHECK(s->lifetime->references==2); /* List/shutdown owner plus actor; no I/O pin exists. */
    probe_watch=&actor->watch;process_t *target=shell_actor_create(actor,"command",dummy_entry,s,0,7);CHECK(target && actor->watch.owner==target && target->join_waiters==1);
    s->runner=target;s->running=true;shell_actor_complete(actor);
    uint64_t f=scheduler_lock_acquire("onCPU");target->state=PROCESS_STATE_ZOMBIE;target->exit_status=23;target->running_thread_count=1;target->threads->state=THREAD_STATE_ZOMBIE;target->threads->running_cpu=1;g_current_threads[1]=target->threads;scheduler_lock_release(f);
    __atomic_store_n(&late_writer,true,__ATOMIC_RELEASE);uint64_t closed=closed_fds,freed=freed_sessions,waits=join_waits;
    shell_session_lock(s);(void)shell_session_cleanup_runner_locked(s);CHECK(s->running && s->runner_actor==actor);shell_session_unlock(s);
    shell_service_cleanup_process(owner);CHECK(!g_shell_sessions && closed_fds==closed && freed_sessions==freed);
    pthread_t *worker=calloc(1,sizeof(*worker));CHECK(worker);drain_done=false;CHECK(!pthread_create(worker,NULL,drainer,NULL));wait_counter(&join_waits,waits);
    CHECK(!drain_done && closed_fds==closed && freed_sessions==freed);s->capture_len=17;CHECK(s->state.lifetime_owner && s->capture_len==17);
    waits=__atomic_load_n(&join_waits,__ATOMIC_ACQUIRE);thread_t *target_thread=target->threads;set_offcpu(target,target_thread,1,true);
    f=scheduler_lock_acquire("switch-out only");target_thread->in_transition=false;scheduler_lock_release(f);wait_counter(&join_waits,waits);
    CHECK(!drain_done && closed_fds==closed);__atomic_store_n(&late_writer,false,__ATOMIC_RELEASE);set_offcpu(target,target_thread,1,false);
    CHECK(!pthread_join(*worker,NULL));free(worker);CHECK(drain_done && closed_fds==closed+1 && freed_sessions==freed+1 && !creator->first_child);
}
static void case_abandoned_constructor(process_t *owner,process_t *creator) {
    shell_session_t *s=make_session(owner);shell_actor_t *actor=NULL;CHECK(shell_actor_begin(&s->state,&actor,shell_session_runner_retired,s));s->runner_actor=actor;s->running=true;
    probe_watch=&actor->watch;constructor_environment=calloc(1,sizeof(*constructor_environment));CHECK(constructor_environment);abort_constructor=true;
    if(setjmp(*constructor_environment)==0){(void)shell_actor_create(actor,"unpublished",dummy_entry,s,0,7);CHECK(false);}
    abort_constructor=false;CHECK(actor->watch.owner && !actor->watch.constructed && !actor->watch.complete);
    shell_session_lock(s);(void)shell_session_cleanup_runner_locked(s);CHECK(s->running && s->runner_actor==actor);shell_session_unlock(s);
    uint64_t f=scheduler_lock_acquire("creator zombie");creator->threads->state=THREAD_STATE_ZOMBIE;creator->threads->running_cpu=0;g_current_threads[0]=creator->threads;scheduler_lock_release(f);
    __atomic_store_n(&late_writer,true,__ATOMIC_RELEASE);uint64_t closed=closed_fds,freed=freed_sessions,waits=sleep_waits;
    shell_service_cleanup_process(owner);pthread_t *worker=calloc(1,sizeof(*worker));CHECK(worker);drain_done=false;CHECK(!pthread_create(worker,NULL,drainer,NULL));wait_counter(&sleep_waits,waits);
    CHECK(!drain_done && closed_fds==closed && freed_sessions==freed);s->capture_len=29;
    __atomic_store_n(&late_writer,false,__ATOMIC_RELEASE);set_offcpu(creator,creator->threads,0,false);
    CHECK(!pthread_join(*worker,NULL));free(worker);free(constructor_environment);constructor_environment=NULL;
    CHECK(closed_fds==closed+1 && freed_sessions==freed+1);
    f=scheduler_lock_acquire("creator ready");creator->threads->state=THREAD_STATE_READY;scheduler_lock_release(f);
}
static void case_creation_failure(process_t *owner) {
    shell_session_t *s=make_session(owner);shell_actor_t *actor=NULL;CHECK(shell_actor_begin(&s->state,&actor,NULL,NULL));probe_watch=&actor->watch;fail_thread=true;
    CHECK(!shell_actor_create(actor,"oom-thread",dummy_entry,s,0,7) && actor->watch.owner && actor->watch.constructed);fail_thread=false;shell_actor_complete(actor);
    uint64_t before=destroyed_processes;shell_actors_reap(&s->state);cleanup_worker=true;while(fd_retirement_queue_drain(retirement,128)){}cleanup_worker=false;
    CHECK(destroyed_processes==before+1 && !s->state.actor_live && !s->state.actors);
    model_current=owner;CHECK(shell_service_close_session(1));model_current=cleanup_process;cleanup_worker=true;while(fd_retirement_queue_drain(retirement,128)){}cleanup_worker=false;CHECK(!g_shell_sessions);
}
static void case_retained_child_progress(void) {
    process_t *parent=new_process(),*child=new_process();parent->join_waiters=1;child->join_waiters=1;child->state=PROCESS_STATE_ZOMBIE;child->exit_status=47;child->parent=parent;parent->first_child=child;
    cleanup_worker=true;process_kill_tree(parent);CHECK(parent->first_child==NULL && child->parent==NULL && child->join_waiters==1 && child->exit_status==47);
    process_destroy_retained(child);process_destroy_retained(parent);cleanup_worker=false;
}
static void case_no_factory(process_t *owner) {
    shell_session_t *s=make_session(owner);shell_actor_t *actor=NULL;CHECK(shell_actor_begin(&s->state,&actor,shell_session_runner_retired,s));
    s->runner_actor=actor;s->running=true;shell_actor_complete(actor);
    shell_session_lock(s);(void)shell_session_cleanup_runner_locked(s);CHECK(!s->running);shell_session_unlock(s);
    cleanup_worker=true;while(fd_retirement_queue_drain(retirement,128)){}cleanup_worker=false;
    CHECK(!s->runner_actor && !s->state.actor_live);model_current=owner;CHECK(shell_service_close_session(1));
    model_current=cleanup_process;cleanup_worker=true;while(fd_retirement_queue_drain(retirement,128)){}cleanup_worker=false;
}
static void case_bounded_admission(process_t *owner) {
    shell_session_t *s=make_session(owner);shell_actor_t *actor=NULL;
    for(unsigned i=0;i<SHELL_ACTOR_LIMIT;++i) { CHECK(shell_actor_begin(&s->state,&actor,NULL,NULL));shell_actor_complete(actor); }
    CHECK(s->state.actor_live==SHELL_ACTOR_LIMIT);actor=NULL;CHECK(!shell_actor_begin(&s->state,&actor,NULL,NULL) && !actor);
    cleanup_worker=true;while(fd_retirement_queue_drain(retirement,512)){}cleanup_worker=false;
    shell_actors_reap(&s->state);cleanup_worker=true;while(fd_retirement_queue_drain(retirement,512)){}cleanup_worker=false;
    CHECK(!s->state.actor_live && s->lifetime->references==1);model_current=owner;CHECK(shell_service_close_session(1));model_current=cleanup_process;
    cleanup_worker=true;while(fd_retirement_queue_drain(retirement,512)){}cleanup_worker=false;
}
int main(void) {
    retirement=fd_retirement_queue_create(512);CHECK(retirement);spinlock_init(&g_thread_registry_lock);spinlock_init(&list_lock);
    process_t *owner=new_process(),*creator=new_process();cleanup_process=new_process();cleanup_process->kernel_service=true;
    thread_t *creator_thread=calloc(1,sizeof(*creator_thread));CHECK(creator_thread);add_thread(creator,creator_thread);model_current=creator;model_thread=creator_thread;
    case_zombie_oncpu(owner,creator);case_abandoned_constructor(owner,creator);case_creation_failure(owner);model_current=creator;case_no_factory(owner);model_current=creator;case_bounded_admission(owner);case_retained_child_progress();
    CHECK(closed_fds==5 && freed_sessions==5 && !held && !preempt && !g_shell_sessions);
    creator->state=PROCESS_STATE_ZOMBIE;creator->threads->state=THREAD_STATE_ZOMBIE;creator->join_waiters=1;cleanup_worker=true;process_destroy_retained(creator);cleanup_worker=false;
    free(owner);free(cleanup_process);fd_retirement_queue_shutdown(retirement);CHECK(!fd_retirement_queue_destroy(retirement));CHECK(!allocations);
    puts("shell actor lifetime: PASS zombie-onCPU/switch-out/abandoned creator/failed constructor/retained-child progress/capture-slot ordering");return 0;
}
'''
    previous=os.environ.get('HOST_CC');os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
    try:compile_and_run('shell-actor-lifetime',code)
    finally:
        if previous is None:os.environ.pop('HOST_CC',None)
        else:os.environ['HOST_CC']=previous
    print('registered shell actor teardown production contracts: PASS')

if __name__=='__main__':main()
