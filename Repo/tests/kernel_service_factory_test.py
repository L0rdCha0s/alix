#!/usr/bin/env python3
"""Execute the staged protected-service factory, kill filter and retained join."""
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition
from io_service_contract_test import staged_sources


def main():
    staged = staged_sources()
    api = staged["src/kernel/process/process_api.c"]
    thread = staged["src/kernel/process/process_thread.c"]
    scheduler = (ROOT / "src/kernel/process/process_scheduler.c").read_text()
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"kernel service factory line %d: %s\n",__LINE__,#c); abort(); } } while(0)
#define PROCESS_MAGIC 0x50524353u
enum { PROCESS_STATE_READY, PROCESS_STATE_RUNNING, PROCESS_STATE_ZOMBIE };
enum { THREAD_STATE_READY, THREAD_STATE_RUNNING, THREAD_STATE_ZOMBIE };
enum { PROCESS_LIFETIME_ALIVE, PROCESS_LIFETIME_DESTROYING };
typedef struct { bool held; } spinlock_t;
typedef struct { unsigned unused; } wait_queue_t;
typedef bool (*wait_queue_predicate_t)(void *);
typedef void (*thread_entry_t)(void *);
typedef struct { uint64_t cr3; } paging_space_t;
typedef struct vfs_node { unsigned identity; } vfs_node_t;
typedef struct process process_t;
typedef struct { uint64_t creator_pid,creator_tid,pid; process_t *owner; bool constructed,complete; } process_creation_watch_t;
typedef struct thread {
    process_t *process; thread_entry_t entry; void *argument;
    int exit_status,state; bool exited,preempt_pending; unsigned time_slice_remaining;
    wait_queue_t join_queue;
} thread_t;
struct process {
    uint64_t pid,cr3; paging_space_t address_space; char name[32]; uint32_t magic,lifetime_state,join_waiters,uid,gid;
    bool is_user,kernel_service,quiescent,context_ready; int state,exit_status,stdout_fd; uint32_t wait_status;
    thread_t *main_thread,*current_thread; process_t *parent,*next; vfs_node_t *cwd; wait_queue_t wait_queue;
};
static process_t creator,*current,*g_process_list,*g_idle_process;
static vfs_node_t root_node,inherited_node;
static spinlock_t g_process_lock;
static bool scheduler_locked,fail_process,fail_thread,fail_context,expect_service,run_immediately,exit_armed;
static uint64_t irq_flags=514,next_pid=1;
static unsigned live_allocations,destroyed,page_destroys,publications,marks,child_queries;
static unsigned context_attempts,context_releases,prep_depth;
static void spinlock_preempt_disable(void) { ++prep_depth; }
static void spinlock_preempt_enable(void) { CHECK(prep_depth); --prep_depth; }
static int g_console_stdout_fd=1;
static jmp_buf exit_target;
static uint64_t cpu_save_flags(void) { return irq_flags; }
static void cpu_cli(void) { irq_flags &= ~512ULL; }
static void cpu_restore_flags(uint64_t flags) { irq_flags=flags; }
static void spinlock_lock(spinlock_t *lock) { CHECK(!lock->held); lock->held=true; }
static void spinlock_unlock(spinlock_t *lock) { CHECK(lock->held); lock->held=false; }
static uint64_t scheduler_lock_acquire(const char *where) {
    (void)where; CHECK(!scheduler_locked && !g_process_lock.held); uint64_t flags=irq_flags; cpu_cli(); scheduler_locked=true; return flags;
}
static void scheduler_lock_release(uint64_t flags) { CHECK(scheduler_locked && !g_process_lock.held); scheduler_locked=false; irq_flags=flags; }
static void *owned_malloc(size_t bytes) { void *value=calloc(1,bytes); CHECK(value); ++live_allocations; return value; }
static void owned_free(void *value) { if(value) { CHECK(live_allocations && !scheduler_locked && !g_process_lock.held); --live_allocations; free(value); } }
#define malloc owned_malloc
#define free owned_free
static void process_create_log(const char *name,const char *event) { (void)name; (void)event; }
static void serial_printf(const char *format,...) { (void)format; }
static bool string_name_equals(const char *a,const char *b) { return a && b && !strcmp(a,b); }
static process_t *current_process_local(void) { return current; }
static thread_t *current_thread_local(void) { return current ? current->main_thread : NULL; }
static vfs_node_t *vfs_root(void) { return &root_node; }
static void procfs_register_process_priority(process_t *process) { CHECK(process->magic==PROCESS_MAGIC); }
static void process_attach_child(process_t *parent,process_t *process) {
    CHECK(parent && !process->kernel_service); process->parent=parent;
}
static void process_attach_child_pid(uint64_t pid,process_t *process) { (void)pid;(void)process;CHECK(!"unexpected explicit user parent"); }
static void paging_destroy_space(paging_space_t *space) { CHECK(space->cr3==0x1000); ++page_destroys; }
static process_t *allocate_process(const char *name,bool user) {
    if(fail_process) { fail_process=false; return NULL; }
    process_t *process=malloc(sizeof(*process)); process->pid=next_pid++; process->is_user=user;
    process->magic=PROCESS_MAGIC; process->state=PROCESS_STATE_READY; process->lifetime_state=PROCESS_LIFETIME_ALIVE;
    process->cr3=process->address_space.cr3=0x1000; strncpy(process->name,name,sizeof(process->name)-1); return process;
}
/* Context ownership has its own production suite. Model that dependency here
 * and verify it is acquired before thread publication and released on failure. */
static bool process_prepare_inherited_context(process_t *process,process_t *parent,bool parentless) {
    CHECK(!process->main_thread&&!process->context_ready&&parentless==expect_service);++context_attempts;
    if(fail_context) { fail_context=false;return false; }
    process_t *source=parentless?NULL:parent?parent:current;
    process->uid=source?source->uid:0;process->gid=source?source->gid:0;
    process->cwd=source&&source->cwd?source->cwd:vfs_root();process->context_ready=true;return true;
}
static void process_release_context(process_t *process) {
    if(process->context_ready) { ++context_releases;process->context_ready=false; }
    process->cwd=NULL;
}
static thread_t *thread_create(process_t *process,const char *name,thread_entry_t entry,void *argument,size_t size,bool idle,bool user) {
    (void)name; (void)size; CHECK(!idle && !user && process->kernel_service==expect_service);
    CHECK(process->join_waiters==(expect_service ? 1u : 0u)&&process->context_ready); ++publications;
    if(fail_thread) { fail_thread=false; return NULL; }
    thread_t *thread=malloc(sizeof(*thread)); thread->process=process; thread->entry=entry; thread->argument=argument; return thread;
}
static bool process_threads_quiescent_locked(process_t *process) { CHECK(scheduler_locked); return process->quiescent; }
static bool process_try_mark_destroying(process_t *process) {
    CHECK(scheduler_locked && g_process_lock.held);
    if(process->lifetime_state!=PROCESS_LIFETIME_ALIVE) return false;
    process->lifetime_state=PROCESS_LIFETIME_DESTROYING; return true;
}
static void process_destroy_marked(process_t *process) {
    CHECK(!scheduler_locked && !g_process_lock.held && process->quiescent && process->join_waiters==0);
    process_t **link=&g_process_list; while(*link && *link!=process) link=&(*link)->next; CHECK(*link);
    *link=process->next; ++destroyed;process_release_context(process); free(process->main_thread); free(process);
}
static void process_reap_orphans(void);
static void enqueue_thread(thread_t *thread) {
    process_t *process=thread->process;
    CHECK(process->kernel_service==expect_service && process->join_waiters==(expect_service ? 1u : 0u));
    if(process->kernel_service) CHECK(!process->parent && process->uid==0 && process->gid==0 && process->cwd==&root_node);
    else CHECK(process->parent==&creator && process->uid==37 && process->gid==41 && process->cwd==&inherited_node);
    if(run_immediately) {
        thread->entry(thread->argument); process->exit_status=17; process->state=PROCESS_STATE_ZOMBIE; process->quiescent=true;
        thread->exited=true; thread->state=THREAD_STATE_ZOMBIE;
        process_reap_orphans(); /* Must not destroy an exited service before factory returns. */
    }
}
static void process_mark_terminated(process_t *process,int status,uint32_t wait_status) {
    ++marks; process->state=PROCESS_STATE_ZOMBIE; process->exit_status=status;
    process->wait_status=wait_status;
    process->main_thread->state=THREAD_STATE_ZOMBIE; process->main_thread->exited=true;
}
static void smp_broadcast_schedule_ipi(bool exclude_self) { (void)exclude_self; }
static void wait_queue_wake_all(wait_queue_t *queue) { (void)queue; }
static void scheduler_schedule(bool requeue) {
    CHECK(!requeue && exit_armed && current); current->quiescent=true; longjmp(exit_target,1);
}
static void __attribute__((noreturn)) fatal(const char *message) { fprintf(stderr,"unexpected fatal %s\n",message); abort(); }
static void wait_queue_wait(wait_queue_t *queue,wait_queue_predicate_t predicate,void *context) {
    process_t *process=context; CHECK(queue==&process->wait_queue && process->join_waiters==2);
    uint64_t flags=scheduler_lock_acquire("host_join");
    bool ready=predicate(context); scheduler_lock_release(flags);
    if(!ready) {
        process_mark_terminated(process,19,19u<<8); process->quiescent=true; process_reap_orphans();
        CHECK(process->join_waiters==2); flags=scheduler_lock_acquire("host_join_done");
        CHECK(predicate(context)); scheduler_lock_release(flags);
    }
}
static void process_detach_child(process_t *process) { process->parent=NULL; }
static process_t *process_retain_first_child(process_t *process) { (void)process; ++child_queries; return NULL; }
static int process_join(process_t *process,int *status) { (void)process; (void)status; CHECK(!"unexpected child join"); return -1; }
process_t *process_finalize_new_process(process_t *,thread_t *,int,process_t *);
void process_exit(int) __attribute__((noreturn));
static void process_exit_with_status(int,uint32_t) __attribute__((noreturn));
'''
    code += function_definition(thread, "static process_t *process_finalize_internal(") + "\n"
    code += function_definition(thread, "process_t *process_finalize_new_process(") + "\n"
    for signature in ("static process_t *process_create_kernel_internal(", "process_t *process_create_kernel(",
                      "process_t *process_create_kernel_with_parent(", "process_t *process_create_kernel_service("):
        code += function_definition(api, signature) + "\n"
    code += function_definition(scheduler, "void process_release_reference(") + "\n"
    for signature in ("static void process_destroy_retained(", "static bool process_join_ready(",
                      "static bool process_join_begin(", "static void process_join_end(",
                      "int process_join_kernel_service(", "static void process_exit_with_status(", "void process_exit(",
                      "static bool process_kill_with_status(", "bool process_kill(", "bool process_is_zombie(", "void process_kill_tree("):
        code += function_definition(api, signature) + "\n"
    code += function_definition(scheduler, "static void process_reap_orphans(") + r'''
static void body(void *argument) { CHECK(argument); ++*(unsigned *)argument; }
int main(void) {
    creator=(process_t){.uid=37,.gid=41,.cwd=&inherited_node}; current=&creator;
    unsigned *argument=malloc(sizeof(*argument)); *argument=0;
    expect_service=true; fail_process=true;
    CHECK(!process_create_kernel_service("allocation-fail",body,argument,0) && live_allocations==1);
    fail_context=true;
    CHECK(!process_create_kernel_service("context-fail",body,argument,0)&&live_allocations==1&&page_destroys==1&&!publications);
    fail_thread=true;
    CHECK(!process_create_kernel_service("thread-fail",body,argument,0) && live_allocations==1 && page_destroys==2&&context_releases==1);
    CHECK(!process_create_kernel_service("invalid",NULL,argument,0) && live_allocations==1);

    run_immediately=true;
    process_t *service=process_create_kernel_service("early-exit",body,argument,0);
    CHECK(service && service->kernel_service && service->join_waiters==1 && service->state==PROCESS_STATE_ZOMBIE);
    CHECK(!destroyed && *argument==1 && !service->parent);
    process_reap_orphans(); CHECK(!destroyed && service->join_waiters==1);
    int status=0; CHECK(process_join_kernel_service(service,&status)==0 && status==17 && destroyed==1 && live_allocations==1);

    run_immediately=false;
    service=process_create_kernel_service("protected",body,argument,0); CHECK(service && service->join_waiters==1);
    CHECK(!process_kill(service,55) && marks==0 && service->join_waiters==1);
    process_kill_tree(service); CHECK(!child_queries && marks==0);
    current=service; CHECK(!process_kill(service,56) && marks==0);
    CHECK(process_join_kernel_service(service,NULL)==-22 && service->join_waiters==1);
    /* Normal process_exit still works from a protected service body. */
    exit_armed=true;
    if(setjmp(exit_target)==0) process_exit(23);
    exit_armed=false; current=&creator;
    CHECK(service->state==PROCESS_STATE_ZOMBIE && service->quiescent && service->join_waiters==1);
    CHECK(process_join_kernel_service(service,&status)==0 && status==23 && destroyed==2 && live_allocations==1);

    expect_service=false; run_immediately=true;
    process_t *normal=process_create_kernel("normal",body,argument,0,-1);
    CHECK(normal && !normal->kernel_service && normal->join_waiters==0 && normal->parent==&creator);
    CHECK(process_join_kernel_service(normal,NULL)==-22);
    CHECK(process_kill(normal,7)); normal->quiescent=true; normal->parent=NULL;
    process_reap_orphans(); CHECK(destroyed==3 && live_allocations==1);
    normal=process_create_kernel_with_parent("normal-parent",body,argument,0,-1,&creator);
    CHECK(normal && !normal->kernel_service && normal->parent==&creator);
    normal->parent=NULL; process_reap_orphans(); CHECK(destroyed==4 && live_allocations==1);
    free(argument); CHECK(!g_process_list && !live_allocations && irq_flags==514&&context_attempts==6&&context_releases==5);
    puts("production service factory publication retention, parent isolation, kill protection and quiescent owner join passed");
    return 0;
}
'''
    compile_and_run("kernel-service-factory", code)
    print("protected kernel service factory contracts passed")


if __name__ == "__main__":
    main()
