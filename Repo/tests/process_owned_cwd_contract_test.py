#!/usr/bin/env python3
"""Production cwd owner capture, deferred retirement and request rollback."""
import os
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    tree = ROOT / "build/ports/zen/process-owned-cwd"
    fd_tree = ROOT / "build/ports/zen/fd-retirement"
    def stripped(path):
        return "\n".join(line for line in path.read_text().splitlines() if not line.startswith("#include "))
    api=(tree / "src/kernel/process/process_api.c").read_text()
    for signature in ("static process_t *process_create_kernel_internal(", "static process_t *process_create_user_dummy_internal(", "static process_t *process_create_user_elf_internal("):
        body=function_definition(api,signature)
        assert body.index("process_prepare_inherited_context(") < body.index("thread_create(")
        assert body.count("free(proc);")==body.count("process_release_context(proc);")
    code=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"cwd ownership line %d: %s\n",__LINE__,#x); abort(); } } while(0)
typedef struct syscall_stat syscall_stat_t;
typedef struct { uint32_t value; } spinlock_t;
static _Thread_local unsigned locks,preempt,fail_allocations;
static _Thread_local bool cleanup_worker;
static uint64_t allocations, destroyed_nodes;
static void spinlock_init(spinlock_t *s) { s->value=0; }
static void spinlock_lock(spinlock_t *s) { while(__atomic_exchange_n(&s->value,1,__ATOMIC_ACQUIRE)) sched_yield(); ++locks; }
static void spinlock_unlock(spinlock_t *s) { CHECK(locks); --locks; __atomic_store_n(&s->value,0,__ATOMIC_RELEASE); }
static void spinlock_preempt_disable(void) { ++preempt; }
static void spinlock_preempt_enable(void) { CHECK(preempt); --preempt; }
static bool spinlock_preempt_disabled(void) { return locks || preempt; }
static void *owned_calloc(size_t n,size_t size) { CHECK(!locks); if(fail_allocations) { --fail_allocations; return NULL; } void *p=calloc(n,size); if(p) __atomic_fetch_add(&allocations,1,__ATOMIC_RELAXED); return p; }
static void owned_free(void *p) { CHECK(!locks); if(p) { CHECK(__atomic_fetch_sub(&allocations,1,__ATOMIC_RELAXED)); free(p); } }
#define calloc owned_calloc
#define free owned_free
'''
    for path in (ROOT / "include/fd.h",fd_tree / "include/fd_table.h",tree / "include/io_request.h"):
        code+=stripped(path)+"\n"
    code+=stripped(fd_tree / "src/kernel/fd/table.c")+"\n"+stripped(tree / "src/kernel/io/request.c")+r'''
#define VFS_UID_ROOT 0u
#define VFS_GID_ROOT 0u
enum { PROCESS_LIFETIME_ALIVE,PROCESS_LIFETIME_FREED };
enum { PROCESS_STATE_READY,PROCESS_STATE_ZOMBIE };
typedef struct vfs_node { uint32_t refs; bool directory; } vfs_node_t;
typedef struct process {
    spinlock_t context_lock; uint32_t uid,gid; vfs_node_t *cwd; fd_description_t *cwd_owner;
    int state,lifetime_state;
} process_t;
static vfs_node_t *root;
static _Thread_local process_t *current_process;
static unsigned worker_creations;
static bool fail_worker;
static vfs_node_t *vfs_root(void) { return root; }
static bool vfs_is_dir(const vfs_node_t *n) { return n && n->directory; }
static bool vfs_node_try_retain(vfs_node_t *n) {
    uint32_t count=__atomic_load_n(&n->refs,__ATOMIC_RELAXED);
    while(count && count!=UINT32_MAX) if(__atomic_compare_exchange_n(&n->refs,&count,count+1,false,__ATOMIC_RELAXED,__ATOMIC_RELAXED)) return true;
    return false;
}
static void vfs_node_release(vfs_node_t *n) {
    if(__atomic_fetch_sub(&n->refs,1,__ATOMIC_ACQ_REL)==1) { CHECK(cleanup_worker && !locks && !preempt); ++destroyed_nodes; free(n); }
}
static process_t *current_process_local(void) { CHECK(preempt || locks); return current_process; }
static process_t *process_current(void) { return current_process; }
static void fatal(const char *s) { fprintf(stderr,"fatal: %s\n",s); abort(); }
static void process_sleep_ms(uint32_t ms) { (void)ms; CHECK(false); }
static process_t *process_create_kernel_service(const char *name,void (*entry)(void *),void *arg,size_t bytes) {
    CHECK(!strcmp(name,"fd-cleanup") && entry && !arg && !bytes && !locks && !preempt);
    ++worker_creations; return fail_worker ? NULL : calloc(1,sizeof(process_t));
}
'''
    code+=stripped(tree / "src/kernel/process/process_resources.c")+r'''
static vfs_node_t *new_node(void) { vfs_node_t *n=calloc(1,sizeof(*n)); CHECK(n); n->refs=1; n->directory=true; return n; }
static process_t *new_process(process_t *parent) {
    process_t *p=calloc(1,sizeof(*p)); CHECK(p); spinlock_init(&p->context_lock);
    CHECK(process_prepare_inherited_context(p,parent,false)); return p;
}
static void drop_process(process_t *p) { process_release_context(p); free(p); }
static void drain(void) { CHECK(!locks && !preempt); cleanup_worker=true; while(fd_retirement_queue_drain(g_process_retirement,32)) {} cleanup_worker=false; }
static fd_description_t *node_owner(vfs_node_t *n) {
    spinlock_preempt_disable(); fd_description_t *d=process_cwd_description_create_owned(n); spinlock_preempt_enable(); CHECK(d); return d;
}
static void install(process_t *p,fd_description_t *d) { spinlock_preempt_disable(); CHECK(!process_set_cwd_description_owned(p,d)); spinlock_preempt_enable(); }
static void early_inheritance_rollback(void) {
    process_resource_system_init(); CHECK(g_process_retirement); process_resource_system_init();
    process_t *early=new_process(NULL); CHECK(!early->cwd_owner && !early->cwd);
    root=new_node(); spinlock_preempt_disable();
    uint32_t uid=99,gid=99; fd_description_t *captured=process_acquire_cwd_owner(early,&uid,&gid);
    CHECK(captured && fd_description_context(captured)==root && uid==0 && gid==0); fd_description_put(captured); spinlock_preempt_enable();
    drain(); CHECK(root->refs==1); drop_process(early);
    process_t *failure=calloc(1,sizeof(*failure)); CHECK(failure); fail_allocations=1;
    CHECK(!process_prepare_inherited_context(failure,NULL,false) && !failure->cwd_owner && root->refs==1); drop_process(failure);
    process_t *parent=new_process(NULL); process_set_identity(parent,37,41); process_t *child=new_process(parent);
    CHECK(child->cwd_owner==parent->cwd_owner && child->uid==37 && child->gid==41 && root->refs==2);
    drop_process(parent); drain(); CHECK(root->refs==2); drop_process(child); drain(); CHECK(root->refs==1);
    fail_worker=true; CHECK(!process_resource_start_cleanup() && worker_creations==1 && g_process_retirement_start==0);
    fail_worker=false; CHECK(process_resource_start_cleanup() && worker_creations==2); CHECK(process_resource_start_cleanup() && worker_creations==2);
    free(g_process_retirement_worker); g_process_retirement_worker=NULL;
}
static void request_failure_and_killed_owner(void) {
    process_t *p=new_process(NULL); vfs_node_t *node=new_node(); install(p,node_owner(node)); drain();
    io_queue_t *q=io_queue_create(1); CHECK(q); io_request_t *occupied=NULL,*request=NULL;
    CHECK(!io_request_create(q,0,0,0,&occupied));
    spinlock_preempt_disable(); uint32_t uid,gid; fd_description_t *cwd=process_acquire_cwd_owner(p,&uid,&gid); CHECK(cwd);
    CHECK(io_request_create(q,8,uid,gid,&request)==-EAGAIN && !request); fd_description_put(cwd); spinlock_preempt_enable();
    CHECK(!io_request_waiter_abandon(occupied)); cleanup_worker=true; CHECK(io_queue_drain(q,1)==1); cleanup_worker=false;
    spinlock_preempt_disable(); cwd=process_acquire_cwd_owner(p,&uid,&gid); CHECK(cwd); fail_allocations=1;
    CHECK(io_request_create(q,8,uid,gid,&request)==-ENOMEM && !request); fd_description_put(cwd); spinlock_preempt_enable();
    spinlock_preempt_disable(); cwd=process_acquire_cwd_owner(p,&uid,&gid); CHECK(cwd);
    CHECK(!io_request_create(q,8,uid,gid,&request)); CHECK(!io_request_bind_cwd_owner(request,NULL,cwd));
    CHECK(io_request_cwd(request)==node && io_request_bind_cwd_owner(request,NULL,cwd)==-EBUSY);
    CHECK(!io_request_submit(request)); spinlock_preempt_enable(); CHECK(io_queue_take(q)==request);
    /* Process dies; EXECUTOR and registered waiter own the request. All raw
     * node destruction remains deferred through its separate cwd owner. */
    drop_process(p); CHECK(!io_request_waiter_abandon(request)); drain(); CHECK(node->refs==1);
    CHECK(!io_request_publish_complete(request,0,NULL)); CHECK(!io_request_worker_release(request));
    uint64_t before=destroyed_nodes; cleanup_worker=true; CHECK(io_queue_drain(q,1)==1); cleanup_worker=false;
    CHECK(destroyed_nodes==before); drain(); CHECK(destroyed_nodes==before+1);
    io_queue_shutdown(q); CHECK(!io_queue_destroy(q));
}
typedef struct { process_t *process; fd_description_t *a,*b; unsigned loops; } race_arg_t;
static void *change_context(void *opaque) {
    race_arg_t *a=opaque;
    for(unsigned i=0;i<a->loops;++i) {
        spinlock_preempt_disable(); fd_description_t *d=i&1?a->a:a->b; CHECK(fd_description_get(d));
        CHECK(!process_set_cwd_description_owned(a->process,d)); process_set_identity(a->process,i&1?37:55,i&1?41:77); spinlock_preempt_enable();
    } return NULL;
}
static void *capture_context(void *opaque) {
    race_arg_t *a=opaque;
    for(unsigned i=0;i<a->loops;++i) {
        spinlock_preempt_disable(); uint32_t uid,gid; fd_description_t *d=process_acquire_cwd_owner(a->process,&uid,&gid);
        CHECK(d && (d==a->a || d==a->b) && ((uid==37 && gid==41)||(uid==55 && gid==77)));
        CHECK(((vfs_node_t *)fd_description_context(d))->refs==1); fd_description_put(d); spinlock_preempt_enable();
    } return NULL;
}
static void concurrent_capture(void) {
    enum { N=5, LOOPS=4000 }; process_t *p=new_process(NULL); process_set_identity(p,37,41);
    fd_description_t *a=node_owner(new_node()), *b=node_owner(new_node()); CHECK(fd_description_get(a)); install(p,a); drain();
    pthread_t *threads=calloc(N,sizeof(*threads)); race_arg_t *args=calloc(N,sizeof(*args)); CHECK(threads && args);
    for(unsigned i=0;i<N;++i) { args[i]=(race_arg_t){.process=p,.a=a,.b=b,.loops=LOOPS}; CHECK(!pthread_create(&threads[i],NULL,i?capture_context:change_context,&args[i])); }
    for(unsigned i=0;i<N;++i) CHECK(!pthread_join(threads[i],NULL));
    free(args); free(threads); drop_process(p); fd_description_put(a); fd_description_put(b); drain();
}
static void reject_unsafe_owner(void) {
    process_t *p=new_process(NULL); fd_description_t *original=p->cwd_owner;
    fd_description_t *sync=fd_description_create(&process_cwd_ops,new_node()); CHECK(sync);
    fd_retirement_queue_t *other=fd_retirement_queue_create(1); CHECK(other);
    fd_description_t *foreign=fd_description_create_deferred(&process_cwd_ops,new_node(),other); CHECK(foreign);
    spinlock_preempt_disable();
    CHECK(process_set_cwd_description_owned(p,sync)==-EINVAL && process_set_cwd_description_owned(p,foreign)==-EINVAL && p->cwd_owner==original);
    spinlock_preempt_enable(); cleanup_worker=true; fd_description_put(sync); cleanup_worker=false;
    fd_description_put(foreign); cleanup_worker=true; CHECK(fd_retirement_queue_drain(other,1)==1); cleanup_worker=false;
    fd_retirement_queue_shutdown(other); CHECK(!fd_retirement_queue_destroy(other)); drop_process(p); drain();
}
int main(void) {
    early_inheritance_rollback(); request_failure_and_killed_owner(); concurrent_capture(); reject_unsafe_owner();
    CHECK(root->refs==1); cleanup_worker=true; vfs_node_release(root); cleanup_worker=false;
    fd_retirement_queue_shutdown(g_process_retirement); CHECK(!fd_retirement_queue_destroy(g_process_retirement));
    CHECK(!allocations && !preempt && !locks); puts("process cwd: PASS early init/inheritance/OOM/admission/cancel/deferred destruction/16000 concurrent captures"); return 0;
}
'''
    previous=os.environ.get("HOST_CC")
    os.environ["HOST_CC"]=shlex.join(shlex.split(previous or "cc")+["-pthread"])
    try:
        compile_and_run("process-owned-cwd",code)
    finally:
        if previous is None: os.environ.pop("HOST_CC",None)
        else: os.environ["HOST_CC"]=previous
    print("process owned cwd production contracts: PASS")


if __name__=="__main__":
    main()
