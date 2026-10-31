#!/usr/bin/env python3
"""Production deferred FD cleanup, saturation, ownership and concurrent races."""
import os
from pathlib import Path
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def main():
    tree = Path(os.environ.get("FD_TABLE_SOURCE_TREE", str(ROOT)))
    if "fd_retirement_queue_create" not in (tree / "include/fd_table.h").read_text():
        tree = ROOT / "build/ports/zen/fd-retirement"
    def source(path):
        target = tree / path
        if not target.exists():
            target = ROOT / path
        return "\n".join(line for line in target.read_text().splitlines()
                         if not line.startswith("#include "))
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FD retirement line %d: %s\n",__LINE__,#x); abort(); } } while(0)
typedef struct syscall_stat syscall_stat_t;
typedef struct { uint32_t value; } spinlock_t;
static _Thread_local unsigned held_locks, fail_allocations;
static _Thread_local unsigned preempt_depth;
static _Thread_local bool cleanup_worker, caller_guard, block_next_allocation;
static bool inject_abandonment;
static spinlock_t *watched_table_lock;
static unsigned protected_transfers;
static void spinlock_preempt_disable(void) { ++preempt_depth; }
static void spinlock_preempt_enable(void) { CHECK(preempt_depth); --preempt_depth; }
static void interruption_point(void) {
    if (inject_abandonment) { CHECK(preempt_depth || caller_guard); ++protected_transfers; }
}
static uint32_t model_reference_sub(uint32_t *value, uint32_t amount, int order) {
    uint32_t previous=__atomic_fetch_sub(value,amount,order);
    if(previous==1) interruption_point();
    return previous;
}
static uint64_t allocations, closes;
static bool allocation_entered, allocation_resume;
static void spinlock_init(spinlock_t *lock) { lock->value=0; }
static void spinlock_lock(spinlock_t *lock) {
    while (__atomic_exchange_n(&lock->value,1,__ATOMIC_ACQUIRE)) sched_yield(); ++held_locks;
}
static void spinlock_unlock(spinlock_t *lock) { CHECK(held_locks); --held_locks; __atomic_store_n(&lock->value,0,__ATOMIC_RELEASE); if(lock==watched_table_lock) interruption_point(); }
static void *owned_calloc(size_t count,size_t size) {
    CHECK(!held_locks);
    if (block_next_allocation) {
        block_next_allocation=false; __atomic_store_n(&allocation_entered,true,__ATOMIC_RELEASE);
        while (!__atomic_load_n(&allocation_resume,__ATOMIC_ACQUIRE)) sched_yield();
    }
    if (fail_allocations) { --fail_allocations; return NULL; }
    void *p=calloc(count,size); if(p) __atomic_fetch_add(&allocations,1,__ATOMIC_RELAXED); return p;
}
static void owned_free(void *p) {
    CHECK(!held_locks); if (p) { CHECK(__atomic_fetch_sub(&allocations,1,__ATOMIC_RELAXED)); free(p); }
}
#define calloc owned_calloc
#define free owned_free
'''
    code += source("include/fd.h") + "\n" + source("include/fd_table.h") + "\n"
    code += "#define __atomic_fetch_sub(value,amount,order) model_reference_sub(value,amount,order)\n"
    code += source("src/kernel/fd/table.c") + r'''
#undef __atomic_fetch_sub
typedef struct {
    uint64_t magic;
    fd_retirement_queue_t *queue;
    fd_table_t *reenter_table;
    fd_description_t *replacement;
    bool block, entered, resume;
} context_t;
static int close_context(void *opaque) {
    context_t *ctx=opaque;
    CHECK(cleanup_worker && !caller_guard && !held_locks && !preempt_depth && ctx->magic==0xabc123);
    fd_retirement_status_t status;
    CHECK(!fd_retirement_queue_snapshot(ctx->queue,&status) && status.live && status.drainers);
    CHECK(fd_retirement_queue_destroy(ctx->queue)==-EBUSY);
    if (ctx->reenter_table) CHECK(fd_table_install_at(ctx->reenter_table,3,ctx->replacement,0)==3);
    if(ctx->block) {
        __atomic_store_n(&ctx->entered,true,__ATOMIC_RELEASE);
        while(!__atomic_load_n(&ctx->resume,__ATOMIC_ACQUIRE)) sched_yield();
    }
    ctx->magic=0; __atomic_fetch_add(&closes,1,__ATOMIC_RELAXED); free(ctx); return -EIO;
}
static const fd_ops_t ops={ .close=close_context };
static context_t *new_context(fd_retirement_queue_t *q) {
    context_t *c=calloc(1,sizeof(*c)); CHECK(c); c->magic=0xabc123; c->queue=q; return c;
}
static fd_description_t *new_description(fd_retirement_queue_t *q) {
    context_t *c=new_context(q); fd_description_t *d=fd_description_create_deferred(&ops,c,q);
    if(!d) free(c); return d;
}
static fd_retirement_status_t snapshot(fd_retirement_queue_t *q) {
    fd_retirement_status_t s; CHECK(!fd_retirement_queue_snapshot(q,&s)); return s;
}
static size_t drain(fd_retirement_queue_t *q,size_t budget) {
    CHECK(!cleanup_worker); cleanup_worker=true; size_t n=fd_retirement_queue_drain(q,budget); cleanup_worker=false; return n;
}
static void destroy_empty(fd_retirement_queue_t *q) {
    fd_retirement_queue_shutdown(q); while(drain(q,7)) {} CHECK(!snapshot(q).live); CHECK(!fd_retirement_queue_destroy(q));
}
static void saturation_and_close(void) {
    CHECK(!fd_retirement_queue_create(0) && !fd_retirement_queue_create(FD_RETIREMENT_MAX_OBJECTS+1u));
    fail_allocations=1; CHECK(!fd_retirement_queue_create(2)); CHECK(!fail_allocations);
    fd_retirement_queue_t *q=fd_retirement_queue_create(2); CHECK(q);
    fail_allocations=1; CHECK(!fd_table_create_deferred(8,q)); CHECK(!snapshot(q).live);
    context_t *unowned=new_context(q); fail_allocations=1;
    CHECK(!fd_description_create_deferred(&ops,unowned,q)); CHECK(unowned->magic==0xabc123 && !snapshot(q).live); free(unowned);
    fd_table_t *table=fd_table_create_deferred(8,q); CHECK(table);
    fd_description_t *d=new_description(q); CHECK(d); CHECK(snapshot(q).live==2);
    CHECK(!new_description(q)); CHECK(!fd_table_create_deferred(1,q));
    CHECK(fd_table_install_at(table,3,d,0)==3); CHECK(!fd_description_put(d));
    uint64_t before=closes; caller_guard=true; fail_allocations=2;
    CHECK(!fd_table_close(table,3)); fd_table_put(table);
    CHECK(fail_allocations==2 && closes==before && snapshot(q).pending==2 && snapshot(q).live==2);
    caller_guard=false; fail_allocations=0;
    fd_retirement_queue_shutdown(q); CHECK(!new_description(q)); CHECK(fd_retirement_queue_destroy(q)==-EBUSY);
    CHECK(drain(q,0)==0); CHECK(drain(q,1)==1 && closes==before+1 && snapshot(q).live==1);
    CHECK(drain(q,1)==1 && !snapshot(q).live); CHECK(!fd_retirement_queue_destroy(q));
}
static void identity_dup_and_pin(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(16), *other=fd_retirement_queue_create(2); CHECK(q && other);
    fd_table_t *table=fd_table_create_deferred(8,q); fd_description_t *a=new_description(q), *b=new_description(q), *foreign=new_description(other);
    fd_description_t *sync=fd_description_create(&(fd_ops_t){0},NULL); CHECK(table && a && b && foreign && sync);
    CHECK(fd_table_install(table,foreign,0,0)==-EINVAL && fd_table_install_at(table,0,sync,0)==-EINVAL);
    CHECK(fd_table_install_at(table,3,a,0)==3 && fd_table_install_at(table,4,b,0)==4);
    CHECK(!fd_description_put(a) && !fd_description_put(b));
    fd_description_t *pin=NULL; CHECK(!fd_table_pin(table,4,&pin,NULL));
    caller_guard=true; CHECK(fd_table_dup2(table,3,4)==4); CHECK(!snapshot(q).pending);
    CHECK(!fd_table_close(table,3)); fd_table_shutdown(table); fd_table_put(table);
    CHECK(snapshot(q).pending==2); CHECK(!fd_description_put(pin)); CHECK(snapshot(q).pending==3); caller_guard=false;
    CHECK(drain(q,99)==3); CHECK(!snapshot(q).live);
    CHECK(!fd_description_put(sync)); CHECK(!fd_description_put(foreign)); destroy_empty(other); destroy_empty(q);
}
static void reentrant_callbacks(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(8); fd_table_t *t=fd_table_create_deferred(8,q);
    fd_description_t *a=new_description(q), *b=new_description(q); CHECK(q && t && a && b);
    context_t *ctx=fd_description_context(a); ctx->reenter_table=t; ctx->replacement=b;
    CHECK(!fd_description_put(a)); CHECK(drain(q,1)==1);
    fd_description_t *pin=NULL; CHECK(!fd_table_pin(t,3,&pin,NULL) && pin==b);
    fd_description_put(pin); fd_description_put(b); fd_table_put(t);
    CHECK(drain(q,1)==1 && snapshot(q).pending==1); CHECK(drain(q,1)==1); destroy_empty(q);
}
typedef struct { fd_retirement_queue_t *queue; fd_description_t *created; unsigned iterations; } worker_arg_t;
static void *blocked_allocator(void *opaque) {
    worker_arg_t *arg=opaque; block_next_allocation=true;
    arg->created=fd_description_create_deferred(&(fd_ops_t){0},NULL,arg->queue); return NULL;
}
static void reservation_and_queue_refs(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(1); worker_arg_t *arg=calloc(1,sizeof(*arg)); pthread_t *worker=calloc(1,sizeof(*worker)); CHECK(q && arg && worker);
    arg->queue=q; CHECK(fd_retirement_queue_get(q));
    CHECK(!pthread_create(worker,NULL,blocked_allocator,arg));
    while(!__atomic_load_n(&allocation_entered,__ATOMIC_ACQUIRE)) sched_yield();
    CHECK(snapshot(q).live==1 && !snapshot(q).pending); fd_retirement_queue_shutdown(q);
    CHECK(fd_retirement_queue_destroy(q)==-EBUSY); __atomic_store_n(&allocation_resume,true,__ATOMIC_RELEASE);
    CHECK(!pthread_join(*worker,NULL) && arg->created); fd_description_put(arg->created);
    CHECK(drain(q,1)==1 && !snapshot(q).live && fd_retirement_queue_destroy(q)==-EBUSY);
    CHECK(!fd_retirement_queue_put(q)); CHECK(fd_retirement_queue_put(q)==-EINVAL);
    CHECK(!fd_retirement_queue_destroy(q)); free(worker); free(arg);
}
static void *drain_worker(void *opaque) {
    worker_arg_t *arg=opaque; cleanup_worker=true;
    for(unsigned i=0;i<arg->iterations;++i) { fd_retirement_queue_drain(arg->queue,5); if(!(i%7)) sched_yield(); }
    cleanup_worker=false; CHECK(!fd_retirement_queue_put(arg->queue)); return NULL;
}
static void blocked_callback(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(1); fd_description_t *d=new_description(q); CHECK(q && d);
    context_t *ctx=fd_description_context(d); ctx->block=true; fd_description_put(d); fd_retirement_queue_shutdown(q);
    worker_arg_t *arg=calloc(1,sizeof(*arg)); pthread_t *worker=calloc(1,sizeof(*worker)); CHECK(arg && worker);
    arg->queue=q; arg->iterations=1; CHECK(fd_retirement_queue_get(q)); CHECK(!pthread_create(worker,NULL,drain_worker,arg));
    while(!__atomic_load_n(&ctx->entered,__ATOMIC_ACQUIRE)) sched_yield();
    fd_retirement_status_t s=snapshot(q); CHECK(s.live==1 && !s.pending && s.drainers==1 && fd_retirement_queue_destroy(q)==-EBUSY);
    __atomic_store_n(&ctx->resume,true,__ATOMIC_RELEASE); CHECK(!pthread_join(*worker,NULL));
    CHECK(!snapshot(q).live && !fd_retirement_queue_destroy(q)); free(worker); free(arg);
}
static void *producer(void *opaque) {
    worker_arg_t *arg=opaque;
    for(unsigned i=0;i<arg->iterations;++i) {
        fd_description_t *d=NULL;
        while(!(d=new_description(arg->queue))) sched_yield();
        caller_guard=true; fd_description_put(d); caller_guard=false;
    }
    CHECK(!fd_retirement_queue_put(arg->queue)); return NULL;
}
static void concurrent_finalizers(void) {
    enum { WORKERS=8, LOOPS=2000 }; fd_retirement_queue_t *q=fd_retirement_queue_create(65536); CHECK(q);
    worker_arg_t *args=calloc(WORKERS,sizeof(*args)); pthread_t *workers=calloc(WORKERS,sizeof(*workers)); CHECK(args && workers);
    uint64_t before=closes;
    for(unsigned i=0;i<WORKERS;++i) {
        args[i].queue=q; args[i].iterations=LOOPS; CHECK(fd_retirement_queue_get(q));
        CHECK(!pthread_create(&workers[i],NULL,i<WORKERS/2?producer:drain_worker,&args[i]));
    }
    for(unsigned i=0;i<WORKERS;++i) CHECK(!pthread_join(workers[i],NULL));
    while(drain(q,7)) {} CHECK(closes==before+(WORKERS/2)*LOOPS); destroy_empty(q); free(workers); free(args);
}
static void overflow_guards(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(4); CHECK(q);
    q->references=UINT32_MAX; CHECK(!fd_retirement_queue_get(q)); q->references=1;
    q->drainers=SIZE_MAX; CHECK(!drain(q,1)); q->drainers=0; destroy_empty(q);
}
static void detach_enqueue_interruption(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(8); fd_table_t *t=fd_table_create_deferred(8,q);
    fd_description_t *a=new_description(q), *b=new_description(q); CHECK(q && t && a && b);
    CHECK(fd_table_install_at(t,3,a,0)==3 && fd_table_install_at(t,4,b,0)==4);
    fd_description_put(a); fd_description_put(b);
    watched_table_lock=&t->lock; inject_abandonment=true;
    CHECK(fd_table_dup2(t,3,4)==4); CHECK(!fd_table_close(t,3));
    fd_table_shutdown(t); fd_table_shutdown(t); fd_table_put(t);
    inject_abandonment=false; watched_table_lock=NULL;
    CHECK(protected_transfers>=7 && !preempt_depth);
    CHECK(drain(q,99)==3); fd_retirement_queue_shutdown(q);
    watched_table_lock=&q->lock; inject_abandonment=true;
    CHECK(!fd_retirement_queue_destroy(q));
    inject_abandonment=false; watched_table_lock=NULL; CHECK(!preempt_depth);
}
int main(void) {
    saturation_and_close(); identity_dup_and_pin(); reentrant_callbacks(); reservation_and_queue_refs();
    blocked_callback(); concurrent_finalizers(); overflow_guards(); detach_enqueue_interruption();
    CHECK(!allocations && !held_locks); puts("FD retirement: PASS saturation/OOM/queue lifetime/identity/reentry/8000 concurrent finalizers"); return 0;
}
'''
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("fd-retirement", code)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("deferred FD retirement production contracts: PASS")


if __name__ == "__main__":
    main()
