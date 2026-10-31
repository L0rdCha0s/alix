#!/usr/bin/env python3
"""Execute production phase-fair rwlocks with concurrent native-primitive models."""
import os
import re
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def main():
    header = (ROOT / "include/pthread.h").read_text()
    types = header[header.index("/* Native phase-fair"):header.index('#ifdef __cplusplus', header.index("/* Native phase-fair"))]
    declarations = header[header.index("int pthread_rwlockattr_init"):header.index("int pthread_once")]
    source = (ROOT / "user/lib/pthread_rwlock.c").read_text()
    source = "\n".join(line for line in source.splitlines() if not line.startswith("#include"))
    def rename(value):
        value = re.sub(r"\bpthread_rwlock(\w*)", r"test_pthread_rwlock\1", value)
        return value.replace("PTHREAD_RWLOCK_INITIALIZER", "TEST_RWLOCK_INITIALIZER")
    source = rename(source).replace("pthread_self()", "test_thread_self()")
    source = source.replace("__cxa_thread_atexit_impl", "test_register_cleanup").replace("__dso_handle", "test_dso")
    source = re.sub(r"\bmalloc\(", "tracked_malloc(", source)
    source = re.sub(r"\bfree\(", "tracked_free(", source)
    program = r'''
#define _DEFAULT_SOURCE 1
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"rwlock check failed line %d: %s\n",__LINE__,#c); abort(); } } while(0)
typedef struct { volatile uint32_t state; } alix_mutex_t;
typedef struct { volatile uint32_t sequence; } alix_cond_t;
static pthread_mutex_t wait_guard=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static pthread_mutex_t allocation_guard=PTHREAD_MUTEX_INITIALIZER;
static void *allocations[256]; static size_t allocation_count;
static _Thread_local bool fail_allocation, fail_registration;
static _Thread_local int wait_error;
static _Thread_local bool exit_in_wait;
static _Thread_local volatile unsigned *wait_release;
static _Thread_local void (*cleanup_function)(void*);
static _Thread_local void *cleanup_argument;
void *test_dso;
static uint64_t test_thread_self(void) { return (uint64_t)(uintptr_t)pthread_self(); }
static void *tracked_malloc(size_t bytes) {
    if(fail_allocation){fail_allocation=false;errno=ENOMEM;return NULL;}
    void *value=malloc(bytes); CHECK(value);
    pthread_mutex_lock(&allocation_guard);CHECK(allocation_count<256);
    allocations[allocation_count++]=value;pthread_mutex_unlock(&allocation_guard);return value;
}
static void tracked_free(void *value) {
    if(!value)return;
    pthread_mutex_lock(&allocation_guard);size_t index=0;
    while(index<allocation_count && allocations[index]!=value)++index;
    CHECK(index<allocation_count);allocations[index]=allocations[--allocation_count];
    pthread_mutex_unlock(&allocation_guard);free(value);
}
int test_register_cleanup(void (*function)(void*),void *argument,void *dso) {
    CHECK(dso==test_dso);
    if(fail_registration){fail_registration=false;errno=ENOMEM;return -1;}
    CHECK(!cleanup_function);cleanup_function=function;cleanup_argument=argument;return 0;
}
static void finish_thread(void) {
    if(cleanup_function){void(*function)(void*)=cleanup_function;void *argument=cleanup_argument;
        cleanup_function=NULL;cleanup_argument=NULL;function(argument);}
}
static void alix_mutex_lock(alix_mutex_t *mutex) {
    while(__atomic_exchange_n(&mutex->state,1,__ATOMIC_ACQUIRE)) sched_yield();
}
static bool alix_mutex_trylock(alix_mutex_t *mutex) {
    uint32_t expected=0;return __atomic_compare_exchange_n(&mutex->state,&expected,1,false,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED);
}
static void alix_mutex_unlock(alix_mutex_t *mutex) { __atomic_store_n(&mutex->state,0,__ATOMIC_RELEASE); }
static int alix_cond_broadcast(alix_cond_t *condition) {
    pthread_mutex_lock(&wait_guard);__atomic_add_fetch(&condition->sequence,1,__ATOMIC_RELEASE);
    pthread_cond_broadcast(&changed);pthread_mutex_unlock(&wait_guard);return 0;
}
static int alix_cond_wait(alix_cond_t *condition,alix_mutex_t *mutex) {
    if(wait_error || exit_in_wait){int error=wait_error;wait_error=0;alix_mutex_unlock(mutex);
        while(wait_release && !__atomic_load_n(wait_release,__ATOMIC_ACQUIRE))sched_yield();
        if(exit_in_wait){finish_thread();pthread_exit(NULL);}
        alix_mutex_lock(mutex);return -error;}
    uint32_t sequence=__atomic_load_n(&condition->sequence,__ATOMIC_ACQUIRE);
    pthread_mutex_lock(&wait_guard);alix_mutex_unlock(mutex);
    while(sequence==__atomic_load_n(&condition->sequence,__ATOMIC_ACQUIRE))pthread_cond_wait(&changed,&wait_guard);
    pthread_mutex_unlock(&wait_guard);alix_mutex_lock(mutex);return 0;
}
''' + rename(types) + rename(declarations) + source + r'''
typedef struct {
    test_pthread_rwlock_t *lock;pthread_t thread;unsigned tag;bool writer;
    volatile unsigned entered,release,exit_release;int error;bool cancel;int result,unlock_result;
    unsigned *order;volatile unsigned *order_count;
} job_t;
static void *run_job(void *argument) {
    job_t *job=argument;wait_error=job->error;exit_in_wait=job->cancel;wait_release=&job->exit_release;
    errno=1234;job->result=job->writer?test_pthread_rwlock_wrlock(job->lock):test_pthread_rwlock_rdlock(job->lock);
    CHECK(errno==1234);
    if(job->result==0){if(job->order){unsigned at=__atomic_fetch_add(job->order_count,1,__ATOMIC_ACQ_REL);job->order[at]=job->tag;}
        __atomic_store_n(&job->entered,1,__ATOMIC_RELEASE);
        while(!__atomic_load_n(&job->release,__ATOMIC_ACQUIRE))sched_yield();
        job->unlock_result=test_pthread_rwlock_unlock(job->lock);}
    finish_thread();return NULL;
}
static void *run_try_reader(void *argument) {
    job_t *job=argument;job->result=test_pthread_rwlock_tryrdlock(job->lock);
    if(!job->result)job->unlock_result=test_pthread_rwlock_unlock(job->lock);
    finish_thread();return NULL;
}
static job_t *launch(test_pthread_rwlock_t *lock,bool writer,unsigned tag,unsigned *order,volatile unsigned *count,int error,bool cancel) {
    job_t *job=calloc(1,sizeof(*job));CHECK(job);job->lock=lock;job->writer=writer;job->tag=tag;job->order=order;job->order_count=count;job->error=error;job->cancel=cancel;
    CHECK(pthread_create(&job->thread,NULL,run_job,job)==0);return job;
}
static void join_job(job_t *job,int result) {
    CHECK(pthread_join(job->thread,NULL)==0);if(!job->cancel)CHECK(job->result==result && (result || job->unlock_result==0));free(job);
}
static void wait_counts(test_pthread_rwlock_t *lock,unsigned readers,unsigned writers) {
    for(;;){alix_mutex_lock(&lock->gate);bool ready=lock->waiting_readers==readers && lock->waiting_writers==writers;
        for(rw_record_t *r=lock->read_head;r;r=r->queue_next)CHECK(r->kind==RW_READER_WAIT);
        for(rw_record_t *r=lock->write_head;r;r=r->queue_next)CHECK(r->kind==RW_WRITER_WAIT);
        alix_mutex_unlock(&lock->gate);if(ready)return;sched_yield();}
}
static void wait_entered(job_t *job) { while(!__atomic_load_n(&job->entered,__ATOMIC_ACQUIRE))sched_yield(); }
static void release_job(job_t *job) { __atomic_store_n(&job->release,1,__ATOMIC_RELEASE); }
typedef struct { test_pthread_rwlock_t lock;uint64_t value,mirror;volatile unsigned failed,active_readers,active_writer; } stress_t;
typedef struct { stress_t *state;pthread_t thread;unsigned index; } stress_worker_t;
static void *stress_worker(void *argument) {
    stress_worker_t *worker=argument;stress_t *state=worker->state;
    for(unsigned i=0;i<1500;++i){
        if(worker->index&1){CHECK(test_pthread_rwlock_wrlock(&state->lock)==0);
            CHECK(!__atomic_load_n(&state->active_readers,__ATOMIC_ACQUIRE));
            CHECK(__atomic_exchange_n(&state->active_writer,1,__ATOMIC_ACQ_REL)==0);
            ++state->value;if((i&31)==0)sched_yield();state->mirror=state->value^0xa5a5a5a5ULL;
            __atomic_store_n(&state->active_writer,0,__ATOMIC_RELEASE);CHECK(test_pthread_rwlock_unlock(&state->lock)==0);
        }else{CHECK(test_pthread_rwlock_rdlock(&state->lock)==0);__atomic_add_fetch(&state->active_readers,1,__ATOMIC_ACQ_REL);
            CHECK(!__atomic_load_n(&state->active_writer,__ATOMIC_ACQUIRE));CHECK(state->mirror==(state->value^0xa5a5a5a5ULL));
            if((i&31)==0){CHECK(test_pthread_rwlock_rdlock(&state->lock)==0);CHECK(test_pthread_rwlock_unlock(&state->lock)==0);}
            __atomic_sub_fetch(&state->active_readers,1,__ATOMIC_ACQ_REL);CHECK(test_pthread_rwlock_unlock(&state->lock)==0);}}
    finish_thread();return NULL;
}
int main(void) {
    alarm(120);
    test_pthread_rwlock_t *lock=malloc(sizeof(*lock));CHECK(lock);*lock=(test_pthread_rwlock_t)TEST_RWLOCK_INITIALIZER;
    test_pthread_rwlockattr_t attribute;int shared=-1;
    CHECK(test_pthread_rwlockattr_init(&attribute)==0 && test_pthread_rwlockattr_getpshared(&attribute,&shared)==0 && shared==PTHREAD_PROCESS_PRIVATE);
    CHECK(test_pthread_rwlockattr_setpshared(&attribute,PTHREAD_PROCESS_SHARED)==ENOTSUP && attribute.shared==PTHREAD_PROCESS_PRIVATE);
    CHECK(test_pthread_rwlockattr_setpshared(&attribute,123)==EINVAL && test_pthread_rwlockattr_destroy(&attribute)==0);
    CHECK(test_pthread_rwlock_init(lock,&attribute)==EINVAL && test_pthread_rwlock_init(lock,NULL)==0);
    fail_registration=true;errno=456;CHECK(test_pthread_rwlock_rdlock(lock)==EAGAIN && errno==456 && allocation_count==0);
    fail_allocation=true;CHECK(test_pthread_rwlock_rdlock(lock)==EAGAIN && errno==456 && allocation_count==0);
    CHECK(test_pthread_rwlock_unlock(lock)==EPERM && test_pthread_rwlock_rdlock(lock)==0);
    CHECK(test_pthread_rwlock_wrlock(lock)==EDEADLK && test_pthread_rwlock_trywrlock(lock)==EBUSY);
    CHECK(test_pthread_rwlock_rdlock(lock)==0 && test_pthread_rwlock_unlock(lock)==0);
    lock->readers=RWCOUNT_MAX;CHECK(test_pthread_rwlock_tryrdlock(lock)==EAGAIN);lock->readers=1;
    rw_reader_owned(lock)->depth=RWCOUNT_MAX;CHECK(test_pthread_rwlock_rdlock(lock)==EAGAIN);rw_reader_owned(lock)->depth=1;
    CHECK(test_pthread_rwlock_destroy(lock)==EBUSY && test_pthread_rwlock_unlock(lock)==0);
    CHECK(test_pthread_rwlock_wrlock(lock)==0 && test_pthread_rwlock_wrlock(lock)==EDEADLK && test_pthread_rwlock_rdlock(lock)==EDEADLK);
    CHECK(test_pthread_rwlock_tryrdlock(lock)==EBUSY && test_pthread_rwlock_trywrlock(lock)==EBUSY && test_pthread_rwlock_unlock(lock)==0);

    unsigned *order=calloc(8,sizeof(*order));volatile unsigned *count=calloc(1,sizeof(*count));CHECK(order&&count);
    CHECK(test_pthread_rwlock_rdlock(lock)==0);
    job_t *a=launch(lock,true,1,order,count,0,false);wait_counts(lock,0,1);
    job_t *try_reader=calloc(1,sizeof(*try_reader));CHECK(try_reader);try_reader->lock=lock;
    CHECK(pthread_create(&try_reader->thread,NULL,run_try_reader,try_reader)==0);join_job(try_reader,EBUSY);
    CHECK(test_pthread_rwlock_rdlock(lock)==0 && test_pthread_rwlock_tryrdlock(lock)==0);
    CHECK(test_pthread_rwlock_unlock(lock)==0 && test_pthread_rwlock_unlock(lock)==0);
    job_t *b=launch(lock,false,2,order,count,0,false);wait_counts(lock,1,1);
    job_t *c=launch(lock,true,3,order,count,0,false);wait_counts(lock,1,2);
    CHECK(!b->entered && !c->entered && test_pthread_rwlock_unlock(lock)==0);wait_entered(a);
    CHECK(test_pthread_rwlock_unlock(lock)==EPERM && test_pthread_rwlock_tryrdlock(lock)==EBUSY);
    release_job(a);wait_entered(b);
    CHECK(test_pthread_rwlock_unlock(lock)==EPERM);
    job_t *d=launch(lock,false,4,order,count,0,false);wait_counts(lock,1,1);CHECK(!d->entered && !c->entered);
    release_job(b);wait_entered(c);CHECK(!d->entered);release_job(c);wait_entered(d);release_job(d);
    join_job(a,0);join_job(b,0);join_job(c,0);join_job(d,0);
    CHECK(*count==4 && order[0]==1 && order[1]==2 && order[2]==3 && order[3]==4);free(order);free((void*)count);

    CHECK(test_pthread_rwlock_rdlock(lock)==0);
    a=launch(lock,true,0,NULL,NULL,EIO,false);wait_counts(lock,0,1);
    b=launch(lock,true,0,NULL,NULL,0,false);wait_counts(lock,0,2);
    __atomic_store_n(&a->exit_release,1,__ATOMIC_RELEASE);join_job(a,EIO);wait_counts(lock,0,1);
    CHECK(test_pthread_rwlock_unlock(lock)==0);wait_entered(b);release_job(b);join_job(b,0);
    CHECK(test_pthread_rwlock_wrlock(lock)==0);
    a=launch(lock,false,0,NULL,NULL,0,true);wait_counts(lock,1,0);
    b=launch(lock,true,0,NULL,NULL,0,false);wait_counts(lock,1,1);
    CHECK(test_pthread_rwlock_unlock(lock)==0);
    __atomic_store_n(&a->exit_release,1,__ATOMIC_RELEASE);join_job(a,0);
    wait_entered(b);release_job(b);join_job(b,0);wait_counts(lock,0,0);
    CHECK(test_pthread_rwlock_rdlock(lock)==0);
    a=launch(lock,true,0,NULL,NULL,0,true);wait_counts(lock,0,1);
    b=launch(lock,true,0,NULL,NULL,0,false);wait_counts(lock,0,2);
    __atomic_store_n(&a->exit_release,1,__ATOMIC_RELEASE);join_job(a,0);wait_counts(lock,0,1);
    CHECK(test_pthread_rwlock_unlock(lock)==0);wait_entered(b);release_job(b);join_job(b,0);
    CHECK(test_pthread_rwlock_wrlock(lock)==0);
    a=launch(lock,false,0,NULL,NULL,EIO,false);wait_counts(lock,1,0);
    b=launch(lock,true,0,NULL,NULL,0,false);wait_counts(lock,1,1);
    CHECK(test_pthread_rwlock_unlock(lock)==0);
    __atomic_store_n(&a->exit_release,1,__ATOMIC_RELEASE);join_job(a,EIO);
    wait_entered(b);release_job(b);join_job(b,0);
    CHECK(test_pthread_rwlock_rdlock(lock)==0);
    a=launch(lock,true,0,NULL,NULL,EINTR,false);wait_counts(lock,0,1);
    b=launch(lock,true,0,NULL,NULL,0,false);wait_counts(lock,0,2);
    __atomic_store_n(&a->exit_release,1,__ATOMIC_RELEASE);
    CHECK(test_pthread_rwlock_unlock(lock)==0);wait_entered(a);CHECK(!b->entered);
    release_job(a);wait_entered(b);release_job(b);join_job(a,0);join_job(b,0);
    CHECK(test_pthread_rwlock_wrlock(lock)==0);
    a=launch(lock,false,0,NULL,NULL,EINTR,false);wait_counts(lock,1,0);
    b=launch(lock,true,0,NULL,NULL,0,false);wait_counts(lock,1,1);
    CHECK(test_pthread_rwlock_unlock(lock)==0);
    __atomic_store_n(&a->exit_release,1,__ATOMIC_RELEASE);wait_entered(a);CHECK(!b->entered);
    release_job(a);wait_entered(b);release_job(b);join_job(a,0);join_job(b,0);
    CHECK(test_pthread_rwlock_wrlock(lock)==0);lock->waiting_readers=RWCOUNT_MAX;
    a=launch(lock,false,0,NULL,NULL,0,false);join_job(a,EAGAIN);CHECK(lock->waiting_readers==RWCOUNT_MAX);
    lock->waiting_readers=0;CHECK(test_pthread_rwlock_unlock(lock)==0);
    CHECK(test_pthread_rwlock_rdlock(lock)==0);lock->waiting_writers=RWCOUNT_MAX;
    a=launch(lock,true,0,NULL,NULL,0,false);join_job(a,EAGAIN);CHECK(lock->waiting_writers==RWCOUNT_MAX);
    lock->waiting_writers=0;CHECK(test_pthread_rwlock_unlock(lock)==0);
    CHECK(lock->reader_batch==0 && test_pthread_rwlock_destroy(lock)==0 && test_pthread_rwlock_rdlock(lock)==EINVAL);free(lock);

    stress_t *state=calloc(1,sizeof(*state));stress_worker_t *workers=calloc(8,sizeof(*workers));CHECK(state&&workers);
    CHECK(test_pthread_rwlock_init(&state->lock,NULL)==0);state->mirror=0xa5a5a5a5ULL;
    for(unsigned i=0;i<8;++i){workers[i].state=state;workers[i].index=i;CHECK(pthread_create(&workers[i].thread,NULL,stress_worker,&workers[i])==0);}
    for(unsigned i=0;i<8;++i)CHECK(pthread_join(workers[i].thread,NULL)==0);
    CHECK(state->value==6000 && test_pthread_rwlock_destroy(&state->lock)==0);free(workers);free(state);
    finish_thread();CHECK(allocation_count==0);
    puts("phase-fair rwlock recursion, FIFO/cohorts, cancellation, saturation and concurrent ownership contracts passed");
}
'''
    previous = os.environ.get("HOST_CC", "cc")
    os.environ["HOST_CC"] = previous + " -pthread"
    compile_and_run("pthread-rwlock", program)
    print("Production rwlock FIFO/cohort fairness, recursion, queue failure/cancellation and SMP contracts passed")


if __name__ == "__main__":
    main()
