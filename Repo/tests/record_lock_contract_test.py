#!/usr/bin/env python3
"""Production record locks, FD close observers and request retirement on host threads."""
import os
import re
from audio_stream_contract_test import ROOT, compile_and_run

os.environ["HOST_CC"] = os.environ.get("HOST_CC", "cc") + " -pthread"
def body(path):
    return re.sub(r'^\s*#include[^\n]*\n', '', (ROOT/path).read_text(), flags=re.M)

code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#define CHECK(c) do{if(!(c)){fprintf(stderr,"record lock contract %d: %s\n",__LINE__,#c);abort();}}while(0)
typedef struct {uint64_t size_bytes;uint32_t type,reserved;uint64_t atime,mtime,ctime;} syscall_stat_t;
typedef struct {int64_t start,length;int32_t pid;int16_t type,whence;} syscall_record_lock_t;
#define SYSCALL_F_GETLK 5
#define SYSCALL_F_SETLK 6
#define SYSCALL_F_SETLKW 7
#define SYSCALL_F_RDLCK 0
#define SYSCALL_F_WRLCK 1
#define SYSCALL_F_UNLCK 2
#define SYSCALL_SEEK_SET 0
#define SYSCALL_SEEK_CUR 1
#define SYSCALL_SEEK_END 2
typedef struct {atomic_uint value;} spinlock_t;
static _Thread_local unsigned guards;
static void spinlock_preempt_disable(void){++guards;}
static void spinlock_preempt_enable(void){CHECK(guards);--guards;}
static bool spinlock_preempt_disabled(void){return guards!=0;}
static void spinlock_init(spinlock_t*l){atomic_init(&l->value,0);}
static void spinlock_lock(spinlock_t*l){spinlock_preempt_disable();while(atomic_exchange_explicit(&l->value,1,memory_order_acquire))sched_yield();}
static void spinlock_unlock(spinlock_t*l){atomic_store_explicit(&l->value,0,memory_order_release);spinlock_preempt_enable();}
'''
for header in ('include/fd.h','include/fd_table.h','include/io_request.h','include/io_service.h',
               'include/io_event_service.h','include/io_record_lock.h'):
    code += body(header) + '\n'
for source in ('src/kernel/fd/table.c','src/kernel/io/request.c'):
    code += body(source) + '\n'
code += r'''
typedef struct {const void *key;int64_t offset,size;} file_t;
static int file_close(void*opaque){free(opaque);return 0;}
static const fd_ops_t file_ops={.close=file_close};
static const void *io_vfs_record_key(const fd_description_t*d){
    return d&&fd_description_ops(d)->close==file_close?((file_t*)fd_description_context(d))->key:NULL;
}
static int io_vfs_record_base(const fd_description_t*d,int whence,int64_t*base){
    CHECK(io_vfs_record_key(d));file_t*f=fd_description_context(d);
    if(whence==0)*base=0;else if(whence==1)*base=f->offset;else if(whence==2)*base=f->size;else return -EINVAL;return 0;
}
static _Thread_local unsigned fail_countdown;
static void *record_calloc(size_t count,size_t bytes){return fail_countdown&&!--fail_countdown?NULL:calloc(count,bytes);}
#define calloc record_calloc
'''
code += body('src/kernel/io/record_lock.c') + '\n#undef calloc\n'
code += r'''
static fd_retirement_queue_t *retirement;
static io_queue_t *queue;
static _Thread_local io_queue_t *thread_queue;
static unsigned keys[16];
static fd_description_t *file_new(unsigned key,uint32_t access){
    spinlock_preempt_disable();file_t*f=calloc(1,sizeof(*f));CHECK(f);f->key=&keys[key];f->offset=200;f->size=500;
    fd_description_t*d=fd_description_create_deferred(&file_ops,f,retirement);CHECK(d);CHECK(!fd_description_initialize_status(d,access));
    spinlock_preempt_enable();return d;
}
static fd_table_t *table_new(fd_description_t*d){
    spinlock_preempt_disable();fd_table_t*t=fd_table_create_deferred(16,retirement);CHECK(t&&fd_table_install(t,d,0,0)==0);
    spinlock_preempt_enable();return t;
}
static void drain(void){
    for(unsigned n=0;n<100;++n){size_t count=io_queue_drain(thread_queue?thread_queue:queue,4096)+fd_retirement_queue_drain(retirement,4096)+io_record_lock_drain(4096);
        if(!count)return;}CHECK(false);
}
static io_request_t *prepare(fd_table_t*t,fd_description_t*d,unsigned pid,unsigned command,
                             int type,int whence,int64_t start,int64_t length,int *error){
    spinlock_preempt_disable();CHECK(fd_description_get(d));fd_description_t*lease=NULL;
    *error=io_record_lock_create(retirement,t,d,pid,command,&lease);
    if(!*error){*io_record_lock_query(lease)=(syscall_record_lock_t){.start=start,.length=length,.type=type,.whence=whence,.pid=999};
        *error=io_record_lock_validate(lease);}
    if(!*error&&!io_record_lock_resolved(lease))*error=io_record_lock_resolve(lease);
    io_request_t*r=NULL;
    if(!*error){io_queue_t*q=thread_queue?thread_queue:queue;CHECK(!io_request_create(q,0,1,2,&r));CHECK(!io_request_bind(r,lease,NULL,NULL));CHECK(!io_request_submit(r));CHECK(io_queue_take(q)==r);}
    else fd_description_put(lease);
    spinlock_preempt_enable();return r;
}
static int finish(io_request_t*r,io_service_result_t*result,syscall_record_lock_t*out,bool abandon){
    CHECK(!io_request_publish_complete(r,result->result,result->description_owned));
    if(abandon){CHECK(!io_request_waiter_abandon(r));CHECK(!io_request_worker_release(r));return -ECANCELED;}
    CHECK(!io_request_worker_release(r));int value=result->result;
    if(!value){fd_description_t*grant=NULL;CHECK(!io_request_take_result(r,&grant));value=io_record_lock_commit(grant);
        if(!value&&out)*out=*io_record_lock_query(grant);fd_description_put(grant);}
    CHECK(!io_request_waiter_release(r));return value;
}
static int action(fd_table_t*t,fd_description_t*d,unsigned pid,unsigned command,int type,int whence,
                  int64_t start,int64_t length,syscall_record_lock_t*out){
    int error;io_request_t*r=prepare(t,d,pid,command,type,whence,start,length,&error);if(error)return error;
    io_service_result_t result;CHECK(io_record_lock_execute(r,&result));int value=finish(r,&result,out,false);drain();return value;
}
static void intervals(void){
    fd_description_t*a=file_new(0,3),*b=file_new(0,3),*alias=file_new(0,3);fd_table_t*ta=table_new(a),*tb=table_new(b);
    syscall_record_lock_t*q=calloc(1,sizeof(*q));CHECK(q);
    CHECK(!action(ta,a,11,6,1,0,0,100,NULL));
    CHECK(!action(tb,b,22,5,1,0,20,1,q)&&q->type==1&&q->pid==11&&q->start==0&&q->length==100);
    CHECK(!action(ta,alias,11,5,1,0,20,1,q)&&q->type==2&&q->start==20&&q->length==1&&q->pid==999);
    CHECK(action(tb,b,22,6,0,0,20,1,NULL)==-EAGAIN);
    CHECK(!action(ta,a,11,6,2,0,20,20,NULL));
    CHECK(!action(tb,b,22,5,1,0,30,1,q)&&q->type==2);
    CHECK(!action(tb,b,22,5,1,0,50,1,q)&&q->type==1&&q->start==40&&q->length==60);
    CHECK(!action(ta,alias,11,6,0,0,10,40,NULL));
    CHECK(!action(tb,b,22,5,0,0,11,1,q)&&q->type==2);
    CHECK(!action(tb,b,22,5,1,0,11,1,q)&&q->type==0&&q->start==10&&q->length==40);
    CHECK(!action(ta,a,11,6,0,0,50,50,NULL));
    CHECK(!action(tb,b,22,5,1,0,50,1,q)&&q->type==0&&q->start==10&&q->length==90);
    CHECK(!action(ta,a,11,6,1,0,100,0,NULL));
    CHECK(!action(tb,b,22,5,1,0,200,3,q)&&q->type==1&&q->start==100&&!q->length);
    CHECK(!action(ta,a,11,6,1,0,80,-10,NULL));
    CHECK(!action(tb,b,22,5,1,0,75,1,q)&&q->type==1&&q->start==70&&q->length==10);
    CHECK(!fd_table_close(ta,0));drain();
    CHECK(!action(tb,b,22,5,1,0,75,1,q)&&q->type==2);
    fd_table_put(ta);fd_table_put(tb);fd_description_put(alias);fd_description_put(a);fd_description_put(b);free(q);drain();
}
static void lifetime(void){
    fd_description_t*a=file_new(1,3),*b=file_new(1,3),*same=file_new(1,3);fd_table_t*ta=table_new(a),*tb=table_new(b);
    CHECK(fd_table_install(ta,same,1,0)==1);CHECK(!action(ta,a,11,6,1,0,0,0,NULL));
    int error;io_request_t*r=prepare(tb,b,22,7,1,0,0,0,&error);CHECK(!error);io_service_result_t result;
    CHECK(!io_record_lock_execute(r,&result));CHECK(!fd_table_close(ta,1));
    CHECK(io_record_lock_execute(r,&result)&&!finish(r,&result,NULL,false));drain();
    CHECK(action(ta,a,11,6,1,0,0,1,NULL)==-EAGAIN);
    /* Last table owner must actually shut down despite its held record. */
    fd_table_put(tb);drain();CHECK(!action(ta,a,11,6,1,0,0,1,NULL));
    spinlock_preempt_disable();fd_table_t*child=NULL;CHECK(!fd_table_clone_deferred(ta,false,&child));spinlock_preempt_enable();
    CHECK(action(child,a,33,6,1,0,0,1,NULL)==-EAGAIN);fd_table_put(child);drain();
    CHECK(fd_table_dup2(ta,0,2)==2);CHECK(!action(ta,a,11,6,1,0,0,1,NULL));
    CHECK(fd_table_dup2(ta,0,2)==2); /* replacing even the same open description releases */
    fd_table_t*tc=table_new(b);CHECK(!action(tc,b,44,6,1,0,0,1,NULL));
    CHECK(!fd_table_close(tc,0));CHECK(!action(ta,a,11,6,0,0,10,10,NULL));
    /* Cancel after a successful reservation: conversion must preserve old read lock. */
    r=prepare(ta,a,11,6,1,0,10,10,&error);CHECK(!error&&io_record_lock_execute(r,&result));
    CHECK(finish(r,&result,NULL,true)==-ECANCELED);drain();
    syscall_record_lock_t*q=calloc(1,sizeof(*q));CHECK(q);
    CHECK(!action(tc,b,44,5,1,0,10,1,q)&&q->type==0);
    CHECK(!action(tc,b,44,6,0,0,10,1,NULL));
    r=prepare(ta,a,11,7,1,0,10,1,&error);CHECK(!error&&!io_record_lock_execute(r,&result));
    CHECK(!io_request_waiter_abandon(r));result.result=-ECANCELED;result.description_owned=NULL;
    CHECK(!io_request_publish_complete(r,result.result,NULL)&&!io_request_worker_release(r));drain();
    fd_table_put(tc);fd_table_put(ta);fd_description_put(same);fd_description_put(a);fd_description_put(b);free(q);drain();
}
static void ranges_and_failures(void){
    fd_description_t*a=file_new(2,3),*b=file_new(2,3),*ro=file_new(2,1);fd_table_t*ta=table_new(a),*tb=table_new(b);
    syscall_record_lock_t*q=calloc(1,sizeof(*q));CHECK(q);
    CHECK(!action(ta,a,11,6,0,1,-10,25,NULL));
    CHECK(!action(tb,b,22,5,1,0,200,1,q)&&q->start==190&&q->length==25&&q->whence==0);
    CHECK(!action(ta,a,11,6,1,2,-5,-5,NULL));
    CHECK(!action(tb,b,22,5,1,0,492,1,q)&&q->start==490&&q->length==5);
    CHECK(action(ta,a,11,6,1,0,INT64_MAX,2,NULL)==-EOVERFLOW);
    CHECK(action(ta,a,11,6,1,0,0,-1,NULL)==-EINVAL);
    CHECK(action(ta,a,11,6,77,0,0,1,NULL)==-EINVAL);
    CHECK(action(ta,a,11,6,1,77,0,1,NULL)==-EINVAL);
    CHECK(action(ta,ro,11,6,1,0,0,1,NULL)==-EBADF);
    CHECK(!action(tb,ro,22,5,1,0,200,1,q)&&q->type==0);
    fail_countdown=1;CHECK(action(ta,a,11,6,1,0,0,1,NULL)==-ENOMEM);fail_countdown=0;drain();
    fail_countdown=2;CHECK(action(ta,a,11,6,1,0,0,1,NULL)==-ENOLCK);fail_countdown=0;drain();
    fd_table_put(ta);fd_table_put(tb);fd_description_put(a);fd_description_put(b);fd_description_put(ro);free(q);drain();
}
typedef struct{unsigned number;} job_t;
static void *worker(void*argument){
    thread_queue=io_queue_create(16);CHECK(thread_queue);
    job_t*j=argument;fd_description_t*d=file_new(4+j->number,3);fd_table_t*t=table_new(d);
    for(unsigned i=0;i<128;++i){CHECK(!action(t,d,100+j->number,6,1,0,0,0,NULL));CHECK(!action(t,d,100+j->number,6,2,0,0,0,NULL));}
    fd_table_put(t);fd_description_put(d);drain();io_queue_shutdown(thread_queue);CHECK(!io_queue_destroy(thread_queue));thread_queue=NULL;return NULL;
}
int main(void){
    retirement=fd_retirement_queue_create(16384);queue=io_queue_create(256);CHECK(retirement&&queue);
    intervals();lifetime();ranges_and_failures();
    job_t*jobs=calloc(8,sizeof(*jobs));pthread_t*threads=calloc(8,sizeof(*threads));CHECK(jobs&&threads);
    for(unsigned i=0;i<8;++i){jobs[i].number=i;CHECK(!pthread_create(&threads[i],NULL,worker,&jobs[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));free(jobs);free(threads);drain();
    CHECK(!record_allocated&&!held_records&&!record_leases&&!retired_records);
    io_queue_shutdown(queue);CHECK(!io_queue_destroy(queue));fd_retirement_queue_shutdown(retirement);CHECK(!fd_retirement_queue_destroy(retirement));
    puts("RECORD_LOCK_CONTRACT: PASS cpus=8 operations=2048 intervals=1 queries=1 reservations=1 cancel=1 close_any=1 dup2=1 spawn=1 owner_cleanup=1 offsets=1 allocation_failure=1");
}
'''
compile_and_run('record-lock',code)
print('Production record locks, close observers and retirement: PASS')
