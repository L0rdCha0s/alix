#!/usr/bin/env python3
"""Production lock engine with real request/FD retirement ownership primitives."""
import re
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

def body(path):
    return re.sub(r'^\s*#include[^\n]*\n', '', (ROOT / path).read_text(), flags=re.M)

program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/types.h>
#define CHECK(c) do { if(!(c)){fprintf(stderr,"flock contract line %d: %s\n",__LINE__,#c);abort();} }while(0)
typedef struct {uint64_t size_bytes;uint32_t type,reserved;uint64_t atime,mtime,ctime;} syscall_stat_t;
typedef struct {atomic_uint value;} spinlock_t;
static _Thread_local unsigned guards;
static void spinlock_preempt_disable(void){++guards;}
static void spinlock_preempt_enable(void){CHECK(guards);--guards;}
static bool spinlock_preempt_disabled(void){return guards!=0;}
static void spinlock_init(spinlock_t *lock){atomic_init(&lock->value,0);}
static void spinlock_lock(spinlock_t *lock){spinlock_preempt_disable();while(atomic_exchange_explicit(&lock->value,1,memory_order_acquire))sched_yield();}
static void spinlock_unlock(spinlock_t *lock){atomic_store_explicit(&lock->value,0,memory_order_release);spinlock_preempt_enable();}
#define SYSCALL_FLOCK_SHARED 1u
#define SYSCALL_FLOCK_EXCLUSIVE 2u
#define SYSCALL_FLOCK_NONBLOCK 4u
#define SYSCALL_FLOCK_UNLOCK 8u
'''
for header in ('include/fd.h', 'include/fd_table.h', 'include/io_request.h',
               'include/io_service.h', 'include/io_event_service.h', 'include/io_flock.h'):
    program += body(header) + '\n'
for source in ('src/kernel/fd/table.c', 'src/kernel/io/request.c'):
    program += body(source) + '\n'
program += r'''
static _Thread_local bool fail_lease_allocation;
static void *lease_calloc(size_t count,size_t size){return fail_lease_allocation?NULL:calloc(count,size);}
#define calloc lease_calloc
'''
program += body('src/kernel/io/flock.c') + '\n#undef calloc\n'
program += r'''
typedef struct {io_flock_state_t state;} test_file_t;
static unsigned keys[2];
static fd_retirement_queue_t *retirement;
static int test_file_close(void *opaque){test_file_t *file=opaque;io_flock_state_close(&file->state);free(file);return 0;}
static const fd_ops_t file_ops={.close=test_file_close};
static fd_description_t *file_new(unsigned key){
    spinlock_preempt_disable();test_file_t *file=calloc(1,sizeof(*file));CHECK(file);
    fd_description_t *description=fd_description_create_deferred(&file_ops,file,retirement);CHECK(description);
    io_flock_state_init(&file->state,&keys[key],description);spinlock_preempt_enable();return description;
}
static io_flock_state_t *state(fd_description_t *file){return &((test_file_t *)fd_description_context(file))->state;}
enum {USER_FLOCK=6};
#define SYSCALL_FILE_FLOCK FLOCK_SYSCALL_NUMBER
static fd_description_t *syscall_file;
static io_queue_t *syscall_queue;
static unsigned syscall_failure_stage;
static fd_retirement_queue_t *process_fd_retirement_queue(void){return retirement;}
static io_flock_state_t *io_vfs_flock_state(const fd_description_t *file){return state((fd_description_t *)file);}
static int user_file_pin(uint64_t fd,fd_description_t **out){*out=NULL;if(fd!=7)return -EBADF;CHECK(fd_description_get(syscall_file));*out=syscall_file;return 0;}
static int user_file_create(int kind,size_t bytes,fd_description_t *owned,fd_description_t *cwd,io_request_t **out){
    CHECK(kind==USER_FLOCK && !bytes && !cwd);*out=NULL;
    if(syscall_failure_stage==1){fd_description_put(owned);return -EAGAIN;}
    CHECK(syscall_failure_stage==2);CHECK(!io_request_create(syscall_queue,0,0,0,out));CHECK(!io_request_bind(*out,owned,NULL,NULL));return 0;
}
static int user_file_submit(int kind,io_request_t *request){CHECK(kind==USER_FLOCK && syscall_failure_stage==2);CHECK(!io_request_waiter_abandon(request));return -EAGAIN;}
static int64_t user_file_finish(int kind,unsigned operation,void *output,size_t bytes,unsigned flags){(void)kind;(void)operation;(void)output;(void)bytes;(void)flags;CHECK(false);return -EIO;}
/* PROD_USER_FLOCK */
static void drain(void){while(fd_retirement_queue_drain(retirement,4096)){};}
static io_request_t *prepare(io_queue_t *queue,fd_description_t *file,uint32_t operation){
    spinlock_preempt_disable();CHECK(fd_description_get(file));fd_description_t *lease=NULL;
    CHECK(!io_flock_create(retirement,file,state(file),operation,&lease) && lease);
    io_request_t *request=NULL;CHECK(!io_request_create(queue,0,37,41,&request));
    CHECK(!io_request_bind(request,lease,NULL,NULL));CHECK(!io_request_submit(request));CHECK(io_queue_take(queue)==request);
    spinlock_preempt_enable();return request;
}
static bool execute(io_request_t *request){
    io_service_result_t *result=calloc(1,sizeof(*result));CHECK(result);
    bool ready=io_flock_execute(request,result);
    if(ready){CHECK(!io_request_publish_complete(request,result->result,result->description_owned));CHECK(!io_request_worker_release(request));}
    else CHECK(!result->description_owned);
    free(result);return ready;
}
static int claim(io_queue_t *queue,io_request_t *request){
    spinlock_preempt_disable();io_request_status_t status;CHECK(!io_request_status(request,&status));CHECK(status.state==IO_REQUEST_COMPLETED);
    int result=(int)status.result;fd_description_t *lease=NULL;
    if(!result){result=io_request_take_result(request,&lease);if(!result){CHECK(lease);result=io_flock_commit(lease);}fd_description_put(lease);}
    if(result<0)io_flock_abort(io_request_description(request));
    CHECK(!io_request_waiter_release(request));spinlock_preempt_enable();CHECK(io_queue_drain(queue,64)==1);return result;
}
static int try_lock(io_queue_t *queue,fd_description_t *file,unsigned mode){
    io_request_t *request=prepare(queue,file,mode|SYSCALL_FLOCK_NONBLOCK);CHECK(execute(request));return claim(queue,request);
}
static void cancel(io_queue_t *queue,io_request_t *request,bool running){
    CHECK(!io_request_cancel(request));
    if(running){CHECK(!io_request_publish_complete(request,-ECANCELED,NULL));CHECK(!io_request_worker_release(request));}
    CHECK(!io_request_waiter_abandon(request));CHECK(io_queue_drain(queue,64)==1);drain();
}
static void basics(io_queue_t *queue){
    fd_description_t *a=file_new(0),*b=file_new(0),*other=file_new(1);
    CHECK(!try_lock(queue,a,SYSCALL_FLOCK_SHARED));CHECK(!try_lock(queue,b,SYSCALL_FLOCK_SHARED));
    CHECK(try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE)==-EWOULDBLOCK);
    CHECK(!try_lock(queue,other,SYSCALL_FLOCK_EXCLUSIVE));CHECK(!io_flock_unlock(state(b)));
    CHECK(!try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE));CHECK(try_lock(queue,b,SYSCALL_FLOCK_SHARED)==-EWOULDBLOCK);
    CHECK(fd_description_get(a));fd_description_put(a);CHECK(try_lock(queue,b,SYSCALL_FLOCK_EXCLUSIVE)==-EWOULDBLOCK);
    CHECK(!io_flock_unlock(state(a)));CHECK(!try_lock(queue,b,SYSCALL_FLOCK_EXCLUSIVE));
    CHECK(!io_flock_unlock(state(b)));CHECK(!io_flock_unlock(state(other)));
    fd_description_put(a);fd_description_put(b);fd_description_put(other);drain();
}
static void cancellation(io_queue_t *queue){
    fd_description_t *a=file_new(0),*b=file_new(0);
    CHECK(!try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE));
    io_request_t *pending=prepare(queue,b,SYSCALL_FLOCK_EXCLUSIVE);CHECK(!execute(pending));cancel(queue,pending,true);
    CHECK(!io_flock_unlock(state(a)));CHECK(!try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE));CHECK(!io_flock_unlock(state(a)));
    io_request_t *reserved=prepare(queue,a,SYSCALL_FLOCK_EXCLUSIVE);CHECK(execute(reserved));
    CHECK(try_lock(queue,b,SYSCALL_FLOCK_EXCLUSIVE)==-EWOULDBLOCK);cancel(queue,reserved,false);
    CHECK(!try_lock(queue,b,SYSCALL_FLOCK_EXCLUSIVE));CHECK(!io_flock_unlock(state(b)));
    reserved=prepare(queue,a,SYSCALL_FLOCK_EXCLUSIVE);CHECK(execute(reserved));CHECK(!io_flock_unlock(state(a)));
    CHECK(!try_lock(queue,b,SYSCALL_FLOCK_EXCLUSIVE));CHECK(claim(queue,reserved)==-ECANCELED);
    CHECK(try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE)==-EWOULDBLOCK);CHECK(!io_flock_unlock(state(b)));
    CHECK(!try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE));
    pending=prepare(queue,b,SYSCALL_FLOCK_EXCLUSIVE);CHECK(!execute(pending));
    CHECK(!io_flock_unlock(state(b)));CHECK(execute(pending));CHECK(claim(queue,pending)==-ECANCELED);
    CHECK(!io_flock_unlock(state(a)));fd_description_put(a);fd_description_put(b);drain();
}
static void close_visibility(io_queue_t *queue){
    fd_description_t *a=file_new(0),*b=file_new(0);fd_table_t *table=fd_table_create_deferred(4,retirement);CHECK(table);
    CHECK(fd_table_install(table,a,0,0)==0);
    CHECK(!try_lock(queue,a,SYSCALL_FLOCK_SHARED) && !try_lock(queue,b,SYSCALL_FLOCK_SHARED));
    CHECK(try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE)==-EWOULDBLOCK);
    CHECK(!io_flock_unlock(state(b)) && !try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE));fd_description_put(a);
    /* Keep the already-completed lease finalizer queued: it must no longer
     * retain the committed file. No retirement drain precedes this close. */
    CHECK(!fd_table_close(table,0));CHECK(!try_lock(queue,b,SYSCALL_FLOCK_EXCLUSIVE));
    CHECK(!io_flock_unlock(state(b)));fd_description_put(b);fd_table_shutdown(table);fd_table_put(table);drain();
}
static void admission(io_queue_t *queue){
    fd_description_t *a=file_new(0),*b=file_new(0),*out=(void *)1;
    CHECK(fd_description_get(a));fail_lease_allocation=true;
    CHECK(io_flock_create(retirement,a,state(a),SYSCALL_FLOCK_EXCLUSIVE,&out)==-ENOMEM && !out);
    fail_lease_allocation=false;CHECK(fd_description_referenced(a));
    CHECK(!try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE));
    io_queue_t *one=io_queue_create(1);CHECK(one);io_request_t *pending=prepare(one,b,SYSCALL_FLOCK_EXCLUSIVE);CHECK(!execute(pending));
    io_request_t *extra=(void *)1;CHECK(io_request_create(one,0,0,0,&extra)==-EAGAIN && !extra);
    CHECK(!io_flock_unlock(state(a)));CHECK(execute(pending));CHECK(!claim(one,pending));CHECK(!io_flock_unlock(state(b)));
    io_queue_shutdown(one);CHECK(!io_queue_destroy(one));fd_description_put(a);fd_description_put(b);drain();
    fd_retirement_queue_t *original=retirement;retirement=fd_retirement_queue_create(2);CHECK(retirement);
    a=file_new(1);CHECK(!try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE));
    CHECK(fd_description_get(a));CHECK(io_flock_create(retirement,a,state(a),SYSCALL_FLOCK_EXCLUSIVE,&out)==-ENOMEM && !out);
    CHECK(!io_flock_unlock(state(a)));fd_description_put(a);drain();fd_retirement_queue_shutdown(retirement);CHECK(!fd_retirement_queue_destroy(retirement));retirement=original;
}
static void syscall_preparation(io_queue_t *queue){
    for(unsigned failure=1;failure<=2;++failure){
        fd_description_t *a=file_new(0),*b=file_new(0);CHECK(!try_lock(queue,a,SYSCALL_FLOCK_EXCLUSIVE));
        syscall_file=a;syscall_queue=io_queue_create(1);CHECK(syscall_queue);syscall_failure_stage=failure;
        CHECK(user_file_flock(7,SYSCALL_FLOCK_EXCLUSIVE)==-EAGAIN);fd_description_put(a);
        /* Neither the failed lease nor a cancelled NEW request may retain
         * the target after the syscall returns. Cleanup is deliberately delayed. */
        CHECK(!try_lock(queue,b,SYSCALL_FLOCK_EXCLUSIVE));CHECK(!io_flock_unlock(state(b)));fd_description_put(b);
        (void)io_queue_drain(syscall_queue,64);io_queue_shutdown(syscall_queue);CHECK(!io_queue_destroy(syscall_queue));
        syscall_file=NULL;syscall_queue=NULL;drain();
    }
}
static int shared_count;
typedef struct {fd_retirement_queue_t *queue;atomic_bool stop;} cleanup_t;
static void *cleanup_worker(void *opaque){
    cleanup_t *cleanup=opaque;
    while(!atomic_load(&cleanup->stop)){(void)fd_retirement_queue_drain(cleanup->queue,64);sched_yield();}
    while(fd_retirement_queue_drain(cleanup->queue,4096)){};
    CHECK(!fd_retirement_queue_put(cleanup->queue));CHECK(!guards);return NULL;
}
typedef struct {fd_description_t *file;io_queue_t *queue;} worker_t;
static void *worker(void *opaque){
    worker_t *arg=opaque;
    for(unsigned i=0;i<128;++i){io_request_t *request=prepare(arg->queue,arg->file,SYSCALL_FLOCK_EXCLUSIVE);
        while(!execute(request))sched_yield();CHECK(!claim(arg->queue,request));
        int old=shared_count;sched_yield();shared_count=old+1;CHECK(!io_flock_unlock(state(arg->file)));
        fd_description_t *noise=file_new(0);int result=try_lock(arg->queue,noise,SYSCALL_FLOCK_SHARED);
        CHECK(result==0 || result==-EWOULDBLOCK);fd_description_put(noise);}
    CHECK(!guards);return NULL;
}
int main(void){
    retirement=fd_retirement_queue_create(4096);CHECK(retirement);io_queue_t *queue=io_queue_create(16);CHECK(queue);
    CHECK(!io_flock_flags_valid(0) && !io_flock_flags_valid(3) && !io_flock_flags_valid(16));
    basics(queue);cancellation(queue);close_visibility(queue);admission(queue);syscall_preparation(queue);
    fd_description_t *invalid=file_new(0),*out=(void *)1;CHECK(fd_description_get(invalid));
    CHECK(io_flock_create(retirement,invalid,state(invalid),0,&out)==-EINVAL && !out);fd_description_put(invalid);drain();
    cleanup_t *cleanup=calloc(1,sizeof(*cleanup));CHECK(cleanup);cleanup->queue=retirement;CHECK(fd_retirement_queue_get(retirement));
    pthread_t cleaner;CHECK(!pthread_create(&cleaner,NULL,cleanup_worker,cleanup));
    worker_t *args=calloc(8,sizeof(*args));CHECK(args);pthread_t threads[8];
    for(unsigned i=0;i<8;++i){args[i].file=file_new(0);args[i].queue=io_queue_create(2);CHECK(args[i].queue);CHECK(!pthread_create(&threads[i],NULL,worker,&args[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));CHECK(shared_count==1024);
    for(unsigned i=0;i<8;++i){fd_description_put(args[i].file);io_queue_shutdown(args[i].queue);CHECK(!io_queue_destroy(args[i].queue));}
    free(args);atomic_store(&cleanup->stop,true);CHECK(!pthread_join(cleaner,NULL));free(cleanup);
    drain();io_queue_shutdown(queue);CHECK(!io_queue_destroy(queue));
    fd_retirement_status_t status;CHECK(!fd_retirement_queue_snapshot(retirement,&status));CHECK(!status.live && !status.pending);
    fd_retirement_queue_shutdown(retirement);CHECK(!fd_retirement_queue_destroy(retirement));CHECK(!flock_registry && !guards);
    puts("FLOCK_CONTRACT_TEST: PASS shared=1 exclusive=1 alias=1 rollback=1 supersede=1 close=1 isolation=1 concurrent=1024");return 0;
}
'''
enum_body = re.search(r'typedef enum\s*\{([^}]+)\}\s*syscall_file_operation_t', (ROOT / 'include/syscall_defs.h').read_text(), re.S).group(1)
operation = [name.strip() for name in enum_body.split(',')].index('SYSCALL_FILE_FLOCK')
program = program.replace('FLOCK_SYSCALL_NUMBER', str(operation))
program = program.replace('/* PROD_USER_FLOCK */', function_definition((ROOT / 'src/kernel/io/user_file.c').read_text(), 'static int64_t user_file_flock('))
compile_and_run('flock-contract', program)
print('Production flock/request/FD contracts: PASS ownership, rollback, close visibility and 1024 concurrent critical sections')
