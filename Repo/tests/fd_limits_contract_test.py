#!/usr/bin/env python3
"""Production FD limits, allocation admission, inheritance and checked metadata."""
import contextlib
import io
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition
import fd_retirement_contract_test as base

captured=[]
original=base.compile_and_run
base.compile_and_run=lambda label,code:captured.append(code)
try:
    with contextlib.redirect_stdout(io.StringIO()):base.main()
finally:base.compile_and_run=original
code=captured[0].replace('int main(void)','static int baseline(void)',1)
code+=r'''
static void limits(void){
    static const fd_ops_t ops={0};fd_description_t *description=fd_description_create(&ops,NULL);fd_table_t *table=fd_table_create(8);CHECK(description && table);
    uint64_t soft=0,hard=0;CHECK(!fd_table_get_limits(table,&soft,&hard) && soft==8 && hard==8);
    CHECK(fd_table_install_at(table,6,description,0)==6 && !fd_table_set_limits(table,2,4,false));
    CHECK(fd_table_dup2(table,6,6)==6 && fd_table_dup2(table,6,3)==-EBADF && fd_table_dup3(table,6,6,0)==-EINVAL);
    CHECK(fd_table_install_at(table,3,description,0)==-EMFILE && fd_table_dup_minimum(table,6,2,0)==-EINVAL && fd_table_dup(table,6,2,0)==-EMFILE);
    CHECK(fd_table_dup(table,6,0,0)==0 && fd_table_install(table,description,0,0)==1 && fd_table_dup(table,6,0,0)==-EMFILE);
    CHECK(!fd_table_set_limits(table,0,4,false) && fd_table_dup(table,6,0,0)==-EMFILE && fd_table_dup_minimum(table,6,0,0)==-EINVAL);
    fd_description_t *pin=NULL;CHECK(!fd_table_pin(table,6,&pin,NULL) && pin==description && !fd_description_put(pin));
    CHECK(fd_table_set_limits(table,0,8,false)==-EPERM && fd_table_set_limits(table,5,4,true)==-EINVAL && fd_table_set_limits(table,9,9,true)==-EPERM && fd_table_set_limits(table,UINT64_MAX,UINT64_MAX,true)==-EPERM);
    CHECK(!fd_table_get_limits(table,&soft,&hard) && soft==0 && hard==4);
    fail_allocations=1;CHECK(!fd_table_set_limits(table,8,8,true) && fail_allocations==1);fail_allocations=0;
    CHECK(!fd_table_close(table,6));fd_table_shutdown(table);soft=91;hard=92;
    CHECK(fd_table_get_limits(table,&soft,&hard)==-EBADF && soft==91 && hard==92 && fd_table_set_limits(table,1,8,true)==-EBADF);
    fd_table_put(table);CHECK(!fd_description_put(description));
}
static void admission_and_inheritance(void){
    fd_retirement_queue_t *queue=fd_retirement_queue_create(64);CHECK(queue);static const fd_ops_t ops={0};
    fd_table_t *table=fd_table_create_deferred(8,queue);fd_description_t *description=fd_description_create_deferred(&ops,NULL,queue);CHECK(table && description);
    CHECK(fd_table_install_at(table,0,description,0)==0 && fd_table_install_at(table,1,description,0)==1 && fd_table_install_at(table,6,description,0)==6);
    spinlock_preempt_disable();fd_description_t *reservation=NULL;CHECK(!fd_table_reserve_deferred(table,&reservation));
    CHECK(!fd_table_set_limits(table,0,4,false));
    CHECK(fd_table_reservation_commit(reservation,description,0)==2);CHECK(!fd_description_put(reservation));
    fd_table_t *copy=NULL;CHECK(!fd_table_clone_deferred(table,true,&copy));spinlock_preempt_enable();
    uint64_t soft=99,hard=99;CHECK(!fd_table_get_limits(copy,&soft,&hard) && soft==0 && hard==4);
    fd_description_t *pin=NULL;CHECK(!fd_table_pin(copy,6,&pin,NULL) && pin==description && !fd_description_put(pin));
    CHECK(fd_table_dup(copy,6,0,0)==-EMFILE && !fd_table_set_limits(table,3,4,false));
    int slots[2]={91,92};CHECK(fd_table_install_pair(table,description,description,0,slots)==-EMFILE && slots[0]==91 && slots[1]==92);
    CHECK(!fd_table_close(table,1) && fd_table_install_pair(table,description,description,0,slots)==-EMFILE);
    CHECK(!fd_table_close(table,2) && !fd_table_install_pair(table,description,description,0,slots) && slots[0]==1 && slots[1]==2);
    CHECK(!fd_table_get_limits(copy,&soft,&hard) && soft==0 && hard==4);
    fd_table_put(copy);fd_table_put(table);CHECK(!fd_description_put(description));destroy_empty(queue);
}
typedef struct {fd_table_t *table;fd_description_t *description;fd_retirement_queue_t *queue;unsigned kind;} limits_job_t;
static void *limits_worker(void *opaque){
    limits_job_t *job=opaque;
    for(unsigned round=0;round<1000;++round){
        if(!job->kind){CHECK(!fd_table_set_limits(job->table,round%2?8:16,16,false));continue;}
        uint64_t soft=0,hard=0;CHECK(!fd_table_get_limits(job->table,&soft,&hard) && (soft==8 || soft==16) && hard==16);
        if(job->kind==1){int fd=fd_table_dup(job->table,31,0,0);if(fd>=0){CHECK(fd<16);CHECK(!fd_table_close(job->table,fd));}else CHECK(fd==-EMFILE);}
        else if(job->kind==2){int slots[2]={-1,-1};int result=fd_table_install_pair(job->table,job->description,job->description,0,slots);if(!result){CHECK(slots[0]<16 && slots[1]<16 && slots[0]!=slots[1]);CHECK(!fd_table_close(job->table,slots[0]) && !fd_table_close(job->table,slots[1]));}else CHECK(result==-EMFILE && slots[0]==-1 && slots[1]==-1);}
        else {spinlock_preempt_disable();fd_description_t *reservation=NULL;int result=fd_table_reserve_deferred(job->table,&reservation);if(!result){int fd=fd_table_reservation_commit(reservation,job->description,0);CHECK(fd>=0 && fd<16);CHECK(!fd_description_put(reservation));spinlock_preempt_enable();CHECK(!fd_table_close(job->table,fd));}else{CHECK(result==-EMFILE);spinlock_preempt_enable();}drain(job->queue,8);}
    }
    CHECK(!held_locks && !preempt_depth);return NULL;
}
static void concurrent(void){
    fd_retirement_queue_t *queue=fd_retirement_queue_create(65536);CHECK(queue);static const fd_ops_t ops={0};
    fd_table_t *table=fd_table_create_deferred(32,queue);fd_description_t *description=fd_description_create_deferred(&ops,NULL,queue);CHECK(table && description);
    CHECK(fd_table_install_at(table,31,description,0)==31 && !fd_table_set_limits(table,16,16,false));
    limits_job_t *jobs=calloc(8,sizeof(*jobs));pthread_t threads[8];CHECK(jobs);
    for(unsigned i=0;i<8;++i){jobs[i]=(limits_job_t){table,description,queue,i==0?0:i<5?1:i<7?2:3};CHECK(!pthread_create(&threads[i],NULL,limits_worker,&jobs[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(!fd_table_close(table,31));free(jobs);fd_table_put(table);CHECK(!fd_description_put(description));destroy_empty(queue);
}
typedef struct {uint64_t current,maximum;} syscall_rlimit_t;
#define SYSCALL_RESOURCE_NOFILE 7u
#define SYSCALL_RESOURCE_AS 9u
typedef struct {bool is_user;uint32_t uid;fd_table_t *table;} process_t;
static process_t limit_process;
static _Thread_local bool deny_read,deny_write;
static process_t *current_process_local(void){CHECK(preempt_depth);return &limit_process;}
static fd_table_t *process_current_fd_table(void){CHECK(preempt_depth);return limit_process.table;}
static uint32_t process_get_uid(process_t *process){CHECK(preempt_depth);return process->uid;}
static bool user_ptr_range_valid(void *data,size_t bytes){return (uintptr_t)data>4096 && bytes==16;}
static bool user_copy_from_user(void *out,const void *in,size_t bytes){CHECK(preempt_depth && bytes==16);if(deny_read)return false;memcpy(out,in,bytes);return true;}
static bool user_copy_to_user(void *out,const void *in,size_t bytes){CHECK(preempt_depth && bytes==16);if(deny_write)return false;memcpy(out,in,bytes);return true;}
'''
code+=function_definition((ROOT/'src/kernel/io/user_file.c').read_text(),'static int64_t user_resource_limit(')
code+=r'''
static void metadata(void){
    limit_process=(process_t){true,37,fd_table_create(8)};CHECK(limit_process.table);syscall_rlimit_t wire={91,92};
    CHECK(!user_resource_limit(false,7,&wire,16) && wire.current==8 && wire.maximum==8);
    wire=(syscall_rlimit_t){4,4};CHECK(!user_resource_limit(true,7,&wire,16));wire=(syscall_rlimit_t){8,8};CHECK(user_resource_limit(true,7,&wire,16)==-EPERM);
    limit_process.uid=0;CHECK(!user_resource_limit(true,7,&wire,16));
    deny_read=true;wire=(syscall_rlimit_t){0,0};CHECK(user_resource_limit(true,7,&wire,16)==-EFAULT);deny_read=false;
    CHECK(!user_resource_limit(false,7,&wire,16) && wire.current==8 && wire.maximum==8);
    deny_write=true;wire=(syscall_rlimit_t){91,92};CHECK(user_resource_limit(false,7,&wire,16)==-EFAULT && wire.current==91 && wire.maximum==92);deny_write=false;
    CHECK(user_resource_limit(false,7,NULL,16)==-EFAULT && user_resource_limit(false,7,&wire,15)==-EINVAL && user_resource_limit(false,99,&wire,16)==-EINVAL);
    CHECK(!user_resource_limit(false,9,&wire,16) && wire.current==UINT64_MAX && wire.maximum==UINT64_MAX && user_resource_limit(true,9,&wire,16)==-ENOTSUP);
    fd_table_put(limit_process.table);limit_process.table=NULL;CHECK(user_resource_limit(false,7,&wire,16)==-ESRCH && !preempt_depth);
}
int main(void){CHECK(!baseline());limits();admission_and_inheritance();concurrent();metadata();CHECK(!allocations && !held_locks && !preempt_depth);puts("FD_LIMITS_CONTRACT: PASS operations=8000 limits=1 admission=1 inheritance=1 high_slots=1 privilege=1 copy=1");return 0;}
'''
compile_and_run('fd-limits-contract',code)
print('Production FD limits: PASS 8000 concurrent operations, admission, inherited policy, high slots, privilege and checked metadata')
