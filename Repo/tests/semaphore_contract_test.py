#!/usr/bin/env python3
"""Run actual Alix semaphore code with deterministic and pthread futex models."""
import os,shlex
from audio_stream_contract_test import ROOT,compile_and_run
from audio_hda_state_test import typedef


def main():
    header=(ROOT/'include/semaphore.h').read_text()
    code=r'''
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"semaphore contract line %d: %s\n",__LINE__,#x);abort();}}while(0)
#define sem_t native_sem_t
#define sem_init native_sem_init
#define sem_destroy native_sem_destroy
#define sem_post native_sem_post
#define sem_wait native_sem_wait
#define sem_trywait native_sem_trywait
#define sem_timedwait native_sem_timedwait
#define sem_getvalue native_sem_getvalue
#define SEM_VALUE_MAX INT_MAX
'''
    code+=typedef(header,'sem_t')+'\n'
    code+='\n'.join(line for line in (ROOT/'include/syscall_defs.h').read_text().splitlines() if line.startswith('#define SYSCALL_FUTEX_'))+'\n'
    code+=r'''
static pthread_mutex_t futex_gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t futex_changed=PTHREAD_COND_INITIALIZER;
static bool fake_clock;static struct timespec fake_now;
static int injected_result;static unsigned calls;static uint32_t timeout_seen;
static int model_clock_gettime(clockid_t id,struct timespec*out){if(fake_clock){CHECK(id==CLOCK_REALTIME);*out=fake_now;return 0;}return clock_gettime(id,out);}
static int sys_futex_wait(volatile uint32_t*address,uint32_t expected,uint32_t timeout){
 if(fake_clock||injected_result){
  ++calls;timeout_seen=timeout;
  if(injected_result){int r=injected_result;injected_result=0;return r;}
  CHECK(timeout!=SYSCALL_FUTEX_WAIT_FOREVER);fake_now.tv_nsec+=(long)timeout*1000000;
  fake_now.tv_sec+=fake_now.tv_nsec/1000000000;fake_now.tv_nsec%=1000000000;return SYSCALL_FUTEX_TIMED_OUT;
 }
 CHECK(!pthread_mutex_lock(&futex_gate));int result=0;
 if(__atomic_load_n(address,__ATOMIC_ACQUIRE)!=expected)result=SYSCALL_FUTEX_AGAIN;
 else if(timeout==SYSCALL_FUTEX_WAIT_FOREVER)CHECK(!pthread_cond_wait(&futex_changed,&futex_gate));
 else{
  struct timespec deadline;CHECK(!clock_gettime(CLOCK_REALTIME,&deadline));deadline.tv_nsec+=(long)(timeout%1000)*1000000;deadline.tv_sec+=timeout/1000+deadline.tv_nsec/1000000000;deadline.tv_nsec%=1000000000;
  int status=pthread_cond_timedwait(&futex_changed,&futex_gate,&deadline);CHECK(!status||status==ETIMEDOUT);if(status==ETIMEDOUT)result=SYSCALL_FUTEX_TIMED_OUT;
 }
 CHECK(!pthread_mutex_unlock(&futex_gate));return result;
}
static int sys_futex_wake(volatile uint32_t*address,uint32_t maximum){(void)address;CHECK(maximum==1);CHECK(!pthread_mutex_lock(&futex_gate));CHECK(!pthread_cond_broadcast(&futex_changed));CHECK(!pthread_mutex_unlock(&futex_gate));return 1;}
#define clock_gettime model_clock_gettime
'''
    code+='\n'.join(line for line in (ROOT/'user/lib/semaphore.c').read_text().splitlines() if not line.startswith('#include '))+'\n'
    code+=r'''
static void deterministic(void){
 sem_t*s=calloc(1,sizeof(*s));struct timespec*d=calloc(1,sizeof(*d));int*value=calloc(1,sizeof(*value));CHECK(s&&d&&value);
 CHECK(sem_init(NULL,0,0)==-1&&errno==EINVAL);CHECK(sem_init(s,1,0)==-1&&errno==ENOTSUP);CHECK(sem_init(s,0,UINT_MAX)==-1&&errno==EINVAL);
 CHECK(!sem_init(s,0,1)&&!sem_getvalue(s,value)&&*value==1&&!sem_trywait(s));CHECK(sem_trywait(s)==-1&&errno==EAGAIN);
 CHECK(!sem_post(s)&&!sem_wait(s)&&!sem_getvalue(s,value)&&!*value);CHECK(sem_getvalue(s,NULL)==-1&&errno==EINVAL);
 fake_clock=true;fake_now=(struct timespec){10,100000000};*d=(struct timespec){10,105000000};calls=0;
 CHECK(sem_timedwait(s,d)==-1&&errno==ETIMEDOUT&&calls==1&&timeout_seen==5&&!s->waiters);
 *d=(struct timespec){9,0};calls=0;CHECK(sem_timedwait(s,d)==-1&&errno==ETIMEDOUT&&!calls);
 *d=(struct timespec){20,1000000000};CHECK(sem_timedwait(s,d)==-1&&errno==EINVAL);CHECK(!sem_post(s)&&!sem_timedwait(s,d));
 for(unsigned i=0;i<3;++i){injected_result=i==0?SYSCALL_FUTEX_INTERRUPTED:i==1?SYSCALL_FUTEX_FAULT:SYSCALL_FUTEX_INVALID;
  CHECK(sem_wait(s)==-1&&errno==(i==0?EINTR:i==1?EFAULT:EINVAL)&&!s->waiters);
 }
 CHECK(!sem_destroy(s)&&sem_post(s)==-1&&errno==EINVAL&&sem_destroy(s)==-1&&errno==EINVAL);
 CHECK(!sem_init(s,0,SEM_VALUE_MAX)&&sem_post(s)==-1&&errno==EOVERFLOW&&!sem_getvalue(s,value)&&*value==SEM_VALUE_MAX&&!sem_destroy(s));
 fake_clock=false;free(s);free(d);free(value);
}
typedef struct{pthread_t thread;sem_t*semaphore;bool producer;unsigned loops;uint64_t*consumed;}job_t;
static void*run(void*pointer){job_t*j=pointer;for(unsigned i=0;i<j->loops;++i){if(j->producer)CHECK(!sem_post(j->semaphore));else{CHECK(!sem_wait(j->semaphore));__atomic_add_fetch(j->consumed,1,__ATOMIC_RELAXED);}}return NULL;}
static void concurrent(void){
 sem_t*s=calloc(1,sizeof(*s));job_t*jobs=calloc(8,sizeof(*jobs));uint64_t*consumed=calloc(1,sizeof(*consumed));CHECK(s&&jobs&&consumed&&!sem_init(s,0,0));
 for(unsigned i=0;i<8;++i){jobs[i].semaphore=s;jobs[i].producer=i>=4;jobs[i].loops=10000;jobs[i].consumed=consumed;CHECK(!pthread_create(&jobs[i].thread,NULL,run,&jobs[i]));}
 for(unsigned i=0;i<8;++i)CHECK(!pthread_join(jobs[i].thread,NULL));int value=-1;CHECK(*consumed==40000&&!sem_getvalue(s,&value)&&!value&&!s->waiters&&!sem_destroy(s));
 free(s);free(jobs);free(consumed);
}
int main(void){deterministic();concurrent();puts("Semaphore contracts PASS: deadlines, EINTR/errors, overflow and 40000 concurrent handoffs");return 0;}
'''
    previous=os.environ.get('HOST_CC')
    os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
    try:compile_and_run('semaphore',code)
    finally:
        if previous is None:os.environ.pop('HOST_CC',None)
        else:os.environ['HOST_CC']=previous

if __name__=='__main__':main()
