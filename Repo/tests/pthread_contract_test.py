#!/usr/bin/env python3
"""Run production pthread code with deterministic native syscall interleavings."""
import re
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def rename(text):
    text = re.sub(r"\bpthread_(\w+)", r"test_pthread_\1", text)
    text = re.sub(r"\bsigset_t\b", "test_sigset_t", text)
    text = text.replace("clockid_t", "mock_clockid_t").replace("struct timespec", "struct mock_timespec")
    text = re.sub(r"\bclock_gettime\b", "mock_clock_gettime", text)
    return re.sub(r"\bexit\(", "mock_process_exit(", text)


def main():
    header = (ROOT / "include/pthread.h").read_text()
    types = header[header.index("typedef uint64_t pthread_t;"):header.index('#ifdef __cplusplus')]
    declarations = header[header.index("int pthread_attr_init"):header.rindex('#ifdef __cplusplus')]
    source = (ROOT / "user/lib/pthread.c").read_text()
    source = "\n".join(line for line in source.splitlines() if not line.startswith("#include"))
    errors = "\n".join(line for line in (ROOT / "include/errno.h").read_text().splitlines()
                        if line.startswith("#define E"))
    program = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"pthread contract failed line %d: %s\n",__LINE__,#c); abort(); } } while(0)
typedef int mock_clockid_t;
typedef uint64_t test_sigset_t;
struct mock_timespec { int64_t tv_sec; long tv_nsec; };
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define ALIX_WAIT_FOREVER UINT32_MAX
#define SYSCALL_FUTEX_OK 0
#define SYSCALL_FUTEX_AGAIN (-11)
#define SYSCALL_THREAD_INFO_MAIN 1u
#define SYSCALL_THREAD_PRIORITY_QUERY (-1)
#define SYSCALL_THREAD_INFO_DETACHED 2u
#define SYSCALL_THREAD_STATE_ZOMBIE 3u
typedef struct { volatile uint32_t state; } alix_mutex_t;
typedef struct { volatile uint32_t sequence; } alix_cond_t;
typedef struct { volatile uint32_t state; } alix_once_t;
typedef uint64_t alix_tls_key_t;
typedef struct {
    uint64_t tid,stack_base,stack_size,guard_size;uint32_t flags,state,cpu_index,reserved;char name[32];
} syscall_thread_info_t;
static int test_errno;
#undef errno
#define errno test_errno
static uint64_t current_tid=1,next_tid=100;
static int prepared_winner, process_exits, native_exits, tls_destructors;
static bool fail_spawn, fail_join, fail_detach, fail_allocation, exit_during_publication, in_child;
static jmp_buf child_exit, initial_exit;
static int64_t now_millis[2];
static unsigned wait_calls, callback_calls, wake_calls;
static int wait_behavior; /* 0 timeout, 1 notify, 2 clock-backward then notify. */
static uint32_t last_wait;
static void *live_allocations[128];static unsigned live_count;
static void *checked_malloc(size_t size) {
    if(fail_allocation){fail_allocation=false;return NULL;}
    void *p=malloc(size);CHECK(p && live_count<128);live_allocations[live_count++]=p;return p;
}
static void *checked_calloc(size_t count,size_t size) { void *p=checked_malloc(count*size);if(p)memset(p,0,count*size);return p; }
static void checked_free(void *p) {
    if(!p)return;
    unsigned index=0;while(index<live_count && live_allocations[index]!=p)++index;
    CHECK(index<live_count);live_allocations[index]=live_allocations[--live_count];free(p);
}
static bool is_allocation(void *p) { for(unsigned i=0;i<live_count;i++)if(live_allocations[i]==p)return true;return false; }
static void alix_mutex_lock(alix_mutex_t *mutex) { CHECK(mutex->state==0);mutex->state=1; }
static bool alix_mutex_trylock(alix_mutex_t *mutex) { if(mutex->state)return false;mutex->state=1;return true; }
static void alix_mutex_unlock(alix_mutex_t *mutex) { CHECK(mutex->state==1);mutex->state=0; }
static int alix_cond_timedwait(alix_cond_t *,alix_mutex_t *,uint32_t);
static int alix_cond_signal(alix_cond_t *c) { ++c->sequence;return 0; }
static int alix_cond_broadcast(alix_cond_t *c) { ++c->sequence;return 0; }
static int alix_call_once(alix_once_t *once,void(*f)(void)) { if(!once||!f)return -22;if(once->state==0){once->state=1;f();once->state=2;}return 0; }
static int alix_tls_key_create(alix_tls_key_t *key,void(*destroy)(void*)) { (void)destroy;if(!key)return -22;*key=0x100000001ULL;return 0; }
static int alix_tls_key_delete(alix_tls_key_t key) { return key==0x100000001ULL?0:-22; }
static void *specific;
static void *alix_tls_get(alix_tls_key_t key) { return key==0x100000001ULL?specific:NULL; }
static int alix_tls_set(alix_tls_key_t key,void *value) { if(key!=0x100000001ULL)return -22;specific=value;return 0; }
static void alix_thread_run_tls_destructors(void) { ++tls_destructors; }
static uint64_t sys_thread_self(void) { return current_tid; }
static int64_t sys_thread_create(uintptr_t,uintptr_t,size_t,const char*);
static int sys_thread_join(uint64_t,int*);
static int sys_thread_detach(uint64_t);
static int sys_thread_info(uint64_t,syscall_thread_info_t*);
static int sys_thread_set_name(uint64_t,const char*);
static int sys_thread_priority(uint64_t tid,int priority) { (void)tid;(void)priority;return -38; }
static int sys_thread_prepare_exit(void) { return prepared_winner; }
static void sys_thread_exit(int) __attribute__((noreturn));
static void mock_process_exit(int) __attribute__((noreturn));
static int sys_futex_wait(volatile uint32_t*,uint32_t,uint32_t);
static int sys_futex_wake(volatile uint32_t*,uint32_t);
static int mock_clock_gettime(mock_clockid_t clock,struct mock_timespec *now) {
    if(clock<0||clock>1){test_errno=22;return -1;}
    now->tv_sec=now_millis[clock]/1000;now->tv_nsec=(long)(now_millis[clock]%1000)*1000000;return 0;
}
'''
    program += errors + "\n" + rename(types + declarations)
    program += "\n#define malloc checked_malloc\n#define calloc checked_calloc\n#define free checked_free\n"
    program += rename(source)
    program += r'''
#undef malloc
#undef calloc
#undef free
typedef struct { uint64_t tid;void(*entry)(void*);void *argument;bool finished,joined,detached; } native_t;
static native_t native[64];static unsigned native_count;
static test_pthread_mutex_t *expected_mutex;
static test_pthread_cond_t *expected_condition;
static native_t *native_find(uint64_t tid) { for(unsigned i=0;i<native_count;i++)if(native[i].tid==tid)return &native[i];return NULL; }
static void run_child(native_t *n) {
    CHECK(n && !n->finished && !in_child);
    uint64_t saved_tid=current_tid,saved_cache=self_tid_cache;test_pthread_control_t *saved_control=self_control;
    bool saved_exiting=exiting,saved_released=control_released;void *saved_result=exit_result;
    current_tid=n->tid;self_tid_cache=0;self_control=NULL;exiting=control_released=false;exit_result=NULL;in_child=true;
    if(setjmp(child_exit)==0){n->entry(n->argument);CHECK(false);}
    n->finished=true;current_tid=saved_tid;self_tid_cache=saved_cache;self_control=saved_control;
    exiting=saved_exiting;control_released=saved_released;exit_result=saved_result;in_child=false;
}
static int64_t sys_thread_create(uintptr_t entry,uintptr_t argument,size_t stack,const char *name) {
    CHECK(stack>=PTHREAD_STACK_MIN && name && is_allocation((void *)argument));
    test_pthread_control_t *control=(void *)argument;
    CHECK(control->published==0 && control->references==2 && !control->in_registry);
    if(fail_spawn){fail_spawn=false;return -1;}
    CHECK(native_count<64);native_t *n=&native[native_count++];
    *n=(native_t){.tid=next_tid++,.entry=(void(*)(void*))entry,.argument=(void*)argument};return (int64_t)n->tid;
}
static int sys_thread_join(uint64_t tid,int *status) {
    CHECK(registry_mutex.state==0);
    if(fail_join){fail_join=false;return -1;}
    if(tid==1){if(status)*status=0;return 0;}
    native_t *n=native_find(tid);if(!n||n->joined||n->detached)return -1;
    if(!n->finished)run_child(n);n->joined=true;if(status)*status=0;return 0;
}
static int sys_thread_detach(uint64_t tid) {
    if(fail_detach){fail_detach=false;return -1;}
    if(tid==1)return 0;
    native_t *n=native_find(tid);if(!n||n->joined||n->detached)return -1;n->detached=true;return 0;
}
static int sys_thread_info(uint64_t tid,syscall_thread_info_t *info) {
    if(!info)return -22;memset(info,0,sizeof(*info));
    if(tid!=1)return -3;
    info->tid=1;info->flags=SYSCALL_THREAD_INFO_MAIN;info->state=1;
    info->stack_base=0x100000000ULL;info->stack_size=65536;strcpy(info->name,"initial");return 0;
}
static int sys_thread_set_name(uint64_t tid,const char *name) { if(tid!=1)return -3;return strlen(name)>31?-34:0; }
static void sys_thread_exit(int status) { CHECK(status==0);++native_exits;if(in_child)longjmp(child_exit,1);longjmp(initial_exit,1); }
static void mock_process_exit(int status) { CHECK(status==0);++process_exits;if(in_child)longjmp(child_exit,1);longjmp(initial_exit,1); }
static int sys_futex_wait(volatile uint32_t *address,uint32_t expected,uint32_t timeout) {
    CHECK(timeout==UINT32_MAX);return *address!=expected?SYSCALL_FUTEX_AGAIN:0;
}
static int sys_futex_wake(volatile uint32_t *address,uint32_t count) {
    CHECK(*address==1 && count==UINT32_MAX);++wake_calls;
    if(exit_during_publication) {
        for(unsigned i=0;i<native_count;i++) {
            native_t *n=&native[i];
            if(!n->finished && &((test_pthread_control_t*)n->argument)->published==address){run_child(n);break;}
        }
    }
    return 1;
}
static int alix_cond_timedwait(alix_cond_t *condition,alix_mutex_t *mutex,uint32_t timeout) {
    CHECK(expected_mutex && expected_condition && mutex==&expected_mutex->gate && condition==&expected_condition->native);
    CHECK(mutex->state==1 && expected_mutex->owner==0 && expected_mutex->depth==0);
    CHECK(expected_mutex->waiters==1 && expected_condition->waiters==1);
    CHECK(test_pthread_mutex_destroy(expected_mutex)==EBUSY && test_pthread_cond_destroy(expected_condition)==EBUSY);
    mutex->state=0;
    CHECK(test_pthread_mutex_destroy(expected_mutex)==EBUSY);
    ++wait_calls;last_wait=timeout;
    if(wait_behavior==1){++condition->sequence;mutex->state=1;return 0;}
    if(wait_behavior==2){now_millis[expected_condition->clock]-=1000;wait_behavior=1;}
    else now_millis[expected_condition->clock]+=timeout;
    mutex->state=1;return -ETIMEDOUT;
}
typedef struct { test_pthread_t thread;uint64_t value; } cookie_t;
static void *callback(void *argument) {
    cookie_t *cookie=argument;CHECK(cookie->thread==current_tid);++callback_calls;return &cookie->value;
}
static unsigned once_count;
static void initialize(void) { ++once_count; }
int main(void) {
    test_pthread_attr_t attr;CHECK(test_pthread_attr_init(&attr)==0);
    CHECK(test_pthread_attr_setstacksize(&attr,PTHREAD_STACK_MIN-1)==EINVAL);
    CHECK(test_pthread_attr_setguardsize(&attr,0)==ENOTSUP);
    CHECK(test_pthread_attr_setguardsize(&attr,1)==0 && attr.guard_size==1);
    CHECK(test_pthread_attr_setstack(&attr,(void*)0x1000,65536)==ENOTSUP);
    CHECK(test_pthread_attr_setstacksize(&attr,65536)==0);
    cookie_t *cookie=calloc(1,sizeof(*cookie));CHECK(cookie);cookie->value=0x123456789ABCDEF0ULL;

    /* The child finishes inside the creator's publication wake, before create
     * returns. Creator/registry references must keep the control alive. */
    exit_during_publication=true;
    CHECK(test_pthread_create(&cookie->thread,&attr,callback,cookie)==0 && live_count==1);
    void *result=NULL;CHECK(test_pthread_join(cookie->thread,&result)==0 && result==&cookie->value);
    CHECK(live_count==0 && registry==NULL && callback_calls==1);
    CHECK(test_pthread_join(cookie->thread,&result)==ESRCH && test_pthread_join(1,NULL)==EDEADLK);

    CHECK(test_pthread_create(&cookie->thread,&attr,callback,cookie)==0);
    CHECK(test_pthread_detach(cookie->thread)==0 && live_count==0 && registry==NULL);
    CHECK(test_pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED)==0);
    CHECK(test_pthread_create(&cookie->thread,&attr,callback,cookie)==0 && live_count==0 && registry==NULL);
    CHECK(test_pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_JOINABLE)==0);
    exit_during_publication=false;
    CHECK(test_pthread_create(&cookie->thread,&attr,callback,cookie)==0 && live_count==1);
    fail_join=true;CHECK(test_pthread_join(cookie->thread,NULL)==ESRCH && registry->references==2 && !registry->join_claimed);
    CHECK(test_pthread_join(cookie->thread,&result)==0 && result==&cookie->value && live_count==0);
    CHECK(test_pthread_create(&cookie->thread,&attr,callback,cookie)==0);
    CHECK(test_pthread_detach(cookie->thread)==0 && test_pthread_detach(cookie->thread)==EINVAL && test_pthread_join(cookie->thread,NULL)==EINVAL);
    run_child(native_find(cookie->thread));CHECK(live_count==0 && registry==NULL);
    fail_spawn=true;uint64_t old=cookie->thread;
    CHECK(test_pthread_create(&cookie->thread,&attr,callback,cookie)==EAGAIN && cookie->thread==old && live_count==0);
    fail_allocation=true;CHECK(test_pthread_create(&cookie->thread,&attr,callback,cookie)==EAGAIN && cookie->thread==old && live_count==0);
    CHECK(test_pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED)==0);
    fail_detach=true;unsigned called=callback_calls;
    CHECK(test_pthread_create(&cookie->thread,&attr,callback,cookie)==EAGAIN && callback_calls==called && live_count==0);
    CHECK(test_pthread_attr_destroy(&attr)==0 && test_pthread_attr_destroy(&attr)==EINVAL);

    test_pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
    test_pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
    expected_mutex=&mutex;expected_condition=&condition;
    CHECK(test_pthread_mutex_lock(&mutex)==0 && test_pthread_mutex_trylock(&mutex)==EBUSY);
    struct mock_timespec deadline={0,25000000};now_millis[0]=0;wait_behavior=0;
    CHECK(test_pthread_cond_timedwait(&condition,&mutex,&deadline)==ETIMEDOUT && last_wait==25);
    CHECK(mutex.owner==1 && mutex.depth==1 && mutex.gate.state==1 && !mutex.waiters && !condition.waiters);
    deadline=(struct mock_timespec){5,0};now_millis[0]=1000;wait_behavior=2;
    unsigned waits=wait_calls;CHECK(test_pthread_cond_timedwait(&condition,&mutex,&deadline)==0 && wait_calls==waits+2 && last_wait==100);
    CHECK(mutex.owner==1 && mutex.depth==1);
    condition.clock=CLOCK_MONOTONIC;now_millis[1]=0;wait_behavior=0;deadline=(struct mock_timespec){0,1};
    CHECK(test_pthread_cond_timedwait(&condition,&mutex,&deadline)==ETIMEDOUT && last_wait==1);
    CHECK(test_pthread_mutex_unlock(&mutex)==0 && test_pthread_mutex_unlock(&mutex)==EPERM);
    CHECK(test_pthread_cond_wait(&condition,&mutex)==EPERM);
    test_pthread_mutexattr_t ma;CHECK(test_pthread_mutexattr_init(&ma)==0);
    CHECK(test_pthread_mutexattr_settype(&ma,PTHREAD_MUTEX_RECURSIVE)==0 && test_pthread_mutex_init(&mutex,&ma)==0);
    CHECK(test_pthread_mutex_lock(&mutex)==0 && test_pthread_mutex_lock(&mutex)==0 && mutex.depth==2);
    CHECK(test_pthread_cond_wait(&condition,&mutex)==EINVAL);
    CHECK(test_pthread_mutex_unlock(&mutex)==0 && test_pthread_mutex_unlock(&mutex)==0);
    CHECK(test_pthread_mutexattr_settype(&ma,PTHREAD_MUTEX_ERRORCHECK)==0 && test_pthread_mutex_init(&mutex,&ma)==0);
    CHECK(test_pthread_mutex_lock(&mutex)==0 && test_pthread_mutex_lock(&mutex)==EDEADLK);
    CHECK(test_pthread_mutex_unlock(&mutex)==0 && test_pthread_mutex_destroy(&mutex)==0);
    test_pthread_once_t once=PTHREAD_ONCE_INIT;CHECK(test_pthread_once(&once,initialize)==0 && test_pthread_once(&once,initialize)==0 && once_count==1);

    /* Initial thread storage is static; winner calls process exit only after
     * publishing the full pointer result and releasing its live reference. */
    prepared_winner=1;current_tid=1;exiting=false;control_released=false;self_control=NULL;
    if(setjmp(initial_exit)==0)test_pthread_exit(&cookie->value);
    CHECK(process_exits==1 && initial_thread_control.completed && initial_thread_control.result==&cookie->value && initial_thread_control.references==1);
    current_tid=2;self_tid_cache=0;CHECK(test_pthread_join(1,&result)==0 && result==&cookie->value && !registry && live_count==0);
    CHECK(tls_destructors>=6 && native_exits>=5 && wake_calls>=6);
    free(cookie);puts("pthread publication/refcount/detach/retval/main-exit/deadline/ownership contracts passed");
    return 0;
}
'''
    compile_and_run("pthread-contract", program)
    print("pthread production contracts passed")


if __name__ == "__main__":
    main()
