#!/usr/bin/env python3
"""Execute production CPU-clock snapshots and libc conversions with faults."""
import re
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

wire = re.search(r'typedef struct \{ uint64_t ticks;[^\n]+syscall_cpu_clock_t;',
                 (ROOT / "include/syscall_defs.h").read_text()).group(0)
code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#define CHECK(c) do{if(!(c)){fprintf(stderr,"CPU clock contract %d: %s\n",__LINE__,#c);abort();}}while(0)
#define SYSCALL_USAGE_CLOCK_PROCESS 256
#define SYSCALL_USAGE_CLOCK_THREAD 257
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3
#define CLOCK_BOOTTIME 7
#define _SC_PAGESIZE 1
typedef int clockid_t;
typedef int64_t time_t;
struct timespec {int64_t tv_sec;long tv_nsec;};
typedef struct {bool is_user;uint64_t runtime_ticks;} process_t;
typedef struct {uint64_t runtime_ticks;} thread_t;
'''
code += wire + "\n"
code += r'''
static process_t*process;static thread_t*thread;
static int64_t sys_monotonic_resolution_ns(void){return -ENOSYS;}
static unsigned depth,allocations,copies;static uint32_t frequency=100;
static bool fail_allocation,fail_copy,release_at_unpin;
static void spinlock_preempt_disable(void){CHECK(!depth);++depth;}
static void spinlock_preempt_enable(void){CHECK(depth==1&&!allocations);--depth;if(release_at_unpin){release_at_unpin=false;free(process);free(thread);process=NULL;thread=NULL;}}
static process_t*current_process_local(void){CHECK(depth);return process;}
static thread_t*current_thread_local(void){CHECK(depth);return thread;}
static bool user_ptr_range_valid(const void*p,size_t bytes){CHECK(bytes==16);return (uintptr_t)p>=4096;}
static void*checked_calloc(size_t count,size_t bytes){CHECK(depth&&count==1&&bytes==16);if(fail_allocation)return NULL;void*p=calloc(count,bytes);CHECK(p);++allocations;return p;}
static void checked_free(void*p){CHECK(depth&&allocations);--allocations;free(p);}
static uint32_t timer_frequency(void){return frequency;}
static bool user_copy_to_user(void*out,const void*in,size_t bytes){CHECK(depth&&allocations&&bytes==16);++copies;if(fail_copy)return false;memcpy(out,in,bytes);return true;}
#define calloc checked_calloc
#define free checked_free
'''
code += function_definition((ROOT / "src/kernel/process/process_clock.c").read_text(),
                            "int process_user_cpu_clock(")
code += r'''
#undef calloc
#undef free
static syscall_cpu_clock_t user_snapshot;
static int user_error,user_selector;
static int sys_cpu_clock(int which,syscall_cpu_clock_t*out){user_selector=which;if(user_error)return user_error;*out=user_snapshot;return 0;}
static uint64_t sys_monotonic_millis(void){return 1234567;}
static uint64_t sys_time_millis(void){return 1793622334123ull;}
static long sysconf(int selector){CHECK(selector==1);return 4096;}
'''
lib = (ROOT / "user/lib/libc.c").read_text()
for signature in ("static int libc_cpu_clock(", "int clock_gettime(", "int clock_getres(", "int getpagesize("):
    code += function_definition(lib, signature) + "\n"
code += r'''
int main(void){
    process=calloc(1,sizeof(*process));thread=calloc(1,sizeof(*thread));CHECK(process&&thread);
    process->is_user=true;process->runtime_ticks=987;thread->runtime_ticks=123;
    syscall_cpu_clock_t*out=calloc(1,sizeof(*out));CHECK(out);
    CHECK(!process_user_cpu_clock(256,(uintptr_t)out,16)&&out->ticks==987&&out->tick_frequency==100&&!out->reserved);
    CHECK(!process_user_cpu_clock(257,(uintptr_t)out,16)&&out->ticks==123);
    syscall_cpu_clock_t saved=*out;unsigned before=copies;
    CHECK(process_user_cpu_clock(255,(uintptr_t)out,16)==-EINVAL&&copies==before&&!memcmp(out,&saved,16));
    CHECK(process_user_cpu_clock(256,(uintptr_t)out,15)==-EINVAL);
    CHECK(process_user_cpu_clock(256,1,16)==-EFAULT);
    fail_allocation=true;CHECK(process_user_cpu_clock(256,(uintptr_t)out,16)==-ENOMEM&&!allocations);fail_allocation=false;
    fail_copy=true;CHECK(process_user_cpu_clock(257,(uintptr_t)out,16)==-EFAULT&&!allocations);fail_copy=false;
    frequency=0;before=copies;CHECK(process_user_cpu_clock(256,(uintptr_t)out,16)==-EAGAIN&&copies==before);frequency=100;
    release_at_unpin=true;CHECK(!process_user_cpu_clock(256,(uintptr_t)out,16)&&!process&&!thread&&!depth&&!allocations);
    CHECK(process_user_cpu_clock(257,(uintptr_t)out,16)==-ESRCH);free(out);
    struct timespec result={123,456},old=result;
    CHECK(clock_gettime(99,&result)==-1&&errno==EINVAL&&!memcmp(&old,&result,sizeof(old)));
    CHECK(clock_gettime(0,NULL)==-1&&errno==EFAULT);
    CHECK(clock_getres(99,&result)==-1&&errno==EINVAL&&!memcmp(&old,&result,sizeof(old)));
    CHECK(!clock_getres(3,NULL));
    user_snapshot=(syscall_cpu_clock_t){.ticks=125,.tick_frequency=100};errno=EDOM;
    CHECK(!clock_gettime(2,&result)&&result.tv_sec==1&&result.tv_nsec==250000000&&errno==EDOM&&user_selector==256);
    CHECK(!clock_gettime(3,&result)&&user_selector==257);
    CHECK(!clock_getres(2,&result)&&!result.tv_sec&&result.tv_nsec==10000000);
    user_snapshot.tick_frequency=1;CHECK(!clock_getres(2,&result)&&result.tv_sec==1&&!result.tv_nsec);
    user_snapshot.tick_frequency=UINT32_MAX;CHECK(!clock_getres(2,&result)&&!result.tv_sec&&result.tv_nsec==1);
    CHECK(!clock_getres(0,&result)&&!result.tv_sec&&result.tv_nsec==1000000);
    for(uint32_t hz=1;hz<10000;hz+=37){user_snapshot.tick_frequency=hz;user_snapshot.ticks=(uint64_t)hz*7+hz/3;
        CHECK(!clock_gettime(3,&result)&&result.tv_sec==7&&result.tv_nsec==(long)((uint64_t)(hz/3)*1000000000/hz));}
    old=result;user_error=-ENOMEM;CHECK(clock_gettime(2,&result)==-1&&errno==ENOMEM&&!memcmp(&result,&old,sizeof(old)));user_error=0;
    user_snapshot.reserved=1;CHECK(clock_gettime(2,&result)==-1&&errno==EIO);user_snapshot.reserved=0;
    user_snapshot.tick_frequency=0;CHECK(clock_getres(2,&result)==-1&&errno==EIO);
    user_snapshot.tick_frequency=1;user_snapshot.ticks=UINT64_MAX;CHECK(clock_gettime(2,&result)==-1&&errno==EOVERFLOW);
    CHECK(!clock_gettime(1,&result)&&result.tv_sec==1234&&result.tv_nsec==567000000);
    CHECK(!clock_gettime(0,&result)&&result.tv_sec==1793622334&&result.tv_nsec==123000000);
    CHECK(getpagesize()==4096);
}
'''
compile_and_run("cpu-clock", code)
print("CPU clock contract: PASS ownership/copy/allocation faults, process/thread selection, frequency/resolution, overflow and errors")
