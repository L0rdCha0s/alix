#!/usr/bin/env python3
"""Exercise production resource accounting, snapshot ownership and conversion."""
from pathlib import Path
import os,shlex,sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run,function_definition

def stripped(path):return '\n'.join(x for x in path.read_text().splitlines() if not x.startswith('#include'))
defs=(ROOT/'include/syscall_defs.h').read_text()
wire=defs[defs.index('#define SYSCALL_USAGE_VERSION'):defs.index('#define SYSCALL_TIMEZONE_VERSION')]
code=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <sys/time.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"usage line %d: %s\n",__LINE__,#x);abort();}}while(0)
typedef pthread_mutex_t spinlock_t;
typedef struct {spinlock_t usage_lock;bool is_user;uint64_t usage_user_ticks,usage_system_ticks,usage_minor_faults,usage_major_faults;} process_t;
static process_t *current;
static _Thread_local unsigned depth,locked;
static _Thread_local uint64_t irq=0x202;
static bool fail_allocation,fail_copy,release_at_unpin;
static unsigned allocations,copies,finished;static uint32_t frequency=100;
static uint64_t cpu_save_flags(void){return irq;}
static void cpu_cli(void){irq&=~0x200ULL;}
static void cpu_restore_flags(uint64_t flags){irq=flags;}
static void spinlock_preempt_disable(void){++depth;}
static void spinlock_preempt_enable(void){CHECK(depth&&!locked);--depth;if(!depth&&release_at_unpin){CHECK(current);free(current);current=NULL;release_at_unpin=false;}}
static void spinlock_lock(spinlock_t *lock){CHECK(!(irq&0x200)&&!locked);CHECK(!pthread_mutex_lock(lock));++locked;}
static void spinlock_unlock(spinlock_t *lock){CHECK(locked);--locked;CHECK(!pthread_mutex_unlock(lock));}
static process_t *current_process_local(void){CHECK(depth);return current;}
static uint32_t timer_frequency(void){return frequency;}
static void *owned_calloc(size_t count,size_t bytes){CHECK(depth&&!locked);if(fail_allocation){fail_allocation=false;return NULL;}void*p=calloc(count,bytes);CHECK(p);++allocations;return p;}
static void owned_free(void*p){CHECK(depth&&!locked&&p&&allocations);--allocations;free(p);}
static bool user_ptr_range_valid(const void*p,size_t bytes){return (uintptr_t)p>4096&&bytes<=UINTPTR_MAX-(uintptr_t)p;}
static bool user_copy_to_user(void*out,const void*in,size_t bytes){CHECK(depth&&!locked);++copies;if(fail_copy)return false;memcpy(out,in,bytes);return true;}
'''+wire+r'''
#define calloc owned_calloc
#define free owned_free
'''+stripped(ROOT/'src/kernel/process/process_usage.c')+r'''
#undef calloc
#undef free
static process_t *new_process(void){process_t*p=calloc(1,sizeof(*p));CHECK(p&&!pthread_mutex_init(&p->usage_lock,NULL));p->is_user=true;return p;}
static void *counter_worker(void*argument){process_t*p=argument;for(unsigned i=0;i<10000;++i){process_usage_add_cpu(p,1,i&1);process_usage_add_fault(p,i&1);}CHECK(!locked&&irq==0x202);__atomic_add_fetch(&finished,1,__ATOMIC_RELEASE);return NULL;}
static void kernel_contract(void){
    current=new_process();process_usage_add_cpu(current,25,true);process_usage_add_cpu(current,17,false);process_usage_add_fault(current,false);process_usage_add_fault(current,true);
    syscall_resource_usage_t out;memset(&out,0xa5,sizeof(out));
    CHECK(!process_user_resource_usage(0,(uintptr_t)&out,sizeof(out))&&out.version==1&&out.size==sizeof(out)&&out.tick_frequency==100&&!out.reserved);
    CHECK(out.user_ticks==25&&out.system_ticks==17&&out.minor_faults==1&&out.major_faults==1);
    CHECK(!allocations&&!depth&&!locked&&irq==0x202);
    syscall_resource_usage_t saved=out;unsigned before=copies;
    CHECK(process_user_resource_usage(-1,(uintptr_t)&out,sizeof(out))==-EINVAL&&copies==before&&!memcmp(&out,&saved,sizeof(out)));
    CHECK(process_user_resource_usage(0,(uintptr_t)&out,sizeof(out)-1)==-EINVAL);
    CHECK(process_user_resource_usage(0,1,sizeof(out))==-EFAULT);
    fail_allocation=true;CHECK(process_user_resource_usage(0,(uintptr_t)&out,sizeof(out))==-ENOMEM&&!allocations);
    fail_copy=true;CHECK(process_user_resource_usage(0,(uintptr_t)&out,sizeof(out))==-EFAULT&&!allocations);fail_copy=false;
    frequency=0;before=copies;CHECK(process_user_resource_usage(0,(uintptr_t)&out,sizeof(out))==-EAGAIN&&copies==before);frequency=100;
    current->usage_user_ticks=UINT64_MAX-1;process_usage_add_cpu(current,10,true);CHECK(current->usage_user_ticks==UINT64_MAX);
    current->usage_minor_faults=UINT64_MAX;process_usage_add_fault(current,false);CHECK(current->usage_minor_faults==UINT64_MAX);
    current->usage_user_ticks=current->usage_system_ticks=current->usage_minor_faults=current->usage_major_faults=0;
    pthread_t *threads=calloc(8,sizeof(*threads));CHECK(threads);
    for(unsigned i=0;i<8;++i)CHECK(!pthread_create(&threads[i],NULL,counter_worker,current));
    syscall_resource_usage_t last={0};
    while(__atomic_load_n(&finished,__ATOMIC_ACQUIRE)!=8){CHECK(!process_user_resource_usage(0,(uintptr_t)&out,sizeof(out)));CHECK(out.user_ticks>=last.user_ticks&&out.system_ticks>=last.system_ticks&&out.minor_faults>=last.minor_faults&&out.major_faults>=last.major_faults);last=out;sched_yield();}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));free(threads);
    CHECK(!process_user_resource_usage(0,(uintptr_t)&out,sizeof(out))&&out.user_ticks==40000&&out.system_ticks==40000&&out.minor_faults==40000&&out.major_faults==40000);
    release_at_unpin=true;CHECK(!process_user_resource_usage(0,(uintptr_t)&out,sizeof(out))&&!current&&!allocations);
    CHECK(process_user_resource_usage(0,(uintptr_t)&out,sizeof(out))==-ESRCH&&!depth);
}
'''
lib=(ROOT/'user/lib/process_posix.c').read_text()
code+=r'''
typedef int64_t time_t_native;
typedef int64_t suseconds_t_native;
struct native_timeval {time_t_native tv_sec;suseconds_t_native tv_usec;};
struct native_rusage {struct native_timeval ru_utime,ru_stime;long ru_minflt,ru_majflt;};
static _Thread_local int test_errno;
#undef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC 1000
static syscall_resource_usage_t user_wire;static int user_error;
static int sys_resource_usage(int which,syscall_resource_usage_t*out,size_t bytes){CHECK(bytes==sizeof(*out));if(which)return-EINVAL;if(user_error)return user_error;*out=user_wire;return 0;}
'''
for signature in ['static int resource_snapshot(', 'clock_t clock(', 'static void resource_ticks_to_timeval(','int getrusage(']:
    source=function_definition(lib,signature)
    for old,new in [('struct timeval','struct native_timeval'),('struct rusage','struct native_rusage'),('time_t','time_t_native'),('suseconds_t','suseconds_t_native'),('getrusage','native_getrusage'),('clock_t','int64_t'),('clock','native_clock'),('errno','test_errno')]:
        import re
        source=re.sub(r'\b'+re.escape(old)+r'\b',new,source)
    code+=source+'\n'
code+=r'''
static void conversion_contract(void){
    user_wire=(syscall_resource_usage_t){.version=1,.size=48,.tick_frequency=100,.user_ticks=125,.system_ticks=257,.minor_faults=81,.major_faults=2};
    struct native_rusage out;test_errno=EDOM;CHECK(!native_getrusage(0,&out)&&test_errno==EDOM);
    CHECK(out.ru_utime.tv_sec==1&&out.ru_utime.tv_usec==250000&&out.ru_stime.tv_sec==2&&out.ru_stime.tv_usec==570000&&out.ru_minflt==81&&out.ru_majflt==2);
    struct native_rusage saved=out;CHECK(native_getrusage(-1,&out)==-1&&test_errno==EINVAL&&!memcmp(&out,&saved,sizeof(out)));
    CHECK(native_getrusage(0,NULL)==-1&&test_errno==EFAULT);
    user_error=-ENOMEM;CHECK(native_getrusage(0,&out)==-1&&test_errno==ENOMEM&&!memcmp(&out,&saved,sizeof(out)));user_error=0;
    for(unsigned i=0;i<4;++i){uint32_t *field=i==0?&user_wire.version:i==1?&user_wire.size:i==2?&user_wire.tick_frequency:&user_wire.reserved;uint32_t old=*field;*field=i==3?1:0;CHECK(native_getrusage(0,&out)==-1&&test_errno==EIO&&!memcmp(&out,&saved,sizeof(out)));*field=old;}
    user_wire.tick_frequency=1;user_wire.user_ticks=UINT64_MAX;user_wire.minor_faults=UINT64_MAX;user_wire.major_faults=UINT64_MAX;
    CHECK(!native_getrusage(0,&out)&&out.ru_utime.tv_sec==INT64_MAX&&out.ru_utime.tv_usec==999999&&out.ru_minflt==LONG_MAX&&out.ru_majflt==LONG_MAX);
    for(uint32_t hz=1;hz<10000;hz+=37){user_wire.tick_frequency=hz;user_wire.user_ticks=(uint64_t)hz*7+hz/3;CHECK(!native_getrusage(0,&out)&&out.ru_utime.tv_sec==7&&out.ru_utime.tv_usec==(long)((uint64_t)(hz/3)*1000000/hz));}
    user_wire=(syscall_resource_usage_t){.version=1,.size=48,.tick_frequency=100,.user_ticks=125,.system_ticks=257};
    test_errno=EDOM;CHECK(native_clock()==3820&&test_errno==EDOM);
    user_wire.tick_frequency=3;user_wire.user_ticks=2;user_wire.system_ticks=0;CHECK(native_clock()==666);
    user_wire.tick_frequency=0;CHECK(native_clock()==-1&&test_errno==EIO);user_wire.tick_frequency=1;
    user_wire.user_ticks=UINT64_MAX;user_wire.system_ticks=1;CHECK(native_clock()==-1&&test_errno==EOVERFLOW);
    user_wire.system_ticks=0;CHECK(native_clock()==-1&&test_errno==EOVERFLOW);
    user_wire.tick_frequency=1000;user_wire.user_ticks=INT64_MAX;CHECK(native_clock()==INT64_MAX);
    ++user_wire.user_ticks;CHECK(native_clock()==-1&&test_errno==EOVERFLOW);
    user_error=-EAGAIN;CHECK(native_clock()==-1&&test_errno==EAGAIN);user_error=0;
}
int main(void){kernel_contract();conversion_contract();puts("RESOURCE_USAGE: PASS cpu=1 faults=1 saturation=1 copy_errors=1 lifetime=1 workers=8 events=80000 conversion=1");return 0;}
'''
previous=os.environ.get('HOST_CC')
try:
    os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
    compile_and_run('resource-usage',code)
finally:
    if previous is None:os.environ.pop('HOST_CC',None)
    else:os.environ['HOST_CC']=previous
print('Native resource usage production contracts passed')
