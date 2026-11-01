#!/usr/bin/env python3
"""Exercise production user-copy code with inaccessible VAs and revocation races."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition, uint_macro


def copy_test():
    source = (ROOT / 'src/kernel/user_copy.c').read_text()
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"user copy check failed line %d: %s\n",__LINE__,#c); exit(1); } } while (0)
#define PAGE_SIZE_BYTES_LOCAL 4096u
#define USER_POINTER_BASE 0x100000000ULL
#define USER_POINTER_LIMIT (USER_POINTER_BASE + 3 * PAGE_SIZE_BYTES_LOCAL - 1)
typedef struct { bool is_user; } process_t;
static process_t process = {.is_user=true};
static process_t *current = &process;
static bool locked, revoke_next, protect_next;
static unsigned locks, resolves, copies;
static uint8_t *pages[3];
static bool readable[3], writable[3];
static process_t *process_current(void) { return current; }
static uint64_t process_memory_lock(process_t *p) { CHECK(p==&process && !locked); locked=true; ++locks; return 512; }
static void process_memory_unlock(process_t *p,uint64_t flags) {
    CHECK(p==&process && locked && flags==512); locked=false;
    if (revoke_next) { free(pages[1]); pages[1]=NULL; revoke_next=false; }
    if (protect_next) { writable[1]=false; protect_next=false; }
}
static bool process_memory_resolve_user_locked(process_t *p,uintptr_t address,bool write,uint8_t **host,size_t *available) {
    CHECK(p==&process && locked); ++resolves;
    if(address<USER_POINTER_BASE || address>USER_POINTER_LIMIT)return false;
    size_t index=(address-USER_POINTER_BASE)/PAGE_SIZE_BYTES_LOCAL;
    size_t offset=(address-USER_POINTER_BASE)%PAGE_SIZE_BYTES_LOCAL;
    if(!pages[index] || !readable[index] || (write&&!writable[index]))return false;
    *host=pages[index]+offset;
    /* Deliberately oversized: production copy must still bound each lock to one page. */
    *available=2*PAGE_SIZE_BYTES_LOCAL;
    return true;
}
static void *checked_memcpy(void *dst,const void *src,size_t n) {
    CHECK(locked && n<=PAGE_SIZE_BYTES_LOCAL); ++copies; return memcpy(dst,src,n);
}
#undef memcpy
#define memcpy checked_memcpy
'''
    for signature in ('static inline bool user_pointer_canonical', 'bool user_ptr_range_valid',
                      'static bool user_copy_bytes', 'bool user_copy_from_user',
                      'bool user_copy_to_user', 'int user_copy_cstring_from_user', 'bool user_copy_string_from_user'):
        program += function_definition(source, signature) + '\n'
    program += r'''
#undef memcpy
static void reset(void) {
    CHECK(!locked); current=&process; process.is_user=true; locks=resolves=copies=0; revoke_next=protect_next=false;
    for(unsigned i=0;i<3;i++) { if(!pages[i])pages[i]=malloc(PAGE_SIZE_BYTES_LOCAL); CHECK(pages[i]);
        memset(pages[i],0x31+i,PAGE_SIZE_BYTES_LOCAL); readable[i]=writable[i]=true; }
}
int main(void) {
    uint8_t *buffer=malloc(2*PAGE_SIZE_BYTES_LOCAL+16); CHECK(buffer);
    reset(); CHECK(user_copy_from_user(NULL,NULL,0)); CHECK(user_copy_to_user(NULL,NULL,0));
    CHECK(!user_copy_from_user(NULL,(void*)USER_POINTER_BASE,1));
    CHECK(!user_ptr_range_valid((void*)(USER_POINTER_BASE-1),1));
    CHECK(!user_ptr_range_valid((void*)USER_POINTER_LIMIT,2));
    CHECK(!user_ptr_range_valid((void*)(uintptr_t)-4,8));
    CHECK(!user_ptr_range_valid((void*)0x0000800000000000ULL,1));
    CHECK(locks==0);
    CHECK(user_copy_from_user(buffer,(void*)(USER_POINTER_BASE+4093),8));
    CHECK(locks==2 && resolves==2 && copies==2);
    CHECK(buffer[0]==0x31 && buffer[2]==0x31 && buffer[3]==0x32 && buffer[7]==0x32);
    reset(); memset(buffer,0xA7,8192);
    CHECK(user_copy_to_user((void*)(USER_POINTER_BASE+4093),buffer,8));
    CHECK(pages[0][4092]==0x31 && pages[0][4093]==0xA7 && pages[1][4]==0xA7 && pages[1][5]==0x32);
    reset(); writable[0]=false;
    CHECK(!user_copy_to_user((void*)USER_POINTER_BASE,buffer,1)); CHECK(!locked && copies==0 && pages[0][0]==0x31);
    CHECK(user_copy_from_user(buffer,(void*)USER_POINTER_BASE,1));
    readable[0]=false; CHECK(!user_copy_from_user(buffer,(void*)USER_POINTER_BASE,1)); CHECK(!locked);
    reset(); free(pages[1]); pages[1]=NULL; memset(buffer,0xCC,16);
    CHECK(!user_copy_from_user(buffer,(void*)(USER_POINTER_BASE+4093),8));
    CHECK(buffer[2]==0x31 && buffer[3]==0xCC && !locked);
    reset(); revoke_next=true; memset(buffer,0xCC,8192);
    CHECK(!user_copy_from_user(buffer,(void*)USER_POINTER_BASE,8192));
    CHECK(buffer[4095]==0x31 && buffer[4096]==0xCC && !locked);
    reset(); protect_next=true; memset(buffer,0xA7,8192);
    CHECK(!user_copy_to_user((void*)USER_POINTER_BASE,buffer,8192));
    CHECK(pages[0][4095]==0xA7 && pages[1][0]==0x32 && !locked);
    reset(); free(pages[1]); pages[1]=NULL; pages[0][4095]=0;
    size_t length=99; CHECK(user_copy_string_from_user((char*)buffer,8192,(char*)(USER_POINTER_BASE+4093),&length));
    CHECK(length==2 && buffer[0]==0x31 && buffer[2]==0 && resolves==1 && !locked);
    reset(); pages[2][4095]=0; length=99;
    CHECK(user_copy_string_from_user((char*)buffer,8192,(char*)USER_POINTER_LIMIT,&length) && length==0);
    reset(); pages[0][0]=0; buffer[0]=0xAA; buffer[1]=0xBB;
    CHECK(user_copy_string_from_user((char*)buffer,1,(char*)USER_POINTER_BASE,&length));
    CHECK(length==0 && buffer[0]==0 && buffer[1]==0xBB);
    reset(); buffer[0]=0xAA; buffer[1]=0xBB;
    CHECK(!user_copy_string_from_user((char*)buffer,1,(char*)USER_POINTER_BASE,&length));
    CHECK(buffer[0]==0x31 && buffer[1]==0xBB && !locked);
    CHECK(user_copy_cstring_from_user((char*)buffer,1,(char*)USER_POINTER_BASE,&length)==-ENAMETOOLONG);
    readable[0]=false; CHECK(user_copy_cstring_from_user((char*)buffer,1,(char*)USER_POINTER_BASE,&length)==-EFAULT);
    reset(); pages[1][1]=0;
    CHECK(user_copy_string_from_user((char*)buffer,8,(char*)(USER_POINTER_BASE+4094),&length));
    CHECK(length==3 && buffer[0]==0x31 && buffer[2]==0x32 && buffer[3]==0 && resolves==2);
    reset(); current=NULL; CHECK(!user_copy_from_user(buffer,(void*)USER_POINTER_BASE,1));
    current=&process; process.is_user=false; CHECK(!user_copy_to_user((void*)USER_POINTER_BASE,buffer,1));
    CHECK(!user_copy_string_from_user((char*)buffer,8,(char*)USER_POINTER_BASE,&length)); CHECK(locks==0);
    for(unsigned i=0;i<3;i++)free(pages[i]); free(buffer);
    puts("user-copy physical spans, permissions, revocation and string boundaries passed");
}
'''
    compile_and_run('user-copy', program)


def declaration(source, name):
    end = source.index('} ' + name + ';') + len('} ' + name + ';')
    start = source.rfind('typedef struct', 0, end)
    return source[start:end] + '\n'


def syscall_test():
    source = (ROOT / 'src/kernel/syscall.c').read_text()
    process = (ROOT / 'include/process.h').read_text()
    defs = (ROOT / 'include/syscall_defs.h').read_text()
    network = (ROOT / 'include/net/interface.h').read_text()
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"syscall copy check failed line %d: %s\n",__LINE__,#c); exit(1); } } while (0)
#define PROCESS_NAME_MAX 32
#define SYSCALL_PROCESS_NAME_MAX 32
#define SYSCALL_NET_IF_NAME_MAX 8
#define SYSCALL_CPU_MAX 32
typedef int process_state_t;
typedef int thread_state_t;
'''
    for name in ('process_info_t', 'process_cpu_info_t'):
        program += declaration(process, name)
    for name in ('syscall_process_info_t', 'syscall_net_stats_t', 'syscall_cpu_stats_t'):
        program += declaration(defs, name)
    program += declaration(network, 'net_interface_stats_t')
    program += r'''
static int64_t syscall_do_proc_snapshot(syscall_process_info_t*,size_t);
static int64_t syscall_do_net_snapshot(syscall_net_stats_t*,size_t);
static int64_t syscall_do_cpu_snapshot(syscall_cpu_stats_t*,size_t);
static syscall_process_info_t proc_outer,proc_inner;
static syscall_net_stats_t net_outer,net_inner;
static syscall_cpu_stats_t cpu_outer,cpu_inner;
static unsigned live_allocations, allocation_calls, fail_at;
static void *tracked_malloc(size_t n) { ++allocation_calls; if(fail_at==allocation_calls)return NULL; void *p=malloc(n); if(p)++live_allocations;return p; }
static void *tracked_calloc(size_t n,size_t s) { ++allocation_calls; if(fail_at==allocation_calls)return NULL; void *p=calloc(n,s);if(p)++live_allocations;return p; }
static void tracked_free(void *p) { if(p){ CHECK(live_allocations);--live_allocations;free(p); } }
static bool user_ptr_range_valid(const void *p,size_t bytes) { return bytes==0||p!=NULL; }
static bool inject, copy_fails;
static unsigned snapshot_kind;
static uint64_t generation;
static bool user_copy_to_user(void *dst,const void *src,size_t bytes) {
    if(copy_fails)return false;
    if(inject) {
        inject=false; generation=222;
        if(snapshot_kind==0)CHECK(syscall_do_proc_snapshot(&proc_inner,1)==1);
        if(snapshot_kind==1)CHECK(syscall_do_net_snapshot(&net_inner,1)==1);
        if(snapshot_kind==2)CHECK(syscall_do_cpu_snapshot(&cpu_inner,1)==1);
    }
    memcpy(dst,src,bytes);return true;
}
static size_t process_snapshot(process_info_t *out,size_t cap) {
    CHECK(cap);memset(out,0,sizeof(*out));out->pid=generation;strcpy(out->name,"process");strcpy(out->thread_name,"thread");return 1;
}
static size_t net_if_snapshot(net_interface_stats_t *out,size_t cap) {
    CHECK(cap);memset(out,0,sizeof(*out));out->name="net0";out->rx_bytes=generation;return 1;
}
static size_t process_cpu_snapshot(process_cpu_info_t *out,size_t cap) {
    CHECK(cap&&cap<=SYSCALL_CPU_MAX);memset(out,0,sizeof(*out));out->current_pid=generation;strcpy(out->current_process_name,"process");return 1;
}
static char shell_user_output[16];
static unsigned service_calls;
static bool service_fails, revoke_during_service;
static ssize_t shell_service_poll(uint32_t handle,char *output,size_t capacity,int *status,int *running) {
    CHECK(handle==7);++service_calls;CHECK(output!=shell_user_output);
    if(service_fails)return -1;
    if(status)*status=17;if(running)*running=0;
    if(revoke_during_service)copy_fails=true;
    if(output&&capacity>0) { CHECK(capacity>=3);memcpy(output,"ok",3);return 2; }
    return 0;
}
#define malloc tracked_malloc
#define calloc tracked_calloc
#define free tracked_free
'''
    for signature in ('static void syscall_copy_string', 'static int64_t syscall_do_proc_snapshot',
                      'static int64_t syscall_do_net_snapshot', 'static int64_t syscall_do_cpu_snapshot',
                      'static int64_t syscall_do_shell_poll'):
        program += function_definition(source, signature) + '\n'
    program += r'''
int main(void) {
    snapshot_kind=0;generation=111;inject=true;CHECK(syscall_do_proc_snapshot(&proc_outer,1)==1);
    CHECK(proc_outer.pid==111&&proc_inner.pid==222&&live_allocations==0);
    for(size_t i=offsetof(syscall_process_info_t,thread_name)+sizeof(proc_outer.thread_name);
        i<offsetof(syscall_process_info_t,heap_used_bytes);++i)CHECK(((unsigned char*)&proc_outer)[i]==0);
    snapshot_kind=1;generation=111;inject=true;CHECK(syscall_do_net_snapshot(&net_outer,1)==1);
    CHECK(net_outer.rx_bytes==111&&net_inner.rx_bytes==222&&live_allocations==0);
    snapshot_kind=2;generation=111;inject=true;CHECK(syscall_do_cpu_snapshot(&cpu_outer,1)==1);
    CHECK(cpu_outer.current_pid==111&&cpu_inner.current_pid==222&&live_allocations==0);
    copy_fails=true;CHECK(syscall_do_proc_snapshot(&proc_outer,1)==-1&&live_allocations==0);
    CHECK(syscall_do_net_snapshot(&net_outer,1)==-1&&live_allocations==0);
    CHECK(syscall_do_cpu_snapshot(&cpu_outer,1)==-1&&live_allocations==0);copy_fails=false;
    fail_at=allocation_calls+2;CHECK(syscall_do_proc_snapshot(&proc_outer,1)==-1&&live_allocations==0);fail_at=0;
    CHECK(syscall_do_proc_snapshot(&proc_outer,SIZE_MAX)==-1&&live_allocations==0);
    CHECK(syscall_do_cpu_snapshot(&cpu_outer,1000000)==1&&live_allocations==0);
    int status=-1,running=-1;CHECK(syscall_do_shell_poll(7,shell_user_output,16,&status,&running)==2);
    CHECK(strcmp(shell_user_output,"ok")==0&&status==17&&running==0&&live_allocations==0);
    memset(shell_user_output,0xA5,16);status=running=-1;revoke_during_service=true;
    CHECK(syscall_do_shell_poll(7,shell_user_output,16,&status,&running)==-1);
    CHECK((unsigned char)shell_user_output[0]==0xA5&&status==-1&&running==-1&&live_allocations==0);
    revoke_during_service=copy_fails=false;service_fails=true;
    CHECK(syscall_do_shell_poll(7,shell_user_output,16,&status,&running)==-1&&live_allocations==0);
    service_fails=false;CHECK(syscall_do_shell_poll(7,NULL,0,&status,&running)==0&&status==17&&running==0);
    puts("private concurrent syscall snapshots and shell-poll copyout passed");
}
'''
    compile_and_run('syscall-copy', program)


def atk_test():
    source = (ROOT / 'src/kernel/user_atk.c').read_text()
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"ATK copy check failed line %d: %s\n",__LINE__,#c); exit(1); } } while (0)
#define USER_ATK_DEBUG 0
#define USER_ATK_POLL_FLAG_BLOCK 1u
typedef struct { unsigned type; } user_atk_event_t;
typedef struct { bool closed; unsigned event_waiters; } user_atk_window_t;
static user_atk_window_t window;
static bool event_ready,copy_ok;
static unsigned releases;
static unsigned preempt_depth;
static void spinlock_preempt_disable(void){++preempt_depth;}
static void spinlock_preempt_enable(void){CHECK(preempt_depth);--preempt_depth;}
static void *process_current(void){return &window;}
static bool user_ptr_range_valid(const void *p,size_t n){(void)n;return p!=NULL;}
static user_atk_window_t *user_atk_find(uint32_t h,void *p){CHECK(h==7&&p==&window);return &window;}
static void user_atk_window_release(user_atk_window_t *p){CHECK(p==&window);++releases;}
static bool user_atk_pop_event(user_atk_window_t *p,user_atk_event_t *event){CHECK(p==&window);event->type=42;return event_ready;}
static bool user_atk_event_ready(void *p){(void)p;return false;}
static bool user_copy_to_user(void *dst,const void *src,size_t n){if(copy_ok)memcpy(dst,src,n);return copy_ok;}
static uint32_t timer_frequency(void){return 100;}
static void wait_queue_wait(unsigned *q,bool(*predicate)(void*),void *p){(void)q;(void)predicate;(void)p;window.closed=true;}
static bool wait_queue_wait_timeout(unsigned *q,bool(*predicate)(void*),void *p,uint64_t t){(void)q;(void)predicate;(void)p;CHECK(t);return false;}
'''
    for signature in ('static int64_t user_atk_poll_event_impl(', 'int64_t user_atk_sys_poll_event(',
                      'static uint64_t user_atk_timeout_to_ticks',
                      'int64_t user_atk_sys_poll_event_timeout('):
        program += function_definition(source, signature) + '\n'
    program += r'''
int main(void) {
    user_atk_event_t output;
    CHECK(user_atk_sys_poll_event(7,&output,0)==-1&&releases==1);
    releases=0;CHECK(user_atk_sys_poll_event(7,&output,1)==-1&&releases==1);
    window.closed=false;releases=0;CHECK(user_atk_sys_poll_event_timeout(7,&output,0)==-1&&releases==1);
    window.closed=true;releases=0;CHECK(user_atk_sys_poll_event_timeout(7,&output,20)==-1&&releases==1);
    window.closed=false;releases=0;CHECK(user_atk_sys_poll_event_timeout(7,&output,20)==-1&&releases==1);
    event_ready=true;releases=0;CHECK(user_atk_sys_poll_event(7,&output,0)==-1&&releases==1);
    copy_ok=true;CHECK(user_atk_sys_poll_event(7,&output,0)==1&&output.type==42);
    event_ready=false;CHECK(user_atk_sys_poll_event(7,&output,0)==0&&output.type==0);
    puts("ATK empty-event copy failures propagate correctly");
}
'''
    compile_and_run('atk-copy', program)


if __name__ == '__main__':
    copy_test()
    syscall_test()
    atk_test()
    print('user-copy ownership, revocation, syscall concurrency and ATK error tests passed')
