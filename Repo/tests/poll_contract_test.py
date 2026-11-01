#!/usr/bin/env python3
"""Production poll ownership, deadline, error masking and concurrency checks."""
import contextlib
import io
import os
import shlex

from audio_stream_contract_test import ROOT, compile_and_run
import fd_retirement_contract_test as foundation


def main():
    captured = []
    original = foundation.compile_and_run
    foundation.compile_and_run = lambda _label, code: captured.append(code)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            foundation.main()
    finally:
        foundation.compile_and_run = original
    code = captured[0].replace("int main(void)", "static int baseline(void)", 1)
    code += r'''
typedef struct { int32_t fd; int16_t events,revents; } syscall_pollfd_t;
typedef struct { fd_description_t *description; } io_request_t;
typedef struct { int64_t result; fd_description_t *description_owned; } io_service_result_t;
static fd_description_t *io_request_description(io_request_t *request) { return request->description; }
static uint64_t poll_now;
static uint64_t timer_monotonic_millis(void) { return poll_now; }
static unsigned poll_allocation,fail_poll_allocation;
static void *poll_calloc(size_t count,size_t size) {
    ++poll_allocation;
    if(poll_allocation==fail_poll_allocation)return NULL;
    void *result=owned_calloc(count,size);
    if(poll_allocation==2&&fail_poll_allocation==3)fail_allocations=1;
    return result;
}
#undef calloc
#define calloc poll_calloc
'''
    for path in ("include/io_poll.h", "src/kernel/io/poll.c"):
        code += "\n".join(line for line in (ROOT / path).read_text().splitlines()
                           if not line.startswith("#include ")) + "\n"
    code += r'''
#undef calloc
#define calloc owned_calloc
typedef struct { context_t lifetime; uint32_t flags; } target_t;
static uint32_t readiness(void *pointer) { return __atomic_load_n(&((target_t*)pointer)->flags,__ATOMIC_ACQUIRE); }
static const fd_ops_t poll_target_ops={.close=close_context,.poll=readiness};
static void failure_cases(void) {
    for(unsigned index=1;index<=3;++index) {
        fd_retirement_queue_t *q=fd_retirement_queue_create(8);CHECK(q);
        fd_description_t *set=(void*)1;poll_allocation=0;fail_poll_allocation=index;
        spinlock_preempt_disable();CHECK(io_poll_create(q,8,-1,&set)==-ENOMEM&&!set);spinlock_preempt_enable();
        fail_poll_allocation=0;CHECK(!fail_allocations&&!snapshot(q).live);destroy_empty(q);
    }
    fd_retirement_queue_t *q=fd_retirement_queue_create(1);CHECK(q);
    fd_description_t *occupied=new_description(q),*set=NULL;CHECK(occupied);
    CHECK(io_poll_create(q,0,0,&set)==-ENOMEM&&!set);fd_description_put(occupied);destroy_empty(q);
}
static void poll_semantics(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(32);fd_table_t *table=fd_table_create_deferred(8,q);CHECK(q&&table);
    target_t *target=calloc(1,sizeof(*target));CHECK(target);target->lifetime.magic=0xabc123;target->lifetime.queue=q;
    spinlock_preempt_disable();
    fd_description_t *original=fd_description_create_deferred(&poll_target_ops,target,q),*set=NULL;CHECK(original);
    CHECK(fd_table_install_at(table,3,original,0)==3);fd_description_put(original);
    CHECK(!io_poll_create(q,3,-1,&set));syscall_pollfd_t *entries=io_poll_entries(set);
    entries[0]=(syscall_pollfd_t){.fd=-1,.events=-1,.revents=-1};
    entries[1]=(syscall_pollfd_t){.fd=3,.events=SYSCALL_POLL_IN};
    entries[2]=(syscall_pollfd_t){.fd=3,.events=SYSCALL_POLL_OUT};
    CHECK(!io_poll_pin(set,table)&&io_poll_pin(set,table)==-EINVAL);spinlock_preempt_enable();
    io_request_t *request=calloc(1,sizeof(*request));CHECK(request);request->description=set;io_service_result_t result;
    CHECK(!io_poll_execute(request,&result)&&!entries[0].revents);
    target->flags=SYSCALL_POLL_IN;CHECK(io_poll_execute(request,&result)&&result.result==1&&entries[1].revents==SYSCALL_POLL_IN&&!entries[2].revents);
    target->flags=SYSCALL_POLL_IN|SYSCALL_POLL_OUT;CHECK(io_poll_execute(request,&result)&&result.result==2);
    target->flags=SYSCALL_POLL_ERR|SYSCALL_POLL_HUP;entries[1].events=entries[2].events=0;
    CHECK(io_poll_execute(request,&result)&&result.result==2&&entries[1].revents==(SYSCALL_POLL_ERR|SYSCALL_POLL_HUP));
    spinlock_preempt_disable();CHECK(!fd_table_close(table,3));fd_description_t *replacement=new_description(q);CHECK(replacement);
    CHECK(fd_table_install_at(table,3,replacement,0)==3);fd_description_put(replacement);spinlock_preempt_enable();
    CHECK(!drain(q,99));target->flags=SYSCALL_POLL_IN;entries[1].events=SYSCALL_POLL_IN;
    CHECK(io_poll_execute(request,&result)&&result.result==1&&entries[1].revents==SYSCALL_POLL_IN);
    fd_description_put(set);CHECK(drain(q,99)>=1);while(drain(q,99)){}
    for(unsigned timeout=0;timeout<=20;timeout+=20) {
        poll_now=100;spinlock_preempt_disable();CHECK(!io_poll_create(q,0,(int)timeout,&set)&&!io_poll_pin(set,table));spinlock_preempt_enable();
        request->description=set;CHECK(io_poll_execute(request,&result)==(timeout==0));
        poll_now=119;if(timeout)CHECK(!io_poll_execute(request,&result));
        poll_now=120;CHECK(io_poll_execute(request,&result)&&!result.result);fd_description_put(set);
    }
    poll_now=UINT64_MAX-4;spinlock_preempt_disable();CHECK(!io_poll_create(q,1,20,&set));entries=io_poll_entries(set);
    entries[0].fd=-1;CHECK(!io_poll_pin(set,table));spinlock_preempt_enable();request->description=set;
    CHECK(!io_poll_execute(request,&result));poll_now=UINT64_MAX;CHECK(io_poll_execute(request,&result)&&!result.result);fd_description_put(set);
    poll_now=0;spinlock_preempt_disable();CHECK(!io_poll_create(q,2,-1,&set));entries=io_poll_entries(set);
    entries[0].fd=255;entries[1].fd=3;CHECK(!io_poll_pin(set,table));spinlock_preempt_enable();request->description=set;
    CHECK(io_poll_execute(request,&result)&&result.result==2&&entries[0].revents==SYSCALL_POLL_NVAL&&entries[1].revents==SYSCALL_POLL_ERR);
    fd_description_put(set);free(request);fd_table_shutdown(table);fd_table_put(table);destroy_empty(q);
}
static void select_semantics(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(32);fd_table_t *table=fd_table_create_deferred(8,q);CHECK(q&&table);
    target_t *target=calloc(1,sizeof(*target));CHECK(target);target->lifetime.magic=0xabc123;target->lifetime.queue=q;
    spinlock_preempt_disable();
    fd_description_t *original=fd_description_create_deferred(&poll_target_ops,target,q),*set=NULL;CHECK(original);
    CHECK(fd_table_install_at(table,3,original,0)==3);fd_description_put(original);
    CHECK(io_select_create(q,4,-2,&set)==-EINVAL && !set);
    poll_now=100;CHECK(!io_select_create(q,4,INT64_C(5000000000),&set));
    syscall_pollfd_t *entries=io_poll_entries(set);
    for(unsigned i=0;i<4;++i)entries[i].fd=-1;
    entries[3]=(syscall_pollfd_t){.fd=3,.events=SYSCALL_POLL_PRI};
    CHECK(!io_poll_pin(set,table));spinlock_preempt_enable();
    io_request_t *request=calloc(1,sizeof(*request));CHECK(request);request->description=set;io_service_result_t result;
    target->flags=SYSCALL_POLL_HUP|SYSCALL_POLL_ERR;
    CHECK(!io_poll_execute(request,&result) && !entries[3].revents);
    poll_now=INT64_C(3000000000);CHECK(!io_poll_execute(request,&result));
    entries[3].events=SYSCALL_POLL_IN|SYSCALL_POLL_OUT;
    CHECK(io_poll_execute(request,&result) && result.result==1 && entries[3].revents==(SYSCALL_POLL_IN|SYSCALL_POLL_OUT));
    target->flags=SYSCALL_POLL_HUP;
    CHECK(io_poll_execute(request,&result) && entries[3].revents==SYSCALL_POLL_IN);
    entries[3].events=SYSCALL_POLL_PRI;target->flags=SYSCALL_POLL_PRI;
    CHECK(io_poll_execute(request,&result) && entries[3].revents==SYSCALL_POLL_PRI);
    spinlock_preempt_disable();CHECK(!fd_table_close(table,3));fd_description_t *replacement=new_description(q);CHECK(replacement);
    CHECK(fd_table_install_at(table,3,replacement,0)==3);fd_description_put(replacement);spinlock_preempt_enable();
    target->flags=0;CHECK(!io_poll_execute(request,&result));
    target->flags=SYSCALL_POLL_PRI;CHECK(io_poll_execute(request,&result) && entries[3].revents==SYSCALL_POLL_PRI);
    entries[3].events=SYSCALL_POLL_IN;target->flags=0;poll_now=INT64_C(5000000100);
    CHECK(io_poll_execute(request,&result) && !result.result);
    fd_description_put(set);while(drain(q,99)){}
    spinlock_preempt_disable();CHECK(!io_select_create(q,1,0,&set));entries=io_poll_entries(set);
    entries[0]=(syscall_pollfd_t){.fd=255,.events=SYSCALL_POLL_PRI};CHECK(!io_poll_pin(set,table));spinlock_preempt_enable();
    request->description=set;CHECK(io_poll_execute(request,&result) && result.result==1 && entries[0].revents==SYSCALL_POLL_NVAL);
    fd_description_put(set);free(request);fd_table_shutdown(table);fd_table_put(table);destroy_empty(q);
}
typedef struct { pthread_t thread; io_request_t request; target_t *target; unsigned mode; } race_t;
static void *poll_race(void *pointer) {
    race_t *race=pointer;
    for(unsigned index=0;index<10000;++index) {
        if(race->mode==2)__atomic_store_n(&race->target->flags,index%2 ? SYSCALL_POLL_IN : SYSCALL_POLL_OUT,__ATOMIC_RELEASE);
        else {
            io_service_result_t result;CHECK(io_poll_execute(&race->request,&result)&&result.result==1);
        }
    }
    return NULL;
}
static void concurrent_sets(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(16);fd_table_t *table=fd_table_create_deferred(8,q);CHECK(q&&table);
    target_t *target=calloc(1,sizeof(*target));race_t *races=calloc(3,sizeof(*races));CHECK(target&&races);
    target->lifetime.magic=0xabc123;target->lifetime.queue=q;target->flags=SYSCALL_POLL_IN;
    spinlock_preempt_disable();fd_description_t *original=fd_description_create_deferred(&poll_target_ops,target,q);CHECK(original);
    CHECK(fd_table_install_at(table,3,original,0)==3);fd_description_put(original);
    for(unsigned index=0;index<2;++index) {
        CHECK(!(index ? io_select_create(q,1,-1,&races[index].request.description) :
                        io_poll_create(q,1,-1,&races[index].request.description)));
        syscall_pollfd_t *entry=io_poll_entries(races[index].request.description);
        entry->fd=3;entry->events=SYSCALL_POLL_IN|SYSCALL_POLL_OUT;CHECK(!io_poll_pin(races[index].request.description,table));
    }
    CHECK(!fd_table_close(table,3));spinlock_preempt_enable();
    for(unsigned index=0;index<3;++index) {races[index].target=target;races[index].mode=index;CHECK(!pthread_create(&races[index].thread,NULL,poll_race,&races[index]));}
    for(unsigned index=0;index<3;++index)CHECK(!pthread_join(races[index].thread,NULL));
    for(unsigned index=0;index<2;++index)fd_description_put(races[index].request.description);
    fd_table_shutdown(table);fd_table_put(table);destroy_empty(q);free(races);
}
int main(void) {
    CHECK(!baseline());failure_cases();poll_semantics();select_semantics();concurrent_sets();CHECK(!allocations&&!held_locks&&!preempt_depth);
    puts("Poll/select production contracts PASS: OOM, pins, close/reuse, 64-bit deadlines, select masks, and 20000 concurrent snapshots");return 0;
}
'''
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("poll", code)
        print("Production poll/select: PASS masks, 64-bit deadlines, ownership, OOM and 20000 concurrent snapshots")
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous


if __name__ == "__main__":
    main()
