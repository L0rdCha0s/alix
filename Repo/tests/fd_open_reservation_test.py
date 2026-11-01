#!/usr/bin/env python3
"""Production OPEN-slot leases: no side effect before admission, safe cancellation."""
import contextlib
import io
import os
import shlex
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run
import fd_retirement_contract_test as base

def main():
    captured=[]; original=base.compile_and_run
    base.compile_and_run=lambda _label,code:captured.append(code)
    try:
        with contextlib.redirect_stdout(io.StringIO()): base.main()
    finally: base.compile_and_run=original
    code=captured[0].replace('int main(void) {','static int retirement_baseline(void) {',1)
    code+=r'''
static void reserved_admission_and_commit(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(64);fd_table_t *table=fd_table_create_deferred(4,q);
    fd_description_t *a=new_description(q),*b=new_description(q),*c=new_description(q);CHECK(q&&table&&a&&b&&c);
    CHECK(fd_table_install_at(table,0,a,0)==0);
    fd_description_t *first=NULL,*second=NULL,*failed=NULL;
    CHECK(fd_table_reserve_deferred(table,&failed)==-EINVAL&&!failed);
    spinlock_preempt_disable();
    CHECK(!fd_table_reserve_deferred(table,&first)&&!fd_table_reserve_deferred(table,&second));
    CHECK(fd_table_reservation_valid(first)&&fd_table_reservation_valid(second));
    CHECK(fd_table_install(table,b,0,0)==3); /* Reservations cannot be reused by install/dup. */
    CHECK(fd_table_reserve_deferred(table,&failed)==-EMFILE&&!failed);
    fd_description_t *pin=NULL;uint32_t flags;
    CHECK(fd_table_pin(table,1,&pin,NULL)==-EBADF&&!pin&&fd_table_close(table,1)==-EBADF);
    CHECK(fd_table_get_flags(table,1,&flags)==-EBADF&&fd_table_install_at(table,1,c,0)==-EEXIST);
    CHECK(fd_table_dup2(table,0,1)==-EBUSY&&fd_table_dup(table,0,0,0)==-EMFILE);
    fd_table_t *copy=NULL;CHECK(!fd_table_clone_deferred(table,false,&copy));
    CHECK(fd_table_pin(copy,1,&pin,NULL)==-EBADF&&!copy->entries[1].reservation);
    CHECK(fd_table_reservation_commit(first,b,FD_TABLE_CLOEXEC)==1);
    CHECK(!fd_table_get_flags(table,1,&flags)&&flags==FD_TABLE_CLOEXEC);
    CHECK(fd_table_reservation_commit(first,c,0)==-EAGAIN&&fd_table_reservation_cancel(first)==-EAGAIN);
    CHECK(!fd_table_reservation_cancel(second));
    CHECK(fd_table_install(table,c,0,0)==2); /* Failure returns the slot before deferred cleanup. */
    CHECK(fd_table_reservation_commit(second,b,0)==-EAGAIN);
    fd_description_put(first);fd_description_put(second);
    CHECK(!fd_table_close(table,3));fd_description_t *closing=NULL;CHECK(!fd_table_reserve_deferred(table,&closing));
    fd_table_shutdown(table);CHECK(fd_table_reservation_commit(closing,b,0)==-EBADF&&fd_table_reservation_cancel(closing)==-EBADF);
    fd_table_put(table);fd_description_put(closing);fd_table_put(copy);
    fd_description_put(a);fd_description_put(b);fd_description_put(c);
    spinlock_preempt_enable();destroy_empty(q);
}
static void reservation_failure_paths(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(32);fd_table_t *table=fd_table_create_deferred(2,q);CHECK(q&&table);
    fd_description_t *reservation=NULL;
    spinlock_preempt_disable();fail_allocations=1;
    CHECK(fd_table_reserve_deferred(table,&reservation)==-ENOMEM&&!reservation&&!table->entries[0].reservation);
    table->references=UINT32_MAX;CHECK(fd_table_reserve_deferred(table,&reservation)==-EOVERFLOW&&!reservation);table->references=1;
    table->next_ticket=UINT64_MAX;CHECK(fd_table_reserve_deferred(table,&reservation)==-EOVERFLOW&&!reservation);table->next_ticket=1;
    CHECK(!fd_table_reserve_deferred(table,&reservation));
    fd_table_put(table); /* A killed process drops its table; request lease keeps it alive. */
    fd_description_put(reservation);spinlock_preempt_enable();destroy_empty(q);
}
typedef struct { fd_table_t *table;fd_description_t *target;unsigned *done; } reserve_worker_t;
static void *reserve_churn(void *argument) {
    reserve_worker_t *worker=argument;
    for(unsigned i=0;i<256;++i) {
        fd_description_t *reservation=NULL;spinlock_preempt_disable();
        CHECK(!fd_table_reserve_deferred(worker->table,&reservation));
        if(i&1) {
            int fd=fd_table_reservation_commit(reservation,worker->target,0);CHECK(fd>=0);
            CHECK(!fd_table_close(worker->table,fd));
        } else CHECK(!fd_table_reservation_cancel(reservation));
        fd_description_put(reservation);spinlock_preempt_enable();
    }
    __atomic_add_fetch(worker->done,1,__ATOMIC_RELEASE);return NULL;
}
static void concurrent_reservations(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(65536);fd_table_t *table=fd_table_create_deferred(64,q);fd_description_t *target=new_description(q);CHECK(q&&table&&target);
    reserve_worker_t *args=calloc(8,sizeof(*args));pthread_t *threads=calloc(8,sizeof(*threads));unsigned *done=calloc(1,sizeof(*done));CHECK(args&&threads&&done);
    for(unsigned i=0;i<8;++i) { args[i]=(reserve_worker_t){table,target,done};CHECK(!pthread_create(&threads[i],NULL,reserve_churn,&args[i])); }
    while(__atomic_load_n(done,__ATOMIC_ACQUIRE)!=8) { (void)drain(q,32);sched_yield(); }
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    fd_table_put(table);fd_description_put(target);destroy_empty(q);free(done);free(threads);free(args);
}
int main(void) {
    CHECK(!retirement_baseline());reserved_admission_and_commit();reservation_failure_paths();concurrent_reservations();
    CHECK(!allocations&&!held_locks&&!preempt_depth);
    puts("FD_OPEN_RESERVATION: PASS hidden_slots=1 immediate_cancel=1 commit_identity=1 no_cycle=1 workers=8 leases=2048 OOM=1");return 0;
}
'''
    previous=os.environ.get('HOST_CC')
    try:
        os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
        compile_and_run('fd-open-reservation',code)
    finally:
        if previous is None:os.environ.pop('HOST_CC',None)
        else:os.environ['HOST_CC']=previous
    print('Production OPEN reservation contracts passed')

if __name__=='__main__':main()
