#!/usr/bin/env python3
"""Active child records: claim rollback, orphaning and quiescent retirement."""
import contextlib
import io
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run, function_definition
import fd_retirement_contract_test as base

ROOT = Path(__file__).resolve().parents[1]


def main():
    captured = []
    original = base.compile_and_run
    base.compile_and_run = lambda _label, code: captured.append(code)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            base.main()
    finally:
        base.compile_and_run = original
    code = captured[0].replace("int main(void)", "static int baseline(void)", 1)
    source = (ROOT / "src/kernel/io/process.c").read_text()
    code += r'''
#define CHILD_ARGUMENTS 256u
#define SYSCALL_PROCESS_NOHANG 1u
#define ALIX_SIGKILL 9
#define ALIX_SIGCHLD 17
#define ALIX_CLD_EXITED 1
#define ALIX_CLD_KILLED 2
#define ALIX_CLD_DUMPED 3
typedef struct {
    int32_t si_signo,si_errno,si_code,si_status;void *si_addr;int32_t si_pid;uint32_t si_uid;
    uint64_t si_tid,si_trapno,si_error,reserved;
} alix_siginfo_t;
typedef struct {bool terminal,quiescent,context_closed;uint32_t status,pid,kills;fd_table_t *files;} process_t;
typedef struct {process_t *owner;uint64_t pid;bool complete;} process_creation_watch_t;
typedef struct {fd_description_t *cwd;fd_table_t *files;uint32_t uid,gid;uint64_t parent_pid;} process_launch_context_t;
typedef struct {void *buffer;size_t bytes;fd_description_t *description;} io_request_t;
typedef struct {int64_t result;fd_description_t *description_owned;} io_service_result_t;
static fd_retirement_queue_t *active_retirement;
static unsigned released_children,closed_contexts,killed_children,next_child=1;
static bool fail_output;
static void *io_request_buffer(io_request_t *request){return request->buffer;}
static size_t io_request_buffer_size(io_request_t *request){return request->bytes;}
static fd_description_t *io_request_description(io_request_t *request){return request->description;}
static fd_retirement_queue_t *process_fd_retirement_queue(void){return active_retirement;}
static int process_wait_status_snapshot(process_t *process,uint32_t *status){
    CHECK(process);if(!process->terminal||!process->quiescent)return-EAGAIN;*status=process->status;return 0;
}
static bool process_kill_signal(process_t *process,int number){
    CHECK(number==ALIX_SIGKILL);++process->kills;++killed_children;process->terminal=true;process->status=9;return true;
}
static void process_release_context(process_t *process){
    CHECK(process->terminal&&process->quiescent&&!process->context_closed&&!held_locks&&!preempt_depth);
    process->context_closed=true;++closed_contexts;fd_table_put(process->files);process->files=NULL;
}
static void process_creation_watch_release(process_creation_watch_t *watch){
    if(!watch->owner)return;process_t *process=watch->owner;
    CHECK(watch->complete&&process->terminal&&process->quiescent&&process->context_closed&&!held_locks&&!preempt_depth);
    watch->owner=NULL;++released_children;free(process);
}
static bool user_copy_to_user(void *out,const void *in,size_t size){
    CHECK(preempt_depth);if(fail_output)return false;memcpy(out,in,size);return true;
}
'''
    code += source[source.index("typedef struct child_record"):source.index("static io_service_t *g_launch_service;")]
    code += r'''
static spinlock_t g_orphan_lock;
static child_record_t *g_orphan_head,*g_orphan_tail,*g_reap_batch[64];
'''
    for signature in ("static void child_enqueue_orphan(", "static void child_record_put(",
                      "static int child_record_close(", "static bool child_record_valid(",
                      "static int child_table_close(", "static void child_claim_release(",
                      "static int child_claim_close(", "static void child_reap_once(",
                      "static bool child_wait_handler(", "static int child_wait_commit(",
                      "static int child_wait_commit_info("):
        code += function_definition(source, signature) + "\n"
        operation = {
            "static int child_record_close(": ("child_record_ops", "child_record_close"),
            "static int child_table_close(": ("child_table_ops", "child_table_close"),
            "static int child_claim_close(": ("child_claim_ops", "child_claim_close"),
        }.get(signature)
        if operation:
            code += "static const fd_ops_t %s = {.close=%s};\n" % operation
    code += r'''
static fd_description_t *new_record(fd_retirement_queue_t *queue,bool published,child_record_t **out){
    child_record_t *record=calloc(1,sizeof(*record));process_t *process=calloc(1,sizeof(*process));CHECK(record&&process);
    process->pid=next_child++;process->files=fd_table_create_deferred(2,queue);CHECK(process->files);
    fd_description_t *file=new_description(queue);CHECK(fd_table_install(process->files,file,0,0)==0);fd_description_put(file);
    record->watch=(process_creation_watch_t){.owner=process,.pid=process->pid,.complete=true};
    record->references=2;record->published=published;
    fd_description_t *description=fd_description_create_deferred(&child_record_ops,record,queue);CHECK(description);
    child_enqueue_orphan(record);*out=record;return description;
}
static void monitor_contract(void){
    for(unsigned published=0;published<2;++published){
        fd_retirement_queue_t *queue=fd_retirement_queue_create(32);CHECK(queue);active_retirement=queue;
        child_record_t *record=NULL;fd_description_t *description=new_record(queue,published,&record);process_t *process=record->watch.owner;
        fd_description_put(description);(void)drain(queue,99);CHECK(record->closed&&record->references==1);
        unsigned prior=killed_children,releases=released_children;
        child_reap_once();CHECK(!process->context_closed&&released_children==releases&&process->kills==(published?0u:1u));
        child_reap_once();CHECK(killed_children==prior+(published?0u:1u));
        process->terminal=true;process->quiescent=true;child_reap_once();
        CHECK(released_children==releases+1&&!g_orphan_head&&!g_orphan_tail);destroy_empty(queue);
    }
}
typedef struct {fd_retirement_queue_t *queue;fd_description_t *description;} close_race_t;
static void *close_race(void *argument){close_race_t *race=argument;fd_description_put(race->description);(void)drain(race->queue,99);return NULL;}
static void *monitor_race(void *argument){(void)argument;child_reap_once();return NULL;}
static void concurrent_retirement(void){
    for(unsigned index=0;index<64;++index){
        fd_retirement_queue_t *queue=fd_retirement_queue_create(32);CHECK(queue);active_retirement=queue;
        child_record_t *record=NULL;fd_description_t *description=new_record(queue,true,&record);
        record->watch.owner->terminal=record->watch.owner->quiescent=true;
        close_race_t *race=calloc(1,sizeof(*race));pthread_t *threads=calloc(2,sizeof(*threads));CHECK(race&&threads);
        *race=(close_race_t){queue,description};
        CHECK(!pthread_create(&threads[0],NULL,index&1?monitor_race:close_race,race));
        CHECK(!pthread_create(&threads[1],NULL,index&1?close_race:monitor_race,race));
        CHECK(!pthread_join(threads[0],NULL)&&!pthread_join(threads[1],NULL));
        CHECK(!g_orphan_head&&!g_orphan_tail);free(threads);free(race);destroy_empty(queue);
    }
}
static void claims_contract(void){
    fd_retirement_queue_t *queue=fd_retirement_queue_create(64);CHECK(queue);active_retirement=queue;
    fd_table_t *table=fd_table_create_deferred(4,queue);CHECK(table);
    child_record_t *record=NULL;fd_description_t *description=new_record(queue,true,&record);
    CHECK(fd_table_install(table,description,0,0)==0);fd_description_put(description);
    child_table_owner_t *owner=calloc(1,sizeof(*owner));CHECK(owner&&fd_table_get(table));owner->table=table;
    fd_description_t *table_owner=fd_description_create_deferred(&child_table_ops,owner,queue);CHECK(table_owner);
    child_wait_work_t work={.pid=-1,.flags=SYSCALL_PROCESS_NOHANG};
    io_request_t request={&work,sizeof(work),table_owner};io_service_result_t result;
    CHECK(child_wait_handler(&request,&result)&&!result.result&&!result.description_owned);
    record->watch.owner->terminal=true;record->watch.owner->status=37u<<8;
    CHECK(child_wait_handler(&request,&result)&&!result.result&&!result.description_owned);
    work.flags=0;CHECK(!child_wait_handler(&request,&result)&&!result.description_owned);
    record->watch.owner->quiescent=true;unsigned releases=released_children;
    child_reap_once();CHECK(record->references==1&&record->watch.owner->context_closed&&released_children==releases);
    fail_allocations=1;CHECK(child_wait_handler(&request,&result)&&result.result==-ENOMEM&&!result.description_owned&&!record->claimed);
    CHECK(child_wait_handler(&request,&result)&&result.result==(int64_t)record->watch.pid&&result.description_owned&&record->claimed);
    fd_description_t *lease=result.description_owned;uint32_t output=12345;
    spinlock_preempt_disable();fail_output=true;
    CHECK(child_wait_commit(lease,table,&output,work.status)==-EFAULT&&output==12345&&!record->claimed&&!record->reaped);
    fail_output=false;spinlock_preempt_enable();fd_description_put(lease);(void)drain(queue,99);
    CHECK(child_wait_handler(&request,&result)&&result.description_owned&&record->claimed);
    /* A completed claim abandoned with its caller releases ownership without reaping. */
    fd_description_put(result.description_owned);(void)drain(queue,99);CHECK(!record->claimed&&!record->reaped);
    CHECK(child_wait_handler(&request,&result)&&result.description_owned);lease=result.description_owned;
    spinlock_preempt_disable();CHECK(!child_wait_commit(lease,table,&output,work.status)&&output==(37u<<8)&&record->reaped);
    spinlock_preempt_enable();
    CHECK(child_wait_handler(&request,&result)&&result.result==-ECHILD&&!result.description_owned);
    fd_description_put(lease);(void)drain(queue,99);CHECK(released_children==releases+1);
    fd_description_put(table_owner);fd_table_put(table);destroy_empty(queue);
}
static void info_contract(void){
    for(unsigned phase=0;phase<4;++phase){
        fd_retirement_queue_t *queue=fd_retirement_queue_create(64);CHECK(queue);active_retirement=queue;
        fd_table_t *table=fd_table_create_deferred(4,queue);CHECK(table);
        child_record_t *record=NULL;fd_description_t *description=new_record(queue,true,&record);
        record->launch.uid=101;record->watch.owner->terminal=record->watch.owner->quiescent=true;
        record->watch.owner->status=phase==0?0:phase==1?(255u<<8):phase==2?9u:(11u|0x80u);
        int pid=(int)record->watch.pid;
        CHECK(fd_table_install(table,description,0,0)==0);fd_description_put(description);
        child_table_owner_t *owner=calloc(1,sizeof(*owner));CHECK(owner&&fd_table_get(table));owner->table=table;
        fd_description_t *table_owner=fd_description_create_deferred(&child_table_ops,owner,queue);CHECK(table_owner);
        child_wait_work_t work={.pid=pid,.flags=CHILD_WAIT_INFO|CHILD_WAIT_PEEK};
        io_request_t request={&work,sizeof(work),table_owner};io_service_result_t result;alix_siginfo_t output;
        for(unsigned attempt=0;attempt<3;++attempt){
            CHECK(child_wait_handler(&request,&result)&&result.result==pid&&result.description_owned);
            memset(&output,0x5a,sizeof(output));spinlock_preempt_disable();fail_output=attempt==0;
            CHECK(child_wait_commit_info(result.description_owned,table,&output,&work)==(fail_output?-EFAULT:0));
            if(!fail_output)CHECK(output.si_signo==ALIX_SIGCHLD&&output.si_pid==pid&&output.si_uid==101&&
                output.si_code==(phase<2?ALIX_CLD_EXITED:phase==2?ALIX_CLD_KILLED:ALIX_CLD_DUMPED)&&
                output.si_status==(phase==0?0:phase==1?255:phase==2?9:11)&&!output.reserved&&!output.si_errno);
            CHECK(!record->reaped&&!record->claimed);fail_output=false;spinlock_preempt_enable();
            fd_description_put(result.description_owned);(void)drain(queue,99);
        }
        /* Abandon an information request after its claim was published. */
        CHECK(child_wait_handler(&request,&result)&&result.description_owned);
        fd_description_put(result.description_owned);(void)drain(queue,99);CHECK(!record->claimed&&!record->reaped);
        work.flags=CHILD_WAIT_INFO;
        CHECK(child_wait_handler(&request,&result)&&result.description_owned);
        spinlock_preempt_disable();CHECK(!child_wait_commit_info(result.description_owned,table,&output,&work)&&record->reaped);
        spinlock_preempt_enable();fd_description_put(result.description_owned);(void)drain(queue,99);
        CHECK(child_wait_handler(&request,&result)&&result.result==-ECHILD&&!result.description_owned);
        child_reap_once();fd_description_put(table_owner);fd_table_put(table);destroy_empty(queue);
    }
}
int main(void){
    CHECK(!baseline());monitor_contract();claims_contract();info_contract();concurrent_retirement();
    CHECK(!allocations&&!held_locks&&!preempt_depth&&!g_orphan_head&&released_children==71&&closed_contexts==71);
    puts("Child lifecycle contracts PASS");return 0;
}
'''
    compile_and_run("process-child", code)
    print("Child lifecycle contracts PASS: orphan survival, abandoned launch kill, quiescence, OOM, claim cancel/copy rollback, waitid peek/reap")
    return 0


if __name__ == "__main__":
    sys.exit(main())
