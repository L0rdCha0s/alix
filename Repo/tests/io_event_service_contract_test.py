#!/usr/bin/env python3
"""Run the production multiplexed executor and ownership queues on host threads."""
import ast
import os
import shlex
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

def stripped(path):
    return '\n'.join(line for line in path.read_text().splitlines() if not line.startswith('#include '))

def main():
    # Reuse the tracked host scheduler/heap model, without the older executor's
    # staged-source loader. All production inputs below come from the active tree.
    tree = ast.parse((ROOT / 'tests/io_service_contract_test.py').read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    literal = next(node.value.value for node in function.body if isinstance(node, ast.Assign) and
                   any(isinstance(target, ast.Name) and target.id == 'code' for target in node.targets) and
                   isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))
    code = literal.replace('!strcmp(name,"io-cleanup")', 'strstr(name,"cleanup")!=NULL')
    for path in ('include/fd.h','include/fd_table.h','include/io_request.h','include/io_service.h',
                 'include/io_event_service.h','src/kernel/fd/table.c','src/kernel/io/request.c'):
        code += stripped(ROOT / path) + '\n'
    code += 'static wait_queue_t g_io_completion_queue={.initialized=true};\n'
    glue = (ROOT / 'src/kernel/process/process_io.c').read_text()
    for signature in ('void process_io_notify_completion(', 'int process_io_complete_request('):
        code += function_definition(glue, signature) + '\n'
    code += stripped(ROOT / 'src/kernel/io/event_service.c') + r'''

typedef struct {
    io_event_service_t *service;
    uint32_t gate,handled,created,closed,reentered,shutdown_done;
    int shutdown_result;
} control_t;
typedef struct { control_t *control;bool reenter;uint64_t magic; } asset_t;
typedef struct { control_t *control;unsigned kind;unsigned char payload[32]; } job_t;
#define MAGIC UINT64_C(0x23456789abcdef01)
static void close_checks(asset_t *asset) {
    CHECK(!held_locks&&!prep_guard&&current_process&&current_process->cleanup_role&&asset->magic==MAGIC);
    if(asset->reenter) {
        io_event_service_status_t status;
        CHECK(!io_event_service_snapshot(asset->control->service,&status)&&status.queue.live);
        CHECK(io_event_service_shutdown(asset->control->service)==-EDEADLK);
        CHECK(io_event_service_destroy(asset->control->service)==-EBUSY);
        prep_guard=true;io_request_t *nested=NULL;
        int result=io_event_service_request_create(asset->control->service,0,1,2,&nested);
        CHECK(!result||result==-ECANCELED||result==-EAGAIN);
        if(!result) CHECK(!io_request_waiter_abandon(nested));
        prep_guard=false;__atomic_add_fetch(&asset->control->reentered,1,__ATOMIC_RELAXED);
    }
    __atomic_add_fetch(&asset->control->closed,1,__ATOMIC_RELEASE);asset->magic=0;free(asset);
}
static int close_asset(void *context) { close_checks(context);return 0; }
static void release_cwd(void *context) { close_checks(context); }
static const fd_ops_t asset_operations={.close=close_asset};
static asset_t *new_asset(control_t *control,bool reenter) {
    asset_t *asset=calloc(1,sizeof(*asset));CHECK(asset);*asset=(asset_t){control,reenter,MAGIC};
    __atomic_add_fetch(&control->created,1,__ATOMIC_RELAXED);return asset;
}
static fd_description_t *new_description(control_t *control,bool reenter) {
    fd_description_t *description=fd_description_create(&asset_operations,new_asset(control,reenter));CHECK(description);return description;
}
static bool event_step(io_request_t *request,io_service_result_t *result) {
    CHECK(!held_locks&&!prep_guard&&current_process&&current_process->kernel_service&&!current_process->cleanup_role);
    CHECK(heap_contains(result,sizeof(*result))&&io_request_uid(request)==37&&io_request_gid(request)==41);
    CHECK(!current_process->uid&&!current_process->gid);
    job_t *job=io_request_buffer(request);CHECK(heap_contains(job,sizeof(*job)));
    asset_t *input=fd_description_context(io_request_description(request)),*cwd=io_request_cwd(request);
    CHECK(input->magic==MAGIC&&cwd->magic==MAGIC&&input->control==job->control&&cwd->control==job->control);
    __atomic_add_fetch(&job->control->handled,1,__ATOMIC_RELAXED);
    CHECK(io_event_service_shutdown(job->control->service)==-EDEADLK);
    if(job->kind==1&&!__atomic_load_n(&job->control->gate,__ATOMIC_ACQUIRE)) return false;
    if(job->kind==2) { result->result=-EIO;return true; }
    memset(job->payload,0x5a,sizeof(job->payload));result->result=32;
    if(job->kind==3) result->description_owned=new_description(job->control,false);
    return true;
}
static io_request_t *make_request(control_t *control,unsigned kind,bool reenter) {
    prep_guard=true;io_request_t *request=NULL;
    int result=io_event_service_request_create(control->service,sizeof(job_t),37,41,&request);
    if(result==-EAGAIN) { prep_guard=false;return NULL; } CHECK(!result&&request);
    job_t *job=io_request_buffer(request);job->control=control;job->kind=kind;
    CHECK(!io_request_bind(request,new_description(control,reenter),new_asset(control,false),release_cwd));
    CHECK(!io_event_service_submit(control->service,request));prep_guard=false;return request;
}
static uint64_t milliseconds(void) { struct timespec time;CHECK(!clock_gettime(CLOCK_MONOTONIC,&time));return (uint64_t)time.tv_sec*1000+(uint64_t)time.tv_nsec/1000000; }
static void wait_done(io_request_t *request,bool cancelled,int64_t expected) {
    uint64_t deadline=milliseconds()+5000;io_request_status_t status;
    for(;;) {
        CHECK(!io_request_status(request,&status));if(status.state==IO_REQUEST_COMPLETED)break;
        CHECK(milliseconds()<deadline);process_sleep_ms(1);
    }
    CHECK(status.cancelled==cancelled&&status.result==expected);
}
static void wait_live(control_t *control,size_t live) {
    uint64_t deadline=milliseconds()+5000;io_event_service_status_t status;
    do { CHECK(!io_event_service_snapshot(control->service,&status));if(status.queue.live==live)return;CHECK(milliseconds()<deadline);process_sleep_ms(1); } while(1);
}
static void allocation_and_factory_failures(void) {
    for(int allocation=0;allocation<5;++allocation) {
        fail_allocation_after=allocation;CHECK(!io_event_service_create(4,event_step));fail_allocation_after=-1;
        CHECK(!live_allocations&&spawned==joined);
    }
    for(unsigned worker=0;worker<2;++worker) {
        fail_spawn_at=(int)spawn_calls+(int)worker;CHECK(!io_event_service_create(4,event_step));fail_spawn_at=-1;
        CHECK(!live_allocations&&spawned==joined);
    }
    CHECK(!io_event_service_create(0,event_step)&&!io_event_service_create(IO_QUEUE_MAX_REQUESTS+1,event_step)&&!io_event_service_create(4,NULL));
    prep_guard=true;CHECK(!io_event_service_create(4,event_step));prep_guard=false;
}
static void *shutdown_controller(void *argument) {
    control_t *control=argument;control->shutdown_result=io_event_service_shutdown(control->service);
    __atomic_store_n(&control->shutdown_done,1,__ATOMIC_RELEASE);return NULL;
}
static void pending_cancel_and_shutdown(control_t *control) {
    control->service=io_event_service_create(4,event_step);CHECK(control->service);
    CHECK(io_event_service_destroy(control->service)==-EBUSY);
    io_request_t **requests=calloc(4,sizeof(*requests));CHECK(requests);
    for(unsigned i=0;i<4;++i) { requests[i]=make_request(control,1,i==0);CHECK(requests[i]); }
    uint64_t deadline=milliseconds()+5000;io_event_service_status_t status;
    do { CHECK(!io_event_service_snapshot(control->service,&status));if(status.pending==4)break;CHECK(milliseconds()<deadline);process_sleep_ms(1); } while(1);
    CHECK(!make_request(control,0,false)); /* Live admission includes every pending owner. */
    prep_guard=true;
    for(unsigned i=0;i<2;++i) { CHECK(!io_request_waiter_abandon(requests[i]));requests[i]=NULL; }
    prep_guard=false;wait_live(control,2);
    io_request_t *fresh=make_request(control,3,false);CHECK(fresh);wait_done(fresh,false,32);
    job_t *job=io_request_buffer(fresh);for(unsigned i=0;i<32;++i)CHECK(job->payload[i]==0x5a);
    CHECK(!io_request_waiter_release(fresh));wait_live(control,2);CHECK(control->reentered);
    pthread_t *thread=calloc(1,sizeof(*thread));CHECK(thread&&!pthread_create(thread,NULL,shutdown_controller,control));
    for(unsigned i=2;i<4;++i) wait_done(requests[i],true,-ECANCELED);
    CHECK(!__atomic_load_n(&control->shutdown_done,__ATOMIC_ACQUIRE));
    CHECK(io_event_service_shutdown(control->service)==-EBUSY&&io_event_service_destroy(control->service)==-EBUSY);
    prep_guard=true;fresh=(void *)1;
    CHECK(io_event_service_request_create(control->service,0,0,0,&fresh)==-ECANCELED&&!fresh);
    prep_guard=false;
    for(unsigned i=2;i<4;++i) CHECK(!io_request_waiter_release(requests[i]));
    CHECK(!pthread_join(*thread,NULL)&&!control->shutdown_result&&control->shutdown_done);free(thread);free(requests);
    CHECK(!io_event_service_snapshot(control->service,&status)&&status.stopped&&!status.pending&&!status.worker_alive&&!status.queue.live);
    CHECK(!io_event_service_shutdown(control->service)&&!io_event_service_destroy(control->service));control->service=NULL;
    CHECK(control->created==control->closed&&spawned==joined);
}
typedef struct { control_t *control;unsigned index; } producer_t;
static void *producer(void *argument) {
    producer_t *producer=argument;
    for(unsigned i=0;i<128;++i) {
        unsigned kind=(i+producer->index)%4;io_request_t *request;
        while(!(request=make_request(producer->control,kind,false)))sched_yield();
        if(i%3==0) CHECK(!io_request_waiter_abandon(request));
        else { wait_done(request,false,kind==2?-EIO:32);CHECK(!io_request_waiter_release(request)); }
    }
    return NULL;
}
static void concurrent_callers(control_t *control) {
    control->service=io_event_service_create(64,event_step);CHECK(control->service);control->gate=1;
    producer_t *producers=calloc(8,sizeof(*producers));pthread_t *threads=calloc(8,sizeof(*threads));CHECK(producers&&threads);
    for(unsigned i=0;i<8;++i) { producers[i]=(producer_t){control,i};CHECK(!pthread_create(&threads[i],NULL,producer,&producers[i])); }
    for(unsigned i=0;i<8;++i) CHECK(!pthread_join(threads[i],NULL));
    free(threads);free(producers);wait_live(control,0);
    CHECK(control->created==control->closed);
    prep_guard=true;CHECK(io_event_service_shutdown(control->service)==-EINVAL&&io_event_service_destroy(control->service)==-EINVAL);prep_guard=false;
    CHECK(!io_event_service_shutdown(control->service)&&!io_event_service_destroy(control->service));control->service=NULL;
}
int main(void) {
    allocation_and_factory_failures();control_t *control=calloc(1,sizeof(*control));CHECK(control);
    pending_cancel_and_shutdown(control);concurrent_callers(control);free(control);
    CHECK(!live_allocations&&spawned==joined&&!held_locks&&!prep_guard&&!owned_preempt_depth);
    puts("IO_EVENT: PASS pending=4 fresh_progress=1 cancellation=1 cleanup=independent callers=8 jobs=1024 retained_join=1 OOM=1");return 0;
}
'''
    previous = os.environ.get('HOST_CC')
    try:
        os.environ['HOST_CC'] = shlex.join(shlex.split(previous or 'cc') + ['-pthread'])
        compile_and_run('io-event-service', code)
    finally:
        if previous is None: os.environ.pop('HOST_CC', None)
        else: os.environ['HOST_CC'] = previous
    print('Production multiplexed event executor contracts passed')

if __name__ == '__main__': main()
