#!/usr/bin/env python3
"""Run pending/active protected I/O executor against real host worker threads."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def without_includes(text):
    return "\n".join(line for line in text.splitlines() if not line.startswith("#include "))


def staged_sources():
    manifest = ROOT / "build/ports/zen/io-service-process.pending.json"
    paths = list(json.loads(manifest.read_text())["files"])
    active = (ROOT / "src/kernel/process/process_api.c").read_text()
    if "process_t *process_create_kernel_service(" in active:
        result = {path: (ROOT / path).read_text() for path in paths}
    else:
        with tempfile.TemporaryDirectory(prefix="alix-io-service-stage-") as directory:
            stage = Path(directory)
            for path in paths:
                dest = stage / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, dest)
            applied = subprocess.run(["patch", "--quiet", "-p1", "-i", str(ROOT / "build/ports/zen/io-service-process.pending.patch")],
                                     cwd=stage, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if applied.returncode:
                raise RuntimeError("pending I/O service patch does not apply: " + applied.stdout + applied.stderr)
            result = {path: (stage / path).read_text() for path in paths}
    for path in ("include/io_service.h", "src/kernel/io/service.c"):
        source = ROOT / (path + ".pending")
        result[path] = (source if source.exists() else ROOT / path).read_text()
    return result


def main():
    staged = staged_sources()
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"I/O executor line %d: %s\n",__LINE__,#c); abort(); } } while(0)
typedef struct syscall_stat syscall_stat_t;
typedef struct { uint32_t value; } spinlock_t;
typedef struct { bool initialized; } wait_queue_t;
typedef bool (*wait_queue_predicate_t)(void *);
typedef void (*thread_entry_t)(void *);
typedef struct process {
    pthread_t thread; thread_entry_t entry; void *argument;
    bool kernel_service, cleanup_role, exited, is_user; unsigned owner_refs; uint32_t uid,gid;
} process_t;
static _Thread_local process_t *current_process;
static _Thread_local unsigned held_locks;
static _Thread_local bool prep_guard;
static uint64_t g_io_cleanup_sequence;
static uint64_t process_io_admission_sequence(void){return __atomic_load_n(&g_io_cleanup_sequence,__ATOMIC_ACQUIRE);}
static void process_io_record_admission(uint64_t sequence){CHECK(prep_guard);(void)sequence;}
static _Thread_local int fail_allocation_after=-1;
static pthread_mutex_t heap_lock=PTHREAD_MUTEX_INITIALIZER;
typedef struct { void *address; size_t size; } allocation_t;
static allocation_t allocations[8192]; static unsigned live_allocations;
static uint32_t spawned,joined,spawn_calls;
static int fail_spawn_at=-1;
static bool hold_process_start;
static void *checked_calloc(size_t n,size_t bytes) {
    CHECK(!held_locks);
    if(fail_allocation_after==0) { fail_allocation_after=-1; return NULL; }
    if(fail_allocation_after>0) --fail_allocation_after;
    if(bytes && n>SIZE_MAX/bytes) return NULL;
    void *value=calloc(n,bytes); if(!value) return NULL;
    CHECK(!pthread_mutex_lock(&heap_lock)); CHECK(live_allocations<8192);
    allocations[live_allocations++]=(allocation_t){value,n*bytes};
    CHECK(!pthread_mutex_unlock(&heap_lock)); return value;
}
static void checked_free(void *value) {
    CHECK(!held_locks); if(!value) return;
    CHECK(!pthread_mutex_lock(&heap_lock)); unsigned index=0;
    while(index<live_allocations && allocations[index].address!=value) ++index; CHECK(index<live_allocations);
    allocations[index]=allocations[--live_allocations]; CHECK(!pthread_mutex_unlock(&heap_lock)); free(value);
}
static bool heap_contains(const void *value,size_t bytes) {
    bool found=false; uintptr_t address=(uintptr_t)value;
    CHECK(!pthread_mutex_lock(&heap_lock));
    for(unsigned i=0;i<live_allocations;++i) {
        uintptr_t base=(uintptr_t)allocations[i].address;
        if(address>=base && address-base<=allocations[i].size && bytes<=allocations[i].size-(address-base)) { found=true; break; }
    }
    CHECK(!pthread_mutex_unlock(&heap_lock)); return found;
}
#define calloc checked_calloc
#define free checked_free
static void spinlock_init(spinlock_t *lock) { lock->value=0; }
static void spinlock_lock(spinlock_t *lock) {
    while(__atomic_exchange_n(&lock->value,1,__ATOMIC_ACQUIRE)) sched_yield(); ++held_locks;
}
static void spinlock_unlock(spinlock_t *lock) { CHECK(held_locks); --held_locks; __atomic_store_n(&lock->value,0,__ATOMIC_RELEASE); }
static _Thread_local unsigned owned_preempt_depth;
static void spinlock_preempt_disable(void) { ++owned_preempt_depth; }
static void spinlock_preempt_enable(void) { CHECK(owned_preempt_depth); --owned_preempt_depth; }
static bool spinlock_preempt_disabled(void) { return prep_guard || held_locks || owned_preempt_depth; }
static pthread_mutex_t wait_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait_changed=PTHREAD_COND_INITIALIZER;
static void wait_queue_init(wait_queue_t *queue) { queue->initialized=true; }
static void wait_queue_wait(wait_queue_t *queue,wait_queue_predicate_t predicate,void *context) {
    CHECK(queue->initialized && !held_locks && !prep_guard && heap_contains(context,1));
    CHECK(!pthread_mutex_lock(&wait_lock)); ++held_locks;
    while(!predicate(context)) { --held_locks; CHECK(!pthread_cond_wait(&wait_changed,&wait_lock)); ++held_locks; }
    --held_locks; CHECK(!pthread_mutex_unlock(&wait_lock));
}
static void wait_queue_wake_all(wait_queue_t *queue) {
    CHECK(queue->initialized && !held_locks);
    CHECK(!pthread_mutex_lock(&wait_lock)); CHECK(!pthread_cond_broadcast(&wait_changed)); CHECK(!pthread_mutex_unlock(&wait_lock));
}
static void process_sleep_ms(uint32_t ms) {
    CHECK(!held_locks && !prep_guard); struct timespec pause={.tv_sec=0,.tv_nsec=(long)ms*1000000}; nanosleep(&pause,NULL);
}
static process_t *process_current(void) { return current_process; }
static void *host_process_entry(void *argument) {
    process_t *process=argument; current_process=process;
    CHECK(process->kernel_service && process->owner_refs==1 && heap_contains(process->argument,1));
    while(__atomic_load_n(&hold_process_start,__ATOMIC_ACQUIRE)) process_sleep_ms(1);
    process->entry(process->argument);
    __atomic_store_n(&process->exited,true,__ATOMIC_RELEASE); return NULL;
}
static process_t *process_create_kernel_service(const char *name,thread_entry_t entry,void *argument,size_t stack_size) {
    (void)stack_size; CHECK(!held_locks && heap_contains(argument,1));
    unsigned call=__atomic_fetch_add(&spawn_calls,1,__ATOMIC_RELAXED);
    if(fail_spawn_at>=0 && call==(unsigned)fail_spawn_at) return NULL;
    process_t *process=calloc(1,sizeof(*process)); if(!process) return NULL;
    process->kernel_service=true; process->owner_refs=1; process->entry=entry; process->argument=argument;
    process->cleanup_role=!strcmp(name,"io-cleanup");
    if(pthread_create(&process->thread,NULL,host_process_entry,process)!=0) { free(process); return NULL; }
    __atomic_fetch_add(&spawned,1,__ATOMIC_RELAXED); return process;
}
static int process_join_kernel_service(process_t *process,int *status) {
    CHECK(!held_locks && !prep_guard && process && process!=current_process && process->kernel_service && process->owner_refs==1);
    CHECK(!pthread_join(process->thread,NULL)); CHECK(__atomic_load_n(&process->exited,__ATOMIC_ACQUIRE));
    CHECK(process->owner_refs==1); process->owner_refs=0; if(status) *status=0;
    __atomic_fetch_add(&joined,1,__ATOMIC_RELAXED); free(process); return 0;
}
static void __attribute__((noreturn)) fatal(const char *message) { fprintf(stderr,"kernel fatal: %s\n",message); abort(); }
'''
    errors = (ROOT / "include/errno.h").read_text()
    for name in ("EINVAL", "ECANCELED", "EAGAIN", "ENOMEM", "EBADF", "EOVERFLOW", "EBUSY", "EDEADLK", "EIO", "EEXIST"):
        line = next(line for line in errors.splitlines() if line.startswith("#define " + name + " "))
        code += "\n#undef " + name + "\n" + line + "\n"
    for path in ("include/fd.h", "include/fd_table.h"):
        code += without_includes((ROOT / path).read_text()) + "\n"
    code += without_includes(staged["include/io_request.h"]) + "\n"
    code += without_includes(staged["include/io_service.h"]) + "\n"
    code += without_includes((ROOT / "src/kernel/fd/table.c").read_text()) + "\n"
    code += without_includes(staged["src/kernel/io/request.c"]) + "\n"
    code += "static wait_queue_t g_io_completion_queue={.initialized=true};\n"
    code += "static wait_queue_t g_io_cleanup_queue={.initialized=true};\n"
    code += r'''
static bool process_io_wait_cleanup(wait_queue_predicate_t predicate,void *context,uint64_t ticks) {
    CHECK(!held_locks&&!prep_guard&&heap_contains(context,1));
    struct timespec deadline; CHECK(!clock_gettime(CLOCK_REALTIME,&deadline));
    deadline.tv_nsec+=(long)ticks*10000000; deadline.tv_sec+=deadline.tv_nsec/1000000000; deadline.tv_nsec%=1000000000;
    CHECK(!pthread_mutex_lock(&wait_lock)); ++held_locks;
    bool ready;
    while(!(ready=predicate(context))) {
        --held_locks; int result=pthread_cond_timedwait(&wait_changed,&wait_lock,&deadline); ++held_locks;
        CHECK(!result||result==ETIMEDOUT); if(result==ETIMEDOUT)break;
    }
    --held_locks; CHECK(!pthread_mutex_unlock(&wait_lock)); return ready;
}
static bool process_io_wait_cleanup_for(uintptr_t key,wait_queue_predicate_t predicate,void *context,uint64_t ticks) {
    (void)key; return process_io_wait_cleanup(predicate,context,ticks);
}
'''
    code += "static uint64_t g_io_completion_broadcasts;\n"
    glue = (ROOT / "src/kernel/process/process_io.c").read_text()
    for signature in ("void process_io_notify_completion(", "void process_io_notify_cleanup(", "int process_io_complete_request("):
        if signature == "int process_io_complete_request(":
            code += "static void process_io_notify_request(io_request_t *request) { (void)request; process_io_notify_completion(); }\n"
            code += "static void process_io_notify_cleanup_for(uintptr_t key) { (void)key; process_io_notify_cleanup(); }\n"
        code += function_definition(glue, signature) + "\n"
    code += without_includes(staged["src/kernel/io/service.c"]) + r'''

typedef struct {
    io_service_t *service; wait_queue_t latch;
    bool release; uint32_t blocked,handled,input_closed,output_closed,cwd_closed;
} control_t;
typedef struct { control_t *control; unsigned kind; bool reenter; uint64_t magic; } asset_t;
typedef struct { control_t *control; unsigned kind; unsigned char payload[32]; } job_t;
#define MAGIC UINT64_C(0x1122aabbccdd3344)
static void finalizer_checks(asset_t *asset) {
    CHECK(!held_locks && current_process && current_process->cleanup_role && asset->magic==MAGIC);
    if(asset->reenter) {
        io_service_status_t status; CHECK(io_service_snapshot(asset->control->service,&status)==0 && status.queue.live>0);
        CHECK(io_service_shutdown(asset->control->service)==-EDEADLK);
        CHECK(io_service_destroy(asset->control->service)==-EBUSY);
        prep_guard=true; io_request_t *nested=NULL;
        int result=io_service_request_create(asset->control->service,0,1,2,&nested);
        CHECK(result==0 || result==-ECANCELED || result==-EAGAIN);
        if(!result) CHECK(io_request_waiter_abandon(nested)==0);
        prep_guard=false;
    }
}
static int close_asset(void *value) {
    asset_t *asset=value; finalizer_checks(asset);
    uint32_t *count=asset->kind ? &asset->control->output_closed : &asset->control->input_closed;
    __atomic_fetch_add(count,1,__ATOMIC_RELEASE); asset->magic=0; free(asset); return 0;
}
static void release_cwd(void *value) {
    asset_t *asset=value; finalizer_checks(asset);
    __atomic_fetch_add(&asset->control->cwd_closed,1,__ATOMIC_RELEASE); asset->magic=0; free(asset);
}
static const fd_ops_t operations={.close=close_asset};
static fd_description_t *make_description(control_t *control,unsigned kind,bool reenter) {
    asset_t *asset=calloc(1,sizeof(*asset)); CHECK(asset);
    *asset=(asset_t){control,kind,reenter,MAGIC};
    fd_description_t *description=fd_description_create(&operations,asset); CHECK(description); return description;
}
static bool released(void *context) { return __atomic_load_n(&((control_t *)context)->release,__ATOMIC_ACQUIRE); }
static void handle_request(io_request_t *request,io_service_result_t *result) {
    CHECK(!held_locks && !prep_guard && current_process && !current_process->cleanup_role && current_process->kernel_service);
    CHECK(heap_contains(result,sizeof(*result)) && io_request_uid(request)==37 && io_request_gid(request)==41);
    CHECK(current_process->uid==0 && current_process->gid==0); /* Request credentials are explicit, not worker identity. */
    asset_t *input=fd_description_context(io_request_description(request));
    asset_t *cwd=io_request_cwd(request); CHECK(input->magic==MAGIC && cwd->magic==MAGIC);
    job_t *job=io_request_buffer(request); CHECK(heap_contains(job,sizeof(*job)));
    control_t *control=job->control;
    __atomic_fetch_add(&control->handled,1,__ATOMIC_RELEASE);
    if(job->kind==1) {
        __atomic_fetch_add(&control->blocked,1,__ATOMIC_RELEASE);
        wait_queue_wait(&control->latch,released,control);
        CHECK(input->magic==MAGIC && cwd->magic==MAGIC); /* Survives abandoned caller. */
    }
    if(job->kind==2) { result->result=-ENOMEM; return; }
    memset(job->payload,0x5a,sizeof(job->payload));
    result->result=32; result->description_owned=make_description(control,1,false);
}
static io_request_t *make_request(control_t *control,unsigned kind,bool reenter) {
    prep_guard=true; io_request_t *request=NULL;
    CHECK(io_service_request_create(control->service,sizeof(job_t),37,41,&request)==0);
    job_t *job=io_request_buffer(request); job->control=control; job->kind=kind;
    asset_t *cwd=calloc(1,sizeof(*cwd)); CHECK(cwd); *cwd=(asset_t){control,0,false,MAGIC};
    CHECK(io_request_bind(request,make_description(control,0,reenter),cwd,release_cwd)==0);
    return request;
}
static bool request_done(void *context) {
    io_request_status_t status; CHECK(io_request_status(context,&status)==0);
    return status.cancelled || status.state==IO_REQUEST_COMPLETED;
}
static void await_count(uint32_t *count,uint32_t expected) {
    for(unsigned attempt=0;attempt<5000;++attempt) {
        if(__atomic_load_n(count,__ATOMIC_ACQUIRE)>=expected) return;
        process_sleep_ms(1);
    }
    CHECK(!"timed out waiting for service progress");
}
static void startup_failures(void) {
    prep_guard=true; fail_allocation_after=0; uint32_t before=spawn_calls;
    CHECK(!io_service_create(4,2,handle_request) && fail_allocation_after==0 && spawn_calls==before);
    prep_guard=false; fail_allocation_after=-1;
    CHECK(!io_service_create(0,1,handle_request) && !io_service_create(1,0,handle_request));
    CHECK(!io_service_create(1,IO_SERVICE_MAX_WORKERS+1,handle_request) && !io_service_create(1,1,NULL));
    for(int failure=0;failure<6;++failure) {
        spawn_calls=0; fail_allocation_after=failure;
        CHECK(!io_service_create(4,2,handle_request)); fail_allocation_after=-1;
        CHECK(live_allocations==0 && spawned==joined);
    }
    for(int failure=0;failure<3;++failure) {
        spawn_calls=0; fail_spawn_at=failure; CHECK(!io_service_create(4,2,handle_request)); fail_spawn_at=-1;
        CHECK(live_allocations==0 && spawned==joined);
    }
    io_service_t *service=io_service_create(2,1,handle_request); CHECK(service);
    prep_guard=true; uint32_t joined_before=joined;
    CHECK(io_service_shutdown(service)==-EINVAL && io_service_destroy(service)==-EINVAL && joined==joined_before);
    io_service_status_t status; CHECK(io_service_snapshot(service,&status)==0 && !status.stopping && !status.queue.closed);
    prep_guard=false; CHECK(io_service_shutdown(service)==0);
    prep_guard=true; CHECK(io_service_destroy(service)==-EINVAL);
    CHECK(io_service_snapshot(service,&status)==0 && status.stopped);
    prep_guard=false; CHECK(io_service_destroy(service)==0 && live_allocations==0 && spawned==joined);
}
static void ordinary_and_wrong_queue(void) {
    control_t *control=calloc(1,sizeof(*control)); CHECK(control); wait_queue_init(&control->latch);
    __atomic_store_n(&hold_process_start,true,__ATOMIC_RELEASE);
    control->service=io_service_create(8,2,handle_request); CHECK(control->service);
    io_service_t *other=io_service_create(1,1,handle_request); CHECK(other);
    io_request_t *request=make_request(control,0,true);
    CHECK(io_service_submit(other,request)==-EINVAL);
    CHECK(io_service_submit(control->service,request)==0); prep_guard=false;
    /* Submission/wake occurs before either worker has entered its wait. */
    __atomic_store_n(&hold_process_start,false,__ATOMIC_RELEASE);
    await_count(&control->handled,1);
    io_request_status_t status;
    do { CHECK(io_request_status(request,&status)==0); process_sleep_ms(1); } while(status.state!=IO_REQUEST_COMPLETED);
    /* Completion/wake occurs before the caller enters its wait as well. */
    wait_queue_wait(&g_io_completion_queue,request_done,request);
    CHECK(io_request_status(request,&status)==0 && !status.cancelled && status.result==32);
    job_t *job=io_request_buffer(request); for(unsigned i=0;i<32;++i) CHECK(job->payload[i]==0x5a);
    prep_guard=true; fd_description_t *output=NULL; CHECK(io_request_take_result(request,&output)==0 && output);
    CHECK(io_request_waiter_release(request)==0);
    io_request_t *retirement=NULL; CHECK(io_service_request_create(control->service,0,1,2,&retirement)==0);
    CHECK(io_request_bind(retirement,output,NULL,NULL)==0 && io_request_waiter_abandon(retirement)==0); prep_guard=false;
    await_count(&control->output_closed,1); await_count(&control->input_closed,1);
    request=make_request(control,2,false); CHECK(io_service_submit(control->service,request)==0); prep_guard=false;
    wait_queue_wait(&g_io_completion_queue,request_done,request);
    CHECK(io_request_status(request,&status)==0 && status.result==-ENOMEM);
    prep_guard=true; CHECK(io_request_waiter_release(request)==0); prep_guard=false;
    CHECK(io_service_shutdown(control->service)==0 && io_service_shutdown(control->service)==0);
    CHECK(io_service_destroy(control->service)==0);
    CHECK(io_service_shutdown(other)==0 && io_service_destroy(other)==0);
    CHECK(control->input_closed==2 && control->output_closed==1 && control->cwd_closed==2);
    free(control); CHECK(live_allocations==0 && spawned==joined);
}
typedef struct { io_service_t *service; pthread_t thread; bool done; int result; } stopper_t;
static void *stop_service(void *context) {
    stopper_t *stop=context; stop->result=io_service_shutdown(stop->service);
    __atomic_store_n(&stop->done,true,__ATOMIC_RELEASE); return NULL;
}
static void blocked_continuations_and_independent_cleanup(void) {
    control_t *control=calloc(1,sizeof(*control)); CHECK(control); wait_queue_init(&control->latch);
    control->service=io_service_create(3,2,handle_request); CHECK(control->service);
    for(unsigned i=0;i<2;++i) {
        io_request_t *request=make_request(control,1,false);
        CHECK(io_service_submit(control->service,request)==0); prep_guard=false;
        await_count(&control->blocked,i+1);
        prep_guard=true; CHECK(io_request_waiter_abandon(request)==0); prep_guard=false;
    }
    io_request_t *queued=make_request(control,0,true);
    CHECK(io_service_submit(control->service,queued)==0);
    io_request_t *extra=NULL; CHECK(io_service_request_create(control->service,0,1,2,&extra)==-EAGAIN && !extra);
    process_t *user=calloc(1,sizeof(*user)); CHECK(user); user->is_user=true; current_process=user;
    CHECK(io_service_request_create(control->service,0,1,2,&extra)==IO_REQUEST_ADMISSION_RETRY && !extra);
    current_process=NULL; free(user);
    CHECK(io_request_waiter_abandon(queued)==0); prep_guard=false;
    await_count(&control->input_closed,1); /* Both storage workers are still blocked. */
    CHECK(control->handled==2 && control->blocked==2);
    stopper_t *stop=calloc(1,sizeof(*stop)); CHECK(stop); stop->service=control->service;
    CHECK(!pthread_create(&stop->thread,NULL,stop_service,stop));
    io_service_status_t status;
    do { CHECK(io_service_snapshot(control->service,&status)==0); process_sleep_ms(1); } while(!status.stopping);
    CHECK(!__atomic_load_n(&stop->done,__ATOMIC_ACQUIRE));
    CHECK(io_service_shutdown(control->service)==-EBUSY);
    prep_guard=true; CHECK(io_service_request_create(control->service,0,1,2,&extra)==-ECANCELED && !extra); prep_guard=false;
    __atomic_store_n(&control->release,true,__ATOMIC_RELEASE); wait_queue_wake_all(&control->latch);
    CHECK(!pthread_join(stop->thread,NULL) && stop->result==0 && stop->done);
    CHECK(control->input_closed==3 && control->output_closed==2 && control->cwd_closed==3);
    CHECK(io_service_destroy(control->service)==0); free(stop); free(control);
    CHECK(live_allocations==0 && spawned==joined);
}
static void shutdown_waits_for_waiter_owner(void) {
    control_t *control=calloc(1,sizeof(*control)); CHECK(control); wait_queue_init(&control->latch);
    control->service=io_service_create(2,1,handle_request); CHECK(control->service);
    io_request_t *request=make_request(control,0,false); CHECK(io_service_submit(control->service,request)==0); prep_guard=false;
    wait_queue_wait(&g_io_completion_queue,request_done,request);
    stopper_t *stop=calloc(1,sizeof(*stop)); CHECK(stop); stop->service=control->service;
    CHECK(!pthread_create(&stop->thread,NULL,stop_service,stop));
    io_service_status_t status;
    do { CHECK(io_service_snapshot(control->service,&status)==0); process_sleep_ms(1); } while(!status.stopping || status.active_workers);
    CHECK(!__atomic_load_n(&stop->done,__ATOMIC_ACQUIRE) && status.queue.live==1 && !control->input_closed);
    prep_guard=true; CHECK(io_request_waiter_abandon(request)==0); prep_guard=false;
    CHECK(!pthread_join(stop->thread,NULL) && stop->result==0);
    CHECK(io_service_destroy(control->service)==0); free(stop); free(control);
    CHECK(live_allocations==0 && spawned==joined);
}
int main(void) {
    alarm(20); /* A lost wake must fail the test rather than hang the runner. */
    startup_failures(); ordinary_and_wrong_queue(); blocked_continuations_and_independent_cleanup(); shutdown_waits_for_waiter_owner();
    CHECK(live_allocations==0 && spawned==joined && !held_locks && !prep_guard);
    alarm(0);
    puts("production protected I/O executor startup failures, captured authority, cancellation and independent cleanup passed");
    return 0;
}
'''
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("io-service", code)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("protected I/O executor contracts passed")


if __name__ == "__main__":
    main()
