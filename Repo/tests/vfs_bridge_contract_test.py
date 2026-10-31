#!/usr/bin/env python3
"""Exercise production syscall bridge with real request/FD/context ownership."""
import contextlib
import io
import os
import shlex
import sys

sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run
import process_owned_cwd_contract_test as cwd_test


def main():
    captured=[]
    original=cwd_test.compile_and_run
    cwd_test.compile_and_run=lambda label,program:captured.append(program)
    try:
        with contextlib.redirect_stdout(io.StringIO()): cwd_test.main()
    finally:
        cwd_test.compile_and_run=original
    code=captured[0].replace("int main(void) {","static int cwd_contract_main(void) {",1)
    code=code.replace("typedef struct syscall_stat syscall_stat_t;", "typedef struct syscall_stat { uint64_t size_bytes; uint32_t type,reserved; uint64_t atime,mtime,ctime; } syscall_stat_t;",1)
    code=code.replace("    int state,lifetime_state;\n} process_t;","    int state,lifetime_state; uint64_t pid; struct process *next;\n} process_t;")
    def stripped(path):
        return "\n".join(line for line in path.read_text().splitlines() if not line.startswith("#include "))
    for path in (ROOT/"include/io_service.h",ROOT/"build/ports/zen/vfs-owned-io/include/io_vfs.h",ROOT/"build/ports/zen/vfs-bridge/include/io_vfs_service.h"):
        code+=stripped(path)+"\n"
    code+=r'''
#define VFS_PATH_MAX 4096u
static spinlock_t g_process_lock;
static process_t *g_process_list;
static bool scheduler_held;
static uint64_t scheduler_lock_acquire(const char *label) { (void)label; CHECK(!scheduler_held && preempt && !locks); scheduler_held=true; return 0; }
static void scheduler_lock_release(uint64_t flags) { (void)flags; CHECK(scheduler_held && !locks); scheduler_held=false; }
struct io_service { io_queue_t *queue; io_service_handler_t handler; io_service_result_t *result; io_request_t *active; };
static io_request_t *registered;
static bool fail_service,fail_register,fail_copyout,complete_on_submit,cancel_queued,cancel_running,mark_target_dead,bad_result;
static unsigned worker_calls,copyouts;
static process_t *model_target;
static void run_worker(io_service_t *service) {
    io_request_t *r=service->active?service->active:io_queue_take(service->queue); if(!r) return;
    service->active=NULL; unsigned saved=preempt; preempt=0; bool previous=cleanup_worker; cleanup_worker=true;
    service->result->result=-EIO; service->result->description_owned=NULL; service->handler(r,service->result); ++worker_calls;
    CHECK(!io_request_publish_complete(r,service->result->result,service->result->description_owned));
    CHECK(!io_request_worker_release(r)); cleanup_worker=previous; preempt=saved;
}
io_service_t *io_service_create(size_t capacity,uint32_t workers,io_service_handler_t handler) {
    CHECK(!preempt && !locks && capacity==128 && workers==2); if(fail_service) return NULL;
    io_service_t *s=calloc(1,sizeof(*s)); CHECK(s); s->queue=io_queue_create(capacity); s->result=calloc(1,sizeof(*s->result)); CHECK(s->queue && s->result); s->handler=handler; return s;
}
int io_service_request_create(io_service_t *s,size_t bytes,uint32_t uid,uint32_t gid,io_request_t **out) {
    CHECK(preempt && !locks); return io_request_create(s->queue,bytes,uid,gid,out);
}
int io_service_submit(io_service_t *s,io_request_t *r) {
    CHECK(preempt && registered==r); int result=io_request_submit(r); if(!result && complete_on_submit) run_worker(s); return result;
}
int io_service_snapshot(io_service_t *s,io_service_status_t *out) { memset(out,0,sizeof(*out)); return io_queue_snapshot(s->queue,&out->queue); }
int process_io_register_current(io_request_t *r) { CHECK(preempt && !registered); if(fail_register) return -ECANCELED; registered=r; return 0; }
static io_service_t *model_service;
int process_io_wait_current(io_request_status_t *out) {
    CHECK(!preempt && !locks && registered);
    if(cancel_running) { model_service->active=io_queue_take(model_service->queue); CHECK(model_service->active==registered); CHECK(!io_request_cancel(registered)); return -ECANCELED; }
    if(cancel_queued) { CHECK(!io_request_cancel(registered)); return -ECANCELED; }
    run_worker(model_service); CHECK(!io_request_status(registered,out)); CHECK(out->state==IO_REQUEST_COMPLETED); return 0;
}
int process_io_result_current(io_request_t **out,io_request_status_t *status) {
    CHECK(preempt && registered); int rc=io_request_status(registered,status); if(!rc && status->cancelled) rc=-ECANCELED; *out=rc?NULL:registered; return rc;
}
int process_io_finish_current(bool abandon) {
    CHECK(preempt && registered); io_request_t *r=registered; registered=NULL;
    return abandon?io_request_waiter_abandon(r):io_request_waiter_release(r);
}
bool user_ptr_range_valid(const void *p,size_t size) { return (uintptr_t)p>4096 && size<=UINTPTR_MAX-(uintptr_t)p; }
int user_copy_cstring_from_user(char *dst,size_t capacity,const char *src,size_t *length) {
    CHECK(preempt && !locks); if((uintptr_t)src<=4096) return -EFAULT;
    for(size_t i=0;i<capacity;++i) { dst[i]=src[i]; if(!dst[i]) { if(length) *length=i; return 0; } } return -ENAMETOOLONG;
}
bool user_copy_to_user(void *dst,const void *src,size_t size) {
    CHECK(preempt && !locks && size<VFS_PATH_MAX); ++copyouts; if(fail_copyout) return false; memcpy(dst,src,size); return true;
}
void io_vfs_execute(io_request_t *r,io_service_result_t *result,fd_retirement_queue_t *q) {
    CHECK(!locks && !preempt && cleanup_worker && q==g_process_retirement);
    CHECK(io_request_uid(r)==37 && io_request_gid(r)==41);
    vfs_node_t *cwd=io_request_cwd(r); CHECK(cwd && cwd->refs==1 && cwd->directory);
    io_vfs_operation_t *op=io_request_buffer(r);
    if(op->opcode==IO_VFS_READLINK) {
        if(!op->data[0]) { result->result=-ENOENT; return; }
        if(!strcmp((char*)op->data,"missing")) { result->result=-ENOENT; return; }
        size_t bytes=op->count<6?op->count:6; memcpy(op->data,"target",bytes); result->result=bad_result?(int64_t)op->count+1:(int64_t)bytes;
    } else {
        CHECK(op->opcode==IO_VFS_RESOLVE_CWD); vfs_node_t *node=new_node();
        result->description_owned=process_cwd_description_create_owned(node); CHECK(result->description_owned); result->result=0;
        if(mark_target_dead) model_target->state=PROCESS_STATE_ZOMBIE;
    }
}
'''
    code+=stripped(ROOT/"build/ports/zen/vfs-bridge/src/kernel/process/process_cwd_apply.c")+"\n"
    code+=stripped(ROOT/"build/ports/zen/vfs-bridge/src/kernel/io/vfs_service.c")+r'''
static void clean_requests(void) {
    CHECK(!registered && !preempt && !locks); cleanup_worker=true;
    while(io_queue_drain(model_service->queue,8)) {} cleanup_worker=false; drain();
}
static void check_clean(void) { clean_requests(); io_queue_status_t status; CHECK(!io_queue_snapshot(model_service->queue,&status) && !status.live && !status.queued && !status.cleanup); }
int main(void) {
    CHECK(!cwd_contract_main());
    g_process_retirement=NULL; g_process_retirement_worker=NULL; g_process_retirement_start=0; root=NULL;
    process_resource_system_init(); root=new_node(); current_process=new_process(NULL); current_process->pid=1;
    install(current_process,node_owner(new_node())); process_set_identity(current_process,37,41); drain();
    model_target=new_process(current_process); model_target->pid=2; current_process->next=model_target; g_process_list=current_process;
    char *path=calloc(4097,1),*output=calloc(8192,1); CHECK(path && output); strcpy(path,"link");
    CHECK(io_vfs_readlink_user(path,output,8)==-ENOSYS && !registered);
    fail_service=true; CHECK(!io_vfs_service_start()); fail_service=false; CHECK(io_vfs_service_start() && io_vfs_service_start()); model_service=g_vfs_service;
    memset(output,0x55,8192); CHECK(io_vfs_readlink_user(path,output,8192)==6 && !memcmp(output,"target",6) && output[6]==0x55); check_clean();
    complete_on_submit=true; CHECK(io_vfs_readlink_user(path,output,2)==2 && !memcmp(output,"ta",2)); complete_on_submit=false; check_clean();
    CHECK(io_vfs_readlink_user(path,output,0)==-EINVAL && io_vfs_readlink_user(path,(void*)1,8)==-EFAULT && !registered);
    CHECK(io_vfs_readlink_user((void*)1,output,8)==-EFAULT); check_clean();
    memset(path,'x',4096); path[4096]=0; CHECK(io_vfs_readlink_user(path,output,8)==-ENAMETOOLONG); check_clean(); strcpy(path,"link");
    fail_allocations=1; CHECK(io_vfs_readlink_user(path,output,8)==-ENOMEM); check_clean();
    model_service->queue->capacity=0; CHECK(io_vfs_readlink_user(path,output,8)==-EAGAIN); model_service->queue->capacity=128; check_clean();
    fail_register=true; CHECK(io_vfs_readlink_user(path,output,8)==-ECANCELED); fail_register=false; check_clean();
    fail_copyout=true; CHECK(io_vfs_readlink_user(path,output,8)==-EFAULT); fail_copyout=false; check_clean();
    bad_result=true; unsigned copied=copyouts; CHECK(io_vfs_readlink_user(path,output,8)==-EIO && copyouts==copied); bad_result=false; check_clean();
    cancel_queued=true; CHECK(io_vfs_readlink_user(path,output,8)==-ECANCELED); cancel_queued=false; check_clean();
    cancel_running=true; CHECK(io_vfs_readlink_user(path,output,8)==-ECANCELED && model_service->active); cancel_running=false;
    CHECK(!registered); run_worker(model_service); check_clean();
    CHECK(io_vfs_readlink_kernel(path,output,8)==6); check_clean();
    CHECK(io_vfs_change_cwd_kernel("dir",2)==0 && current_process->cwd_owner==model_target->cwd_owner); check_clean();
    fd_description_t *before=current_process->cwd_owner; CHECK(io_vfs_change_cwd_kernel("dir",999)==-ESRCH && current_process->cwd_owner==before); check_clean();
    mark_target_dead=true; CHECK(io_vfs_change_cwd_kernel("dir",2)==-ESRCH && current_process->cwd_owner==before); mark_target_dead=false; model_target->state=PROCESS_STATE_READY; check_clean();
    CHECK(io_vfs_change_cwd_kernel("dir",0)==0 && current_process->cwd_owner!=before); check_clean();
    CHECK(!preempt && !locks && !scheduler_held && worker_calls>5);
    drop_process(model_target); drop_process(current_process); current_process=NULL; g_process_list=NULL; drain();
    io_queue_shutdown(model_service->queue); CHECK(!io_queue_destroy(model_service->queue)); free(model_service->result); free(model_service); g_vfs_service=NULL;
    cleanup_worker=true; vfs_node_release(root); cleanup_worker=false; fd_retirement_queue_shutdown(g_process_retirement); CHECK(!fd_retirement_queue_destroy(g_process_retirement));
    free(path); free(output); CHECK(!allocations);
    puts("VFS bridge: PASS typed copy/oversize/OOM/admission/registration/completion/cancellation/PID cwd ownership"); return 0;
}
'''
    previous=os.environ.get("HOST_CC")
    os.environ["HOST_CC"]=shlex.join(shlex.split(previous or "cc")+["-pthread"])
    try: compile_and_run("vfs-bridge",code)
    finally:
        if previous is None: os.environ.pop("HOST_CC",None)
        else: os.environ["HOST_CC"]=previous
    print("protected VFS bridge production contracts: PASS")


if __name__=="__main__": main()
